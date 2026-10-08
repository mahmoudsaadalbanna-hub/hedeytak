const express = require("express");
const path = require("path");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = Number(process.env.PORT || 3000);

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("ERROR: JWT_SECRET must be set and at least 32 characters.");
  process.exit(1);
}

if (!ADMIN_EMAIL || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.error("ERROR: ADMIN_EMAIL and ADMIN_PASSWORD must be set.");
  process.exit(1);
}

const db = new Database(path.join(__dirname, "store.db"));

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

/* =========================
   DATABASE
========================= */

db.exec(`
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  price INTEGER NOT NULL,
  stock INTEGER NOT NULL DEFAULT 0,
  category TEXT DEFAULT 'عام',
  image TEXT DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  address TEXT NOT NULL,
  items_json TEXT NOT NULL,
  total INTEGER NOT NULL,
  payment_method TEXT NOT NULL DEFAULT 'cod',
  shipping_method TEXT NOT NULL DEFAULT 'manual',
  status TEXT NOT NULL DEFAULT 'new',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`);

/* =========================
   ADMIN
========================= */

const existingAdmin = db
  .prepare("SELECT id FROM admins WHERE email = ?")
  .get(ADMIN_EMAIL);

if (!existingAdmin) {
  const passwordHash = bcrypt.hashSync(ADMIN_PASSWORD, 12);

  db.prepare(
    "INSERT INTO admins(email, password_hash) VALUES(?, ?)"
  ).run(ADMIN_EMAIL, passwordHash);
}

/* =========================
   SETTINGS
========================= */

const defaults = {
  shipping_enabled: "1",
  shipping_flat: "0",
  free_shipping_from: "0",
  cod_enabled: "1",
  online_payment_enabled: "0",
};

const insertSetting = db.prepare(
  "INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)"
);

for (const [key, value] of Object.entries(defaults)) {
  insertSetting.run(key, value);
}

/* =========================
   BASIC LOGIN RATE LIMIT
========================= */

const loginAttempts = new Map();

const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000;

function getClientKey(req) {
  return req.ip || "unknown";
}

function checkLoginLimit(req) {
  const key = getClientKey(req);
  const now = Date.now();

  let data = loginAttempts.get(key);

  if (!data || now - data.firstAttempt > WINDOW_MS) {
    data = {
      count: 0,
      firstAttempt: now,
    };
  }

  if (data.count >= MAX_ATTEMPTS) {
    return false;
  }

  data.count++;
  loginAttempts.set(key, data);

  return true;
}

/* =========================
   AUTH
========================= */

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "غير مصرح",
      });
    }

    const token = header.slice(7);

    const decoded = jwt.verify(token, JWT_SECRET);

    req.admin = decoded;

    next();
  } catch {
    return res.status(401).json({
      error: "جلسة الدخول غير صالحة",
    });
  }
}

/* =========================
   HEALTH
========================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    store: "هديتك",
  });
});

/* =========================
   PRODUCTS
========================= */

app.get("/api/products", (req, res) => {
  const products = db
    .prepare(
      `SELECT id,name,description,price,stock,category,image,active
       FROM products
       WHERE active=1
       ORDER BY id DESC`
    )
    .all();

  res.json(products);
});

/* =========================
   ORDERS
========================= */

app.post("/api/orders", (req, res) => {
  try {
    const {
      customer_name,
      phone,
      address,
      items,
      payment_method = "cod",
      shipping_method = "manual",
    } = req.body;

    if (
      typeof customer_name !== "string" ||
      !customer_name.trim() ||
      typeof phone !== "string" ||
      !phone.trim() ||
      typeof address !== "string" ||
      !address.trim() ||
      !Array.isArray(items) ||
      items.length === 0
    ) {
      return res.status(400).json({
        error: "بيانات الطلب غير مكتملة",
      });
    }

    if (items.length > 50) {
      return res.status(400).json({
        error: "عدد المنتجات في الطلب كبير جدًا",
      });
    }

    let calculatedTotal = 0;

    const transaction = db.transaction(() => {
      for (const item of items) {
        const productId = Number(item.id);
        const qty = Number(item.qty);

        if (
          !Number.isInteger(productId) ||
          !Number.isInteger(qty) ||
          qty <= 0 ||
          qty > 100
        ) {
          throw new Error("بيانات المنتج غير صحيحة");
        }

        const product = db
          .prepare(
            `SELECT id,name,price,stock
             FROM products
             WHERE id=? AND active=1`
          )
          .get(productId);

        if (!product) {
          throw new Error("المنتج غير موجود");
        }

        if (product.stock < qty) {
          throw new Error(`الكمية غير متاحة للمنتج: ${product.name}`);
        }

        calculatedTotal += product.price * qty;
      }

      for (const item of items) {
        const productId = Number(item.id);
        const qty = Number(item.qty);

        db.prepare(
          "UPDATE products SET stock = stock - ? WHERE id = ?"
        ).run(qty, productId);
      }

      return db
        .prepare(
          `INSERT INTO orders
          (
            customer_name,
            phone,
            address,
            items_json,
            total,
            payment_method,
            shipping_method
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          customer_name.trim(),
          phone.trim(),
          address.trim(),
          JSON.stringify(items),
          calculatedTotal,
          String(payment_method),
          String(shipping_method)
        );
    });

    res.status(201).json({
      ok: true,
      order_id: transaction.lastInsertRowid,
      total: calculatedTotal,
      payment_status: "pending",
    });
  } catch (error) {
    res.status(400).json({
      error: error.message || "تعذر إنشاء الطلب",
    });
  }
});

/* =========================
   ADMIN LOGIN
========================= */

app.post("/api/admin/login", (req, res) => {
  if (!checkLoginLimit(req)) {
    return res.status(429).json({
      error: "محاولات دخول كثيرة. حاول مرة أخرى بعد قليل.",
    });
  }

  const email =
    typeof req.body.email === "string"
      ? req.body.email.trim()
      : "";

  const password =
    typeof req.body.password === "string"
      ? req.body.password
      : "";

  if (!email || !password) {
    return res.status(400).json({
      error: "أدخل البريد وكلمة المرور",
    });
  }

  const admin = db
    .prepare("SELECT * FROM admins WHERE email=?")
    .get(email);

  if (
    !admin ||
    !bcrypt.compareSync(password, admin.password_hash)
  ) {
    return res.status(401).json({
      error: "بيانات الدخول غير صحيحة",
    });
  }

  const token = jwt.sign(
    {
      id: admin.id,
      email: admin.email,
    },
    JWT_SECRET,
    {
      expiresIn: "8h",
    }
  );

  res.json({
    token,
  });
});

/* =========================
   ADMIN ORDERS
========================= */

app.get("/api/admin/orders", auth, (req, res) => {
  const orders = db
    .prepare("SELECT * FROM orders ORDER BY id DESC")
    .all();

  res.json(orders);
});

/* =========================
   ADMIN PRODUCTS
========================= */

app.get("/api/admin/products", auth, (req, res) => {
  const products = db
    .prepare("SELECT * FROM products ORDER BY id DESC")
    .all();

  res.json(products);
});

app.post("/api/admin/products", auth, (req, res) => {
  const {
    name,
    description = "",
    price,
    stock = 0,
    category = "عام",
    image = "",
  } = req.body;

  const numericPrice = Number(price);
  const numericStock = Number(stock);

  if (
    typeof name !== "string" ||
    !name.trim() ||
    !Number.isFinite(numericPrice) ||
    numericPrice < 0 ||
    !Number.isInteger(numericStock) ||
    numericStock < 0
  ) {
    return res.status(400).json({
      error: "بيانات المنتج غير صحيحة",
    });
  }

  const result = db
    .prepare(
      `INSERT INTO products
      (name,description,price,stock,category,image)
      VALUES (?, ?, ?, ?, ?, ?)`
    )
    .run(
      name.trim(),
      String(description),
      numericPrice,
      numericStock,
      String(category),
      String(image)
    );

  res.json({
    id: result.lastInsertRowid,
  });
});

/* =========================
   ADMIN ORDER STATUS
========================= */

app.patch("/api/admin/orders/:id", auth, (req, res) => {
  const allowed = [
    "new",
    "processing",
    "shipped",
    "delivered",
    "cancelled",
  ];

  if (!allowed.includes(req.body.status)) {
    return res.status(400).json({
      error: "حالة غير صحيحة",
    });
  }

  const orderId = Number(req.params.id);

  if (!Number.isInteger(orderId)) {
    return res.status(400).json({
      error: "رقم الطلب غير صحيح",
    });
  }

  db.prepare(
    "UPDATE orders SET status=? WHERE id=?"
  ).run(req.body.status, orderId);

  res.json({
    ok: true,
  });
});

/* =========================
   ADMIN SETTINGS
========================= */

app.get("/api/admin/settings", auth, (req, res) => {
  const rows = db
    .prepare("SELECT key,value FROM settings")
    .all();

  res.json(
    Object.fromEntries(
      rows.map((row) => [row.key, row.value])
    )
  );
});

app.patch("/api/admin/settings", auth, (req, res) => {
  const stmt = db.prepare(
    `INSERT INTO settings(key,value)
     VALUES(?,?)
     ON CONFLICT(key)
     DO UPDATE SET value=excluded.value`
  );

  const transaction = db.transaction((data) => {
    for (const [key, value] of Object.entries(data)) {
      stmt.run(String(key), String(value));
    }
  });

  transaction(req.body || {});

  res.json({
    ok: true,
  });
});

/* =========================
   FRONTEND
========================= */

app.use((req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

/* =========================
   START
========================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`هديتك يعمل على المنفذ ${PORT}`);
});
