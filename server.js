const express = require("express");
const path = require("path");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_IN_PRODUCTION";
const db = new Database(path.join(__dirname, "store.db"));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

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

const adminEmail = process.env.ADMIN_EMAIL || "admin@example.com";
const adminPassword = process.env.ADMIN_PASSWORD || "CHANGE_THIS_NOW";
if (!db.prepare("SELECT id FROM admins WHERE email=?").get(adminEmail)) {
  db.prepare("INSERT INTO admins(email,password_hash) VALUES(?,?)")
    .run(adminEmail, bcrypt.hashSync(adminPassword, 12));
}

const defaults = {
  shipping_enabled: "1",
  shipping_flat: "0",
  free_shipping_from: "0",
  cod_enabled: "1",
  online_payment_enabled: "0"
};
for (const [k,v] of Object.entries(defaults))
  db.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)").run(k,v);

function auth(req,res,next){
  try {
    const token = (req.headers.authorization || "").replace("Bearer ","");
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({error:"غير مصرح"}); }
}

app.get("/api/health",(req,res)=>res.json({ok:true, store:"هديتك"}));

app.get("/api/products",(req,res)=>{
  res.json(db.prepare("SELECT * FROM products WHERE active=1 ORDER BY id DESC").all());
});

app.post("/api/orders",(req,res)=>{
  const {customer_name,phone,address,items,total,payment_method="cod",shipping_method="manual"}=req.body;
  if(!customer_name || !phone || !address || !Array.isArray(items) || !items.length)
    return res.status(400).json({error:"بيانات الطلب غير مكتملة"});
  const result = db.transaction(()=>{
    for(const item of items){
      const p=db.prepare("SELECT stock FROM products WHERE id=? AND active=1").get(item.id);
      if(!p || p.stock < Number(item.qty)) throw new Error("الكمية غير متاحة");
    }
    for(const item of items)
      db.prepare("UPDATE products SET stock=stock-? WHERE id=?").run(Number(item.qty),item.id);
    return db.prepare(`INSERT INTO orders
      (customer_name,phone,address,items_json,total,payment_method,shipping_method)
      VALUES(?,?,?,?,?,?,?)`).run(customer_name,phone,address,JSON.stringify(items),Number(total),payment_method,shipping_method);
  });
  try { res.status(201).json({ok:true,order_id:result.lastInsertRowid}); }
  catch(e){ res.status(400).json({error:e.message}); }
});

app.post("/api/admin/login",(req,res)=>{
  const {email,password}=req.body;
  const a=db.prepare("SELECT * FROM admins WHERE email=?").get(email);
  if(!a || !bcrypt.compareSync(password,a.password_hash))
    return res.status(401).json({error:"بيانات الدخول غير صحيحة"});
  res.json({token:jwt.sign({id:a.id,email:a.email},JWT_SECRET,{expiresIn:"8h"})});
});

app.get("/api/admin/orders",auth,(req,res)=>{
  res.json(db.prepare("SELECT * FROM orders ORDER BY id DESC").all());
});
app.get("/api/admin/products",auth,(req,res)=>{
  res.json(db.prepare("SELECT * FROM products ORDER BY id DESC").all());
});
app.post("/api/admin/products",auth,(req,res)=>{
  const {name,description="",price,stock=0,category="عام",image=""}=req.body;
  if(!name || !Number.isFinite(Number(price))) return res.status(400).json({error:"بيانات المنتج غير صحيحة"});
  const r=db.prepare(`INSERT INTO products(name,description,price,stock,category,image)
    VALUES(?,?,?,?,?,?)`).run(name,description,Number(price),Number(stock),category,image);
  res.json({id:r.lastInsertRowid});
});
app.patch("/api/admin/orders/:id",auth,(req,res)=>{
  const allowed=["new","processing","shipped","delivered","cancelled"];
  if(!allowed.includes(req.body.status)) return res.status(400).json({error:"حالة غير صحيحة"});
  db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);
  res.json({ok:true});
});
app.get("/api/admin/settings",auth,(req,res)=>{
  const rows=db.prepare("SELECT key,value FROM settings").all();
  res.json(Object.fromEntries(rows.map(x=>[x.key,x.value])));
});
app.patch("/api/admin/settings",auth,(req,res)=>{
  const stmt=db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
  const tx=db.transaction(obj=>Object.entries(obj).forEach(([k,v])=>stmt.run(k,String(v))));
  tx(req.body); res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`هديتك يعمل على http://localhost:${PORT}`));
