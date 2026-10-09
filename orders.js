// Vercel serverless endpoint. Configure a durable database before accepting live orders.
export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const body = req.body || {};
  const customer = body.customer || {};
  const name = typeof customer.name === "string" ? customer.name.trim() : "";
  const phone = typeof customer.phone === "string" ? customer.phone.trim() : "";
  const address = typeof customer.address === "string" ? customer.address.trim() : "";
  const method = body.payment;
  const items = body.items;
  if (!name || name.length > 100 || !phone || phone.length > 25 || !address || address.length > 500) {
    return res.status(400).json({ error: "بيانات العميل غير مكتملة أو غير صحيحة" });
  }
  if (!["wallet", "fawry", "cod"].includes(method)) {
    return res.status(400).json({ error: "طريقة الدفع غير صحيحة" });
  }
  if (!Array.isArray(items) || items.length < 1 || items.length > 30) {
    return res.status(400).json({ error: "السلة غير صحيحة" });
  }
  // Intentionally do not mark orders as paid. Payment integration requires merchant credentials
  // and a verified provider webhook. This endpoint does not yet persist orders.
  const orderId = "HD-" + Date.now().toString(36).toUpperCase();
  return res.status(202).json({ orderId, status: "pending", paymentStatus: "not_configured" });
}
