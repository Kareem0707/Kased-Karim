// Vercel Serverless Function: /api/orders
// Handles Orders Persistence for Kased Karim Lighting Showroom

export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const KV_URL = process.env.KV_REST_API_URL;
  const KV_TOKEN = process.env.KV_REST_API_TOKEN;
  const FIREBASE_URL = process.env.FIREBASE_DB_URL || "https://kased-karim-zayed-default-rtdb.firebaseio.com";

  try {
    // 1. GET: Fetch all orders
    if (req.method === "GET") {
      let orders = [];

      if (KV_URL && KV_TOKEN) {
        // Query Vercel KV / Upstash
        const kvRes = await fetch(`${KV_URL}/get/orders`, {
          headers: { Authorization: `Bearer ${KV_TOKEN}` }
        });
        const kvData = await kvRes.json();
        orders = kvData.result ? (typeof kvData.result === "string" ? JSON.parse(kvData.result) : kvData.result) : [];
      } else if (FIREBASE_URL) {
        // Query Firebase Realtime Database REST API
        try {
          const fbRes = await fetch(`${FIREBASE_URL}/orders.json`);
          if (fbRes.ok) {
            const fbData = await fbRes.json();
            if (fbData) {
              orders = Object.keys(fbData).map(k => ({ ...fbData[k], _fbKey: k }));
            }
          }
        } catch (e) {
          console.warn("Firebase fetch fallback:", e.message);
        }
      }

      return res.status(200).json({ success: true, count: orders.length, orders });
    }

    // 2. POST: Create a new order
    if (req.method === "POST") {
      const order = req.body;
      if (!order || !order.customer) {
        return res.status(400).json({ error: "Invalid order data" });
      }

      // Add server-side timestamp and ID if missing
      if (!order.id) {
        order.id = "ORD-" + Math.floor(1000 + Math.random() * 9000);
      }
      if (!order.timestamp) {
        order.timestamp = Date.now();
      }

      if (KV_URL && KV_TOKEN) {
        // Fetch current orders from KV
        const kvGet = await fetch(`${KV_URL}/get/orders`, {
          headers: { Authorization: `Bearer ${KV_TOKEN}` }
        });
        const kvData = await kvGet.json();
        let orders = kvData.result ? (typeof kvData.result === "string" ? JSON.parse(kvData.result) : kvData.result) : [];
        orders.unshift(order);

        // Save back to KV
        await fetch(`${KV_URL}/set/orders`, {
          method: "POST",
          headers: { Authorization: `Bearer ${KV_TOKEN}`, "Content-Type": "application/json" },
          body: JSON.stringify(orders)
        });
      } else if (FIREBASE_URL) {
        // Save to Firebase
        await fetch(`${FIREBASE_URL}/orders.json`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(order)
        });
      }

      return res.status(201).json({ success: true, order });
    }

    // 3. PATCH: Update order status
    if (req.method === "PATCH") {
      const { id, status, isRead } = req.body || {};
      if (!id) return res.status(400).json({ error: "Missing order ID" });

      if (KV_URL && KV_TOKEN) {
        const kvGet = await fetch(`${KV_URL}/get/orders`, {
          headers: { Authorization: `Bearer ${KV_TOKEN}` }
        });
        const kvData = await kvGet.json();
        let orders = kvData.result ? (typeof kvData.result === "string" ? JSON.parse(kvData.result) : kvData.result) : [];
        const target = orders.find(o => o.id === id);
        if (target) {
          if (status !== undefined) target.status = status;
          if (isRead !== undefined) target.isRead = isRead;
          await fetch(`${KV_URL}/set/orders`, {
            method: "POST",
            headers: { Authorization: `Bearer ${KV_TOKEN}`, "Content-Type": "application/json" },
            body: JSON.stringify(orders)
          });
        }
      }

      return res.status(200).json({ success: true, id, status, isRead });
    }

    // 4. DELETE: Remove order
    if (req.method === "DELETE") {
      const { id } = req.query || {};
      if (!id) return res.status(400).json({ error: "Missing order ID" });

      if (KV_URL && KV_TOKEN) {
        const kvGet = await fetch(`${KV_URL}/get/orders`, {
          headers: { Authorization: `Bearer ${KV_TOKEN}` }
        });
        const kvData = await kvGet.json();
        let orders = kvData.result ? (typeof kvData.result === "string" ? JSON.parse(kvData.result) : kvData.result) : [];
        orders = orders.filter(o => o.id !== id);
        await fetch(`${KV_URL}/set/orders`, {
          method: "POST",
          headers: { Authorization: `Bearer ${KV_TOKEN}`, "Content-Type": "application/json" },
          body: JSON.stringify(orders)
        });
      }

      return res.status(200).json({ success: true, deleted: id });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error("API Error in /api/orders:", err);
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
