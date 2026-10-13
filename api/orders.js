// Vercel Serverless Function: /api/orders
// Handles Shared Cloud Persistence for Kased Karim Lighting Showroom across all devices

const CLOUD_BIN = process.env.CLOUD_BIN_URL || "https://extendsclass.com/api/json-storage/bin/faabcdf";

export default async function handler(req, res) {
  // CORS Headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    // 1. GET: Fetch all orders across all devices
    if (req.method === "GET") {
      let orders = [];
      try {
        const binRes = await fetch(CLOUD_BIN, { headers: { "Accept": "application/json" } });
        if (binRes.ok) {
          const binData = await binRes.json();
          orders = Array.isArray(binData.orders) ? binData.orders : [];
        }
      } catch (err) {
        console.error("Cloud fetch error:", err.message);
      }

      return res.status(200).json({ success: true, count: orders.length, orders });
    }

    // 2. POST: Create a new order from any customer device
    if (req.method === "POST") {
      const order = req.body;
      if (!order || !order.customer) {
        return res.status(400).json({ error: "Invalid order data" });
      }

      // Generate server timestamp and reference ID if not provided
      if (!order.id) {
        order.id = "ORD-" + Math.floor(1000 + Math.random() * 9000);
      }
      if (!order.timestamp) {
        order.timestamp = Date.now();
      }
      if (!order.status) {
        order.status = "pending";
      }
      order.isRead = false;

      // Update Shared Cloud Storage
      try {
        let binData = { orders: [], products: [] };
        const binRes = await fetch(CLOUD_BIN);
        if (binRes.ok) {
          binData = await binRes.json();
          if (!Array.isArray(binData.orders)) binData.orders = [];
        }

        // Avoid duplicate ID
        const exists = binData.orders.some(o => o.id === order.id);
        if (!exists) {
          binData.orders.unshift(order);
        }

        await fetch(CLOUD_BIN, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(binData)
        });
      } catch (err) {
        console.error("Cloud save error:", err.message);
      }

      return res.status(201).json({ success: true, order });
    }

    // 3. PATCH: Update order status (pending -> confirmed -> completed)
    if (req.method === "PATCH") {
      const { id, status, isRead } = req.body || {};
      if (!id) return res.status(400).json({ error: "Missing order ID" });

      try {
        const binRes = await fetch(CLOUD_BIN);
        if (binRes.ok) {
          const binData = await binRes.json();
          if (Array.isArray(binData.orders)) {
            const target = binData.orders.find(o => o.id === id);
            if (target) {
              if (status !== undefined) target.status = status;
              if (isRead !== undefined) target.isRead = isRead;

              await fetch(CLOUD_BIN, {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(binData)
              });
            }
          }
        }
      } catch (err) {
        console.error("Cloud patch error:", err.message);
      }

      return res.status(200).json({ success: true, id, status, isRead });
    }

    // 4. DELETE: Remove order from database
    if (req.method === "DELETE") {
      const { id } = req.query || {};
      if (!id) return res.status(400).json({ error: "Missing order ID" });

      try {
        const binRes = await fetch(CLOUD_BIN);
        if (binRes.ok) {
          const binData = await binRes.json();
          if (Array.isArray(binData.orders)) {
            binData.orders = binData.orders.filter(o => o.id !== id);
            await fetch(CLOUD_BIN, {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(binData)
            });
          }
        }
      } catch (err) {
        console.error("Cloud delete error:", err.message);
      }

      return res.status(200).json({ success: true, deleted: id });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error("API error in /api/orders:", err);
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
