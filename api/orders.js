// Vercel Serverless Function: /api/orders
// Handles Shared Cloud Persistence for Kased Karim Lighting Showroom across all devices
// Strictly disables all caching across Vercel Edge, Browser, and CDNs

export const dynamic = "force-dynamic";
export const revalidate = 0;

const RESTFUL_ORDERS_OBJECT_ID = "ff808181a09d98f701a15f3c2b4443c9";
const RESTFUL_ORDERS_ENDPOINT = `https://api.restful-api.dev/objects/${RESTFUL_ORDERS_OBJECT_ID}`;

const FALLBACK_BINS = [
  "https://extendsclass.com/api/json-storage/bin/faabcdf",
  "https://extendsclass.com/api/json-storage/bin/fdeedbd"
];

async function fetchFromBins() {
  const t = Date.now();

  // 1. Primary: restful-api.dev
  try {
    const res = await fetch(`${RESTFUL_ORDERS_ENDPOINT}?t=${t}`, {
      cache: "no-store",
      headers: {
        "Accept": "application/json",
        "Cache-Control": "no-cache, no-store",
        "Pragma": "no-cache"
      }
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.data && Array.isArray(data.data.orders)) {
        return { data: { orders: data.data.orders }, isRestful: true };
      }
    }
  } catch (e) {}

  // 2. Secondary fallback: extendsclass bins
  for (const binUrl of FALLBACK_BINS) {
    try {
      const res = await fetch(`${binUrl}?t=${t}`, {
        cache: "no-store",
        headers: {
          "Accept": "application/json",
          "Cache-Control": "no-cache, no-store",
          "Pragma": "no-cache"
        }
      });
      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.orders)) {
          return { data, isRestful: false };
        }
      }
    } catch (e) {}
  }
  return { data: { orders: [] }, isRestful: true };
}

async function saveToBins(binData) {
  const promises = [];

  // 1. Primary: restful-api.dev PUT
  promises.push(
    fetch(RESTFUL_ORDERS_ENDPOINT, {
      method: "PUT",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache, no-store"
      },
      body: JSON.stringify({
        name: "kased_karim_orders",
        data: { orders: binData.orders || [] }
      })
    }).catch(err => console.warn("Save restful orders err:", err.message))
  );

  // 2. Secondary fallback: extendsclass PUT
  const jsonStr = JSON.stringify(binData);
  FALLBACK_BINS.forEach(binUrl => {
    promises.push(
      fetch(binUrl, {
        method: "PUT",
        cache: "no-store",
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-cache, no-store"
        },
        body: jsonStr
      }).catch(err => console.warn("Save fallback bin err:", err.message))
    );
  });

  await Promise.allSettled(promises);
}

export default async function handler(req, res) {
  // Ultra-Strict Anti-Caching Headers for instant real-time sync across devices
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
  res.setHeader("CDN-Cache-Control", "no-store");
  res.setHeader("Vercel-CDN-Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-Control", "no-store");

  // CORS Headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Cache-Control, Pragma");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    // 1. GET: Fetch all live orders across all devices
    if (req.method === "GET") {
      const { data } = await fetchFromBins();
      const orders = Array.isArray(data.orders) ? data.orders : [];
      return res.status(200).json({ success: true, count: orders.length, orders });
    }

    // 2. POST: Create a new order from customer device
    if (req.method === "POST") {
      let order = req.body;
      if (typeof order === "string") {
        try { order = JSON.parse(order); } catch (e) {}
      }

      if (!order || !order.customer) {
        return res.status(400).json({ error: "Invalid order data" });
      }

      // 1. Strict Validation: Name must be at least two names
      const name = (order.customer.name || "").trim();
      const nameParts = name.split(/\s+/).filter(p => p.replace(/[.\-_]/g, "").length >= 2);
      if (nameParts.length < 2) {
        return res.status(400).json({ error: "الاسم يجب أن يكون ثنائياً على الأقل" });
      }

      // 2. Strict Validation: Phone must be complete (11 digits)
      const phone = (order.customer.phone || "").replace(/[^0-9]/g, "");
      if (phone.length < 11) {
        return res.status(400).json({ error: "رقم الهاتف غير مكتمل، يجب أن يكون 11 رقماً" });
      }

      // 3. Strict Validation: Address must not be less than 15 characters
      const address = (order.customer.address || "").trim();
      if (address.length < 15) {
        return res.status(400).json({ error: "العنوان يجب ألا يقل عن 15 حرفاً" });
      }

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

      const { data } = await fetchFromBins();
      if (!Array.isArray(data.orders)) data.orders = [];

      // Avoid duplicate ID, place newest order at the very beginning
      const exists = data.orders.some(o => o.id === order.id);
      if (!exists) {
        data.orders.unshift(order);
      } else {
        const idx = data.orders.findIndex(o => o.id === order.id);
        data.orders[idx] = order;
      }

      await saveToBins(data);
      return res.status(201).json({ success: true, order });
    }

    // 3. PATCH: Update order status (pending -> confirmed -> completed)
    if (req.method === "PATCH") {
      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      const { id, status, isRead } = body || {};
      if (!id) return res.status(400).json({ error: "Missing order ID" });

      const { data } = await fetchFromBins();
      if (Array.isArray(data.orders)) {
        const target = data.orders.find(o => o.id === id);
        if (target) {
          if (status !== undefined) target.status = status;
          if (isRead !== undefined) target.isRead = isRead;
          await saveToBins(data);
        }
      }

      return res.status(200).json({ success: true, id, status, isRead });
    }

    // 4. DELETE: Remove order from database
    if (req.method === "DELETE") {
      const { id } = req.query || {};
      if (!id) return res.status(400).json({ error: "Missing order ID" });

      const { data } = await fetchFromBins();
      if (Array.isArray(data.orders)) {
        data.orders = data.orders.filter(o => o.id !== id);
        await saveToBins(data);
      }

      return res.status(200).json({ success: true, deleted: id });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error("API error in /api/orders:", err);
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
