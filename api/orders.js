// Vercel Serverless Function: /api/orders
// Handles Real-Time Orders Cloud Persistence across all devices and phones
// Supports Firebase Realtime Database (Google Cloud) & Vercel KV / Upstash Redis

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Resolve Cloud Database Endpoint
function getFirebaseUrl(req) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) {
    return envUrl.trim().replace(/\/$/, "");
  }
  const headerUrl = req && (req.headers["x-cloud-db-url"] || req.headers["x-firebase-url"]);
  if (headerUrl && typeof headerUrl === "string" && headerUrl.startsWith("http")) {
    return headerUrl.trim().replace(/\/$/, "");
  }
  return "https://kased-karim-default-rtdb.firebaseio.com";
}

// 1. Fetch Orders from Cloud
async function fetchOrdersFromCloud(req) {
  const t = Date.now();
  const firebaseUrl = getFirebaseUrl(req);

  // A. Firebase Realtime Database
  if (firebaseUrl) {
    try {
      const res = await fetch(`${firebaseUrl}/orders.json?t=${t}`, {
        cache: "no-store",
        headers: { "Accept": "application/json", "Cache-Control": "no-cache, no-store" }
      });
      if (res.ok) {
        const raw = await res.json();
        if (raw) {
          if (Array.isArray(raw)) {
            return { orders: raw.filter(Boolean), provider: "firebase-rtdb" };
          }
          if (typeof raw === "object") {
            const list = Object.values(raw).filter(Boolean);
            list.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
            return { orders: list, provider: "firebase-rtdb" };
          }
        }
        return { orders: [], provider: "firebase-rtdb" };
      }
    } catch (err) {
      console.warn("Firebase fetch orders error:", err.message);
    }
  }

  // B. Vercel KV / Upstash Redis
  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  if (kvUrl && kvToken) {
    try {
      const res = await fetch(`${kvUrl}/get/kased_karim_orders`, {
        cache: "no-store",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Cache-Control": "no-cache, no-store"
        }
      });
      if (res.ok) {
        const data = await res.json();
        let orders = data && data.result;
        if (typeof orders === "string") {
          try { orders = JSON.parse(orders); } catch (e) {}
        }
        if (Array.isArray(orders)) {
          return { orders, provider: "vercel-kv" };
        }
      }
    } catch (err) {
      console.warn("KV fetch orders error:", err.message);
    }
  }

  return { orders: [], provider: "none" };
}

// 2. Save / Update Order in Cloud
async function saveOrderToCloud(req, order) {
  const firebaseUrl = getFirebaseUrl(req);

  if (firebaseUrl) {
    try {
      const safeId = encodeURIComponent(order.id);
      const res = await fetch(`${firebaseUrl}/orders/${safeId}.json`, {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(order)
      });
      if (res.ok) {
        return { success: true, provider: "firebase-rtdb" };
      }
    } catch (err) {
      console.warn("Firebase save order error:", err.message);
    }
  }

  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  if (kvUrl && kvToken) {
    try {
      const { orders } = await fetchOrdersFromCloud(req);
      const idx = orders.findIndex(o => o.id === order.id);
      if (idx > -1) {
        orders[idx] = order;
      } else {
        orders.unshift(order);
      }
      const res = await fetch(`${kvUrl}/set/kased_karim_orders`, {
        method: "POST",
        cache: "no-store",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(orders)
      });
      if (res.ok) {
        return { success: true, provider: "vercel-kv" };
      }
    } catch (err) {
      console.warn("KV save order error:", err.message);
    }
  }

  return { success: false, provider: "none" };
}

// 3. Delete Order from Cloud
async function deleteOrderFromCloud(req, orderId) {
  const firebaseUrl = getFirebaseUrl(req);

  if (firebaseUrl) {
    try {
      const safeId = encodeURIComponent(orderId);
      await fetch(`${firebaseUrl}/orders/${safeId}.json`, {
        method: "DELETE",
        cache: "no-store"
      });
      return { success: true, provider: "firebase-rtdb" };
    } catch (err) {
      console.warn("Firebase delete order error:", err.message);
    }
  }

  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  if (kvUrl && kvToken) {
    try {
      const { orders } = await fetchOrdersFromCloud(req);
      const filtered = orders.filter(o => o.id !== orderId);
      await fetch(`${kvUrl}/set/kased_karim_orders`, {
        method: "POST",
        cache: "no-store",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(filtered)
      });
      return { success: true, provider: "vercel-kv" };
    } catch (err) {
      console.warn("KV delete order error:", err.message);
    }
  }

  return { success: false, provider: "none" };
}

export default async function handler(req, res) {
  // Ultra-Strict Anti-Caching Headers for instant real-time sync across devices
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
  res.setHeader("CDN-Cache-Control", "no-store");
  res.setHeader("Vercel-CDN-Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-Control", "no-store");

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Cache-Control, Pragma, x-cloud-db-url, x-firebase-url");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    // 1. GET: Fetch all live orders across all devices
    if (req.method === "GET") {
      const { orders, provider } = await fetchOrdersFromCloud(req);
      return res.status(200).json({ success: true, count: orders.length, provider, orders });
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

      const saveResult = await saveOrderToCloud(req, order);
      return res.status(201).json({ success: true, persistedToCloud: saveResult.success, order });
    }

    // 3. PATCH: Update order status (pending -> confirmed -> completed)
    if (req.method === "PATCH") {
      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      const { id, status, isRead } = body || {};
      if (!id) return res.status(400).json({ error: "Missing order ID" });

      const { orders } = await fetchOrdersFromCloud(req);
      const target = orders.find(o => o.id === id);
      if (target) {
        if (status !== undefined) target.status = status;
        if (isRead !== undefined) target.isRead = isRead;
        await saveOrderToCloud(req, target);
      }

      return res.status(200).json({ success: true, id, status, isRead });
    }

    // 4. DELETE: Remove order from database
    if (req.method === "DELETE") {
      const { id } = req.query || {};
      if (!id) return res.status(400).json({ error: "Missing order ID" });

      const delResult = await deleteOrderFromCloud(req, id);
      return res.status(200).json({ success: true, persistedToCloud: delResult.success, deleted: id });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error("API error in /api/orders:", err);
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
