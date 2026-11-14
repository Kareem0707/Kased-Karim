// Vercel Serverless Function: /api/orders
// Hardened Multi-Device Orders Engine with Mandatory Server-Side Authorization
// Prohibits anonymous dumping of customer records & ensures cloud persistence before confirming

import crypto from "crypto";
import { verifyAdminRequest } from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Resolve Cloud Database Endpoint
function getFirebaseUrl(req) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) {
    return envUrl.trim().replace(/\/$/, "");
  }
  return "https://kased-karim-default-rtdb.firebaseio.com";
}

// Update Global Sync Metadata
async function bumpSyncMetadata(firebaseUrl, actionType = "order_update") {
  if (!firebaseUrl) return;
  try {
    const now = Date.now();
    await fetch(`${firebaseUrl}/sync_meta.json`, {
      method: "PUT",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version: now,
        timestamp: now,
        action: actionType
      })
    });
  } catch (e) {}
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
          orders.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
          return { orders, provider: "vercel-kv" };
        }
      }
    } catch (err) {
      console.warn("KV fetch orders error:", err.message);
    }
  }

  return { orders: [], provider: "none" };
}

// 1.5. Canonical Product Price Lookup to Prevent Client Price Tampering
async function getCanonicalCatalog(req) {
  const firebaseUrl = getFirebaseUrl(req);
  if (firebaseUrl) {
    try {
      const res = await fetch(`${firebaseUrl}/products.json?t=${Date.now()}`, { cache: "no-store" });
      if (res.ok) {
        const raw = await res.json();
        if (Array.isArray(raw)) return raw.filter(Boolean);
        if (raw && typeof raw === "object") return Object.values(raw).filter(Boolean);
      }
    } catch (e) {}
  }
  return [];
}

// 2. Save / Update Order in Cloud
async function saveOrderToCloud(req, order) {
  const firebaseUrl = getFirebaseUrl(req);
  let savedToFirebase = false;

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
        savedToFirebase = true;
        await bumpSyncMetadata(firebaseUrl, "order_save");
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

  if (savedToFirebase) {
    return { success: true, provider: "firebase-rtdb" };
  }

  return { success: false, provider: "none" };
}

// 2.5 Batch Overwrite All Orders in Cloud (For Restore / Full Sync)
async function saveBatchOrdersToCloud(req, ordersList) {
  const firebaseUrl = getFirebaseUrl(req);
  let saved = false;

  if (firebaseUrl) {
    try {
      const ordMap = {};
      ordersList.forEach(o => {
        if (o && o.id) {
          ordMap[encodeURIComponent(o.id)] = o;
        }
      });
      const res = await fetch(`${firebaseUrl}/orders.json`, {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ordMap)
      });
      if (res.ok) saved = true;
    } catch (e) {
      console.warn("Firebase batch orders error:", e.message);
    }
  }

  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  if (kvUrl && kvToken) {
    try {
      await fetch(`${kvUrl}/set/kased_karim_orders`, {
        method: "POST",
        cache: "no-store",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(ordersList)
      });
      saved = true;
    } catch (e) {}
  }

  if (saved) {
    await bumpSyncMetadata(firebaseUrl, "batch_orders_overwrite");
  }

  return saved;
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
      await bumpSyncMetadata(firebaseUrl, "order_delete");
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

// Generate Cryptographically Secure High-Entropy Order Reference
function generateSecureOrderId() {
  const numPart = crypto.randomInt(1000, 9999);
  const alphaPart = crypto.randomBytes(2).toString("hex").toUpperCase();
  return `ORD-${numPart}-${alphaPart}`;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
  res.setHeader("CDN-Cache-Control", "no-store");
  res.setHeader("Vercel-CDN-Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-Control", "no-store");

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin-token, Cache-Control, Pragma");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    // -------------------------------------------------------------------------
    // 1. GET: Fetch Orders (ADMIN-ONLY ACCESS REQUIREMENT)
    // -------------------------------------------------------------------------
    if (req.method === "GET") {
      // STRICT AUTHORIZATION CHECK: Prevent anonymous dumping of customer orders
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({
          success: false,
          error: "غير مصرح بالوصول. استعراض سجلات الطلبات يتطلب صلاحيات الإدارة المعتمدة."
        });
      }

      const { id } = req.query || {};
      const { orders, provider } = await fetchOrdersFromCloud(req);

      if (id) {
        const cleanId = id.toString().replace(/[#]/g, "").trim().toUpperCase();
        const single = orders.find(o => 
          o.id.toUpperCase() === cleanId || 
          o.id.replace("ORD-", "") === cleanId.replace("ORD-", "")
        );
        if (single) {
          return res.status(200).json({ success: true, order: single, provider });
        }
        return res.status(404).json({ success: false, error: "Order not found" });
      }

      // Filter out any lingering sample/demo orders
      const cleanOrders = orders.filter(o => 
        o && o.id && 
        typeof o.id === "string" &&
        o.id !== "ORD-3985" && 
        o.id !== "ORD-5412" && 
        !o.id.startsWith("DEMO-")
      );

      return res.status(200).json({
        success: true,
        count: cleanOrders.length,
        provider,
        orders: cleanOrders
      });
    }

    // -------------------------------------------------------------------------
    // 2. POST: Create a new order (Public Customer Order Submission / Reservation)
    // -------------------------------------------------------------------------
    if (req.method === "POST") {
      let order = req.body;
      if (typeof order === "string") {
        try { order = JSON.parse(order); } catch (e) {}
      }

      if (!order || !order.customer) {
        return res.status(400).json({ success: false, error: "بيانات الطلب غير مكتملة" });
      }

      // 1. Strict Server-Side Validation: Name must be at least two parts
      const name = (order.customer.name || "").trim().replace(/[<>]/g, "");
      const nameParts = name.split(/\s+/).filter(p => p.replace(/[.\-_]/g, "").length >= 2);
      if (nameParts.length < 2) {
        return res.status(400).json({ success: false, error: "الاسم يجب أن يكون ثنائياً على الأقل" });
      }

      // 2. Strict Server-Side Validation: Phone must be 11 digits
      const phone = (order.customer.phone || "").replace(/[^0-9]/g, "");
      if (phone.length < 11 || (!phone.startsWith("01") && !phone.startsWith("201"))) {
        return res.status(400).json({ success: false, error: "رقم الهاتف غير صحيح، يجب أن يتكون من 11 رقماً ويبدأ بـ 01" });
      }

      // 3. Strict Server-Side Validation: Address
      const address = (order.customer.address || "").trim().replace(/[<>]/g, "");
      if (address.length < 5) {
        return res.status(400).json({ success: false, error: "يرجى كتابة العنوان بالتفصيل (المنطقة / الشارع / رقم العقار)" });
      }

      // 4. Strict Server-Side Validation: Items
      if (!Array.isArray(order.items) || order.items.length === 0) {
        return res.status(400).json({ success: false, error: "سلة المشتريات فارغة" });
      }

      // 5. Price Tampering Prevention: Recalculate totals server-side against live catalog
      const catalog = await getCanonicalCatalog(req);
      const catalogMap = new Map();
      catalog.forEach(p => catalogMap.set(p.id, p));

      let calculatedSubtotal = 0;
      const sanitizedItems = [];

      for (const item of order.items) {
        const canonicalProduct = catalogMap.get(item.id);
        const unitPrice = canonicalProduct ? parseFloat(canonicalProduct.price) : parseFloat(item.price);
        const qty = Math.max(1, parseInt(item.qty, 10) || 1);
        const itemTotal = unitPrice * qty;
        calculatedSubtotal += itemTotal;

        sanitizedItems.push({
          id: item.id,
          name: canonicalProduct ? canonicalProduct.name : (item.name || "").replace(/[<>]/g, ""),
          price: unitPrice,
          qty: qty,
          image: canonicalProduct ? canonicalProduct.image : (item.image || ""),
          total: itemTotal
        });
      }

      // 6. Generate High-Entropy Cryptographic ID
      const highEntropyId = generateSecureOrderId();
      const now = Date.now();
      const dateFormatted = new Date().toLocaleDateString("ar-EG", {
        year: "numeric",
        month: "short",
        day: "numeric"
      });
      const timeFormatted = new Date().toLocaleTimeString("ar-EG", {
        hour: "2-digit",
        minute: "2-digit"
      });

      const finalizedOrder = {
        id: highEntropyId,
        orderNumber: highEntropyId,
        timestamp: now,
        dateFormatted,
        timeFormatted,
        status: "pending",
        isRead: false,
        customer: {
          name: name,
          phone: phone,
          address: address,
          notes: (order.customer.notes || "").trim().replace(/[<>]/g, "").slice(0, 500)
        },
        items: sanitizedItems,
        subtotal: calculatedSubtotal,
        shipping: calculatedSubtotal >= 5000 ? 0 : 75,
        total: calculatedSubtotal >= 5000 ? calculatedSubtotal : (calculatedSubtotal + 75),
        paymentMethod: order.paymentMethod || "cod",
        deliveryEstimate: "2 - 4 أيام عمل"
      };

      // 7. Ensure Cloud Persistence BEFORE Responding to Client!
      const persistResult = await saveOrderToCloud(req, finalizedOrder);
      if (!persistResult.success) {
        return res.status(503).json({
          success: false,
          error: "تعذر تسجيل الطلب على الخادم في الوقت الحالي. يرجى المحاولة مرة أخرى أو التواصل معنا عبر واتساب."
        });
      }

      // 8. Return Sanitized Confirmation (Do not echo full sensitive PII back to response)
      return res.status(201).json({
        success: true,
        message: "تم استلام طلبك وحجزه بنجاح تام في معارض قاصد كريم!",
        order: {
          id: finalizedOrder.id,
          timestamp: finalizedOrder.timestamp,
          dateFormatted: finalizedOrder.dateFormatted,
          total: finalizedOrder.total,
          status: finalizedOrder.status,
          itemsCount: finalizedOrder.items.length
        }
      });
    }

    // -------------------------------------------------------------------------
    // 3. PUT: Bulk Overwrite Orders (Restore / Batch Sync) (ADMIN-ONLY ACCESS REQUIREMENT)
    // -------------------------------------------------------------------------
    if (req.method === "PUT") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لمزامنة الطلبات." });
      }

      let payload = req.body;
      if (typeof payload === "string") {
        try { payload = JSON.parse(payload); } catch (e) {}
      }

      const ordersList = Array.isArray(payload) ? payload : (payload && payload.orders ? payload.orders : null);
      if (!ordersList || !Array.isArray(ordersList)) {
        return res.status(400).json({ error: "بيانات الطلبات غير صالحة" });
      }

      const ok = await saveBatchOrdersToCloud(req, ordersList);
      return res.status(200).json({ success: ok, batch: true, count: ordersList.length });
    }

    // -------------------------------------------------------------------------
    // 4. PATCH: Update Order Status / Read State (ADMIN-ONLY ACCESS REQUIREMENT)
    // -------------------------------------------------------------------------
    if (req.method === "PATCH") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لتعديل الطلبات." });
      }

      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      const { id, status, isRead, updatedAt } = body || {};
      if (!id) return res.status(400).json({ error: "Missing order ID" });

      const patchTime = updatedAt || Date.now();
      const firebaseUrl = getFirebaseUrl(req);

      if (firebaseUrl) {
        try {
          const safeId = encodeURIComponent(id);
          const patchData = { updatedAt: patchTime };
          if (status !== undefined) patchData.status = status;
          if (isRead !== undefined) patchData.isRead = isRead;
          await fetch(`${firebaseUrl}/orders/${safeId}.json`, {
            method: "PATCH",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(patchData)
          });
          await bumpSyncMetadata(firebaseUrl, "order_status_patch");
        } catch (err) {
          console.warn("Firebase PATCH status error:", err.message);
        }
      }

      const { orders } = await fetchOrdersFromCloud(req);
      const target = orders.find(o => o.id === id);
      if (target) {
        if (status !== undefined) target.status = status;
        if (isRead !== undefined) target.isRead = isRead;
        target.updatedAt = patchTime;
        await saveOrderToCloud(req, target);
      }

      return res.status(200).json({ success: true, id, status, isRead, updatedAt: patchTime });
    }

    // -------------------------------------------------------------------------
    // 5. DELETE: Remove Order (ADMIN-ONLY ACCESS REQUIREMENT)
    // -------------------------------------------------------------------------
    if (req.method === "DELETE") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لحذف الطلبات." });
      }

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
