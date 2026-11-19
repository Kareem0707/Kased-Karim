// Vercel Serverless Function: /api/orders
// Hardened Multi-Device Orders Engine with Mandatory Server-Side Authorization
// Prohibits anonymous dumping of customer records & ensures cloud persistence before confirming

import crypto from "crypto";
import {
  verifyAdminRequest,
  verifyCustomerRequest,
  getClientIp,
  checkDistributedRateLimit,
  sanitizePathId,
  getFirebaseUrl,
  setSecurityHeaders
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Update Global Sync Metadata
async function bumpSyncMetadata(actionType = "order_update") {
  try {
    const now = Date.now();
    const firebaseUrl = getFirebaseUrl("sync_meta.json");
    await fetch(firebaseUrl, {
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

  // A. Firebase Realtime Database
  try {
    const firebaseUrl = getFirebaseUrl("orders.json", { t });
    const res = await fetch(firebaseUrl, {
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

// 1.5. Canonical Product Price Lookup to Prevent Client Price Tampering (F-06)
async function getCanonicalCatalog() {
  try {
    const firebaseUrl = getFirebaseUrl("products.json", { t: Date.now() });
    const res = await fetch(firebaseUrl, { cache: "no-store" });
    if (res.ok) {
      const raw = await res.json();
      if (Array.isArray(raw)) return raw.filter(Boolean);
      if (raw && typeof raw === "object") return Object.values(raw).filter(Boolean);
    }
  } catch (e) {}
  return [];
}

// 2. Save / Update Order in Cloud
async function saveOrderToCloud(req, order) {
  let savedToFirebase = false;

  const safeId = sanitizePathId(order.id);
  if (safeId) {
    try {
      const firebaseUrl = getFirebaseUrl(`orders/${safeId}.json`);
      const res = await fetch(firebaseUrl, {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(order)
      });
      if (res.ok) {
        savedToFirebase = true;
        await bumpSyncMetadata("order_save");
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

// Strict Allowlist Sanitizer for Batch Orders (CWE-915 Mass Assignment Mitigation)
function sanitizeOrderObject(o) {
  if (!o || typeof o !== "object") return null;
  const safeId = sanitizePathId(o.id);
  if (!safeId) return null;
  return {
    id: safeId,
    orderNumber: typeof o.orderNumber === "string" ? o.orderNumber.slice(0, 32) : safeId,
    timestamp: typeof o.timestamp === "number" ? o.timestamp : Date.now(),
    dateFormatted: typeof o.dateFormatted === "string" ? o.dateFormatted.slice(0, 50) : "",
    timeFormatted: typeof o.timeFormatted === "string" ? o.timeFormatted.slice(0, 50) : "",
    status: typeof o.status === "string" ? o.status.slice(0, 30) : "received",
    statusHistory: Array.isArray(o.statusHistory) ? o.statusHistory.slice(0, 20).map(sh => ({
      status: String(sh?.status || "").slice(0, 30),
      timestamp: typeof sh?.timestamp === "number" ? sh.timestamp : Date.now(),
      note: String(sh?.note || "").slice(0, 200)
    })) : [],
    isRead: Boolean(o.isRead),
    customerId: sanitizePathId(o.customerId) || null,
    email: typeof o.email === "string" ? o.email.trim().toLowerCase().slice(0, 100) : null,
    customer: o.customer && typeof o.customer === "object" ? {
      name: String(o.customer.name || "").replace(/[<>]/g, "").slice(0, 80),
      phone: String(o.customer.phone || "").replace(/[^0-9]/g, "").slice(0, 20),
      city: String(o.customer.city || "").replace(/[<>]/g, "").slice(0, 50),
      deliveryArea: String(o.customer.deliveryArea || "").slice(0, 50),
      deliveryAreaName: String(o.customer.deliveryAreaName || "").slice(0, 50),
      deliveryAreaNameEn: String(o.customer.deliveryAreaNameEn || "").slice(0, 50),
      address: String(o.customer.address || "").replace(/[<>]/g, "").slice(0, 200),
      notes: String(o.customer.notes || "").replace(/[<>]/g, "").slice(0, 500)
    } : {},
    items: Array.isArray(o.items) ? o.items.slice(0, 50).map(it => ({
      id: sanitizePathId(it.id) || "item",
      name: String(it.name || "").replace(/[<>]/g, "").slice(0, 100),
      price: Math.max(0, parseFloat(it.price) || 0),
      qty: Math.min(100, Math.max(1, parseInt(it.qty, 10) || 1)),
      image: String(it.image || "").slice(0, 500),
      total: Math.max(0, parseFloat(it.total) || 0)
    })) : [],
    subtotal: Math.max(0, parseFloat(o.subtotal) || 0),
    shipping: Math.max(0, parseFloat(o.shipping) || 0),
    total: Math.max(0, parseFloat(o.total) || 0),
    paymentMethod: String(o.paymentMethod || "cod").slice(0, 20),
    paymentStatus: String(o.paymentStatus || "uncollected").slice(0, 30),
    paymentStatusText: String(o.paymentStatusText || "").slice(0, 100),
    paymentStatusTextEn: String(o.paymentStatusTextEn || "").slice(0, 100),
    deliveryEstimate: String(o.deliveryEstimate || "").slice(0, 50)
  };
}

// 2.5 Batch Overwrite All Orders in Cloud (For Restore / Full Sync)
async function saveBatchOrdersToCloud(req, ordersList) {
  let saved = false;
  const sanitizedList = (Array.isArray(ordersList) ? ordersList : []).map(sanitizeOrderObject).filter(Boolean);

  try {
    const ordersMap = {};
    sanitizedList.forEach(o => {
      ordersMap[o.id] = o;
    });

    const firebaseUrl = getFirebaseUrl("orders.json");
    const res = await fetch(firebaseUrl, {
      method: "PUT",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ordersMap)
    });
    if (res.ok) {
      saved = true;
      await bumpSyncMetadata("batch_orders_overwrite");
    }
  } catch (err) {
    console.warn("Firebase batch orders error:", err.message);
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
        body: JSON.stringify(sanitizedList)
      });
      saved = true;
    } catch (err) {}
  }

  return saved;
}

// 3. Delete Order from Cloud
async function deleteOrderFromCloud(req, orderId) {
  const safeId = sanitizePathId(orderId);
  if (!safeId) return { success: false };

  try {
    const firebaseUrl = getFirebaseUrl(`orders/${safeId}.json`);
    await fetch(firebaseUrl, {
      method: "DELETE",
      cache: "no-store"
    });
    await bumpSyncMetadata("order_delete");
  } catch (err) {
    console.warn("Firebase delete order error:", err.message);
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
    } catch (err) {}
  }

  return { success: true };
}

// Supported Delivery Areas and Fees (PRD Section 5)
const SUPPORTED_DELIVERY_AREAS = {
  "sheikh-zayed": { nameAr: "الشيخ زايد", nameEn: "Sheikh Zayed", fee: 0, days: "1 - 2 أيام عمل" },
  "october": { nameAr: "السادس من أكتوبر", nameEn: "6th of October", fee: 50, days: "1 - 2 أيام عمل" },
  "new-cairo": { nameAr: "القاهرة الجديدة والتجمع", nameEn: "New Cairo & Tagamoa", fee: 75, days: "2 - 3 أيام عمل" },
  "giza": { nameAr: "الجيزة والدقي والمهندسين", nameEn: "Giza, Dokki & Mohandessin", fee: 60, days: "2 - 3 أيام عمل" },
  "cairo": { nameAr: "وسط البلد ومدينة نصر ومصر الجديدة", nameEn: "Cairo, Nasr City & Heliopolis", fee: 70, days: "2 - 3 أيام عمل" },
  "alexandria": { nameAr: "الإسكندرية والساحل الشمالي", nameEn: "Alexandria & North Coast", fee: 120, days: "3 - 5 أيام عمل" }
};

// Recent orders cache to prevent duplicate submission
const recentOrdersSubmissionCache = new Map();

// Generate Cryptographically Unguessable High-Entropy Order Reference (F-08)
function generateSecureOrderId() {
  const numPart = crypto.randomInt(1000, 9999);
  const alphaPart = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `ORD-${numPart}-${alphaPart}`;
}

export default async function handler(req, res) {
  setSecurityHeaders(req, res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    // Payload Size Limit Check (DoS Mitigation - CWE-400)
    const MAX_ORDERS_PAYLOAD = 512 * 1024; // 512 KB
    const contentLength = parseInt(req.headers["content-length"] || "0", 10);
    if (contentLength > MAX_ORDERS_PAYLOAD) {
      return res.status(413).json({ success: false, error: "حجم بيانات الطلب يتجاوز الحد الأقصى المسموح به (512 كيلوبايت)" });
    }

    // -------------------------------------------------------------------------
    // 1. GET: Fetch Orders (ADMIN-ONLY ACCESS REQUIREMENT) (F-04)
    // -------------------------------------------------------------------------
    if (req.method === "GET") {
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
        const cleanId = String(id).replace(/[#]/g, "").trim().toUpperCase();
        const single = orders.find(o => 
          o.id.toUpperCase() === cleanId || 
          o.id.replace("ORD-", "") === cleanId.replace("ORD-", "")
        );
        if (single) {
          return res.status(200).json({ success: true, order: single, provider });
        }
        return res.status(404).json({ success: false, error: "Order not found" });
      }

      orders.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

      return res.status(200).json({
        success: true,
        count: orders.length,
        provider,
        orders
      });
    }

    // -------------------------------------------------------------------------
    // 2. POST: Create a new order (Public Customer Order Submission)
    // -------------------------------------------------------------------------
    if (req.method === "POST") {
      // 0. Distributed Rate Limiter per Client IP (CWE-770 Anti-Flooding)
      const clientIp = getClientIp(req);
      const rateLimit = await checkDistributedRateLimit(clientIp, "create_order", 5, 15 * 60 * 1000);
      if (!rateLimit.allowed) {
        return res.status(429).json({
          success: false,
          error: `تم تجاوز الحد المسموح لإنشاء الطلبات. يرجى الانتظار ${rateLimit.remainingSec || "بضع"} ثوانٍ والمحاولة مجدداً.`
        });
      }

      let order = req.body;
      if (typeof order === "string") {
        try { order = JSON.parse(order); } catch (e) {}
      }

      if (!order || !order.customer) {
        return res.status(400).json({ success: false, error: "بيانات الطلب غير مكتملة" });
      }

      const isQuickWhatsApp = Boolean(order.isQuickWhatsApp || (order.customer && order.customer.notes && order.customer.notes.includes("واتساب")));

      // 1. Server-Side Validation: Name
      let name = (order.customer.name || "").trim().replace(/[<>]/g, "").slice(0, 80);
      if (!name) name = "عميل واتساب المعرض";
      const nameParts = name.split(/\s+/).filter(p => p.replace(/[.\-_]/g, "").length >= 2);
      if (!isQuickWhatsApp && nameParts.length < 2) {
        return res.status(400).json({ success: false, error: "الاسم يجب أن يكون ثنائياً على الأقل" });
      }

      // 2. Server-Side Validation: Phone
      let phone = (order.customer.phone || "").replace(/[^0-9]/g, "");
      if (isQuickWhatsApp && !phone) {
        phone = "01000000000";
      } else if (phone.length < 11 || (!phone.startsWith("01") && !phone.startsWith("201"))) {
        return res.status(400).json({ success: false, error: "رقم الهاتف غير صحيح، يجب أن يتكون من 11 رقماً ويبدأ بـ 01" });
      }

      // 3. Server-Side Validation: Address
      let address = (order.customer.address || "").trim().replace(/[<>]/g, "").slice(0, 200);
      if (isQuickWhatsApp && address.length < 5) {
        address = "الشيخ زايد - طلب عبر واتساب";
      } else if (address.length < 5) {
        return res.status(400).json({ success: false, error: "يرجى كتابة العنوان بالتفصيل (المنطقة / الشارع / رقم العقار)" });
      }

      // 3.5 Delivery Area Validation & Fee Calculation
      const declaredArea = (order.deliveryArea || order.customer.deliveryArea || order.customer.city || "").toLowerCase().trim();
      let selectedArea = SUPPORTED_DELIVERY_AREAS[declaredArea];
      if (!selectedArea) {
        const match = Object.entries(SUPPORTED_DELIVERY_AREAS).find(([k, v]) => 
          declaredArea.includes(k) || 
          (order.customer.address && order.customer.address.includes(v.nameAr)) || 
          (order.customer.city && order.customer.city.includes(v.nameAr))
        );
        selectedArea = match ? match[1] : (isQuickWhatsApp ? SUPPORTED_DELIVERY_AREAS["sheikh-zayed"] : null);
      }

      if (declaredArea === "unsupported" || (!selectedArea && !isQuickWhatsApp)) {
        return res.status(400).json({
          success: false,
          error: "عفواً، منطقة التوصيل غير مدعومة حالياً. خدمات التوصيل لمعرض قاصد كريم تغطي الشيخ زايد، 6 أكتوبر، القاهرة الكبرى، الجيزة، والإسكندرية والساحل الشمالي."
        });
      }

      // 4. Strict Server-Side Validation: Items
      if (!Array.isArray(order.items) || order.items.length === 0 || order.items.length > 50) {
        return res.status(400).json({ success: false, error: "سلة المشتريات غير صالحة، يجب أن تحتوي بين 1 و 50 منتجاً" });
      }

      // 5. Price Tampering Prevention: Recalculate totals server-side against live catalog (F-06 / CWE-840)
      const catalog = await getCanonicalCatalog();
      if (!catalog || !Array.isArray(catalog) || catalog.length === 0) {
        return res.status(503).json({
          success: false,
          error: "تعذر التحقق من قائمة الأسعار المعتمدة حالياً. يرجى إعادة المحاولة لاحقاً."
        });
      }
      const catalogMap = new Map();
      catalog.forEach(p => {
        if (p && p.id) {
          catalogMap.set(String(p.id), p);
        }
      });

      let calculatedSubtotal = 0;
      const sanitizedItems = [];

      for (const item of order.items) {
        if (!item || !item.id) {
          return res.status(400).json({ success: false, error: "بيانات أحد المنتجات في السلة غير صالحة." });
        }
        const cleanItemId = String(item.id).trim();
        const canonicalProduct = catalogMap.get(cleanItemId);

        // Strict Fail-Closed: Reject any product not found in canonical catalog or with invalid price
        if (!canonicalProduct || canonicalProduct.price === undefined || canonicalProduct.price === null) {
          return res.status(400).json({
            success: false,
            error: "المنتج المختار غير متوفر في كتالوج المعرض المعتمد، ولا يمكن إتمام الطلب بأسعار غير موثقة."
          });
        }

        // Server-Side Stock Exhaustion Guard (Deep Race Condition Mitigation)
        if (canonicalProduct.stock !== undefined && canonicalProduct.stock !== null) {
          const availableStock = parseInt(canonicalProduct.stock, 10);
          if (!isNaN(availableStock) && availableStock <= 0) {
            return res.status(400).json({
              success: false,
              error: `عفواً، نفدت الكمية المتاحة من المنتج: "${canonicalProduct.name || cleanItemId}". لا يمكن إتمام الطلب.`
            });
          }
        }

        const unitPrice = parseFloat(canonicalProduct.price);
        if (isNaN(unitPrice) || unitPrice < 0) {
          return res.status(400).json({
            success: false,
            error: "سعر المنتج في الكتالوج غير صالح."
          });
        }

        const qty = Math.min(100, Math.max(1, parseInt(item.qty, 10) || 1));
        const itemTotal = unitPrice * qty;
        calculatedSubtotal += itemTotal;

        sanitizedItems.push({
          id: sanitizePathId(item.id) || "item",
          name: canonicalProduct.name ? String(canonicalProduct.name).slice(0, 100) : "وحدة إضاءة فاخرة",
          price: unitPrice,
          qty: qty,
          image: canonicalProduct.image ? String(canonicalProduct.image).slice(0, 500) : "",
          total: itemTotal
        });
      }

      const shippingFee = (calculatedSubtotal >= 5000 || !selectedArea) ? 0 : selectedArea.fee;
      const deliveryEstimate = selectedArea ? selectedArea.days : "2 - 4 أيام عمل";

      // Duplicate Order Submission Guard
      const duplicateKey = `${phone}_${calculatedSubtotal}`;
      const lastSubmission = recentOrdersSubmissionCache.get(duplicateKey);
      if (lastSubmission && (Date.now() - lastSubmission.time < 12000)) {
        return res.status(429).json({
          success: false,
          duplicateDetected: true,
          error: "تم استلام هذا الطلب بالفعل مسبقاً لمنع التكرار غير المقصود",
          order: lastSubmission.order
        });
      }

      // 6. Generate High-Entropy Cryptographic ID (F-08)
      const highEntropyId = generateSecureOrderId();
      const now = Date.now();
      const dateFormatted = new Date().toLocaleDateString("ar-EG", {
        timeZone: "Africa/Cairo",
        year: "numeric",
        month: "short",
        day: "numeric"
      });
      const timeFormatted = new Date().toLocaleTimeString("ar-EG", {
        timeZone: "Africa/Cairo",
        hour: "2-digit",
        minute: "2-digit"
      });

      // 7. Verified Customer Account Binding (BOLA / IDOR Prevention - CWE-639)
      const customerAuth = verifyCustomerRequest(req);
      let verifiedCustomerId = null;
      let verifiedCustomerEmail = null;

      if (customerAuth && customerAuth.sub) {
        verifiedCustomerId = sanitizePathId(customerAuth.sub);
        verifiedCustomerEmail = customerAuth.email ? String(customerAuth.email).trim().toLowerCase().slice(0, 100) : null;
      } else {
        // Guest submission: Strictly ignore any client-provided customerId to prevent account spoofing
        verifiedCustomerId = null;
        if (order.customer?.email || order.email) {
          verifiedCustomerEmail = String(order.customer?.email || order.email).trim().toLowerCase().slice(0, 100);
        }
      }

      const finalizedOrder = {
        id: highEntropyId,
        orderNumber: highEntropyId,
        timestamp: now,
        dateFormatted,
        timeFormatted,
        status: "received",
        statusHistory: [
          { status: "received", timestamp: now, note: "تم استلام الطلب وحجزه سحابياً" }
        ],
        isRead: false,
        customerId: verifiedCustomerId,
        email: verifiedCustomerEmail,
        customer: {
          id: verifiedCustomerId,
          email: verifiedCustomerEmail,
          name: name,
          phone: phone,
          city: selectedArea ? selectedArea.nameAr : (order.customer.city || "الشيخ زايد"),
          deliveryArea: declaredArea || (selectedArea ? selectedArea.id : "sheikh-zayed"),
          deliveryAreaName: selectedArea ? selectedArea.nameAr : "الشيخ زايد",
          deliveryAreaNameEn: selectedArea ? selectedArea.nameEn : "Sheikh Zayed",
          address: address,
          notes: (order.customer.notes || "").trim().replace(/[<>]/g, "").slice(0, 500)
        },
        items: sanitizedItems,
        subtotal: calculatedSubtotal,
        shipping: shippingFee,
        total: calculatedSubtotal + shippingFee,
        paymentMethod: "cod",
        paymentStatus: "uncollected",
        paymentStatusText: "الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد",
        paymentStatusTextEn: "Cash on delivery — not yet collected",
        deliveryEstimate: deliveryEstimate
      };

      // 7. Cloud Persistence BEFORE Responding
      const persistResult = await saveOrderToCloud(req, finalizedOrder);
      if (!persistResult.success) {
        return res.status(503).json({
          success: false,
          error: "تعذر تسجيل الطلب على الخادم في الوقت الحالي. يرجى المحاولة مرة أخرى أو التواصل معنا عبر واتساب."
        });
      }

      // Auto-prune memory cache to prevent long-term serverless memory leaks (CWE-400)
      if (recentOrdersSubmissionCache.size > 150) {
        const pruneNow = Date.now();
        for (const [k, v] of recentOrdersSubmissionCache.entries()) {
          if (pruneNow - v.time > 30000) recentOrdersSubmissionCache.delete(k);
        }
      }
      recentOrdersSubmissionCache.set(duplicateKey, { time: now, order: finalizedOrder });

      return res.status(201).json({
        success: true,
        message: "تم استلام طلبك وحجزه بنجاح تام في معارض قاصد كريم!",
        order: finalizedOrder
      });
    }

    // -------------------------------------------------------------------------
    // 3. PUT: Bulk Overwrite Orders (ADMIN-ONLY ACCESS REQUIREMENT) (F-06)
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

      // Step-Up Authentication / Blast Radius Safety Floor (Assume-Breach Mitigation)
      if (ordersList.length === 0) {
        const confirmHeader = req.headers["x-destructive-confirm"];
        if (confirmHeader !== "CONFIRM_EMPTY_ORDERS_DATABASE") {
          return res.status(403).json({
            success: false,
            error: "عملية تفريغ كافة سجلات الطلبات تتطلب تأكيداً إدارياً إضافياً فائق الأمان (Destructive Action Step-up Required)."
          });
        }
      }

      const ok = await saveBatchOrdersToCloud(req, ordersList);
      return res.status(200).json({ success: ok, batch: true, count: ordersList.length });
    }

    // -------------------------------------------------------------------------
    // 4. PATCH: Update Order Status / Read State (ADMIN-ONLY ACCESS REQUIREMENT) (F-06)
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
      const { id, status, isRead, paymentStatus, updatedAt } = body || {};
      const safeId = sanitizePathId(id);
      if (!safeId) return res.status(400).json({ error: "معرف الطلب غير صحيح" });

      const patchTime = updatedAt || Date.now();
      const patchData = { updatedAt: patchTime };
      if (status !== undefined) patchData.status = String(status).slice(0, 30);
      if (isRead !== undefined) patchData.isRead = Boolean(isRead);
      if (paymentStatus !== undefined) {
        patchData.paymentStatus = String(paymentStatus).slice(0, 30);
        patchData.paymentStatusText = paymentStatus === "collected" ? "تم التحصيل نقدياً بنجاح" : "الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد";
        patchData.paymentStatusTextEn = paymentStatus === "collected" ? "Cash Collected Successfully" : "Cash on delivery — not yet collected";
        if (paymentStatus === "collected") {
          patchData.paidAt = patchTime;
          patchData.collectedBy = admin.sub || "admin";
        }
      }

      try {
        const firebaseUrl = getFirebaseUrl(`orders/${safeId}.json`);
        await fetch(firebaseUrl, {
          method: "PATCH",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(patchData)
        });
        await bumpSyncMetadata("order_status_patch");
      } catch (err) {
        console.warn("Firebase PATCH status error:", err.message);
      }

      const { orders } = await fetchOrdersFromCloud(req);
      const target = orders.find(o => o.id === safeId);
      if (target) {
        if (status !== undefined) target.status = patchData.status;
        if (isRead !== undefined) target.isRead = patchData.isRead;
        target.updatedAt = patchTime;
        await saveOrderToCloud(req, target);
      }

      return res.status(200).json({ success: true, id: safeId, status, isRead, updatedAt: patchTime });
    }

    // -------------------------------------------------------------------------
    // 5. DELETE: Remove Order (ADMIN-ONLY ACCESS REQUIREMENT) (F-06)
    // -------------------------------------------------------------------------
    if (req.method === "DELETE") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لحذف الطلبات." });
      }

      const { id } = req.query || {};
      const safeId = sanitizePathId(id);
      if (!safeId) return res.status(400).json({ error: "معرف الطلب غير صحيح" });

      const delResult = await deleteOrderFromCloud(req, safeId);
      return res.status(200).json({ success: true, persistedToCloud: delResult.success, deleted: safeId });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error("API error in /api/orders:", err.message);
    return res.status(500).json({ success: false, error: "حدث خطأ غير متوقع في معالجة الطلب." });
  }
}
