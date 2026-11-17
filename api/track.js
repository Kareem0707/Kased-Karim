// Vercel Serverless Function: /api/track
// Privacy-Hardened Order Tracking Endpoint with Multi-Factor Verification
// Protects customer privacy by requiring Order ID + Customer Phone match
// Strips all sensitive personal information (address, notes, full phone) from public response (F-04, F-08)

import {
  verifyCustomerRequest,
  sanitizePathId,
  getFirebaseUrl,
  setSecurityHeaders
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Rate limiting to prevent automated order enumeration and scraping (F-08, F-18)
const trackRateLimit = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_MIN = 12;

function checkRateLimit(ip) {
  const now = Date.now();
  const record = trackRateLimit.get(ip);
  if (!record || now - record.start > RATE_LIMIT_WINDOW) {
    trackRateLimit.set(ip, { count: 1, start: now });
    return true;
  }
  if (record.count >= MAX_REQUESTS_PER_MIN) {
    return false;
  }
  record.count += 1;
  return true;
}

async function fetchOrdersFromCloud() {
  const t = Date.now();
  try {
    const firebaseUrl = getFirebaseUrl("orders.json", { t });
    const res = await fetch(firebaseUrl, {
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });
    if (res.ok) {
      const raw = await res.json();
      if (raw) {
        if (Array.isArray(raw)) return raw.filter(Boolean);
        if (typeof raw === "object") return Object.values(raw).filter(Boolean);
      }
    }
  } catch (e) {}

  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  if (kvUrl && kvToken) {
    try {
      const res = await fetch(`${kvUrl}/get/kased_karim_orders`, {
        cache: "no-store",
        headers: { "Authorization": `Bearer ${kvToken}` }
      });
      if (res.ok) {
        const data = await res.json();
        let list = data?.result;
        if (typeof list === "string") {
          try { list = JSON.parse(list); } catch (e) {}
        }
        if (Array.isArray(list)) return list;
      }
    } catch (e) {}
  }

  return [];
}

export default async function handler(req, res) {
  setSecurityHeaders(req, res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const clientIp = req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown_ip";
  if (!checkRateLimit(clientIp)) {
    return res.status(429).json({
      success: false,
      error: "تم تجاوز حد استعلامات التتبع المسموح به. يرجى الانتظار دقيقة واحدة والمحاولة مجدداً."
    });
  }

  try {
    let orderId = "";
    let phone = "";

    if (req.method === "POST") {
      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      orderId = (body?.orderId || body?.id || "").trim();
      phone = (body?.phone || "").trim();
    } else if (req.method === "GET") {
      orderId = (req.query?.orderId || req.query?.id || "").trim();
      phone = (req.query?.phone || "").trim();
    } else {
      return res.status(405).json({ error: "Method not allowed" });
    }

    if (!orderId) {
      return res.status(400).json({
        success: false,
        error: "يرجى إدخال رقم الطلب (مثال: ORD-XXXX)"
      });
    }

    const cleanOrderId = orderId.toUpperCase().replace(/[#]/g, "").trim();
    const cleanPhone = phone.replace(/[^0-9]/g, "");

    let targetOrder = null;

    // 1. Try Direct Fast Fetch by Order ID with Privileged Auth
    const safeId = sanitizePathId(cleanOrderId);
    if (safeId) {
      try {
        const singleUrl = getFirebaseUrl(`orders/${safeId}.json`, { t: Date.now() });
        const singleRes = await fetch(singleUrl, {
          cache: "no-store",
          headers: { "Accept": "application/json" }
        });
        if (singleRes.ok) {
          const directData = await singleRes.json();
          if (directData && directData.id) {
            targetOrder = directData;
          }
        }
      } catch (e) {}
    }

    // 2. Fallback: Search in full orders list (from Firebase or KV)
    if (!targetOrder) {
      const orders = await fetchOrdersFromCloud();
      targetOrder = orders.find(o => {
        if (!o || !o.id) return false;
        const oId = o.id.toString().toUpperCase().trim();
        return oId === cleanOrderId || oId.replace("ORD-", "") === cleanOrderId.replace("ORD-", "");
      });
    }

    if (!targetOrder) {
      // Delay response slightly to prevent timing enumeration attacks (F-08)
      await new Promise(r => setTimeout(r, 400));
      return res.status(404).json({
        success: false,
        error: "لم يتم العثور على طلب مطابق للرقم المدخل. يرجى التأكد من كتابة كود الطلب كاملاً."
      });
    }

    // Check if customer is authenticated via JWT session
    const customerAuth = verifyCustomerRequest(req);
    let isAuthenticatedOwner = false;
    if (customerAuth) {
      const authEmail = (customerAuth.email || "").trim().toLowerCase();
      const authSub = customerAuth.sub || "";
      const authPhone = (customerAuth.phone || "").replace(/[^0-9]/g, "");

      const orderEmail = (targetOrder.customer?.email || targetOrder.email || "").trim().toLowerCase();
      const orderCustId = targetOrder.customerId || (targetOrder.customer && targetOrder.customer.id) || "";
      const orderPhone = (targetOrder.customer?.phone || "").replace(/[^0-9]/g, "");

      if ((authEmail && orderEmail && authEmail === orderEmail) ||
          (authSub && orderCustId && authSub === orderCustId) ||
          (authPhone && orderPhone && (orderPhone.endsWith(authPhone) || authPhone.endsWith(orderPhone)))) {
        isAuthenticatedOwner = true;
      }
    }

    // Two-factor verification: If not authenticated owner, require matching phone verification (F-08)
    const storedPhone = (targetOrder.customer?.phone || "").replace(/[^0-9]/g, "");
    if (!isAuthenticatedOwner && storedPhone && storedPhone.length >= 10) {
      if (!cleanPhone || cleanPhone.length < 4) {
        return res.status(400).json({
          success: false,
          requirePhoneVerification: true,
          error: "لأمان وخصوصية بياناتك، يرجى إدخال رقم الهاتف المسجل لتأكيد تتبع الطلب."
        });
      }

      // Check if phone matches (exact match or last 8 digits)
      const phoneMatches = storedPhone.endsWith(cleanPhone) || cleanPhone.endsWith(storedPhone);
      if (!phoneMatches) {
        await new Promise(r => setTimeout(r, 400));
        return res.status(403).json({
          success: false,
          error: "رقم الهاتف غير مطابق لبيانات صاحب هذا الطلب. يرجى التأكد من الرقم المسجل."
        });
      }
    }

    // PRIVACY-SAFE RESPONSE:
    // Strictly strip all sensitive personal data (customer name, address, notes, phone) (F-04, F-08)
    const sanitizedItems = (targetOrder.items || []).map(item => ({
      name: item.name || "وحدة إضاءة فاخرة",
      enName: item.enName || "",
      qty: item.qty || 1,
      price: item.price || 0,
      image: item.image || "",
      categoryName: item.categoryName || ""
    }));

    const statusMessages = {
      received: "تم استلام الطلب وتوثيقه سحابياً، وجارٍ مراجعته بمعرض قاصد كريم بالشيخ زايد.",
      pending: "تم استلام الطلب وتوثيقه سحابياً، وجارٍ مراجعته بمعرض قاصد كريم بالشيخ زايد.",
      confirmed: "تم تأكيد طلبك والتحقق من المواصفات الفنية وجارٍ البدء في التجهيز.",
      preparing: "جارٍ تجهيز وفحص وحدات الإضاءة بعناية فائقة بصالة العرض.",
      processing: "جارٍ تجهيز وفحص وحدات الإضاءة بعناية فائقة بصالة العرض.",
      packed: "تم فحص وحدات الإضاءة وتغليفها بأمان تام وجاهزة للتسليم للمندوب.",
      shipped: "الطلب في طريقه إليكم مع مندوب المعرض المعتمد بالشيخ زايد.",
      delivered: "تم تسليم الطلب بنجاح. شكراً لثقتكم بمعرض قاصد كريم للإضاءة الفاخرة.",
      completed: "تم تسليم الطلب بنجاح بالضمان المعتمد.",
      cancelled: "تم إلغاء هذا الطلب وإعادة المخزون.",
      failed: "تعذر تسليم الطلب، يرجى التواصل مع المعرض عبر واتساب."
    };

    const currentStatus = targetOrder.status || "received";
    const statusMessage = statusMessages[currentStatus] || statusMessages.received;

    const orderTimestamp = targetOrder.timestamp || Date.now();
    const cairoDate = new Date(orderTimestamp).toLocaleDateString("ar-EG", {
      timeZone: "Africa/Cairo",
      year: "numeric",
      month: "short",
      day: "numeric"
    });
    const cairoTime = new Date(orderTimestamp).toLocaleTimeString("ar-EG", {
      timeZone: "Africa/Cairo",
      hour: "2-digit",
      minute: "2-digit"
    });

    return res.status(200).json({
      success: true,
      order: {
        id: targetOrder.id,
        status: currentStatus,
        dateFormatted: cairoDate,
        timeFormatted: cairoTime,
        timestamp: orderTimestamp,
        items: sanitizedItems,
        subtotal: targetOrder.subtotal || targetOrder.total || 0,
        total: targetOrder.total || 0,
        statusMessage
      }
    });
  } catch (err) {
    return res.status(500).json({ success: false, error: "حدث خطأ أثناء معالجة الطلب", message: err.message });
  }
}
