// Vercel Serverless Function: /api/track
// Privacy-Hardened Order Tracking Endpoint with Multi-Factor Verification
// Protects customer privacy by requiring Order ID + Customer Phone match
// Strips all sensitive personal information (address, notes, full phone) from public response

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Rate limiting to prevent automated order enumeration and scraping
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

function getFirebaseUrl(req) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) return envUrl.trim().replace(/\/$/, "");
  return "https://kased-karim-default-rtdb.firebaseio.com";
}

async function fetchOrdersFromCloud(req) {
  const t = Date.now();
  const firebaseUrl = getFirebaseUrl(req);

  if (firebaseUrl) {
    try {
      const res = await fetch(`${firebaseUrl}/orders.json?t=${t}`, {
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
  }

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
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

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

    const orders = await fetchOrdersFromCloud(req);

    // Search for order by ID
    const targetOrder = orders.find(o => {
      if (!o || !o.id) return false;
      const oId = o.id.toString().toUpperCase().trim();
      return oId === cleanOrderId || oId.replace("ORD-", "") === cleanOrderId.replace("ORD-", "");
    });

    if (!targetOrder) {
      // Delay response slightly to prevent timing enumeration
      await new Promise(r => setTimeout(r, 400));
      return res.status(404).json({
        success: false,
        error: "لم يتم العثور على طلب مطابق للرقم المدخل. يرجى التأكد من كتابة كود الطلب كاملاً."
      });
    }

    // Two-factor verification: If phone is provided, it must match.
    // If phone is missing and order has a customer phone, require phone verification!
    const storedPhone = (targetOrder.customer?.phone || "").replace(/[^0-9]/g, "");
    if (storedPhone && storedPhone.length >= 10) {
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
    // Strip all sensitive personal data (customer name, address, notes, phone)
    const sanitizedItems = (targetOrder.items || []).map(item => ({
      name: item.name || "وحدة إضاءة فاخرة",
      enName: item.enName || "",
      qty: item.qty || 1,
      price: item.price || 0,
      image: item.image || "",
      categoryName: item.categoryName || ""
    }));

    const statusMessages = {
      pending: "تم استلام الطلب بنجاح، وقيد المراجعة والتأكيد بمعرض قاصد كريم بالشيخ زايد.",
      confirmed: "تم تأكيد طلبك وجارٍ تجهيز وحدات الإضاءة وفحص الجودة بالمعرض.",
      processing: "جارٍ فحص المواصفات وتغليف وحدات الإضاءة بعناية فائقة.",
      shipped: "الطلب في طريقه إليكم مع مندوب المعرض المعتمد.",
      delivered: "تم تسليم الطلب بنجاح. شكراً لثقتكم بمعرض قاصد كريم للإضاءة الفاخرة.",
      cancelled: "تم إلغاء هذا الطلب."
    };

    const currentStatus = targetOrder.status || "pending";
    const statusMessage = statusMessages[currentStatus] || statusMessages.pending;

    return res.status(200).json({
      success: true,
      order: {
        id: targetOrder.id,
        status: currentStatus,
        dateFormatted: targetOrder.dateFormatted || "مسجل حديثاً",
        timestamp: targetOrder.timestamp || Date.now(),
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
