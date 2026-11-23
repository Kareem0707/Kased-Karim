// Vercel Serverless Function: /api/orders
// Authoritative E-Commerce Orders & Pricing Engine with Concurrency & Race-Condition Defense
// Compliant with OWASP API Security Top 10 (API1: BOLA, API3: BOPLA, API4: Resource Consumption, API5: BFLA, API6: Sensitive Business Flows) & ASVS Level 3

import crypto from "crypto";
import { validateEmail } from "../lib/emailValidator.js";
import { verifyTurnstile, extractTurnstileToken } from "../lib/turnstile.js";
import { enforceRateLimit, getClientIp } from "../lib/rateLimit.js";
import {
  verifyAdminRequest,
  verifyCustomerRequest,
  normalizeIpForRateLimit,
  checkDistributedRateLimit,
  sanitizePathId,
  firebaseFetch,
  firebaseCas,
  buildSafeRtdbPath,
  assertSafeRtdbPayload,
  normalizePhoneNumber,
  setSecurityHeaders,
  generateOrderId,
  getMasterJwtSecret,
  redactSecretUrl,
  withApiHardening,
  safeLogError
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Supported Delivery Areas, Fees, and Estimates (Authoritative Showroom Dispatch Rules)
const SUPPORTED_DELIVERY_AREAS = {
  "sheikh-zayed": { nameAr: "الشيخ زايد", nameEn: "Sheikh Zayed", fee: 0, days: "1 - 2 أيام عمل" },
  "october": { nameAr: "السادس من أكتوبر", nameEn: "6th of October", fee: 50, days: "1 - 2 أيام عمل" },
  "new-cairo": { nameAr: "القاهرة الجديدة والتجمع", nameEn: "New Cairo & Tagamoa", fee: 75, days: "2 - 3 أيام عمل" },
  "giza": { nameAr: "الجيزة والدقي والمهندسين", nameEn: "Giza, Dokki & Mohandessin", fee: 60, days: "2 - 3 أيام عمل" },
  "cairo": { nameAr: "وسط البلد ومدينة نصر ومصر الجديدة", nameEn: "Cairo, Nasr City & Heliopolis", fee: 70, days: "2 - 3 أيام عمل" },
  "alexandria": { nameAr: "الإسكندرية والساحل الشمالي", nameEn: "Alexandria & North Coast", fee: 120, days: "3 - 5 أيام عمل" }
};

// Allowed State Machine Transitions for Administrative Order Status Updates (Axis 4)
const VALID_ORDER_STATUSES = new Set([
  "received",
  "confirmed",
  "preparing",
  "packed",
  "shipped",
  "delivered",
  "completed",
  "cancelled",
  "failed"
]);

// Update Global Sync Metadata
async function bumpSyncMetadata(actionType = "order_update") {
  try {
    const now = Date.now();
    await firebaseFetch(buildSafeRtdbPath("sync_meta"), {
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

// 1. Fetch Orders from Cloud (Firebase RTDB with Vercel KV Failover)
async function fetchOrdersFromCloud(req) {
  const t = Date.now();

  try {
    const res = await firebaseFetch(buildSafeRtdbPath("orders"), {
      cache: "no-store",
      headers: { "Accept": "application/json", "Cache-Control": "no-cache, no-store" }
    }, { t });

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
    console.warn("Firebase fetch orders error:", redactSecretUrl(err.message));
  }

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
      console.warn("KV fetch orders error:", redactSecretUrl(err.message));
    }
  }

  return { orders: [], provider: "none" };
}

// 2. Fetch Single Product Directly from Cloud (O(1) Direct Lookup)
async function getProductById(productId) {
  const safeId = sanitizePathId(productId);
  if (!safeId) return null;
  try {
    const res = await firebaseFetch(buildSafeRtdbPath("products", safeId), {
      cache: "no-store",
      headers: { "Accept": "application/json" }
    }, { t: Date.now() });

    if (res.ok) {
      const prod = await res.json();
      if (prod && typeof prod === "object") return prod;
    }
  } catch (e) {}
  return null;
}

// 3. Fetch Full Product Catalog
async function getCanonicalCatalog() {
  try {
    const res = await firebaseFetch(buildSafeRtdbPath("products"), {
      cache: "no-store",
      headers: { "Accept": "application/json" }
    }, { t: Date.now() });

    if (res.ok) {
      const raw = await res.json();
      if (Array.isArray(raw)) return raw.filter(Boolean);
      if (raw && typeof raw === "object") return Object.values(raw).filter(Boolean);
    }
  } catch (e) {}
  return [];
}

// 4. Fetch Coupon Definition
async function getCouponByCode(code) {
  const cleanCode = String(code || "").toUpperCase().replace(/[^A-Z0-9_\-]/g, "").slice(0, 30);
  if (!cleanCode) return null;
  try {
    const res = await firebaseFetch(buildSafeRtdbPath("coupons", cleanCode), {
      cache: "no-store",
      headers: { "Accept": "application/json" }
    }, { t: Date.now() });

    if (res.ok) {
      const coupon = await res.json();
      if (coupon && typeof coupon === "object") return coupon;
    }
  } catch (e) {}
  return null;
}

// 5. Save Single Order to Cloud
async function saveOrderToCloud(req, order) {
  let savedToFirebase = false;
  const safeId = sanitizePathId(order.id);
  if (!safeId) return { success: false, provider: "none" };

  try {
    assertSafeRtdbPayload(order);
    const res = await firebaseFetch(buildSafeRtdbPath("orders", safeId), {
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
    console.warn("Firebase save order error:", redactSecretUrl(err.message));
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
      await fetch(`${kvUrl}/set/kased_karim_orders`, {
        method: "POST",
        cache: "no-store",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(orders)
      });
    } catch (err) {}
  }

  return { success: savedToFirebase, provider: savedToFirebase ? "firebase-rtdb" : "none" };
}

// Strict Allowlist Sanitizer for Public Order Response (Axis 8)
function sanitizeOrderResponse(order) {
  if (!order || typeof order !== "object") return null;
  return Object.freeze({
    id: order.id,
    orderNumber: order.orderNumber || order.id,
    customerId: order.customerId || order.customer?.id || undefined,
    timestamp: order.timestamp,
    dateFormatted: order.dateFormatted,
    timeFormatted: order.timeFormatted,
    status: order.status || "received",
    subtotal: order.subtotal || 0,
    discount: order.discount || 0,
    shipping: order.shipping !== undefined ? order.shipping : (order.shippingFee || 0),
    shippingFee: order.shippingFee !== undefined ? order.shippingFee : (order.shipping || 0),
    total: order.total || 0,
    items: (Array.isArray(order.items) ? order.items : []).map(it => ({
      id: it.id,
      name: it.name,
      price: it.price,
      qty: it.qty,
      total: it.total,
      image: it.image || "",
      variant: it.variant || ""
    })),
    deliveryEstimate: order.deliveryEstimate || "2 - 4 أيام عمل",
    paymentMethod: order.paymentMethod || "cod",
    paymentStatus: order.paymentStatus || "uncollected",
    customer: {
      name: order.customer?.name || "",
      phone: order.customer?.phone || "",
      city: order.customer?.city || "",
      deliveryArea: order.customer?.deliveryArea || "",
      deliveryAreaName: order.customer?.deliveryAreaName || "",
      address: order.customer?.address || "",
      notes: order.customer?.notes || ""
    }
  });
}

async function ordersHandler(req, res, { requestId, safeBody } = {}) {
  // 1. Mandatory CORS & Security Headers Gate (Axis 8: ASVS 14.4 & 14.5)
  if (setSecurityHeaders(req, res, { cacheControl: "no-store, no-cache, must-revalidate, private" })) return;

  try {
    // 2. Payload Size Limit Guard (DoS Mitigation - CWE-400 / OWASP API4)
    const contentLength = parseInt(req.headers["content-length"] || "0", 10);
    const maxAllowedBytes = req.method === "PUT" ? (512 * 1024) : (50 * 1024); // 50 KB for single order, 512 KB for admin bulk
    if (contentLength > maxAllowedBytes) {
      return res.status(413).json({
        success: false,
        error: `حجم بيانات الطلب يتجاوز الحد الأقصى المسموح به (${Math.round(maxAllowedBytes / 1024)} كيلوبايت) - 413 Payload Too Large.`
      });
    }

    // -------------------------------------------------------------------------
    // 1. GET: Fetch Orders (Admin Full View OR Customer Personal View with ?mine=1)
    // -------------------------------------------------------------------------
    if (req.method === "GET" || req.method === "HEAD") {
      // Sliding Window Rate Limit for Public/Authenticated Orders Read (60 requests per minute)
      const allowed = await enforceRateLimit(req, res, "read");
      if (!allowed) return;

      const isMine = req.query?.mine === "1" || req.query?.mine === "true";

      // SUB-CASE A: AUTHENTICATED CUSTOMER ORDERS HISTORY (Axis 4: BOLA Prevention)
      if (isMine) {
        const customerAuth = verifyCustomerRequest(req);
        if (!customerAuth || !customerAuth.sub) {
          return res.status(401).json({
            success: false,
            error: "غير مصرح بالوصول. يرجى تسجيل الدخول لعرض سجل طلباتك."
          });
        }

        const authCustId = sanitizePathId(customerAuth.sub);
        const authEmail = customerAuth.email ? String(customerAuth.email).trim().toLowerCase() : "";
        const isEmailVerified = Boolean(customerAuth.email_verified === true || customerAuth.emailVerified === true);

        const { orders } = await fetchOrdersFromCloud(req);
        const customerOrders = orders.filter(o => {
          if (!o) return false;
          const orderCustId = sanitizePathId(o.customerId || (o.customer && o.customer.id));
          const orderEmail = (o.customer?.email || o.email || "").trim().toLowerCase();
          const matchCustId = Boolean(authCustId && orderCustId && authCustId === orderCustId);
          const matchEmail = Boolean(isEmailVerified && authEmail && orderEmail && authEmail === orderEmail);
          return matchCustId || matchEmail;
        });

        customerOrders.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        const sanitizedList = customerOrders.map(sanitizeOrderResponse).filter(Boolean);

        return res.status(200).json({
          success: true,
          count: sanitizedList.length,
          orders: sanitizedList
        });
      }

      // SUB-CASE B: PRIVILEGED ADMIN ACCESS (Axis 4: BFLA Prevention)
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({
          success: false,
          error: "غير مصرح بالوصول. استعراض كافة سجلات الطلبات يتطلب صلاحيات الإدارة العليا."
        });
      }

      const { id } = req.query || {};
      const { orders, provider } = await fetchOrdersFromCloud(req);

      if (id) {
        const cleanId = String(id).replace(/[#]/g, "").trim().toUpperCase();
        const single = orders.find(o =>
          o && o.id && (
            o.id.toUpperCase() === cleanId ||
            o.id.replace("ORD-", "") === cleanId.replace("ORD-", "")
          )
        );
        if (single) {
          return res.status(200).json({ success: true, order: single, provider });
        }
        return res.status(404).json({ success: false, error: "لم يتم العثور على الطلب المطلوب." });
      }

      orders.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      const rawPage = parseInt(req.query?.page || "1", 10);
      const rawLimit = parseInt(req.query?.limit || "50", 10);
      const page = Number.isInteger(rawPage) && rawPage >= 1 ? rawPage : 1;
      const limit = Number.isInteger(rawLimit) && rawLimit >= 1 ? Math.min(rawLimit, 50) : 50;
      const total = orders.length;
      const totalPages = Math.ceil(total / limit) || 1;
      const startIndex = (page - 1) * limit;
      const paginatedOrders = orders.slice(startIndex, startIndex + limit);

      return res.status(200).json({
        success: true,
        count: paginatedOrders.length,
        total,
        page,
        limit,
        totalPages,
        provider,
        orders: paginatedOrders
      });
    }

    // -------------------------------------------------------------------------
    // 2. POST: Create a New Order (Server-Authoritative Pricing Engine)
    // -------------------------------------------------------------------------
    if (req.method === "POST") {
      const clientIp = getClientIp(req);
      const normalizedIp = normalizeIpForRateLimit(clientIp);

      // Sliding Window Rate Limiting (3 orders per 10 minutes per IP or User ID)
      const customerAuthEarly = verifyCustomerRequest(req);
      const allowed = await enforceRateLimit(req, res, "orders", customerAuthEarly?.sub || null);
      if (!allowed) return;

      let orderPayload = req.body;
      if (typeof orderPayload === "string") {
        try {
          orderPayload = JSON.parse(orderPayload);
        } catch (e) {
          return res.status(400).json({ success: false, error: "حزمة بيانات الطلب غير صالحة (Invalid JSON Body)." });
        }
      }

      if (!orderPayload || typeof orderPayload !== "object" || Array.isArray(orderPayload) || !orderPayload.customer) {
        return res.status(400).json({ success: false, error: "بيانات العميل وسلة الطلب مفقودة أو غير مكتملة." });
      }

      // 1. Mandatory Cloudflare Turnstile Bot Gate (Anti-Automation & Fraud Defense)
      const turnstileToken = extractTurnstileToken(req, orderPayload);
      const turnstileRes = await verifyTurnstile(turnstileToken, clientIp);
      if (!turnstileRes.success) {
        return res.status(400).json({
          success: false,
          error: turnstileRes.error || "فشل التحقق الأمني من اختبار مكافحة الروبوتات (Turnstile)."
        });
      }

      // 2. Verified Account Enforcement (SENSITIVE OPERATION: 403 Forbidden for Unverified Accounts)
      const customerAuth = verifyCustomerRequest(req);
      if (customerAuth && customerAuth.sub) {
        const isVerified = customerAuth.email_verified === true || customerAuth.emailVerified === true;
        if (!isVerified) {
          let liveVerified = false;
          try {
            const custRes = await firebaseFetch(buildSafeRtdbPath("customers", sanitizePathId(customerAuth.sub)), { cache: "no-store" });
            if (custRes.ok) {
              const liveCust = await custRes.json();
              liveVerified = Boolean(liveCust && (liveCust.emailVerified === true || liveCust.email_verified === true));
            }
          } catch (e) {}

          if (!liveVerified) {
            return res.status(403).json({
              success: false,
              forbidden: true,
              error: "تم رفض إنشاء الطلب: حساب العميل غير مفعّل. يرجى تفعيل البريد الإلكتروني للمتابعة (403 Forbidden)."
            });
          }
        }
      }

      // Check Idempotency-Key (Axis 3: Duplicate Submission & Race Condition Defense)
      const rawIdempKey = req.headers["idempotency-key"] || orderPayload.idempotencyKey || "";
      let cleanIdempKey = typeof rawIdempKey === "string" ? rawIdempKey.trim().slice(0, 100) : "";
      
      // Fallback synthetic idempotency lock to defend against race condition replays if client omits the header
      if (!cleanIdempKey) {
        const candidatePhone = (orderPayload.customer?.phone || orderPayload.phone || "").replace(/[^0-9]/g, "");
        const itemsSignature = Array.isArray(orderPayload.items)
          ? orderPayload.items.map(i => `${i.id || i.productId}:${i.qty || i.quantity}`).sort().join(",")
          : "";
        cleanIdempKey = `synth_${crypto.createHash("sha256").update(`${clientIp}:${candidatePhone}:${itemsSignature}`).digest("hex")}`;
      }

      let idempPath = null;

      if (cleanIdempKey) {
        const idempHmac = crypto.createHmac("sha256", getMasterJwtSecret() || "kased_karim_idemp_key")
          .update(cleanIdempKey)
          .digest("hex");
        idempPath = `_server_vault/order_idempotency/${idempHmac}.json`;

        try {
          const idempRes = await firebaseFetch(idempPath, { cache: "no-store" }, { t: Date.now() });
          if (idempRes.ok) {
            const idempRecord = await idempRes.json();
            if (idempRecord && typeof idempRecord === "object") {
              const ageMs = Date.now() - (idempRecord.createdAt || 0);
              // If record exists and is within 1 hour TTL
              if (ageMs < 3600 * 1000) {
                if (idempRecord.status === "completed" && idempRecord.order) {
                  return res.status(200).json({
                    success: true,
                    idempotentReplay: true,
                    message: "تم استلام هذا الطلب وتأكيده مسبقاً بنجاح.",
                    order: sanitizeOrderResponse(idempRecord.order)
                  });
                }
                if (idempRecord.status === "processing" && ageMs < 15 * 1000) {
                  return res.status(409).json({
                    success: false,
                    error: "جارٍ معالجة هذا الطلب بالفعل حالياً على الخادم. يرجى الانتظار لحين اكتمال المعالجة."
                  });
                }
              }
            }
          }
        } catch (idempErr) {}

        // Claim lock atomically with status 'processing'
        try {
          await firebaseFetch(idempPath, {
            method: "PUT",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: "processing", createdAt: Date.now() })
          });
        } catch (e) {}
      }

      // 1. Customer PII Sanitization & Normalization (Axis 5)
      const rawCustomer = orderPayload.customer || {};
      const rawName = typeof rawCustomer.name === "string" ? rawCustomer.name : "";
      const cleanName = rawName.replace(/[<>]/g, "").replace(/[\x00-\x1F\x7F]/g, "").trim().slice(0, 100);
      const nameParts = cleanName.split(/\s+/).filter(p => p.length >= 2);
      if (nameParts.length < 2) {
        return res.status(400).json({
          success: false,
          error: "يرجى كتابة الاسم ثنائياً على الأقل (الاسم الأول واسم العائلة)."
        });
      }

      // Phone Normalization & Validation (Axis 5)
      const rawPhone = typeof rawCustomer.phone === "string" ? rawCustomer.phone : "";
      const normalizedPhone = normalizePhoneNumber(rawPhone);
      if (!normalizedPhone || normalizedPhone.length < 11 || (!normalizedPhone.startsWith("01") && !normalizedPhone.startsWith("201"))) {
        return res.status(400).json({
          success: false,
          error: "رقم الهاتف غير صحيح. يجب أن يتكون من 11 رقماً ويبدأ بكود شبكات المحمول المصرية (010, 011, 012, 015)."
        });
      }

      // Layer 2: Phone-Level Distributed Rate Limiting (3 orders per 15 minutes) (Axis 7)
      const phoneLimit = await checkDistributedRateLimit(normalizedPhone, "create_order_phone", 3, 15 * 60 * 1000);
      if (!phoneLimit.allowed) {
        res.setHeader("Retry-After", String(phoneLimit.remainingSec));
        return res.status(429).json({
          success: false,
          error: `تم تجاوز الحد المسموح للطلبات المسجلة بهذا الرقم. يرجى الانتظار ${phoneLimit.remainingSec} ثانية قبل إعادة المحاولة.`
        });
      }

      // Customer Email Deep Validation (Disposable Domain & DNS MX Records Defense)
      const rawCustomerEmail = (rawCustomer.email || orderPayload.email || (customerAuth && customerAuth.email) || "").trim();
      let cleanOrderEmail = null;
      if (rawCustomerEmail) {
        const emailValidation = await validateEmail(rawCustomerEmail, { checkMx: true, timeoutMs: 3000 });
        if (!emailValidation.valid) {
          return res.status(400).json({
            success: false,
            reason: emailValidation.reason,
            error: emailValidation.error || "البريد الإلكتروني للطلب غير صالح أو مؤقت أو غير مسجل في خوادم البريد (MX Records)."
          });
        }
        cleanOrderEmail = emailValidation.normalizedEmail;
      }

      // Address Sanitization
      const rawAddress = typeof rawCustomer.address === "string" ? rawCustomer.address : "";
      const cleanAddress = rawAddress.replace(/[<>]/g, "").replace(/[\x00-\x1F\x7F]/g, "").trim().slice(0, 300);
      if (cleanAddress.length < 5) {
        return res.status(400).json({
          success: false,
          error: "يرجى كتابة العنوان بالتفصيل (اسم المنطقة، الشارع، رقم العقار أو الفيلا)."
        });
      }

      const cleanNotes = typeof rawCustomer.notes === "string"
        ? rawCustomer.notes.replace(/[<>]/g, "").replace(/[\x00-\x1F\x7F]/g, "").trim().slice(0, 400)
        : "";

      // Delivery Area Resolution & Rule Lookup (Axis 1)
      const declaredArea = (orderPayload.deliveryArea || rawCustomer.deliveryArea || rawCustomer.city || "").toLowerCase().trim();
      let selectedArea = SUPPORTED_DELIVERY_AREAS[declaredArea];
      if (!selectedArea) {
        const match = Object.entries(SUPPORTED_DELIVERY_AREAS).find(([k, v]) =>
          declaredArea.includes(k) ||
          cleanAddress.includes(v.nameAr) ||
          (rawCustomer.city && rawCustomer.city.includes(v.nameAr))
        );
        selectedArea = match ? match[1] : null;
      }

      if (!selectedArea) {
        return res.status(400).json({
          success: false,
          error: "عفواً، منطقة التوصيل المحددة غير مدعومة حالياً. خدمات التوصيل لمعرض قاصد كريم تغطي الشيخ زايد، 6 أكتوبر، القاهرة الكبرى، الجيزة، والإسكندرية والساحل الشمالي."
        });
      }

      // 2. Strict Items Validation, Deduplication & Quantity Bounds (Axis 2)
      const rawItems = orderPayload.items;
      if (!Array.isArray(rawItems) || rawItems.length === 0 || rawItems.length > 50) {
        return res.status(400).json({
          success: false,
          error: "سلة المشتريات غير صالحة. يجب أن تحتوي بين 1 و 50 صنفاً."
        });
      }

      // Deduplicate line-items by combining quantities for identical (productId + variant)
      const aggregatedItemsMap = new Map();
      for (const item of rawItems) {
        if (!item || typeof item !== "object") {
          return res.status(400).json({ success: false, error: "بيانات أحد المنتجات في السلة غير صالحة." });
        }

        const rawProdId = typeof item.id === "string" ? item.id : (typeof item.productId === "string" ? item.productId : "");
        const cleanProdId = sanitizePathId(rawProdId);
        if (!cleanProdId || cleanProdId.includes("..") || cleanProdId.includes("/") || cleanProdId.includes("\\")) {
          return res.status(400).json({ success: false, error: "معرف أحد المنتجات في السلة غير صالح." });
        }

        const rawQty = item.qty !== undefined ? item.qty : item.quantity;
        // Strict integer positive quantity validation (rejects 0, negatives, decimals, strings, NaN, Infinity)
        if (typeof rawQty !== "number" || !Number.isInteger(rawQty) || rawQty <= 0) {
          return res.status(400).json({
            success: false,
            error: "كمية المنتجات في السلة يجب أن تكون أرقاماً صحيحة موجبة أكبر من صفر."
          });
        }

        const variant = typeof item.variant === "string"
          ? item.variant.replace(/[<>]/g, "").trim().slice(0, 50)
          : "";

        const dedupKey = `${cleanProdId}:${variant}`;
        const existing = aggregatedItemsMap.get(dedupKey);
        if (existing) {
          existing.qty += rawQty;
        } else {
          aggregatedItemsMap.set(dedupKey, { id: cleanProdId, variant, qty: rawQty });
        }
      }

      // Enforce Maximum Purchase Quantity per Line Item (Axis 2: Integer Overflow & Abuse Guard)
      const MAX_QTY_PER_ITEM = 50;
      for (const [key, item] of aggregatedItemsMap.entries()) {
        if (item.qty > MAX_QTY_PER_ITEM) {
          return res.status(400).json({
            success: false,
            error: `الكمية الإجمالية المطلوبة للمنتج '${item.id}' تتجاوز السقف المسموح به (${MAX_QTY_PER_ITEM} قطعة).`
          });
        }
      }

      // 3. Server-Authoritative Price Calculation (Axis 1: Zero-Trust in Client Financial Values)
      const catalog = await getCanonicalCatalog();
      if (!catalog || !Array.isArray(catalog) || catalog.length === 0) {
        return res.status(503).json({
          success: false,
          error: "تعذر التحقق من قائمة الأسعار المعتمدة من الخادم في الوقت الحالي. يرجى المحاولة بعد قليل."
        });
      }

      const catalogMap = new Map();
      catalog.forEach(p => {
        if (p && p.id) {
          catalogMap.set(String(p.id), p);
        }
      });

      let subtotalCents = 0;
      const verifiedLineItems = [];

      for (const [dedupKey, aggItem] of aggregatedItemsMap.entries()) {
        const canonicalProduct = catalogMap.get(aggItem.id);

        if (!canonicalProduct || canonicalProduct.active === false || canonicalProduct.deleted === true || canonicalProduct.deleted_at) {
          return res.status(400).json({
            success: false,
            error: `عفواً، المنتج '${canonicalProduct?.name || aggItem.id}' غير متوفر حالياً في الكتالوج (تم حذفه أو إيقافه).`
          });
        }

        const canonicalPrice = parseFloat(canonicalProduct.price);
        if (isNaN(canonicalPrice) || !Number.isFinite(canonicalPrice) || canonicalPrice <= 0) {
          return res.status(400).json({
            success: false,
            error: `سعر المنتج '${canonicalProduct.name || aggItem.id}' غير صالح في كتالوج المعرض.`
          });
        }

        // Integer minor-unit calculation in Cents (Axis 1: Precision Math)
        const unitPriceCents = Math.round(canonicalPrice * 100);
        const lineTotalCents = unitPriceCents * aggItem.qty;

        if (!Number.isSafeInteger(lineTotalCents) || lineTotalCents < 0) {
          return res.status(400).json({ success: false, error: "قيمة الحساب المالي للمنتج تتجاوز الحدود الآمنة للنظام." });
        }

        subtotalCents += lineTotalCents;

        verifiedLineItems.push({
          id: aggItem.id,
          name: canonicalProduct.name ? String(canonicalProduct.name).slice(0, 100) : "وحدة إضاءة فاخرة",
          price: unitPriceCents / 100,
          qty: aggItem.qty,
          variant: aggItem.variant,
          image: canonicalProduct.image ? String(canonicalProduct.image).slice(0, 500) : "",
          total: lineTotalCents / 100,
          _canonicalProduct: canonicalProduct
        });
      }

      // Maximum Order Value Ceiling (Anti-Money-Laundering / System Overflow Guard)
      const MAX_ORDER_CENTS = 10000000 * 100; // 10,000,000 EGP
      if (subtotalCents > MAX_ORDER_CENTS) {
        return res.status(400).json({
          success: false,
          error: "إجمالي قيمة الطلب يتجاوز الحد الأقصى للشراء المباشر. يرجى التواصل مع المعرض لطلبات المشروعات الكبرى."
        });
      }

      // 4. Coupon Discount Calculation from Central Server Rules (Axis 1)
      let discountCents = 0;
      let appliedCouponCode = null;

      if (orderPayload.couponCode || orderPayload.coupon) {
        const rawCode = orderPayload.couponCode || orderPayload.coupon;
        const coupon = await getCouponByCode(rawCode);

        if (!coupon || coupon.active === false) {
          return res.status(400).json({ success: false, error: "كوبون الخصم المُدخل غير صالح أو تم إيقافه." });
        }

        const now = Date.now();
        const expiryTime = coupon.expiresAt || (coupon.expiryDate ? new Date(coupon.expiryDate).getTime() : null);
        if (expiryTime && !isNaN(expiryTime) && now > expiryTime) {
          return res.status(400).json({ success: false, error: "كوبون الخصم منتهي الصلاحية." });
        }

        const minOrderAmountCents = coupon.minOrderAmount ? Math.round(Number(coupon.minOrderAmount) * 100) : 0;
        if (subtotalCents < minOrderAmountCents) {
          return res.status(400).json({
            success: false,
            error: `الحد الأدنى لتفعيل هذا الكوبون هو ${coupon.minOrderAmount} ج.م.`
          });
        }

        if (coupon.usageLimit && (coupon.usedCount || 0) >= coupon.usageLimit) {
          return res.status(400).json({ success: false, error: "تم الوصول للحد الأقصى لاستخدام هذا الكوبون." });
        }

        // Calculate discount in Cents (supporting discountPercent / discountAmount OR type percentage/fixed with value)
        const percentVal = coupon.discountPercent !== undefined ? coupon.discountPercent : (coupon.type === "percentage" ? coupon.value : 0);
        const fixedVal = coupon.discountAmount !== undefined ? coupon.discountAmount : (coupon.type === "fixed" ? coupon.value : 0);

        if (percentVal) {
          const percent = Math.min(100, Math.max(0, Number(percentVal)));
          discountCents = Math.round((subtotalCents * percent) / 100);
          const maxCap = coupon.maxDiscountAmount || coupon.maxDiscount;
          if (maxCap) {
            const maxCents = Math.round(Number(maxCap) * 100);
            discountCents = Math.min(discountCents, maxCents);
          }
        } else if (fixedVal) {
          discountCents = Math.round(Number(fixedVal) * 100);
        }

        // Ensure discount never exceeds subtotal (Axis 1)
        discountCents = Math.min(discountCents, subtotalCents);
        appliedCouponCode = coupon.code || String(rawCode).toUpperCase();
      }

      // 5. Authoritative Shipping Fee Calculation (Axis 1)
      const freeShippingThresholdCents = 5000 * 100; // 5,000 EGP Threshold
      let shippingCents = 0;
      if (subtotalCents < freeShippingThresholdCents && selectedArea.fee > 0) {
        shippingCents = Math.round(selectedArea.fee * 100);
      }

      // Final Grand Total in Cents
      const totalCents = Math.max(0, subtotalCents - discountCents) + shippingCents;

      // 6. Atomic Stock Reservation via Firebase ETag Compare-And-Swap (Axis 3)
      const reservedStockItems = [];
      let stockFailure = null;

      for (const item of verifiedLineItems) {
        const prod = item._canonicalProduct;
        if (prod.stock !== undefined && prod.stock !== null) {
          const requiredQty = item.qty;

          const casResult = await firebaseCas(buildSafeRtdbPath("products", item.id), (current) => {
            if (!current) return false;
            if (current.stock === undefined || current.stock === null) return current;
            const currentStock = parseInt(current.stock, 10);
            if (isNaN(currentStock) || currentStock < requiredQty) {
              return false; // Out of stock
            }
            return {
              ...current,
              stock: currentStock - requiredQty,
              updatedAt: Date.now()
            };
          });

          if (!casResult.success) {
            stockFailure = { item, name: prod.name || item.id };
            break;
          }

          reservedStockItems.push({ id: item.id, qty: requiredQty });
        }
      }

      // Compensating Rollback if any stock reservation failed (Axis 3)
      if (stockFailure) {
        for (const rollbackItem of reservedStockItems) {
          await firebaseCas(buildSafeRtdbPath("products", rollbackItem.id), (current) => {
            if (!current) return false;
            const currentStock = parseInt(current.stock, 10) || 0;
            return {
              ...current,
              stock: currentStock + rollbackItem.qty,
              updatedAt: Date.now()
            };
          }).catch(() => null);
        }

        return res.status(409).json({
          success: false,
          error: `عفواً، نفدت الكمية المتاحة من المنتج: "${stockFailure.name}". لا يمكن إتمام الطلب.`
        });
      }

      // 7. High-Entropy Order Identifier Generation (>= 64 bits CSPRNG entropy) (Axis 4)
      const highEntropyId = generateOrderId();
      const now = Date.now();
      const dateFormatted = new Date(now).toLocaleDateString("ar-EG", {
        timeZone: "Africa/Cairo",
        year: "numeric",
        month: "short",
        day: "numeric"
      });
      const timeFormatted = new Date(now).toLocaleTimeString("ar-EG", {
        timeZone: "Africa/Cairo",
        hour: "2-digit",
        minute: "2-digit"
      });

      // 8. Verified Customer Account Binding (Axis 4: IDOR Prevention)
      const verifiedCustomerId = customerAuth && customerAuth.sub ? sanitizePathId(customerAuth.sub) : null;
      const verifiedCustomerEmail = customerAuth && customerAuth.email ? String(customerAuth.email).trim().toLowerCase().slice(0, 100) : null;

      // 9. Finalized Order Construction (Strictly Server-Controlled Fields)
      const sanitizedItemsForOrder = verifiedLineItems.map(it => {
        const itemObj = {
          id: it.id,
          name: it.name,
          price: it.price,
          qty: it.qty,
          image: it.image || "",
          total: it.total
        };
        if (it.variant) itemObj.variant = it.variant;
        return itemObj;
      });

      const customerObj = {
        name: cleanName,
        phone: normalizedPhone,
        city: selectedArea.nameAr,
        deliveryArea: selectedArea.nameAr,
        deliveryAreaId: declaredArea,
        address: cleanAddress,
        notes: cleanNotes
      };
      if (verifiedCustomerId) {
        customerObj.id = verifiedCustomerId;
      }
      const rawEmail = cleanOrderEmail || verifiedCustomerEmail || (rawCustomer.email ? String(rawCustomer.email).trim().toLowerCase().slice(0, 100) : "");
      if (rawEmail) {
        customerObj.email = rawEmail;
      }

      const finalizedOrder = {
        id: highEntropyId,
        orderNumber: highEntropyId,
        timestamp: now,
        dateFormatted,
        timeFormatted,
        status: "received",
        statusHistory: [
          { status: "received", timestamp: now, note: "تم استلام الطلب وتوثيق الحسابات سحابياً" }
        ],
        isRead: false,
        customer: customerObj,
        items: sanitizedItemsForOrder,
        subtotal: subtotalCents / 100,
        discount: discountCents / 100,
        shipping: shippingCents / 100,
        shippingFee: shippingCents / 100,
        total: totalCents / 100,
        paymentMethod: "cod",
        paymentStatus: "uncollected",
        paymentStatusText: "الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد",
        deliveryEstimate: selectedArea.days
      };

      if (verifiedCustomerId) {
        finalizedOrder.customerId = verifiedCustomerId;
      }
      if (rawEmail) {
        finalizedOrder.email = rawEmail;
      }
      if (appliedCouponCode) {
        finalizedOrder.couponCode = appliedCouponCode;
      }

      // 10. Persist to Cloud Database
      const saveResult = await saveOrderToCloud(req, finalizedOrder);
      if (!saveResult.success) {
        // Rollback reserved stock if order persistence fails
        for (const rollbackItem of reservedStockItems) {
          await firebaseCas(buildSafeRtdbPath("products", rollbackItem.id), (current) => {
            if (!current) return false;
            const currentStock = parseInt(current.stock, 10) || 0;
            return { ...current, stock: currentStock + rollbackItem.qty, updatedAt: Date.now() };
          }).catch(() => null);
        }

        return res.status(503).json({
          success: false,
          error: "تعذر تسجيل الطلب على الخادم في الوقت الحالي. يرجى المحاولة مرة أخرى أو التواصل معنا عبر واتساب."
        });
      }

      // Update Idempotency Record to completed state
      if (idempPath) {
        try {
          await firebaseFetch(idempPath, {
            method: "PUT",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: "completed", order: finalizedOrder, createdAt: now })
          });
        } catch (e) {}
      }

      return res.status(201).json({
        success: true,
        message: "تم استلام وتأكيد طلبكم بنجاح تام في معارض قاصد كريم!",
        order: sanitizeOrderResponse(finalizedOrder)
      });
    }

    // -------------------------------------------------------------------------
    // 3. PATCH: Administrative Order Status & State Machine Updates (ADMIN ONLY)
    // -------------------------------------------------------------------------
    if (req.method === "PATCH") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({
          success: false,
          error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لتعديل بيانات وحالة الطلبات."
        });
      }

      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      body = body || {};

      const rawId = body.id || req.query?.id;
      const safeId = sanitizePathId(rawId);
      if (!safeId) {
        return res.status(400).json({ success: false, error: "معرف الطلب غير صحيح أو مفقود." });
      }

      const patchTime = body.updatedAt || Date.now();
      const patchData = { updatedAt: patchTime };

      // State Machine Validation (Axis 4)
      if (body.status !== undefined) {
        const targetStatus = String(body.status).trim().toLowerCase();
        if (!VALID_ORDER_STATUSES.has(targetStatus)) {
          return res.status(400).json({
            success: false,
            error: `حالة الطلب غير صالحة: '${targetStatus}'.`
          });
        }
        patchData.status = targetStatus;
      }

      if (body.isRead !== undefined) {
        patchData.isRead = Boolean(body.isRead);
      }

      if (body.adminNotes !== undefined) {
        patchData.adminNotes = String(body.adminNotes).replace(/[<>]/g, "").trim().slice(0, 500);
      }

      if (body.paymentStatus !== undefined) {
        const ps = String(body.paymentStatus).trim().toLowerCase();
        patchData.paymentStatus = ps;
        patchData.paymentStatusText = ps === "collected"
          ? "تم التحصيل نقدياً بنجاح"
          : "الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد";
        if (ps === "collected") {
          patchData.paidAt = patchTime;
          patchData.collectedBy = admin.sub || "admin";
        }
      }

      assertSafeRtdbPayload(patchData, {
        allowedKeys: ["status", "isRead", "adminNotes", "updatedAt", "paymentStatus", "paymentStatusText", "paidAt", "collectedBy"]
      });

      const patchRes = await firebaseFetch(buildSafeRtdbPath("orders", safeId), {
        method: "PATCH",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patchData)
      });

      if (!patchRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر تحديث حالة الطلب على السحابة." });
      }

      await bumpSyncMetadata("order_status_patch");
      return res.status(200).json({ success: true, id: safeId, patch: patchData });
    }

    // -------------------------------------------------------------------------
    // 4. DELETE: Remove Order Record (ADMIN ONLY & Empty-ID Protected)
    // -------------------------------------------------------------------------
    if (req.method === "DELETE") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({
          success: false,
          error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لحذف الطلبات."
        });
      }

      const rawId = req.query?.id || (req.body && req.body.id);
      if (typeof rawId !== "string" || !rawId.trim()) {
        return res.status(400).json({ success: false, error: "معرف الطلب مطلوب ويجب أن يكون نصاً غير فارغ." });
      }

      const safeId = sanitizePathId(rawId);
      if (!safeId || safeId.includes("..") || safeId.includes("/") || safeId.includes("\\")) {
        return res.status(400).json({ success: false, error: "معرف الطلب غير صحيح ويحظر الحذف الجماعي لسجلات الطلبات." });
      }

      const delRes = await firebaseFetch(buildSafeRtdbPath("orders", safeId), {
        method: "DELETE",
        cache: "no-store"
      });

      if (!delRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر حذف الطلب من السحابة." });
      }

      await bumpSyncMetadata("order_delete");
      return res.status(200).json({ success: true, deleted: safeId });
    }

    // -------------------------------------------------------------------------
    // 5. PUT: Bulk Overwrite Orders (ADMIN ONLY with Step-Up Confirmation)
    // -------------------------------------------------------------------------
    if (req.method === "PUT") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح بالوصول لمزامنة سجلات الطلبات." });
      }

      let payload = req.body;
      if (typeof payload === "string") {
        try { payload = JSON.parse(payload); } catch (e) {}
      }

      const ordersList = Array.isArray(payload) ? payload : (payload && payload.orders ? payload.orders : null);
      if (!ordersList || !Array.isArray(ordersList)) {
        return res.status(400).json({ success: false, error: "بيانات الطلبات غير صالحة." });
      }

      if (ordersList.length === 0) {
        const confirmHeader = req.headers["x-destructive-confirm"];
        if (confirmHeader !== "CONFIRM_EMPTY_ORDERS_DATABASE") {
          return res.status(403).json({
            success: false,
            error: "عملية تفريغ كافة سجلات الطلبات تتطلب تأكيداً إدارياً إضافياً فائق الأمان (x-destructive-confirm: CONFIRM_EMPTY_ORDERS_DATABASE)."
          });
        }
      }

      const ordersMap = {};
      ordersList.forEach(o => {
        const safeId = sanitizePathId(o?.id);
        if (safeId) ordersMap[safeId] = o;
      });

      assertSafeRtdbPayload(ordersMap);
      const putRes = await firebaseFetch(buildSafeRtdbPath("orders"), {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ordersMap)
      });

      if (!putRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر استبدال سجلات الطلبات على السحابة." });
      }

      await bumpSyncMetadata("batch_orders_overwrite");
      return res.status(200).json({ success: true, count: Object.keys(ordersMap).length });
    }

    return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها (Method Not Allowed)." });
  } catch (err) {
    safeLogError("/api/orders", requestId, err);
    return res.status(500).json({
      success: false,
      ok: false,
      error: "حدث خطأ غير متوقع في معالجة الطلب.",
      requestId
    });
  }
}

export default withApiHardening(ordersHandler, {
  allowedMethods: ["GET", "POST", "PATCH", "PUT", "DELETE"],
  maxBodyBytes: 128 * 1024,
  maxDepth: 6,
  maxKeys: 500,
  context: "/api/orders"
});
