// Vercel Serverless Function: /api/track
// Privacy-Hardened Order Tracking Endpoint with Multi-Factor Verification & Distributed Anti-Brute-Force
// Compliant with OWASP API Security Top 10 (API1: BOLA, API3: BOPLA, API4: Resource Consumption), OWASP ASVS (Level 3), & NIST Privacy Framework

import crypto from "crypto";
import {
  verifyCustomerRequest,
  sanitizePathId,
  firebaseFetch,
  buildSafeRtdbPath,
  getClientIp,
  normalizeIpForRateLimit,
  checkDistributedRateLimit,
  recordFailedRateLimitAttempt,
  checkRateLimitDistributed,
  recordFailedAttemptDistributed,
  resetRateLimitDistributed,
  setSecurityHeaders,
  normalizePhoneNumber,
  timingSafePhoneCompare,
  withApiHardening,
  safeLogError
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

async function trackHandler(req, res, { requestId, safeBody } = {}) {
  // 1. Mandatory CORS & Security Headers Gate (Axis 8: ASVS 14.4 & 14.5)
  if (setSecurityHeaders(req, res, { cacheControl: "no-store, no-cache, must-revalidate, private" })) return;

  // 2. HTTP Method & PII Leakage Guard (Axis 4: Disallow Phone in GET Query Parameters)
  if (req.method === "GET") {
    if (req.query && (req.query.phone || req.query.tel)) {
      return res.status(400).json({
        success: false,
        error: "لأمان وخصوصية بياناتك، يمنع إرسال أرقام الهواتف عبر رابط الـ URL. يرجى استخدام طلب POST مع حزمة البيانات (Body)."
      });
    }
    return res.status(405).json({
      success: false,
      error: "طريقة الطلب غير مسموح بها. الاستعلام عن التتبع يتطلب إرسال طلب POST مشفر مع حزمة البيانات."
    });
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "طريقة الطلب غير مسموح بها. الاستعلام عن التتبع متاح حصراً عبر طلبات POST."
    });
  }

  const clientIp = getClientIp(req);
  const normalizedIp = normalizeIpForRateLimit(clientIp);

  // 3. Layer 1: IP-Level Distributed Rate Limiting (15 requests per 15-minute window) (Axis 6)
  const ipCheck = await checkDistributedRateLimit(clientIp, "track_ip", 15, 15 * 60 * 1000);
  if (!ipCheck.allowed) {
    res.setHeader("Retry-After", String(ipCheck.remainingSec));
    return res.status(429).json({
      success: false,
      error: `تم تجاوز حد استعلامات التتبع المسموح به لهذا العنوان. يرجى الانتظار ${ipCheck.remainingSec} ثانية والمحاولة مجدداً.`
    });
  }

  try {
    // 4. Request Body Extraction & Safe Input Validation
    let body = req.body;
    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch (e) {
        return res.status(400).json({
          success: false,
          error: "حزمة البيانات المرسلة غير صالحة (Invalid JSON Body)."
        });
      }
    }

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return res.status(400).json({
        success: false,
        error: "حزمة البيانات المرسلة غير صالحة."
      });
    }

    const rawOrderId = typeof body.orderId === "string" ? body.orderId : (typeof body.id === "string" ? body.id : "");
    const rawPhone = typeof body.phone === "string" ? body.phone : "";

    const cleanOrderId = rawOrderId.toUpperCase().replace(/[#]/g, "").trim().slice(0, 64);
    const safeOrderId = sanitizePathId(cleanOrderId);

    // Fail-fast on empty or path traversal identifiers (Axis 7: CWE-22)
    if (!cleanOrderId || !safeOrderId || cleanOrderId.includes("..") || cleanOrderId.includes("/") || cleanOrderId.includes("\\")) {
      return res.status(400).json({
        success: false,
        error: "يرجى إدخال رقم الطلب بشكل صحيح (مثال: ORD-XXXX-XXXX-XXXX-XXXX)."
      });
    }

    // 5. Layer 2: Targeted (IP + OrderID) Rate Limit (5 failed attempts per 15 minutes) (Axis 6)
    const ipOrderKey = `${normalizedIp}:${safeOrderId}`;
    const ipOrderCheck = await checkRateLimitDistributed("track_ip_order", ipOrderKey, 5, 15 * 60 * 1000);
    if (!ipOrderCheck.allowed) {
      res.setHeader("Retry-After", String(ipOrderCheck.remainingSec));
      return res.status(429).json({
        success: false,
        error: `تم تجاوز الحد الأقصى لمحاولات التحقق لهذا الطلب من عنوانك. يرجى الانتظار ${ipOrderCheck.remainingSec} ثانية قبل إعادة المحاولة.`
      });
    }

    // 6. Layer 3: Global OrderID Lock across ALL IPs (15 failed attempts per 30 minutes) (Axis 6)
    // Prevents distributed botnet phone-number brute-force enumeration against a specific order ID
    const globalOrderKey = safeOrderId;
    const globalOrderCheck = await checkRateLimitDistributed("track_global_order", globalOrderKey, 15, 30 * 60 * 1000);
    if (!globalOrderCheck.allowed) {
      res.setHeader("Retry-After", String(globalOrderCheck.remainingSec));
      return res.status(429).json({
        success: false,
        error: `تم قفل الاستعلام عن هذا الطلب مؤقتاً لحماية الخصوصية نظراً لكثرة المحاولات غير المطابقة. يرجى الانتظار ${globalOrderCheck.remainingSec} ثانية أو التواصل مباشرة مع المعرض.`
      });
    }

    // 7. Direct O(1) Firebase RTDB Lookup (Axis 7: Zero Full-Table Scans - CWE-400 / OWASP API4)
    let targetOrder = null;
    try {
      const orderRes = await firebaseFetch(buildSafeRtdbPath("orders", safeOrderId), {
        cache: "no-store",
        headers: { "Accept": "application/json" }
      }, { t: Date.now() });

      if (orderRes.ok) {
        const data = await orderRes.json();
        if (data && typeof data === "object" && !Array.isArray(data) && (data.id || data.orderNumber)) {
          targetOrder = data;
        }
      }
    } catch (dbErr) {
      targetOrder = null;
    }

    // 8. Strict Dual-Mode Ownership Verification (Axis 2: Session vs Full Phone)
    let isAuthorized = false;

    // Vector A: Authenticated Customer Session (JWT)
    const customerAuth = verifyCustomerRequest(req);
    if (customerAuth && customerAuth.sub && targetOrder) {
      const authCustId = sanitizePathId(customerAuth.sub);
      const orderCustId = sanitizePathId(targetOrder.customerId || (targetOrder.customer && targetOrder.customer.id));
      const authEmail = customerAuth.email ? String(customerAuth.email).trim().toLowerCase() : "";
      const orderEmail = (targetOrder.customer?.email || targetOrder.email || "").trim().toLowerCase();

      if ((authCustId && orderCustId && authCustId === orderCustId) ||
          (authEmail && orderEmail && authEmail === orderEmail)) {
        isAuthorized = true;
      }
    }

    // Vector B: Unauthenticated / Guest Full Phone Verification (Timing-Safe)
    if (!isAuthorized && targetOrder) {
      const storedPhone = targetOrder.customer?.phone || "";
      if (storedPhone && rawPhone) {
        // Strict constant-time comparison over SHA-256 digests (Zero 4-digit suffix matches)
        isAuthorized = timingSafePhoneCompare(storedPhone, rawPhone);
      }
    }

    // 9. Unified Anti-Enumeration & Constant-Time Failure Branch (Axis 5: ASVS 13.2.3, CWE-203, CWE-204)
    if (!targetOrder || !isAuthorized) {
      // Record failed attempts on all three layers
      await recordFailedRateLimitAttempt(clientIp, "track_ip", 15, 15 * 60 * 1000);
      await recordFailedAttemptDistributed("track_ip_order", ipOrderKey, 5, 15 * 60 * 1000);
      await recordFailedAttemptDistributed("track_global_order", globalOrderKey, 15, 30 * 60 * 1000);

      // Dummy SHA-256 digest & constant-time comparison when order is missing to match execution profile
      if (!targetOrder) {
        const dummyA = crypto.createHash("sha256").update("dummy_salt_fixed_timing_branch_a").digest();
        const dummyB = crypto.createHash("sha256").update(rawPhone || "dummy_salt_fixed_timing_branch_b").digest();
        crypto.timingSafeEqual(dummyA, dummyB);
      }

      // Calibrated artificial constant delay (550ms) to eliminate timing side channels
      await new Promise(r => setTimeout(r, 550));

      return res.status(404).json({
        success: false,
        error: "تعذر العثور على الطلب أو بيانات التحقق غير مطابقة. يرجى التأكد من كتابة كود الطلب كاملاً ورقم الهاتف المسجل."
      });
    }

    // 10. Verification Success: Reset Targeted Failed Counter (Axis 6)
    await resetRateLimitDistributed("track_ip_order", ipOrderKey);

    // 11. Zero-PII Strict Allowlist Sanitization (Axis 3: OWASP API3: BOPLA & ASVS Level 3)
    // Strictly strip all customer PII (full name, phone, email, address, notes, customerId, costs, margins)
    const sanitizedItems = (Array.isArray(targetOrder.items) ? targetOrder.items : []).map(item => ({
      name: typeof item.name === "string" ? item.name.slice(0, 100) : "وحدة إضاءة فاخرة",
      enName: typeof item.enName === "string" ? item.enName.slice(0, 100) : "",
      qty: Math.min(100, Math.max(1, parseInt(item.qty, 10) || 1)),
      price: Math.max(0, parseFloat(item.price) || 0),
      image: typeof item.image === "string" ? item.image.slice(0, 500) : "",
      categoryName: typeof item.categoryName === "string" ? item.categoryName.slice(0, 100) : ""
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

    const currentStatus = typeof targetOrder.status === "string" ? targetOrder.status : "received";
    const statusMessage = statusMessages[currentStatus] || statusMessages.received;
    const orderTimestamp = typeof targetOrder.timestamp === "number" ? targetOrder.timestamp : Date.now();

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

    const sanitizedOrderDTO = Object.freeze({
      id: typeof targetOrder.id === "string" ? targetOrder.id : safeOrderId,
      status: currentStatus,
      dateFormatted: typeof targetOrder.dateFormatted === "string" ? targetOrder.dateFormatted : cairoDate,
      timeFormatted: typeof targetOrder.timeFormatted === "string" ? targetOrder.timeFormatted : cairoTime,
      timestamp: orderTimestamp,
      items: sanitizedItems,
      subtotal: Math.max(0, parseFloat(targetOrder.subtotal) || 0),
      total: Math.max(0, parseFloat(targetOrder.total) || 0),
      statusMessage,
      estimatedDelivery: typeof targetOrder.deliveryEstimate === "string" ? targetOrder.deliveryEstimate : "2 - 4 أيام عمل"
    });

    return res.status(200).json({
      success: true,
      order: sanitizedOrderDTO
    });
  } catch (err) {
    // Axis 8: Zero-leakage log hygiene. Never log PII, phone numbers, or tokens in server logs.
    safeLogError("/api/track", requestId, err);
    return res.status(500).json({
      success: false,
      ok: false,
      error: "حدث خطأ غير متوقع أثناء معالجة طلب التتبع.",
      requestId
    });
  }
}

export default withApiHardening(trackHandler, {
  allowedMethods: ["GET", "POST"],
  maxBodyBytes: 4 * 1024,
  maxDepth: 4,
  maxKeys: 15,
  context: "/api/track"
});
