// Vercel Serverless Function: /api/reviews
// Product Reviews Submission & Administrative Moderation Engine
// Enforces Strict Input Validation, Moderation Before Display & Zero-PII (OWASP API3, API5 & ASVS Level 3)

import crypto from "crypto";
import { enforceRateLimit, getClientIp } from "../lib/rateLimit.js";
import { verifyTurnstile, extractTurnstileToken } from "../lib/turnstile.js";
import {
  verifyAdminRequest,
  verifyCustomerRequest,
  sanitizePathId,
  firebaseFetch,
  buildSafeRtdbPath,
  assertSafeRtdbPayload,
  checkDistributedRateLimit,
  sanitizeReview,
  redactSecretUrl,
  setSecurityHeaders,
  withApiHardening,
  safeLogError
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// O(1) Direct Review Fetcher
async function fetchReviewById(reviewId) {
  const safeId = sanitizePathId(reviewId);
  if (!safeId) return null;
  try {
    const res = await firebaseFetch(buildSafeRtdbPath("reviews", safeId), { cache: "no-store" }, { t: Date.now() });
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {}
  return null;
}

// Collection Fetcher
async function fetchAllReviewsFromCloud() {
  try {
    const res = await firebaseFetch(buildSafeRtdbPath("reviews"), { cache: "no-store" }, { t: Date.now() });
    if (res.ok) {
      const data = await res.json();
      if (data && typeof data === "object") {
        return Object.values(data).filter(Boolean);
      }
    }
  } catch (e) {}
  return [];
}

async function reviewsHandler(req, res, { requestId, safeBody } = {}) {
  // 1. Mandatory CORS & Security Headers Gate (Axis 7: ASVS 14.4 & 14.5)
  if (setSecurityHeaders(req, res, { cacheControl: "no-store, no-cache, must-revalidate, private" })) return;

  try {
    // 2. Payload Size Limit Guard (DoS Mitigation - CWE-400 / OWASP API4)
    const MAX_REVIEW_PAYLOAD = 10 * 1024; // 10 KB
    const contentLength = parseInt(req.headers["content-length"] || "0", 10);
    if (contentLength > MAX_REVIEW_PAYLOAD) {
      return res.status(413).json({
        success: false,
        error: "حجم الطلب يتجاوز الحد الأقصى المسموح به لتقييمات المنتجات (10 كيلوبايت)."
      });
    }

    // -------------------------------------------------------------------------
    // 1. GET / HEAD: Fetch Product Reviews (Public Approved vs Admin Moderation)
    // -------------------------------------------------------------------------
    if (req.method === "GET" || req.method === "HEAD") {
      // Sliding Window Rate Limiting for Reviews Read (60 requests per minute)
      const allowed = await enforceRateLimit(req, res, "read");
      if (!allowed) return;

      const { productId, all, status } = req.query || {};

      // SUB-CASE A: ADMIN-ONLY REVIEWS MODERATION ACCESS (Axis 1: BFLA)
      if (all === "1" || all === "true" || status) {
        const admin = verifyAdminRequest(req);
        if (!admin) {
          return res.status(401).json({
            success: false,
            error: "غير مصرح بالوصول لمراجعة التقييمات المعلقة أو المرفوضة."
          });
        }

        const allReviews = await fetchAllReviewsFromCloud();
        let filtered = allReviews;

        if (status && ["pending", "approved", "rejected"].includes(status)) {
          filtered = filtered.filter(r => r && r.status === status);
        }
        if (productId) {
          const safeProd = sanitizePathId(productId);
          if (safeProd) {
            filtered = filtered.filter(r => r && r.productId === safeProd);
          }
        }

        filtered.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        const adminSanitized = filtered.map(r => sanitizeReview(r, { forAdmin: true })).filter(Boolean);

        return res.status(200).json({
          success: true,
          count: adminSanitized.length,
          reviews: adminSanitized
        });
      }

      // SUB-CASE B: PUBLIC STOREFRONT READ (Axis 4: Approved Only, Zero-PII)
      const allReviews = await fetchAllReviewsFromCloud();
      const safeProd = productId ? sanitizePathId(productId) : null;

      const approved = allReviews.filter(r => {
        if (!r || r.status !== "approved") return false;
        if (safeProd && r.productId !== safeProd) return false;
        return true;
      });

      approved.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      const publicSanitized = approved.map(r => sanitizeReview(r, { forAdmin: false })).filter(Boolean);

      // Enforce pagination bound (max 50 items)
      const rawPage = parseInt(req.query?.page || "1", 10);
      const rawLimit = parseInt(req.query?.limit || "50", 10);
      const page = Number.isInteger(rawPage) && rawPage >= 1 ? rawPage : 1;
      const limit = Number.isInteger(rawLimit) && rawLimit >= 1 ? Math.min(rawLimit, 50) : 50;
      const total = publicSanitized.length;
      const totalPages = Math.ceil(total / limit) || 1;
      const startIndex = (page - 1) * limit;
      const paginatedReviews = publicSanitized.slice(startIndex, startIndex + limit);

      return res.status(200).json({
        success: true,
        count: paginatedReviews.length,
        total,
        page,
        limit,
        totalPages,
        reviews: paginatedReviews
      });
    }

    // -------------------------------------------------------------------------
    // 2. POST: Submit New Product Review (Public Submission with Moderation Enforcement)
    // -------------------------------------------------------------------------
    if (req.method === "POST") {
      // Sliding Window Rate Limiting (3 submissions per 10 minutes)
      const allowed = await enforceRateLimit(req, res, "orders");
      if (!allowed) return;

      let body = req.body;
      if (typeof body === "string") {
        try {
          body = JSON.parse(body);
        } catch (e) {
          return res.status(400).json({ success: false, error: "حزمة البيانات المرسلة غير صالحة (Invalid JSON Body)." });
        }
      }

      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return res.status(400).json({ success: false, error: "بيانات التقييم غير صالحة." });
      }

      // Mandatory Cloudflare Turnstile Bot Gate (Anti-Spam & Fraud Defense)
      const clientIp = getClientIp(req);
      const turnstileToken = extractTurnstileToken(req, body);
      const turnstileRes = await verifyTurnstile(turnstileToken, clientIp);
      if (!turnstileRes.success) {
        return res.status(400).json({
          success: false,
          error: turnstileRes.error || "فشل التحقق الأمني من اختبار مكافحة الروبوتات (Turnstile)."
        });
      }

      // Strict Product ID Sanitation & Validation (Axis 4)
      const rawProductId = typeof body.productId === "string" ? body.productId : "";
      const productId = sanitizePathId(rawProductId);
      if (!productId || productId.length < 2 || productId.length > 64) {
        return res.status(400).json({ success: false, error: "معرف المنتج غير صحيح أو مفقود." });
      }

      // Strict Rating Validation (Axis 4: Strict Integer 1 to 5)
      const rawRating = body.rating;
      if (!Number.isInteger(rawRating) || rawRating < 1 || rawRating > 5) {
        return res.status(400).json({
          success: false,
          error: "التقييم يجب أن يكون عدداً صحيحاً محصوراً بين 1 و 5 نجوم حصراً."
        });
      }
      const rating = rawRating;

      // Author Name Sanitization (Axis 4)
      const rawAuthor = typeof body.author === "string" ? body.author : (typeof body.name === "string" ? body.name : "");
      const author = rawAuthor.replace(/[<>]/g, "").replace(/[\x00-\x1F\x7F]/g, "").trim().slice(0, 60);
      if (author.length < 2) {
        return res.status(400).json({ success: false, error: "اسم كاتب التقييم يجب ألا يقل عن حرفين." });
      }

      // Comment Sanitization & Stored XSS Mitigation (Axis 4)
      const rawComment = typeof body.comment === "string" ? body.comment : (typeof body.text === "string" ? body.text : "");
      const comment = rawComment.replace(/[<>]/g, "").replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim().slice(0, 1000);
      if (comment.length < 3) {
        return res.status(400).json({ success: false, error: "نص التقييم يجب ألا يقل عن 3 أحرف." });
      }

      const productName = typeof body.productName === "string"
        ? body.productName.replace(/[<>]/g, "").trim().slice(0, 100)
        : "وحدة إضاءة فاخرة";

      // Bind Authenticated Customer ID if caller has valid customer JWT session
      const customerAuth = verifyCustomerRequest(req);
      const verifiedCustomerId = customerAuth && customerAuth.sub ? sanitizePathId(customerAuth.sub) : null;

      // Cryptographically Secure High-Entropy Review ID (Axis 4)
      const reviewId = "REV-" + Date.now() + "-" + crypto.randomBytes(8).toString("hex").toUpperCase();

      // MANDATORY SERVER-CONTROLLED FIELDS (Axis 4: Moderation Bypass Prevention)
      // Client-supplied status, approved, adminReply, or verified flags are STRICTLY IGNORED
      const newReview = {
        id: reviewId,
        productId,
        productName,
        author,
        rating,
        comment,
        status: "pending", // PRD: Strictly requires administrative review before publishing
        approved: false,
        adminReply: "",
        timestamp: Date.now()
      };

      if (verifiedCustomerId) {
        newReview.customerId = verifiedCustomerId;
      }

      assertSafeRtdbPayload(newReview);
      const putRes = await firebaseFetch(buildSafeRtdbPath("reviews", reviewId), {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newReview)
      });

      if (!putRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر حفظ التقييم على السحابة في الوقت الحالي." });
      }

      return res.status(201).json({
        success: true,
        message: "تم استلام تقييمكم بنجاح وسوف يظهر على صفحة المنتج فور اعتماده من إدارة المعرض.",
        review: sanitizeReview(newReview, { forAdmin: false })
      });
    }

    // -------------------------------------------------------------------------
    // 3. PATCH / PUT: Moderate Review (ADMIN ONLY) (Axis 1: BFLA)
    // -------------------------------------------------------------------------
    if (req.method === "PATCH" || req.method === "PUT") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({
          success: false,
          error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة العليا لمراجعة واعتماد التقييمات."
        });
      }

      let body = req.body;
      if (typeof body === "string") {
        try {
          body = JSON.parse(body);
        } catch (e) {
          return res.status(400).json({ success: false, error: "حزمة البيانات غير صالحة (Invalid JSON)." });
        }
      }
      body = body || {};

      const safeId = sanitizePathId(body.id);
      if (!safeId) {
        return res.status(400).json({ success: false, error: "معرف التقييم غير صحيح أو مفقود." });
      }

      const existingReview = await fetchReviewById(safeId);
      if (!existingReview) {
        return res.status(404).json({ success: false, error: "التقييم المطلوب غير موجود." });
      }

      // Update Moderation Status
      if (body.status && ["approved", "rejected", "pending"].includes(body.status)) {
        existingReview.status = body.status;
        existingReview.approved = body.status === "approved";
      }

      // Update Administrative Reply
      if (body.adminReply !== undefined) {
        existingReview.adminReply = typeof body.adminReply === "string"
          ? body.adminReply.replace(/[<>]/g, "").trim().slice(0, 500)
          : "";
      }

      existingReview.moderatedAt = Date.now();
      existingReview.moderatedBy = admin.sub || "admin";

      assertSafeRtdbPayload(existingReview);
      const updateRes = await firebaseFetch(buildSafeRtdbPath("reviews", safeId), {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(existingReview)
      });

      if (!updateRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر تحديث حالة التقييم على السحابة." });
      }

      return res.status(200).json({
        success: true,
        message: "تم تحديث حالة التقييم واعتماده بنجاح.",
        review: sanitizeReview(existingReview, { forAdmin: true })
      });
    }

    // -------------------------------------------------------------------------
    // 4. DELETE: Remove Review (ADMIN ONLY & Empty-ID Protected) (Axis 1 & Axis 5)
    // -------------------------------------------------------------------------
    if (req.method === "DELETE") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({
          success: false,
          error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لحذف التقييمات."
        });
      }

      const rawId = req.query?.id || (req.body && req.body.id);
      if (typeof rawId !== "string" || !rawId.trim()) {
        return res.status(400).json({
          success: false,
          error: "معرف التقييم مطلوب ويجب أن يكون نصاً غير فارغ."
        });
      }

      const safeId = sanitizePathId(rawId);
      // Strict Empty-ID Wipe Prevention (Axis 5)
      if (!safeId || safeId.includes("..") || safeId.includes("/") || safeId.includes("\\")) {
        return res.status(400).json({
          success: false,
          error: "معرف التقييم غير صحيح ويحظر الحذف الجماعي لعقدة التقييمات."
        });
      }

      const delRes = await firebaseFetch(buildSafeRtdbPath("reviews", safeId), {
        method: "DELETE",
        cache: "no-store"
      });

      if (!delRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر حذف التقييم من السحابة." });
      }

      return res.status(200).json({
        success: true,
        message: "تم حذف التقييم بنجاح."
      });
    }

    // 5. Reject all unhandled HTTP methods (Axis 1: ASVS 13.1)
    return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها (Method Not Allowed)." });
  } catch (err) {
    // Axis 8: Zero-leakage log hygiene.
    safeLogError("/api/reviews", requestId, err);
    return res.status(500).json({
      success: false,
      ok: false,
      error: "حدث خطأ غير متوقع في معالجة التقييم.",
      requestId
    });
  }
}

export default withApiHardening(reviewsHandler, {
  allowedMethods: ["GET", "POST", "PATCH", "DELETE"],
  maxBodyBytes: 16 * 1024,
  maxDepth: 4,
  maxKeys: 30,
  context: "/api/reviews"
});
