// Vercel Serverless Function: /api/reviews
// Product Reviews Submission & Administrative Moderation Engine
// PRD Section 11: Moderation before public display (Pending -> Approved / Rejected)

import crypto from "crypto";
import {
  verifyAdminRequest,
  sanitizePathId,
  getFirebaseUrl,
  setSecurityHeaders
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

async function fetchReviews() {
  try {
    const firebaseUrl = getFirebaseUrl("reviews.json", { t: Date.now() });
    const res = await fetch(firebaseUrl, { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      if (data && typeof data === "object") {
        return Object.values(data).filter(Boolean);
      }
    }
  } catch (e) {}
  return [];
}

async function saveReview(review) {
  const safeId = sanitizePathId(review.id);
  if (!safeId) return false;
  const firebaseUrl = getFirebaseUrl(`reviews/${safeId}.json`);
  const res = await fetch(firebaseUrl, {
    method: "PUT",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(review)
  });
  return res.ok;
}

export default async function handler(req, res) {
  setSecurityHeaders(req, res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    // -------------------------------------------------------------------------
    // 1. GET REVIEWS
    // -------------------------------------------------------------------------
    if (req.method === "GET") {
      const { productId, all } = req.query || {};

      if (all === "1" || all === "true") {
        // ADMIN ONLY: View all reviews (Pending, Approved, Rejected) (F-06)
        const admin = verifyAdminRequest(req);
        if (!admin) {
          return res.status(401).json({ success: false, error: "غير مصرح بالوصول لمراجعة التقييمات" });
        }
        const reviews = await fetchReviews();
        reviews.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        return res.status(200).json({ success: true, reviews });
      }

      // PUBLIC STOREFRONT: Only approved reviews for a specific product
      const reviews = await fetchReviews();
      const approved = reviews.filter(r => {
        if (!r || r.status !== "approved") return false;
        if (productId && r.productId !== productId) return false;
        return true;
      });
      approved.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

      return res.status(200).json({ success: true, reviews: approved });
    }

    // -------------------------------------------------------------------------
    // 2. POST: SUBMIT NEW PRODUCT REVIEW (Requires Moderation)
    // -------------------------------------------------------------------------
    if (req.method === "POST") {
      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      body = body || {};

      const productId = sanitizePathId(body.productId || "");
      const productName = (body.productName || "").trim().replace(/[<>]/g, "").slice(0, 100);
      const author = (body.author || body.name || "عميل موثوق").trim().replace(/[<>]/g, "").slice(0, 50);
      const rating = Math.min(5, Math.max(1, parseInt(body.rating, 10) || 5));
      const comment = (body.comment || body.text || "").trim().replace(/[<>]/g, "").slice(0, 500);

      if (!productId) {
        return res.status(400).json({ success: false, error: "معرف المنتج غير صحيح" });
      }

      const reviewId = "REV-" + Date.now() + "-" + crypto.randomBytes(2).toString("hex").toUpperCase();
      const newReview = {
        id: reviewId,
        productId,
        productName,
        author,
        rating,
        comment,
        status: "pending", // PRD: Requires administrative moderation before publication
        timestamp: Date.now()
      };

      await saveReview(newReview);

      return res.status(201).json({
        success: true,
        message: "تم إرسال تقييمك بنجاح وسوف يظهر بعد مراجعته من إدارة المعرض.",
        review: newReview
      });
    }

    // -------------------------------------------------------------------------
    // 3. PATCH: MODERATE REVIEW (ADMIN ONLY) (F-06)
    // -------------------------------------------------------------------------
    if (req.method === "PATCH") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح" });
      }

      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      body = body || {};

      const safeId = sanitizePathId(body.id);
      if (!safeId) {
        return res.status(400).json({ success: false, error: "معرف التقييم غير صحيح" });
      }

      const reviews = await fetchReviews();
      const target = reviews.find(r => r.id === safeId);
      if (!target) {
        return res.status(404).json({ success: false, error: "التقييم غير موجود" });
      }

      if (body.status && ["approved", "rejected", "pending"].includes(body.status)) {
        target.status = body.status;
      }
      target.moderatedAt = Date.now();
      target.moderatedBy = admin.sub || "admin";

      await saveReview(target);

      return res.status(200).json({ success: true, message: "تم تحديث حالة التقييم بنجاح", review: target });
    }

    // -------------------------------------------------------------------------
    // 4. DELETE: REMOVE REVIEW (ADMIN ONLY) (F-06)
    // -------------------------------------------------------------------------
    if (req.method === "DELETE") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح" });
      }

      const { id } = req.query || {};
      const safeId = sanitizePathId(id);
      if (!safeId) return res.status(400).json({ error: "معرف التقييم غير صحيح" });

      const firebaseUrl = getFirebaseUrl(`reviews/${safeId}.json`);
      await fetch(firebaseUrl, { method: "DELETE", cache: "no-store" });
      return res.status(200).json({ success: true, message: "تم حذف التقييم" });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
}
