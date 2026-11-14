// Vercel Serverless Function: /api/reviews
// Product Reviews Submission & Administrative Moderation Engine
// PRD Section 11: Moderation before public display (Pending -> Approved / Rejected)

import crypto from "crypto";
import { verifyAdminRequest } from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

function getFirebaseUrl(req) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) return envUrl.trim().replace(/\/$/, "");
  return "https://kased-karim-default-rtdb.firebaseio.com";
}

async function fetchReviews(firebaseUrl) {
  try {
    const res = await fetch(`${firebaseUrl}/reviews.json?t=${Date.now()}`, { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      if (data && typeof data === "object") {
        return Object.values(data).filter(Boolean);
      }
    }
  } catch (e) {}
  return [];
}

async function saveReview(firebaseUrl, review) {
  const safeId = encodeURIComponent(review.id);
  const res = await fetch(`${firebaseUrl}/reviews/${safeId}.json`, {
    method: "PUT",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(review)
  });
  return res.ok;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin-token");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const firebaseUrl = getFirebaseUrl(req);

  try {
    // -------------------------------------------------------------------------
    // 1. GET REVIEWS
    // -------------------------------------------------------------------------
    if (req.method === "GET") {
      const { productId, all } = req.query || {};

      if (all === "1" || all === "true") {
        // ADMIN ONLY: View all reviews (Pending, Approved, Rejected)
        const admin = verifyAdminRequest(req);
        if (!admin) {
          return res.status(401).json({ success: false, error: "غير مصرح بالوصول لمراجعة التقييمات" });
        }
        const reviews = await fetchReviews(firebaseUrl);
        reviews.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        return res.status(200).json({ success: true, reviews });
      }

      // PUBLIC STOREFRONT: Only approved reviews for a specific product
      const reviews = await fetchReviews(firebaseUrl);
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

      const productId = (body.productId || "").trim();
      const productName = (body.productName || "").trim();
      const author = (body.author || body.name || "عميل موثوق").trim().replace(/[<>]/g, "").slice(0, 50);
      const rating = Math.min(5, Math.max(1, parseInt(body.rating, 10) || 5));
      const comment = (body.comment || body.text || "").trim().replace(/[<>]/g, "").slice(0, 500);

      if (!productId) {
        return res.status(400).json({ success: false, error: "معرف المنتج مطلوب" });
      }
      if (!comment || comment.length < 5) {
        return res.status(400).json({ success: false, error: "يرجى كتابة تقييم لا يقل عن 5 أحرف" });
      }

      const reviewId = "REV-" + crypto.randomInt(1000, 9999) + "-" + crypto.randomBytes(2).toString("hex").toUpperCase();
      const newReview = {
        id: reviewId,
        productId,
        productName: productName || "وحدة إضاءة فاخرة",
        author: author || "عميل معرض قاصد كريم",
        rating,
        comment,
        status: "pending", // PRD: Moderation before public display
        timestamp: Date.now(),
        dateFormatted: new Date().toLocaleDateString("ar-EG", { year: "numeric", month: "short", day: "numeric" })
      };

      await saveReview(firebaseUrl, newReview);

      return res.status(201).json({
        success: true,
        message: "تم استلام تقييمك بنجاح! سيتم نشره بالمعرض فور المراجعة والاعتماد من الإدارة.",
        review: newReview
      });
    }

    // -------------------------------------------------------------------------
    // 3. PATCH: MODERATE REVIEW (ADMIN ONLY: Approve / Reject / Hide)
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

      const { id, status } = body;
      if (!id || !status) {
        return res.status(400).json({ success: false, error: "معرف التقييم والحالة الجديدة مطلوبان" });
      }

      const allowedStatuses = ["pending", "approved", "rejected", "hidden"];
      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({ success: false, error: "حالة التقييم غير صالحة" });
      }

      const reviews = await fetchReviews(firebaseUrl);
      const target = reviews.find(r => r.id === id);
      if (!target) {
        return res.status(404).json({ success: false, error: "لم يتم العثور على التقييم" });
      }

      target.status = status;
      target.moderatedAt = Date.now();
      await saveReview(firebaseUrl, target);

      return res.status(200).json({ success: true, message: "تم تحديث حالة التقييم بنجاح", review: target });
    }

    // -------------------------------------------------------------------------
    // 4. DELETE: DELETE REVIEW (ADMIN ONLY)
    // -------------------------------------------------------------------------
    if (req.method === "DELETE") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح" });
      }

      const id = req.query?.id;
      if (!id) {
        return res.status(400).json({ success: false, error: "معرف التقييم مطلوب" });
      }

      const safeId = encodeURIComponent(id);
      await fetch(`${firebaseUrl}/reviews/${safeId}.json`, { method: "DELETE", cache: "no-store" });

      return res.status(200).json({ success: true, message: "تم حذف التقييم نهائياً" });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
}
