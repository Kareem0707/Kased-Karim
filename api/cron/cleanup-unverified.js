// Vercel Serverless Function: /api/cron/cleanup-unverified
// Automated Purge of Unverified Customer Accounts Older than 24 Hours
// Hardened with Timing-Attack Safe Bearer Authorization & Fail-Closed Guards

import crypto from "crypto";
import {
  firebaseFetch,
  buildSafeRtdbPath,
  sanitizePathId,
  setSecurityHeaders,
  withApiHardening,
  safeLogError
} from "../_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

/**
 * Timing-safe comparison of Authorization header with process.env.CRON_SECRET (CWE-208 Defense).
 * Both strings are hashed to fixed-length 32-byte buffers with SHA-256 before comparison.
 */
function verifyCronAuthorization(req) {
  const cronSecret = process.env.CRON_SECRET;
  if (!cronSecret || typeof cronSecret !== "string" || cronSecret.length < 16) {
    console.error("CRITICAL: CRON_SECRET is not configured or insecure (<16 chars). Fail-Closed.");
    return false;
  }

  const authHeader = req.headers["authorization"] || req.headers["Authorization"] || "";
  const expectedHeader = `Bearer ${cronSecret}`;

  const actualHash = crypto.createHash("sha256").update(authHeader).digest();
  const expectedHash = crypto.createHash("sha256").update(expectedHeader).digest();

  return crypto.timingSafeEqual(actualHash, expectedHash);
}

async function cleanupHandler(req, res, { requestId } = {}) {
  // 1. Mandatory Security Headers
  if (setSecurityHeaders(req, res, { cacheControl: "no-store, no-cache, must-revalidate" })) return;

  // 2. Only allow GET and POST (Vercel cron calls GET by default)
  if (req.method !== "GET" && req.method !== "POST") {
    return res.status(405).json({ success: false, error: "Method not allowed. Use GET or POST for cron trigger." });
  }

  // 3. Timing-Attack Safe Authorization Gate
  if (!verifyCronAuthorization(req)) {
    return res.status(401).json({
      success: false,
      error: "غير مصرح. رمز المصادقة الخاص بالمهام المجدولة غير صحيح أو مفقود (Invalid Cron Secret)."
    });
  }

  try {
    const now = Date.now();
    const cutoffTime = now - (24 * 60 * 60 * 1000); // Exactly 24 hours ago

    // 4. Fetch all customers from Cloud Database (Firebase RTDB)
    const custRes = await firebaseFetch(buildSafeRtdbPath("customers"), { cache: "no-store" }, { t: now });
    let allCustomers = [];
    if (custRes.ok) {
      const data = await custRes.json();
      if (data && typeof data === "object") {
        allCustomers = Object.values(data).filter(Boolean);
      }
    }

    // 5. Filter stale unverified accounts
    const staleAccounts = allCustomers.filter(c => {
      if (!c || !c.id) return false;

      // Never touch admin accounts or Google OAuth accounts (which are pre-verified by Google)
      if (c.role === "admin" || c.authProvider === "google" || c.googleId || c.googleSub) {
        return false;
      }

      // Check verification flags
      const isVerified = Boolean(c.emailVerified || c.email_verified);
      if (isVerified) return false;

      // Check creation timestamp
      const createdAt = Number(c.createdAt) || 0;
      if (!createdAt) return false;

      return createdAt < cutoffTime;
    });

    // 6. Delete each stale unverified account atomically
    const deletedIds = [];
    const deleteErrors = [];

    for (const cust of staleAccounts) {
      const safeId = sanitizePathId(cust.id);
      if (!safeId) continue;

      try {
        const delRes = await firebaseFetch(buildSafeRtdbPath("customers", safeId), {
          method: "DELETE",
          cache: "no-store"
        });

        if (delRes.ok) {
          deletedIds.push(safeId);
        } else {
          deleteErrors.push(safeId);
        }
      } catch (err) {
        deleteErrors.push(safeId);
      }
    }

    console.log(`[Cron:Cleanup] Purged ${deletedIds.length} stale unverified accounts older than 24h. Errors: ${deleteErrors.length}`);

    return res.status(200).json({
      success: true,
      message: `تم تنظيف ${deletedIds.length} حساب غير مفعّل تجاوزت مدة إنشائها 24 ساعة بنجاح.`,
      deletedCount: deletedIds.length,
      failedCount: deleteErrors.length,
      cutoffTimestamp: cutoffTime,
      timestamp: now
    });
  } catch (err) {
    safeLogError("/api/cron/cleanup-unverified", requestId, err);
    return res.status(500).json({
      success: false,
      error: "حدث خطأ غير متوقع أثناء تشغيل مهمة تنظيف الحسابات.",
      requestId
    });
  }
}

export default withApiHardening(cleanupHandler, {
  allowedMethods: ["GET", "POST"],
  maxBodyBytes: 1024,
  context: "/api/cron/cleanup-unverified"
});
