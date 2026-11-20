// Vercel Serverless Function: /api/backup
// Hardened Multi-Device Backup & Cloud Restoration Engine
// Strictly Protected with Admin-Only Authorization (OWASP API5: BFLA & ASVS Level 3)

import {
  verifyAdminRequest,
  sanitizePathId,
  firebaseFetch,
  buildSafeRtdbPath,
  assertSafeRtdbPayload,
  assertSafeBackupPayload,
  ALLOWED_BACKUP_COLLECTIONS,
  redactSecretUrl,
  setSecurityHeaders,
  withApiHardening,
  safeLogError
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

async function backupHandler(req, res, { requestId, safeBody } = {}) {
  // 1. Mandatory CORS & Security Headers Gate (Axis 7: ASVS 14.4 & 14.5)
  if (setSecurityHeaders(req, res, { cacheControl: "no-store, no-cache, must-revalidate, private" })) return;

  // 2. Strict Admin-Only Authorization on ALL HTTP Methods (Axis 1: OWASP API5: BFLA)
  const admin = verifyAdminRequest(req);
  if (!admin) {
    return res.status(401).json({
      success: false,
      error: "غير مصرح بالوصول. النسخ الاحتياطية واسترجاع البيانات تتطلب صلاحيات الإدارة العليا حصراً."
    });
  }

  // 3. Payload Size Guard (DoS Mitigation - CWE-400 / OWASP API4)
  const MAX_BACKUP_PAYLOAD = 5 * 1024 * 1024; // 5 MB
  const contentLength = parseInt(req.headers["content-length"] || "0", 10);
  if (contentLength > MAX_BACKUP_PAYLOAD) {
    return res.status(413).json({
      success: false,
      error: "حجم ملف النسخة الاحتياطية يتجاوز الحد الأقصى المسموح به (5 ميجابايت)."
    });
  }

  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;

  try {
    // -------------------------------------------------------------------------
    // 1. GET / HEAD: Fetch Latest Cloud Snapshot, Export Entire Allowed State, or Sync Version
    // -------------------------------------------------------------------------
    if (req.method === "GET" || req.method === "HEAD") {
      const t = Date.now();
      const action = req.query?.action;

      // Sub-Action A: Query Current Sync Version
      if (action === "sync_version") {
        try {
          const metaRes = await firebaseFetch(buildSafeRtdbPath("sync_meta"), { cache: "no-store" }, { t });
          if (metaRes.ok) {
            const meta = await metaRes.json();
            return res.status(200).json({ success: true, meta: meta || { version: t } });
          }
        } catch (e) {}
        return res.status(200).json({ success: true, meta: { version: t } });
      }

      // Sub-Action B: Full Operational Cloud Export (Strictly Vault-Isolated)
      if (action === "export" || action === "download") {
        const exportData = {};

        // Fetch each allowed collection individually; NEVER read root /.json
        for (const col of ALLOWED_BACKUP_COLLECTIONS) {
          try {
            const colRes = await firebaseFetch(buildSafeRtdbPath(col), { cache: "no-store" }, { t });
            if (colRes.ok) {
              const raw = await colRes.json();
              if (raw && typeof raw === "object") {
                if (Array.isArray(raw)) {
                  exportData[col] = raw.filter(Boolean);
                } else {
                  exportData[col] = Object.values(raw).filter(Boolean);
                }
              } else {
                exportData[col] = [];
              }
            } else {
              exportData[col] = [];
            }
          } catch (colErr) {
            exportData[col] = [];
          }
        }

        res.setHeader("Content-Disposition", `attachment; filename="kased_karim_cloud_backup_${t}.json"`);
        return res.status(200).json({
          success: true,
          metadata: {
            exportedAt: t,
            exportedBy: admin.sub || "admin",
            version: "2.0-hardened",
            collections: ALLOWED_BACKUP_COLLECTIONS
          },
          data: exportData
        });
      }

      // Default GET: Fetch Latest Cloud Snapshot Point
      const snapRes = await firebaseFetch(buildSafeRtdbPath("backups", "latest"), { cache: "no-store" }, { t });
      if (snapRes.ok) {
        const data = await snapRes.json();
        return res.status(200).json({ success: true, backup: data });
      }
      return res.status(404).json({ success: false, message: "لم يتم العثور على نقطة استرجاع سحابية محفوظة." });
    }

    // -------------------------------------------------------------------------
    // 2. POST: Handle Restore Snapshot OR Save Backup Point
    // -------------------------------------------------------------------------
    if (req.method === "POST") {
      let body = req.body;
      if (typeof body === "string") {
        try {
          body = JSON.parse(body);
        } catch (e) {
          return res.status(400).json({ success: false, error: "حزمة بيانات النسخة الاحتياطية غير صالحة (Invalid JSON)." });
        }
      }

      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return res.status(400).json({ success: false, error: "بيانات النسخة الاحتياطية مفقودة أو غير صالحة." });
      }

      const syncTimestamp = Date.now();

      // =======================================================================
      // CASE A: RESTORE ACTION (Destructive Multi-Device Cloud Overwrite)
      // =======================================================================
      if (body.action === "restore" || body.restore === true) {
        // Step-Up Confirmation Guard: Prevents accidental destructive overwrite
        const isConfirmed = req.headers["x-destructive-confirm"] === "CONFIRM_DATABASE_RESTORE" ||
                            body.confirm === true ||
                            body.confirmRestore === true;

        if (!isConfirmed) {
          return res.status(400).json({
            success: false,
            error: "عملية استرجاع البيانات تستبدل سجلات المعرض بالكامل. يلزم تأكيد صريح (x-destructive-confirm: CONFIRM_DATABASE_RESTORE أو confirm: true)."
          });
        }

        const backupData = body.data || body;
        if (!backupData || typeof backupData !== "object") {
          return res.status(400).json({ success: false, error: "محتوى بيانات الاسترجاع غير صالح." });
        }

        // Deep Recursive Verification: Prototype Pollution, RTDB reserved keys, Vault Isolation (Axis 2)
        try {
          assertSafeBackupPayload(backupData);
        } catch (secErr) {
          return res.status(400).json({
            success: false,
            error: secErr.message || "فشل التحقق الأمني من هيكل ملف الاسترجاع (Security Violation Detected)."
          });
        }

        // Validate top-level collections: strictly allow only ALLOWED_BACKUP_COLLECTIONS
        const providedKeys = Object.keys(backupData);
        for (const k of providedKeys) {
          if (!ALLOWED_BACKUP_COLLECTIONS.includes(k) && !["metadata", "summary", "counts", "action", "confirm", "timestamp"].includes(k)) {
            return res.status(400).json({
              success: false,
              error: `حقل غير مسموح به في ملف الاسترجاع: '${k}'. مسموح فقط بالعقد التشغيلية المعزولة.`
            });
          }
        }

        const products = Array.isArray(backupData.products) ? backupData.products : [];
        const orders = Array.isArray(backupData.orders) ? backupData.orders : [];
        const categories = Array.isArray(backupData.categories) ? backupData.categories : [];
        const settings = (backupData.settings && typeof backupData.settings === "object" && !Array.isArray(backupData.settings)) ? backupData.settings : null;
        const reviews = Array.isArray(backupData.reviews) ? backupData.reviews : [];

        // Pre-validation of individual records
        for (const p of products) {
          if (!p || typeof p !== "object" || !p.id) {
            return res.status(400).json({ success: false, error: "يحتوي ملف المنتجات على عنصر غير صالح أو يفتقر لمعرف المنتج." });
          }
          const price = parseFloat(p.price);
          if (isNaN(price) || price < 0 || !Number.isFinite(price)) {
            return res.status(400).json({ success: false, error: `سعر غير صالح للمنتج: '${p.name || p.id}'.` });
          }
        }

        const tasks = [];

        // 1. Overwrite Products in Firebase RTDB
        if (products.length > 0) {
          const prodMap = {};
          products.forEach(p => {
            const safeId = sanitizePathId(p?.id);
            if (safeId) prodMap[safeId] = p;
          });
          assertSafeRtdbPayload(prodMap);
          tasks.push(
            firebaseFetch(buildSafeRtdbPath("products"), {
              method: "PUT",
              cache: "no-store",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(prodMap)
            })
          );
        }

        // 2. Overwrite Orders in Firebase RTDB
        if (orders.length > 0) {
          const ordMap = {};
          orders.forEach(o => {
            const safeId = sanitizePathId(o?.id);
            if (safeId) ordMap[safeId] = o;
          });
          assertSafeRtdbPayload(ordMap);
          tasks.push(
            firebaseFetch(buildSafeRtdbPath("orders"), {
              method: "PUT",
              cache: "no-store",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(ordMap)
            })
          );
        }

        // 3. Overwrite Categories in Firebase RTDB
        if (categories.length > 0) {
          assertSafeRtdbPayload(categories);
          tasks.push(
            firebaseFetch(buildSafeRtdbPath("categories"), {
              method: "PUT",
              cache: "no-store",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(categories)
            })
          );
        }

        // 4. Overwrite Settings in Firebase RTDB
        if (settings) {
          const safeSettings = { ...settings, updatedAt: syncTimestamp };
          assertSafeRtdbPayload(safeSettings);
          tasks.push(
            firebaseFetch(buildSafeRtdbPath("settings"), {
              method: "PUT",
              cache: "no-store",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(safeSettings)
            })
          );
        }

        // 5. Overwrite Reviews in Firebase RTDB (if provided)
        if (reviews.length > 0) {
          const revMap = {};
          reviews.forEach(r => {
            const safeId = sanitizePathId(r?.id);
            if (safeId) revMap[safeId] = r;
          });
          assertSafeRtdbPayload(revMap);
          tasks.push(
            firebaseFetch(buildSafeRtdbPath("reviews"), {
              method: "PUT",
              cache: "no-store",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(revMap)
            })
          );
        }

        // 6. Update Sync Metadata
        tasks.push(
          firebaseFetch(buildSafeRtdbPath("sync_meta"), {
            method: "PUT",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              version: syncTimestamp,
              action: "restore",
              timestamp: syncTimestamp,
              restoredBy: admin.sub || "admin",
              restoredCounts: {
                products: products.length,
                orders: orders.length,
                categories: categories.length,
                reviews: reviews.length
              }
            })
          })
        );

        // 7. Overwrite Vercel KV if available
        if (kvUrl && kvToken) {
          if (products.length > 0) {
            tasks.push(
              fetch(`${kvUrl}/set/kased_karim_products`, {
                method: "POST",
                cache: "no-store",
                headers: { "Authorization": `Bearer ${kvToken}`, "Content-Type": "application/json" },
                body: JSON.stringify(products)
              }).catch(() => null)
            );
          }
          if (orders.length > 0) {
            tasks.push(
              fetch(`${kvUrl}/set/kased_karim_orders`, {
                method: "POST",
                cache: "no-store",
                headers: { "Authorization": `Bearer ${kvToken}`, "Content-Type": "application/json" },
                body: JSON.stringify(orders)
              }).catch(() => null)
            );
          }
        }

        await Promise.all(tasks);

        return res.status(200).json({
          success: true,
          action: "restore",
          message: "تم استرجاع النسخة الاحتياطية ومزامنة كافة المنتجات والطلبات والأقسام والإعدادات على السحابة بنجاح تام.",
          counts: {
            products: products.length,
            orders: orders.length,
            categories: categories.length,
            reviews: reviews.length
          },
          syncVersion: syncTimestamp
        });
      }

      // =======================================================================
      // CASE B: SAVE BACKUP SNAPSHOT POINT
      // =======================================================================
      try {
        assertSafeBackupPayload(body);
      } catch (secErr) {
        return res.status(400).json({
          success: false,
          error: secErr.message || "فشل التحقق الأمني من محتوى نقطة النسخ الاحتياطي."
        });
      }

      assertSafeRtdbPayload(body);
      const snapRes = await firebaseFetch(buildSafeRtdbPath("backups", "latest"), {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      if (!snapRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر حفظ نقطة النسخ الاحتياطي على السحابة." });
      }

      if (body.id) {
        const safeId = sanitizePathId(body.id);
        if (safeId) {
          firebaseFetch(buildSafeRtdbPath("backups", `history/${safeId}`), {
            method: "PUT",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
          }).catch(() => null);
        }
      }

      return res.status(200).json({ success: true, message: "تم حفظ نقطة النسخة الاحتياطية السحابية بنجاح." });
    }

    // 4. Reject all unhandled HTTP methods (Axis 1: ASVS 13.1)
    return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها (Method Not Allowed)." });
  } catch (err) {
    // Axis 8: Zero-leakage log hygiene. Never log credentials or full backup payloads.
    safeLogError("/api/backup", requestId, err);
    return res.status(500).json({
      success: false,
      ok: false,
      error: "حدث خطأ داخلي أثناء معالجة طلب النسخ الاحتياطي.",
      requestId
    });
  }
}

export default withApiHardening(backupHandler, {
  allowedMethods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  maxBodyBytes: 2 * 1024 * 1024,
  maxDepth: 10,
  maxKeys: 10000,
  context: "/api/backup"
});
