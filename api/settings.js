// Vercel Serverless Function: /api/settings
// Handles Cloud Persistence for Categories, Showroom Settings & Contact Links
// Strictly Separates Public Storefront Read from Privileged Admin Mutation (OWASP API5: BFLA & ASVS Level 3)

import {
  verifyAdminRequest,
  firebaseFetch,
  buildSafeRtdbPath,
  assertSafeRtdbPayload,
  sanitizePublicSettings,
  redactSecretUrl,
  setSecurityHeaders,
  withApiHardening,
  safeLogError
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

async function bumpSyncMetadata(actionType = "settings_update") {
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

async function settingsHandler(req, res, { requestId, safeBody } = {}) {
  // 1. Mandatory CORS & Security Headers Gate (Axis 7: ASVS 14.4 & 14.5)
  if (setSecurityHeaders(req, res, { cacheControl: "no-store, no-cache, must-revalidate, private" })) return;

  const type = req.query?.type;

  try {
    // 2. Payload Size Limit Guard (DoS Mitigation - CWE-400 / OWASP API4)
    const MAX_SETTINGS_PAYLOAD = 50 * 1024; // 50 KB
    const contentLength = parseInt(req.headers["content-length"] || "0", 10);
    if (contentLength > MAX_SETTINGS_PAYLOAD) {
      return res.status(413).json({
        success: false,
        error: "حجم الطلب يتجاوز الحد الأقصى المسموح به (50 كيلوبايت)."
      });
    }

    // -------------------------------------------------------------------------
    // 1. GET: Fetch Categories and/or Showroom Settings
    // -------------------------------------------------------------------------
    if (req.method === "GET") {
      const t = Date.now();
      const admin = verifyAdminRequest(req);
      let categories = null;
      let settings = null;

      if (!type || type === "categories") {
        try {
          const catRes = await firebaseFetch(buildSafeRtdbPath("categories"), { cache: "no-store" }, { t });
          if (catRes.ok) {
            const raw = await catRes.json();
            if (Array.isArray(raw)) {
              categories = raw.filter(Boolean);
            } else if (raw && typeof raw === "object") {
              categories = Object.values(raw).filter(Boolean);
            }
          }
        } catch (e) {}
      }

      if (!type || type === "settings") {
        try {
          const setRes = await firebaseFetch(buildSafeRtdbPath("settings"), { cache: "no-store" }, { t });
          if (setRes.ok) {
            settings = await setRes.json();
          }
        } catch (e) {}
      }

      // If requested by an authenticated Admin: return full settings
      if (admin) {
        return res.status(200).json({
          success: true,
          isAdmin: true,
          categories: categories || undefined,
          settings: settings || undefined
        });
      }

      // PUBLIC STOREFRONT READ (Axis 3: Strict Zero-Leakage Allowlist DTO)
      const publicCategories = categories
        ? categories.map((c, idx) => ({
            id: String(c.id || "cat_" + idx).replace(/[^a-zA-Z0-9_\-]/g, "").slice(0, 50),
            name: String(c.name || "").trim().replace(/[<>]/g, "").slice(0, 100),
            nameEn: String(c.nameEn || "").trim().replace(/[<>]/g, "").slice(0, 100),
            icon: String(c.icon || "fa-gem").trim().replace(/[<>]/g, "").slice(0, 50),
            count: parseInt(c.count, 10) || 0
          })).filter(c => c.name)
        : undefined;

      const publicSettings = settings ? sanitizePublicSettings(settings) : undefined;

      return res.status(200).json({
        success: true,
        categories: publicCategories,
        settings: publicSettings
      });
    }

    // -------------------------------------------------------------------------
    // 2. POST / PUT / PATCH: Update Categories or Settings (ADMIN ONLY) (Axis 1: BFLA)
    // -------------------------------------------------------------------------
    if (req.method === "POST" || req.method === "PUT" || req.method === "PATCH") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({
          success: false,
          error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لتعديل إعدادات المعرض."
        });
      }

      let body = req.body;
      if (typeof body === "string") {
        try {
          body = JSON.parse(body);
        } catch (e) {
          return res.status(400).json({ success: false, error: "حزمة البيانات المرسلة غير صالحة (Invalid JSON)." });
        }
      }
      body = body || {};

      // SUB-CASE A: CATEGORIES UPDATE
      if (body.type === "categories" || Array.isArray(body.categories)) {
        const rawCats = Array.isArray(body.categories) ? body.categories : (Array.isArray(body) ? body : []);
        const cleanCats = rawCats.map((c, idx) => ({
          id: String(c.id || "cat_" + idx).replace(/[^a-zA-Z0-9_\-]/g, "").slice(0, 50),
          name: String(c.name || "").trim().replace(/[<>]/g, "").slice(0, 100),
          nameEn: String(c.nameEn || "").trim().replace(/[<>]/g, "").slice(0, 100),
          icon: String(c.icon || "fa-gem").trim().replace(/[<>]/g, "").slice(0, 50),
          count: parseInt(c.count, 10) || 0
        })).filter(c => c.name);

        assertSafeRtdbPayload(cleanCats);
        const catRes = await firebaseFetch(buildSafeRtdbPath("categories"), {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(cleanCats)
        });

        if (!catRes.ok) {
          return res.status(502).json({ success: false, error: "تعذر حفظ تصنيفات المنتجات على السحابة." });
        }

        await bumpSyncMetadata("categories_update");
        return res.status(200).json({ success: true, updated: "categories", categories: cleanCats });
      }

      // SUB-CASE B: SHOWROOM SETTINGS UPDATE
      if (body.type === "settings" || body.settings || body.phone || body.whatsapp) {
        const raw = body.settings || body || {};

        // 1. Business-Critical Numeric Bounds Validation (Axis 3)
        if (raw.freeShippingThreshold !== undefined) {
          const thresh = Number(raw.freeShippingThreshold);
          if (isNaN(thresh) || !Number.isFinite(thresh) || thresh < 0 || thresh > 1000000) {
            return res.status(400).json({
              success: false,
              error: "قيمة حد الشحن المجاني غير صالحة. يجب أن تكون رقماً موجباً بين 0 و 1,000,000 ج.م."
            });
          }
        }

        if (raw.shippingFee !== undefined) {
          const fee = Number(raw.shippingFee);
          if (isNaN(fee) || !Number.isFinite(fee) || fee < 0 || fee > 10000) {
            return res.status(400).json({
              success: false,
              error: "قيمة مصاريف الشحن غير صالحة. يجب أن تكون رقماً موجباً بين 0 و 10,000 ج.م."
            });
          }
        }

        if (raw.taxRate !== undefined) {
          const tax = Number(raw.taxRate);
          if (isNaN(tax) || !Number.isFinite(tax) || tax < 0 || tax > 100) {
            return res.status(400).json({
              success: false,
              error: "نسبة الضريبة غير صالحة. يجب أن تكون رقماً بين 0 و 100%."
            });
          }
        }

        // 2. Stored XSS & Dangerous Protocol Validation (Axis 3)
        const urlFields = ["mapUrl", "mapEmbedUrl", "logo", "banner"];
        for (const uf of urlFields) {
          if (raw[uf]) {
            const val = String(raw[uf]).trim();
            if (val && !val.startsWith("https://")) {
              return res.status(400).json({
                success: false,
                error: `الرابط المُدخل في '${uf}' غير آمن. يجب أن يبدأ ببروتوكول https:// حصراً.`
              });
            }
          }
        }

        const socialRaw = raw.social || {};
        for (const sf of ["facebook", "instagram", "tiktok"]) {
          if (socialRaw[sf]) {
            const val = String(socialRaw[sf]).trim();
            if (val && !val.startsWith("https://")) {
              return res.status(400).json({
                success: false,
                error: `رابط منصة '${sf}' غير آمن. يجب أن يبدأ ببروتوكول https:// حصراً.`
              });
            }
          }
        }

        // 3. Strict Whitelist Construction (CWE-915 Mass Assignment Mitigation)
        const safeSettings = {
          phone: String(raw.phone || "").trim().replace(/[<>]/g, "").slice(0, 25),
          whatsapp: String(raw.whatsapp || "").trim().replace(/[^0-9]/g, "").slice(0, 20),
          email: String(raw.email || "").trim().toLowerCase().slice(0, 100),
          addressAr: String(raw.addressAr || "").trim().replace(/[<>]/g, "").slice(0, 200),
          addressEn: String(raw.addressEn || "").trim().replace(/[<>]/g, "").slice(0, 200),
          workingHoursAr: String(raw.workingHoursAr || raw.workingHours || "").trim().replace(/[<>]/g, "").slice(0, 100),
          workingHoursEn: String(raw.workingHoursEn || "").trim().replace(/[<>]/g, "").slice(0, 100),
          storeNameAr: String(raw.storeNameAr || "معرض قاصد كريم").trim().replace(/[<>]/g, "").slice(0, 100),
          storeNameEn: String(raw.storeNameEn || "Kased Karim Showroom").trim().replace(/[<>]/g, "").slice(0, 100),
          announcement: String(raw.announcement || "").trim().replace(/[<>]/g, "").slice(0, 200),
          googleClientId: typeof raw.googleClientId === "string" && raw.googleClientId.trim().endsWith(".apps.googleusercontent.com")
            ? raw.googleClientId.trim().slice(0, 150)
            : "",
          mapUrl: raw.mapUrl ? String(raw.mapUrl).trim().slice(0, 500) : "",
          mapEmbedUrl: raw.mapEmbedUrl ? String(raw.mapEmbedUrl).trim().slice(0, 800) : "",
          freeShippingThreshold: Number.isFinite(Number(raw.freeShippingThreshold)) ? Math.max(0, Math.min(1000000, Number(raw.freeShippingThreshold))) : 5000,
          social: {
            facebook: socialRaw.facebook ? String(socialRaw.facebook).trim().slice(0, 200) : "",
            instagram: socialRaw.instagram ? String(socialRaw.instagram).trim().slice(0, 200) : "",
            tiktok: socialRaw.tiktok ? String(socialRaw.tiktok).trim().slice(0, 200) : "",
            designerUrl: "https://karimodesign.vercel.app/"
          },
          updatedAt: Date.now()
        };

        assertSafeRtdbPayload(safeSettings);
        const setRes = await firebaseFetch(buildSafeRtdbPath("settings"), {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(safeSettings)
        });

        if (!setRes.ok) {
          return res.status(502).json({ success: false, error: "تعذر حفظ إعدادات المعرض على السحابة." });
        }

        await bumpSyncMetadata("settings_update");
        return res.status(200).json({ success: true, updated: "settings", settings: safeSettings });
      }

      return res.status(400).json({ success: false, error: "نوع حزمة البيانات غير صالح (مطلوب categories أو settings)." });
    }

    // 3. Reject all unhandled HTTP methods (Axis 1: ASVS 13.1)
    return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها (Method Not Allowed)." });
  } catch (err) {
    // Axis 8: Zero-leakage log hygiene.
    safeLogError("/api/settings", requestId, err);
    return res.status(500).json({
      success: false,
      ok: false,
      error: "حدث خطأ داخلي أثناء معالجة إعدادات المعرض.",
      requestId
    });
  }
}

export default withApiHardening(settingsHandler, {
  allowedMethods: ["GET", "PUT", "POST", "PATCH"],
  maxBodyBytes: 64 * 1024,
  maxDepth: 6,
  maxKeys: 150,
  context: "/api/settings"
});
