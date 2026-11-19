// Vercel Serverless Function: /api/settings
// Handles Cloud Persistence for Categories, Showroom Settings & Contact Links
// Protected with Server-Side Authorization for Mutations (F-06)

import {
  verifyAdminRequest,
  getFirebaseUrl,
  setSecurityHeaders
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

async function bumpSyncMetadata(actionType = "settings_update") {
  try {
    const now = Date.now();
    const firebaseUrl = getFirebaseUrl("sync_meta.json");
    await fetch(firebaseUrl, {
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

export default async function handler(req, res) {
  setSecurityHeaders(req, res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const type = req.query?.type;

  try {
    // Payload Size Limit Check (DoS Mitigation - CWE-400)
    const MAX_SETTINGS_PAYLOAD = 300 * 1024; // 300 KB
    const contentLength = parseInt(req.headers["content-length"] || "0", 10);
    if (contentLength > MAX_SETTINGS_PAYLOAD) {
      return res.status(413).json({ success: false, error: "حجم الطلب يتجاوز الحد الأقصى المسموح به (300 كيلوبايت)" });
    }

    // 1. GET: Fetch Categories and/or Settings (Public Storefront Read)
    if (req.method === "GET") {
      const t = Date.now();
      let categories = null;
      let settings = null;

      if (!type || type === "categories") {
        try {
          const catUrl = getFirebaseUrl("categories.json", { t });
          const catRes = await fetch(catUrl, { cache: "no-store" });
          if (catRes.ok) {
            const raw = await catRes.json();
            if (Array.isArray(raw)) categories = raw.filter(Boolean);
            else if (raw && typeof raw === "object") categories = Object.values(raw).filter(Boolean);
          }
        } catch (e) {}
      }

      if (!type || type === "settings") {
        try {
          const setUrl = getFirebaseUrl("settings.json", { t });
          const setRes = await fetch(setUrl, { cache: "no-store" });
          if (setRes.ok) {
            settings = await setRes.json();
          }
        } catch (e) {}
      }

      return res.status(200).json({
        success: true,
        categories: categories || undefined,
        settings: settings || undefined
      });
    }

    // 2. POST / PUT: Update Categories or Settings (ADMIN-ONLY ACCESS REQUIREMENT) (F-06)
    if (req.method === "POST" || req.method === "PUT") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لتعديل الإعدادات." });
      }

      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      body = body || {};

      if (body.type === "categories" || Array.isArray(body.categories)) {
        const rawCats = Array.isArray(body.categories) ? body.categories : (Array.isArray(body) ? body : []);
        // Strict Whitelist Mapping to Prevent Mass Assignment (CWE-915)
        const cleanCats = rawCats.map((c, idx) => ({
          id: String(c.id || "cat_" + idx).replace(/[^a-zA-Z0-9_\-]/g, "").slice(0, 50),
          name: String(c.name || "").trim().replace(/[<>]/g, "").slice(0, 100),
          nameEn: String(c.nameEn || "").trim().replace(/[<>]/g, "").slice(0, 100),
          icon: String(c.icon || "fa-gem").trim().replace(/[<>]/g, "").slice(0, 50),
          count: parseInt(c.count, 10) || 0
        })).filter(c => c.name);

        const catUrl = getFirebaseUrl("categories.json");
        await fetch(catUrl, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(cleanCats)
        });
        await bumpSyncMetadata("categories_update");
        return res.status(200).json({ success: true, updated: "categories", categories: cleanCats });
      }

      if (body.type === "settings" || body.settings || body.phone) {
        const raw = body.settings || body || {};
        // Strict Whitelist Mapping to Prevent Mass Assignment (CWE-915)
        const safeSettings = {
          phone: String(raw.phone || "").trim().replace(/[<>]/g, "").slice(0, 25),
          whatsapp: String(raw.whatsapp || "").trim().replace(/[<>]/g, "").slice(0, 25),
          email: String(raw.email || "").trim().toLowerCase().slice(0, 100),
          addressAr: String(raw.addressAr || "").trim().replace(/[<>]/g, "").slice(0, 200),
          addressEn: String(raw.addressEn || "").trim().replace(/[<>]/g, "").slice(0, 200),
          mapUrl: String(raw.mapUrl || "").trim().slice(0, 300),
          mapEmbedUrl: String(raw.mapEmbedUrl || "").trim().slice(0, 500),
          freeShippingThreshold: Math.max(0, parseInt(raw.freeShippingThreshold, 10) || 5000),
          social: {
            facebook: String(raw.social?.facebook || "").trim().slice(0, 150),
            instagram: String(raw.social?.instagram || "").trim().slice(0, 150),
            tiktok: String(raw.social?.tiktok || "").trim().slice(0, 150),
            designerUrl: "https://karimodesign.vercel.app/"
          },
          updatedAt: Date.now()
        };
        const setUrl = getFirebaseUrl("settings.json");
        await fetch(setUrl, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(safeSettings)
        });
        await bumpSyncMetadata("settings_update");
        return res.status(200).json({ success: true, updated: "settings", settings: safeSettings });
      }

      return res.status(400).json({ error: "Invalid payload type" });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error("API error in /api/settings:", err.message);
    return res.status(500).json({ success: false, error: "حدث خطأ غير متوقع في معالجة الإعدادات." });
  }
}
