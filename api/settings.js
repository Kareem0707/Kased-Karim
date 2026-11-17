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
        const cats = body.categories || body;
        const catUrl = getFirebaseUrl("categories.json");
        await fetch(catUrl, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(cats)
        });
        await bumpSyncMetadata("categories_update");
        return res.status(200).json({ success: true, updated: "categories" });
      }

      if (body.type === "settings" || body.settings || body.phone) {
        const st = { ...(body.settings || body), updatedAt: Date.now() };
        const setUrl = getFirebaseUrl("settings.json");
        await fetch(setUrl, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(st)
        });
        await bumpSyncMetadata("settings_update");
        return res.status(200).json({ success: true, updated: "settings", settings: st });
      }

      return res.status(400).json({ error: "Invalid payload type" });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
