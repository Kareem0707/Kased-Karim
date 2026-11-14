// Vercel Serverless Function: /api/settings
// Handles Cloud Persistence for Categories, Showroom Settings & Contact Links
// Protected with Server-Side Authorization for Mutations

import { verifyAdminRequest } from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

function getFirebaseUrl(req) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) return envUrl.trim().replace(/\/$/, "");
  return "https://kased-karim-default-rtdb.firebaseio.com";
}

async function bumpSyncMetadata(firebaseUrl, actionType = "settings_update") {
  if (!firebaseUrl) return;
  try {
    const now = Date.now();
    await fetch(`${firebaseUrl}/sync_meta.json`, {
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
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin-token");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const firebaseUrl = getFirebaseUrl(req);
  const type = req.query?.type;

  try {
    // 1. GET: Fetch Categories and/or Settings (Public Storefront Read)
    if (req.method === "GET") {
      const t = Date.now();
      let categories = null;
      let settings = null;

      if (!type || type === "categories") {
        try {
          const catRes = await fetch(`${firebaseUrl}/categories.json?t=${t}`, { cache: "no-store" });
          if (catRes.ok) {
            const raw = await catRes.json();
            if (Array.isArray(raw)) categories = raw.filter(Boolean);
            else if (raw && typeof raw === "object") categories = Object.values(raw).filter(Boolean);
          }
        } catch (e) {}
      }

      if (!type || type === "settings") {
        try {
          const setRes = await fetch(`${firebaseUrl}/settings.json?t=${t}`, { cache: "no-store" });
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

    // 2. POST / PUT: Update Categories or Settings (ADMIN-ONLY ACCESS REQUIREMENT)
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
        await fetch(`${firebaseUrl}/categories.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(cats)
        });
        await bumpSyncMetadata(firebaseUrl, "categories_update");
        return res.status(200).json({ success: true, updated: "categories" });
      }

      if (body.type === "settings" || body.settings || body.phone) {
        const st = { ...(body.settings || body), updatedAt: Date.now() };
        await fetch(`${firebaseUrl}/settings.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(st)
        });
        await bumpSyncMetadata(firebaseUrl, "settings_update");
        return res.status(200).json({ success: true, updated: "settings", settings: st });
      }

      return res.status(400).json({ error: "Invalid payload type" });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
