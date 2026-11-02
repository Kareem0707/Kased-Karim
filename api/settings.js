// Vercel Serverless Function: /api/settings
// Handles Cloud Persistence for Categories, Showroom Settings & Contact Links

export const dynamic = "force-dynamic";
export const revalidate = 0;

function getFirebaseUrl(req) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) return envUrl.trim().replace(/\/$/, "");
  const headerUrl = req && (req.headers["x-cloud-db-url"] || req.headers["x-firebase-url"]);
  if (headerUrl && typeof headerUrl === "string" && headerUrl.startsWith("http")) {
    return headerUrl.trim().replace(/\/$/, "");
  }
  return "https://kased-karim-default-rtdb.firebaseio.com";
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-cloud-db-url, x-firebase-url");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const firebaseUrl = getFirebaseUrl(req);
  const type = req.query?.type; // "categories" | "settings" | undefined

  try {
    // GET: Fetch Categories and/or Settings
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

    // POST / PUT: Update Categories or Settings
    if (req.method === "POST" || req.method === "PUT") {
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
        return res.status(200).json({ success: true, updated: "categories" });
      }

      if (body.type === "settings" || body.settings || body.phone) {
        const st = body.settings || body;
        await fetch(`${firebaseUrl}/settings.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(st)
        });
        return res.status(200).json({ success: true, updated: "settings" });
      }

      return res.status(400).json({ error: "Invalid payload type" });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
