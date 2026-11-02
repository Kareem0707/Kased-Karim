// Vercel Serverless Function: /api/backup
// Handles Cloud Snapshots & Remote Backup Synchronization

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
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-cloud-db-url, x-firebase-url");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const firebaseUrl = getFirebaseUrl(req);

  try {
    // GET: Fetch Latest Cloud Backup Point
    if (req.method === "GET") {
      const t = Date.now();
      const snapRes = await fetch(`${firebaseUrl}/backups/latest.json?t=${t}`, { cache: "no-store" });
      if (snapRes.ok) {
        const data = await snapRes.json();
        return res.status(200).json({ success: true, backup: data });
      }
      return res.status(404).json({ success: false, message: "No cloud backup found" });
    }

    // POST: Save Snapshot to Cloud
    if (req.method === "POST") {
      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      if (!body) return res.status(400).json({ error: "Invalid backup data" });

      await fetch(`${firebaseUrl}/backups/latest.json`, {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      return res.status(200).json({ success: true, message: "Cloud backup saved successfully" });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
