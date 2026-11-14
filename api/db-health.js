// Vercel Serverless Function: /api/db-health
// Safe health check and database connectivity indicator

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Access-Control-Allow-Origin", "*");

  const hasKV = !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);
  const firebaseUrl = process.env.FIREBASE_DB_URL || "https://kased-karim-default-rtdb.firebaseio.com";
  const hasFirebase = !!(firebaseUrl && firebaseUrl.trim());

  let firebasePing = "standby";
  if (hasFirebase) {
    try {
      const cleanUrl = firebaseUrl.trim().replace(/\/$/, "");
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      const pingRes = await fetch(`${cleanUrl}/.json?shallow=true`, {
        signal: controller.signal,
        cache: "no-store"
      });
      clearTimeout(timeoutId);
      firebasePing = pingRes.ok ? "connected" : "status_" + pingRes.status;
    } catch (e) {
      firebasePing = "offline";
    }
  }

  return res.status(200).json({
    status: "ok",
    environment: "production",
    timestamp: Date.now(),
    database: {
      provider: hasKV ? "primary-kv" : (hasFirebase ? "primary-cloud" : "local-cache"),
      connected: hasKV || firebasePing === "connected"
    }
  });
}
