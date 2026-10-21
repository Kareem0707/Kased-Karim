// Vercel Serverless Function: /api/db-health
// Health check and database status indicator

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-cloud-db-url, x-firebase-url");
  
  const hasKV = !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);
  const firebaseUrl = process.env.FIREBASE_DB_URL || req.headers["x-cloud-db-url"] || req.headers["x-firebase-url"];
  const hasFirebase = !!(firebaseUrl && firebaseUrl.trim());

  let firebasePing = null;
  if (hasFirebase) {
    try {
      const cleanUrl = firebaseUrl.trim().replace(/\/$/, "");
      const pingRes = await fetch(`${cleanUrl}/.json?shallow=true`, { cache: "no-store" });
      firebasePing = pingRes.ok ? "connected" : "error_" + pingRes.status;
    } catch (e) {
      firebasePing = "unreachable";
    }
  }

  return res.status(200).json({
    status: "ok",
    environment: "vercel-serverless",
    timestamp: new Date().toISOString(),
    database: {
      provider: hasKV ? "vercel-kv" : (hasFirebase ? "firebase-rtdb" : "standby"),
      kvConnected: hasKV,
      firebaseConnected: hasFirebase,
      firebasePing,
      readyForProduction: hasKV || hasFirebase
    }
  });
}
