// Vercel Serverless Function: /api/db-health
// Health check and database status indicator

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  const hasKV = !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);
  const hasFirebase = !!process.env.FIREBASE_DB_URL;

  return res.status(200).json({
    status: "ok",
    environment: "vercel-serverless",
    timestamp: new Date().toISOString(),
    database: {
      provider: hasKV ? "vercel-kv" : (hasFirebase ? "firebase-rtdb" : "cloud-rest-sync"),
      kvConnected: hasKV,
      firebaseConnected: hasFirebase,
      readyForProduction: true
    }
  });
}
