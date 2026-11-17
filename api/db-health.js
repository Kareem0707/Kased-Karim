// Vercel Serverless Function: /api/db-health
// Safe health check and database connectivity indicator

import { getFirebaseUrl, setSecurityHeaders } from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function handler(req, res) {
  setSecurityHeaders(req, res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const hasKV = !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);
  const firebaseUrl = getFirebaseUrl(".json", { shallow: "true" });

  let firebasePing = "standby";
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    const pingRes = await fetch(firebaseUrl, {
      signal: controller.signal,
      cache: "no-store"
    });
    clearTimeout(timeoutId);
    firebasePing = pingRes.ok ? "connected" : "status_" + pingRes.status;
  } catch (e) {
    firebasePing = "offline";
  }

  return res.status(200).json({
    status: "ok",
    environment: "production",
    timestamp: Date.now(),
    database: {
      provider: hasKV ? "primary-kv" : (firebasePing === "connected" ? "primary-cloud" : "local-cache"),
      connected: hasKV || firebasePing === "connected",
      readyForProduction: true
    }
  });
}
