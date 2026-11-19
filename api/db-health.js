// Vercel Serverless Function: /api/db-health
// Safe health check and database connectivity indicator with In-Memory Response Caching (CWE-400 DoS Mitigation)

import { getFirebaseUrl, setSecurityHeaders } from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// In-Memory Cache to prevent RTDB connection & quota exhaustion
let cachedHealthResponse = null;
let lastHealthCheckTime = 0;
const HEALTH_CACHE_TTL_MS = 30 * 1000; // 30 seconds

export default async function handler(req, res) {
  setSecurityHeaders(req, res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "GET") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const now = Date.now();
  if (cachedHealthResponse && (now - lastHealthCheckTime < HEALTH_CACHE_TTL_MS)) {
    return res.status(200).json({
      ...cachedHealthResponse,
      cached: true,
      timestamp: now
    });
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

  const healthData = {
    status: "ok",
    environment: "production",
    timestamp: now,
    database: {
      provider: hasKV ? "primary-kv" : (firebasePing === "connected" ? "primary-cloud" : "local-cache"),
      connected: hasKV || firebasePing === "connected",
      readyForProduction: true
    }
  };

  cachedHealthResponse = healthData;
  lastHealthCheckTime = now;

  return res.status(200).json(healthData);
}
