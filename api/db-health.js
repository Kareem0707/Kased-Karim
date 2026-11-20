// Vercel Serverless Function: /api/db-health
// Hardened Database Health Check & Diagnostic Gateway (OWASP ASVS Level 3 & Secrets Management Cheat Sheet)

import {
  setSecurityHeaders,
  verifyAdminRequest,
  firebaseFetch,
  redactSecretUrl,
  withApiHardening,
  safeLogError
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Short In-Memory Cache for Public Probes (CWE-400 / DoS & Quota Exhaustion Mitigation)
let cachedPublicResponse = null;
let lastPublicProbeTime = 0;
const PUBLIC_CACHE_TTL_MS = 15 * 1000; // 15 seconds

async function dbHealthHandler(req, res, { requestId } = {}) {
  // 1. Mandatory CORS & Security Headers Gate (ASVS 14.4 & 14.5)
  if (setSecurityHeaders(req, res, { allowedMethods: ["GET", "OPTIONS"] })) return;

  if (req.method !== "GET") {
    res.setHeader("Allow", "GET, OPTIONS");
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  // 3. Role & Access Control Gate (Dual-Mode: Public vs. Verified Admin)
  const admin = verifyAdminRequest(req);
  const now = Date.now();

  // If public caller, serve from short in-memory cache if fresh (Prevents Firebase Quota DoS)
  if (!admin && cachedPublicResponse && (now - lastPublicProbeTime < PUBLIC_CACHE_TTL_MS)) {
    const statusCode = cachedPublicResponse.ok ? 200 : 503;
    return res.status(statusCode).json(cachedPublicResponse);
  }

  // 4. Lightweight, Read-Only Database Connectivity Probe
  const startTime = Date.now();
  let isConnected = false;

  try {
    // Probe a dedicated lightweight node in the server vault with shallow=true (Zero root enumeration)
    const probeRes = await firebaseFetch("_server_vault/health_ping.json", {
      method: "GET",
      cache: "no-store",
      timeoutMs: 3000
    }, { shallow: "true" });

    // HTTP 200 (node exists or null) or 404 (vault path not found yet) indicates active connection to Firebase RTDB
    isConnected = probeRes.ok || probeRes.status === 404;
    await probeRes.body?.cancel?.().catch(() => {});
  } catch (probeError) {
    // Log sanitized error internally without leaking database credentials or URLs
    console.warn("DB Health Probe Note:", redactSecretUrl(probeError?.message || "Probe unreachable"));
    isConnected = false;
  }

  const durationMs = Date.now() - startTime;

  // 5. Dual-Mode Response Generation
  if (!admin) {
    // PUBLIC RESPONSE: Zero Metadata / Zero Info-Disclosure (ASVS 7.1.1)
    const publicPayload = { ok: isConnected };
    cachedPublicResponse = publicPayload;
    lastPublicProbeTime = now;

    const statusCode = isConnected ? 200 : 503;
    return res.status(statusCode).json(publicPayload);
  }

  // VERIFIED ADMIN RESPONSE: Rich Diagnostic Details without Leaking Secrets (ASVS 7.1.2)
  const adminPayload = {
    ok: isConnected,
    authenticated: true,
    timestamp: now,
    latencyMs: durationMs,
    database: {
      connected: isConnected,
      status: isConnected ? "healthy" : "unreachable"
    }
  };

  const statusCode = isConnected ? 200 : 503;
  return res.status(statusCode).json(adminPayload);
}

export default withApiHardening(dbHealthHandler, {
  allowedMethods: ["GET"],
  maxBodyBytes: 1024,
  requireJsonBody: false,
  context: "/api/db-health"
});
