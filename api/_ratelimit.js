// Vercel Serverless Distributed Rate Limiter & Abuse Prevention Engine
// Compliant with OWASP ASVS (Level 2/3) & OWASP Automated Threat Handbook
// Native Node.js Crypto (Zero External Dependencies) + Hybrid Redis KV / Firebase RTDB CAS

import crypto from "crypto";
import { getClientIp as getVercelClientIp } from "../lib/rateLimit.js";

// Server Secret for HMAC Key Hashing (Strict Zero Static Secrets)
const EPHEMERAL_SECRET = crypto.randomBytes(32).toString("hex");
const RATE_LIMIT_SECRET = (
  process.env.ADMIN_JWT_SECRET ||
  process.env.ADMIN_SECRET ||
  process.env.FIREBASE_DB_SECRET ||
  EPHEMERAL_SECRET
).trim();

// Zero In-Memory Map/Object Rate Limiting (Serverless Safe)

// -----------------------------------------------------------------------------
// 1. TRUSTED CLIENT IP EXTRACTION & IPV6 /64 SUBNET NORMALIZATION (ASVS 13.1.5)
// -----------------------------------------------------------------------------
export function getClientIp(req) {
  return getVercelClientIp(req);
}

// Normalize IP addresses (IPv4 as-is, IPv6 normalized to /64 subnet prefix to mitigate subnet rotation)
export function normalizeIpForRateLimit(ip) {
  if (!ip || typeof ip !== "string") return "127.0.0.1";
  let clean = ip.trim();

  // Strip IPv4-mapped IPv6 prefix (::ffff:192.168.1.1 -> 192.168.1.1)
  if (clean.startsWith("::ffff:")) {
    clean = clean.slice(7);
  }

  // IPv4 validation
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) {
    return clean;
  }

  // IPv6: Collapse and extract the first 4 blocks (the /64 routing prefix)
  if (clean.includes(":")) {
    try {
      const parts = clean.split("::");
      const left = parts[0] ? parts[0].split(":").filter(Boolean) : [];
      const right = parts[1] ? parts[1].split(":").filter(Boolean) : [];
      const missing = 8 - (left.length + right.length);
      const middle = missing > 0 ? new Array(missing).fill("0") : [];
      const full = [...left, ...middle, ...right];
      const normalizedBlocks = full.slice(0, 8).map(b => b.padStart(4, "0").toLowerCase());
      // /64 prefix is the first 4 blocks (64 bits)
      return normalizedBlocks.slice(0, 4).join(":") + "::/64";
    } catch (e) {
      return clean.slice(0, 32);
    }
  }

  return clean.slice(0, 64);
}

// -----------------------------------------------------------------------------
// 2. SCOPED HMAC KEY DERIVATION & ZERO-PII PATH SAFETY (ASVS 2.2.1)
// -----------------------------------------------------------------------------
export function getRateLimitKey(scope, identifier = "") {
  const cleanScope = String(scope || "default").trim().toLowerCase().replace(/[^a-z0-9_-]/g, "");
  const cleanId = String(identifier || "").trim().toLowerCase();

  const hmac = crypto
    .createHmac("sha256", RATE_LIMIT_SECRET)
    .update(`kased_karim_ratelimit_v1:${cleanScope}:${cleanId}`)
    .digest("hex")
    .slice(0, 32);

  return `${cleanScope}_${hmac}`;
}

// -----------------------------------------------------------------------------
// 3. PERSISTENT BACKEND VAULT URL BUILDER
// -----------------------------------------------------------------------------
function getStorageUrl(path = "", queryParams = {}) {
  const envUrl = (process.env.FIREBASE_DB_URL || "").trim();
  const secret = (process.env.FIREBASE_DB_SECRET || process.env.FIREBASE_AUTH_TOKEN || "").trim();
  if (!envUrl || !secret) {
    throw new Error("Cryptographic Fail-Closed: Firebase configuration missing in rate limiter backend.");
  }
  let parsed;
  try {
    parsed = new URL(envUrl);
  } catch {
    throw new Error("Cryptographic Fail-Closed: FIREBASE_DB_URL is malformed in rate limiter backend.");
  }
  if (parsed.protocol !== "https:") {
    throw new Error("Cryptographic Fail-Closed: FIREBASE_DB_URL must use HTTPS protocol.");
  }
  const cleanPath = path ? (path.startsWith("/") ? path : `/${path}`) : "/";
  const url = new URL(cleanPath, parsed.origin);
  if (url.origin !== parsed.origin) {
    throw new Error("Security Alert: Target origin mismatch in rate limiter URL builder.");
  }
  url.searchParams.set("auth", secret);

  for (const [key, value] of Object.entries(queryParams)) {
    if (value !== undefined && value !== null && key !== "auth" && key !== "__proto__" && key !== "constructor" && key !== "prototype") {
      url.searchParams.set(key, String(value));
    }
  }

  return url.toString();
}

// -----------------------------------------------------------------------------
// 4. ATOMIC DISTRIBUTED RATE LIMIT CHECK (CAS / ETAG / REDIS PIPELINE)
// -----------------------------------------------------------------------------
export async function checkRateLimitDistributed(scope, identifier, maxAttempts = 5, windowMs = 15 * 60 * 1000, options = {}) {
  const { failClosed = false } = options;
  const key = getRateLimitKey(scope, identifier);
  const now = Date.now();

  // 1. Try Redis / KV if configured (Atomic in O(1))
  const kvUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const kvToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (kvUrl && kvToken) {
    try {
      const res = await fetch(`${kvUrl}/pipeline`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify([
          ["GET", `ratelimit:${key}`],
          ["TTL", `ratelimit:${key}`]
        ])
      });
      if (res.ok) {
        const results = await res.json();
        const currentCount = parseInt(results[0]?.result || "0", 10);
        const ttl = parseInt(results[1]?.result || "0", 10);
        if (currentCount >= maxAttempts) {
          const remainingSec = ttl > 0 ? ttl : Math.ceil(windowMs / 1000);
          return { allowed: false, remainingSec, count: currentCount, key };
        }
        return { allowed: true, remainingSec: 0, count: currentCount, key };
      }
    } catch (kvErr) {
      console.warn("KV rate limit read warning:", kvErr.message);
    }
  }

  // 2. Firebase RTDB Vault with ETag (Atomic CAS & Expiration Pruning)
  try {
    const firebaseUrl = getStorageUrl(`_server_vault/rate_limits/${key}.json`, { t: now });
    const res = await fetch(firebaseUrl, {
      cache: "no-store",
      headers: {
        "Accept": "application/json",
        "X-Firebase-ETag": "true"
      }
    });

    if (res.ok) {
      const data = await res.json();
      if (data && typeof data === "object") {
        // Enforce active lockout
        if (data.lockedUntil && data.lockedUntil > now) {
          const remainingSec = Math.ceil((data.lockedUntil - now) / 1000);
          return { allowed: false, remainingSec, count: data.count || maxAttempts, key };
        }

        // Window expired: Opportunistically purge stale node to prevent storage bloat
        if (data.firstAttempt && now - data.firstAttempt > windowMs) {
          fetch(firebaseUrl, { method: "DELETE", cache: "no-store" }).catch(() => {});
          return { allowed: true, count: 0, remainingSec: 0, key };
        }

        // Enforce attempt threshold
        if (data.count && data.count >= maxAttempts) {
          const remainingSec = Math.ceil((windowMs - (now - (data.firstAttempt || now))) / 1000);
          return { allowed: false, remainingSec: remainingSec > 0 ? remainingSec : Math.ceil(windowMs / 1000), count: data.count, key };
        }
      }
      return { allowed: true, count: 0, remainingSec: 0, key };
    }
  } catch (err) {
    if (failClosed) {
      console.error(`CRITICAL: Distributed rate limit check failed on Fail-Closed scope '${scope}':`, err.message);
      return { allowed: false, remainingSec: 60, failClosedError: true, key };
    }
    console.warn(`Distributed rate limit check note on '${scope}':`, err.message);
  }

  // Fallback if Redis/DB is unavailable (Fail-Open without In-Memory Map)
  return { allowed: true, count: 0, remainingSec: 0, key };
}

// -----------------------------------------------------------------------------
// 5. ATOMIC FAILED ATTEMPT RECORDING (INCREMENT WITH ETAG CAS)
// -----------------------------------------------------------------------------
export async function recordFailedAttemptDistributed(scope, identifier, maxAttempts = 5, windowMs = 15 * 60 * 1000) {
  const key = getRateLimitKey(scope, identifier);
  const now = Date.now();
  const windowSec = Math.ceil(windowMs / 1000);

  // 1. Redis / KV Atomic INCR + EXPIRE (O(1))
  const kvUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const kvToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (kvUrl && kvToken) {
    try {
      await fetch(`${kvUrl}/pipeline`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify([
          ["INCR", `ratelimit:${key}`],
          ["EXPIRE", `ratelimit:${key}`, windowSec]
        ])
      });
      return;
    } catch (kvErr) {}
  }

  // 2. Firebase RTDB with Atomic ETag CAS (Retry once on 412 Concurrency)
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const firebaseUrl = getStorageUrl(`_server_vault/rate_limits/${key}.json`, { t: now });
      let currentCount = 0;
      let firstAttempt = now;
      let etag = null;

      const getRes = await fetch(firebaseUrl, {
        cache: "no-store",
        headers: {
          "Accept": "application/json",
          "X-Firebase-ETag": "true"
        }
      });

      if (getRes.ok) {
        etag = getRes.headers.get("etag") || getRes.headers.get("ETag");
        const existing = await getRes.json();
        if (existing && typeof existing === "object") {
          if (existing.firstAttempt && now - existing.firstAttempt < windowMs) {
            currentCount = existing.count || 0;
            firstAttempt = existing.firstAttempt;
          }
        }
      }

      const newCount = currentCount + 1;
      const isLocked = newCount >= maxAttempts;
      const payload = {
        count: newCount,
        firstAttempt,
        lastAttempt: now,
        lockedUntil: isLocked ? now + windowMs : null
      };

      const putHeaders = { "Content-Type": "application/json" };
      if (etag) {
        putHeaders["If-Match"] = etag;
      }

      const putRes = await fetch(firebaseUrl, {
        method: "PUT",
        cache: "no-store",
        headers: putHeaders,
        body: JSON.stringify(payload)
      });

      if (putRes.status === 412) {
        // Concurrency collision (another instance wrote in same millisecond) -> retry
        continue;
      }
      break;
    } catch (e) {
      break;
    }
  }
}

// -----------------------------------------------------------------------------
// 6. ATOMIC RESET / CLEAR (ON SUCCESSFUL AUTHENTICATION)
// -----------------------------------------------------------------------------
export async function resetRateLimitDistributed(scope, identifier) {
  const key = getRateLimitKey(scope, identifier);

  const kvUrl = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const kvToken = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (kvUrl && kvToken) {
    try {
      await fetch(`${kvUrl}/del/ratelimit:${key}`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${kvToken}` }
      });
    } catch (e) {}
  }

  try {
    const firebaseUrl = getStorageUrl(`_server_vault/rate_limits/${key}.json`);
    await fetch(firebaseUrl, { method: "DELETE", cache: "no-store" });
  } catch (e) {}
}

// -----------------------------------------------------------------------------
// 7. HELPER: DUAL-LAYER RATE LIMIT CHECK (IP + TARGET IDENTIFIER)
// -----------------------------------------------------------------------------
export async function checkDualLayerRateLimit({
  ip,
  ipScope,
  ipLimit = 10,
  ipWindowMs = 15 * 60 * 1000,
  target,
  targetScope,
  targetLimit = 5,
  targetWindowMs = 15 * 60 * 1000,
  failClosed = false
}) {
  const normalizedIp = normalizeIpForRateLimit(ip);

  // 1. Check IP-level limit
  if (ipScope && normalizedIp) {
    const ipCheck = await checkRateLimitDistributed(ipScope, normalizedIp, ipLimit, ipWindowMs, { failClosed });
    if (!ipCheck.allowed) {
      return {
        allowed: false,
        layer: "ip",
        remainingSec: ipCheck.remainingSec,
        failClosedError: ipCheck.failClosedError
      };
    }
  }

  // 2. Check Target-level limit (e.g. normalized IP + target identifier)
  if (targetScope && target) {
    const cleanTarget = String(target).trim().toLowerCase();
    const targetKey = `${normalizedIp}:${cleanTarget}`;
    const targetCheck = await checkRateLimitDistributed(targetScope, targetKey, targetLimit, targetWindowMs, { failClosed });
    if (!targetCheck.allowed) {
      return {
        allowed: false,
        layer: "target",
        remainingSec: targetCheck.remainingSec,
        failClosedError: targetCheck.failClosedError
      };
    }
  }

  return { allowed: true, remainingSec: 0 };
}
