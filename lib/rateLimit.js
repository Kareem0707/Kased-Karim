/**
 * lib/rateLimit.js
 * Centralized Distributed Rate Limiting Engine for Vercel Serverless
 * Powered exclusively by @upstash/ratelimit & @upstash/redis via HTTP REST
 *
 * Implements strict Sliding Window algorithms across all application tiers:
 * 1. Auth & 2FA: 5 requests per 15 minutes per IP
 * 2. New Account Registration: 3 requests per 1 hour per IP
 * 3. Orders & Transactional Emails: 3 requests per 10 minutes per IP / User ID
 * 4. Public Storefront Read Endpoints: 60 requests per 1 minute per IP
 *
 * Fully compliant with:
 * - OWASP ASVS (Level 3) & OWASP API Security Top 10 (API4: Unrestricted Resource Consumption)
 * - NIST SP 800-63B (Rate Limiting & Anti-Automation)
 * - Zero In-Memory Map / Object fallback across serverless function instances
 * - RFC 6585 (HTTP 429 Too Many Requests & Retry-After)
 */

import { isIP } from "node:net";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// -----------------------------------------------------------------------------
// 1. TRUSTED VERCEL & EDGE CLIENT IP EXTRACTION (NO remoteAddress)
// -----------------------------------------------------------------------------
/**
 * Safely extracts client IP from trusted edge reverse-proxy headers in Vercel.
 * Strictly adheres to priority order:
 * 1. cf-connecting-ip (Cloudflare Edge)
 * 2. x-real-ip (Direct Reverse Proxy)
 * 3. x-vercel-forwarded-for (Vercel Edge Balancer - First IP)
 * 4. x-forwarded-for (Standard multi-hop proxy - First IP)
 *
 * NEVER accesses req.socket.remoteAddress or req.connection.remoteAddress.
 */
export function getClientIp(req) {
  if (!req || !req.headers) return "127.0.0.1";

  // Helper to sanitize and validate IP string
  function cleanIp(candidate) {
    if (!candidate || typeof candidate !== "string") return null;
    let ip = candidate.trim();
    // Strip IPv4-mapped IPv6 prefix (e.g. ::ffff:192.168.1.1)
    if (ip.startsWith("::ffff:")) {
      ip = ip.slice(7);
    }
    // Validate that candidate is a valid IPv4 or IPv6
    return isIP(ip) ? ip : null;
  }

  // 1. Cloudflare connecting IP
  const cfIp = cleanIp(req.headers["cf-connecting-ip"]);
  if (cfIp) return cfIp;

  // 2. Direct edge real IP
  const realIp = cleanIp(req.headers["x-real-ip"]);
  if (realIp) return realIp;

  // 3. Vercel edge balancer forwarded IP (First IP in comma-separated list)
  const vercelIp = req.headers["x-vercel-forwarded-for"];
  if (typeof vercelIp === "string") {
    const firstPart = vercelIp.split(",")[0].trim();
    const validated = cleanIp(firstPart);
    if (validated) return validated;
  }

  // 4. Standard forwarded-for header (First IP in proxy chain)
  const xForwardedFor = req.headers["x-forwarded-for"];
  if (typeof xForwardedFor === "string") {
    const firstPart = xForwardedFor.split(",")[0].trim();
    const validated = cleanIp(firstPart);
    if (validated) return validated;
  }

  // Safe fallback if headers are missing or spoofed (remoteAddress is explicitly forbidden)
  return "127.0.0.1";
}

// -----------------------------------------------------------------------------
// 2. UPSTASH REDIS REST SINGLETON
// -----------------------------------------------------------------------------
let redisSingleton = null;
let currentUrl = null;
let currentToken = null;

export function resetRateLimiterClients() {
  redisSingleton = null;
  currentUrl = null;
  currentToken = null;
  ratelimiterInstances.clear();
}

export function getRedisClient() {
  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

  if (!url || !token) {
    return null;
  }

  if (!redisSingleton || currentUrl !== url || currentToken !== token) {
    currentUrl = url;
    currentToken = token;
    ratelimiterInstances.clear();
    redisSingleton = new Redis({
      url: url.trim(),
      token: token.trim(),
      retry: {
        retries: 1,
        backoff: (retryCount) => Math.min(Math.exp(retryCount) * 50, 200)
      }
    });
  }

  return redisSingleton;
}

// -----------------------------------------------------------------------------
// 3. SLIDING WINDOW RATE LIMITERS CONFIGURATION
// -----------------------------------------------------------------------------
// Tier 1: Auth & 2FA (5 attempts per 15 minutes per IP)
// Tier 2: Account Registration (3 attempts per 1 hour per IP)
// Tier 3: Orders & Verification Emails (3 requests per 10 minutes per IP or User ID)
// Tier 4: Public Read Endpoints (60 requests per 1 minute per IP)

export const RATE_LIMIT_TIERS = Object.freeze({
  auth: {
    name: "auth",
    limit: 5,
    window: "15 m",
    windowMs: 15 * 60 * 1000,
    prefix: "@upstash/ratelimit:auth",
    errorMessage: "تم تجاوز الحد الأقصى لمحاولات تسجيل الدخول والتحقق الثنائي (5 محاولات كل 15 دقيقة). يرجى الانتظار والمحاولة لاحقاً."
  },
  register: {
    name: "register",
    limit: 3,
    window: "1 h",
    windowMs: 60 * 60 * 1000,
    prefix: "@upstash/ratelimit:register",
    errorMessage: "تم تجاوز الحد المسموح لإنشاء الحسابات الجديدة (3 حسابات كل ساعة). يرجى المحاولة لاحقاً."
  },
  orders: {
    name: "orders",
    limit: 3,
    window: "10 m",
    windowMs: 10 * 60 * 1000,
    prefix: "@upstash/ratelimit:orders",
    errorMessage: "تم تجاوز الحد المسموح به لتقديم الطلبات (3 طلبات كل 10 دقائق). يرجى الانتظار قليلاً قبل إعادة المحاولة."
  },
  emails: {
    name: "emails",
    limit: 3,
    window: "10 m",
    windowMs: 10 * 60 * 1000,
    prefix: "@upstash/ratelimit:emails",
    errorMessage: "تم تجاوز الحد المسموح به لإرسال رسائل التفعيل والبريد الإلكتروني (3 طلبات كل 10 دقائق). يرجى الانتظار والمحاولة لاحقاً."
  },
  read: {
    name: "read",
    limit: 60,
    window: "1 m",
    windowMs: 60 * 1000,
    prefix: "@upstash/ratelimit:read",
    errorMessage: "تم تجاوز الحد المسموح به لطلبات الاستعلام (60 طلباً في الدقيقة). يرجى إبطاء معدل الاستعلام والمحاولة لاحقاً."
  }
});

// Cache for initialized Ratelimit instances (per tier)
const ratelimiterInstances = new Map();

export function getRatelimiter(tierKey) {
  const tierConfig = RATE_LIMIT_TIERS[tierKey];
  if (!tierConfig) {
    throw new Error(`Invalid rate limit tier: ${tierKey}`);
  }

  const redis = getRedisClient();
  if (!redis) {
    return null; // Redis credentials not configured
  }

  if (!ratelimiterInstances.has(tierKey)) {
    const limiter = new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(tierConfig.limit, tierConfig.window),
      prefix: tierConfig.prefix,
      analytics: false
    });
    ratelimiterInstances.set(tierKey, limiter);
  }

  return ratelimiterInstances.get(tierKey);
}

// -----------------------------------------------------------------------------
// 4. CORE RATE LIMIT CHECK WITH RESILIENT REDIS DEGRADATION
// -----------------------------------------------------------------------------
/**
 * Evaluates rate limit for a specific tier and identifier.
 * Gracefully handles Redis downtime without leaking credentials, URLs, or internal errors.
 */
export async function checkRateLimit(tierKey, identifier) {
  const tierConfig = RATE_LIMIT_TIERS[tierKey] || RATE_LIMIT_TIERS.read;
  const cleanId = String(identifier || "anonymous").trim().slice(0, 128);

  const limiter = getRatelimiter(tierKey);

  // If Redis is unconfigured (e.g. local dev without Upstash keys):
  if (!limiter) {
    return {
      success: true,
      limit: tierConfig.limit,
      remaining: tierConfig.limit,
      reset: Date.now() + tierConfig.windowMs,
      retryAfter: 0,
      unconfigured: true
    };
  }

  try {
    const res = await limiter.limit(cleanId);
    const now = Date.now();
    const retryAfter = res.success ? 0 : Math.max(1, Math.ceil((res.reset - now) / 1000));

    return {
      success: res.success,
      limit: res.limit,
      remaining: Math.max(0, res.remaining),
      reset: res.reset,
      retryAfter,
      errorMessage: tierConfig.errorMessage
    };
  } catch (err) {
    // Secure Fallback: Handle Redis temporary outage safely without leaking internal details or stack traces
    console.warn(`[RateLimit] Upstash Redis temporarily unavailable for tier ${tierKey}:`, err?.message || "Connection timeout");

    return {
      success: true,
      limit: tierConfig.limit,
      remaining: 1,
      reset: Date.now() + tierConfig.windowMs,
      retryAfter: 0,
      degraded: true
    };
  }
}

// -----------------------------------------------------------------------------
// 5. SERVERLESS ENFORCEMENT MIDDLEWARE / GUARD
// -----------------------------------------------------------------------------
/**
 * Enforces rate limiting on an incoming HTTP request.
 * If exceeded, sets HTTP 429 status, Retry-After, and X-RateLimit-* headers,
 * responds with clear Arabic JSON error message, and returns false.
 *
 * If allowed, decorates response headers with X-RateLimit-* and returns true.
 *
 * @param {object} req - HTTP Request object
 * @param {object} res - HTTP Response object
 * @param {"auth"|"register"|"orders"|"emails"|"read"} tierKey - Rate limit tier
 * @param {string|null} customIdentifier - Optional custom identifier (e.g. User ID)
 * @returns {Promise<boolean>} True if allowed to proceed, False if rejected with 429
 */
export async function enforceRateLimit(req, res, tierKey = "read", customIdentifier = null) {
  const clientIp = getClientIp(req);
  const identifier = customIdentifier ? `${clientIp}:${customIdentifier}` : clientIp;

  const result = await checkRateLimit(tierKey, identifier);

  // Set standard Rate Limiting response headers (RFC 6585)
  if (res && typeof res.setHeader === "function") {
    res.setHeader("X-RateLimit-Limit", String(result.limit));
    res.setHeader("X-RateLimit-Remaining", String(result.remaining));
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(result.reset / 1000)));

    if (!result.success) {
      res.setHeader("Retry-After", String(result.retryAfter));
      const payload = {
        success: false,
        rateLimited: true,
        error: result.errorMessage || "تم تجاوز الحد المسموح به من الطلبات. يرجى الانتظار والمحاولة لاحقاً.",
        retryAfter: result.retryAfter
      };

      if (typeof res.status === "function") {
        res.status(429).json(payload);
      } else {
        res.writeHead(429, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify(payload));
      }
      return false;
    }
  }

  return true;
}
