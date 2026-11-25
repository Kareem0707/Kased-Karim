// Serverless Authentication & Security Token Vault
// Node.js Native Crypto (Zero External Dependencies)
import crypto from "crypto";
import { promisify } from "util";

const scryptAsync = promisify(crypto.scrypt);

// -----------------------------------------------------------------------------
// SECRETS MANAGEMENT & CRYPTOGRAPHIC KEY SEPARATION (RFC 8725 §3.2 & ASVS 2.10.3)
// -----------------------------------------------------------------------------
export function getMasterJwtSecrets() {
  const raw = (process.env.ADMIN_JWT_SECRET || process.env.ADMIN_SECRET || "").trim();
  if (!raw) return [];
  return raw.split(",").map(s => s.trim()).filter(s => s.length >= 32);
}

export function getMasterJwtSecret() {
  const secrets = getMasterJwtSecrets();
  if (secrets.length === 0) {
    return null; // Strict Fail-Closed: Never fallback to weak or static secrets
  }
  return secrets[0];
}

export function getAdminSigningKey() {
  const master = getMasterJwtSecret();
  if (!master) return null;
  return crypto.createHmac("sha256", master).update("kased_karim_admin_jwt_domain_v2").digest();
}

export function getAdminSigningKeys() {
  const secrets = getMasterJwtSecrets();
  return secrets.map(sec => crypto.createHmac("sha256", sec).update("kased_karim_admin_jwt_domain_v2").digest());
}

export function getCustomerSigningKey() {
  const customCustSecrets = (process.env.CUSTOMER_JWT_SECRET || "").split(",").map(s => s.trim()).filter(s => s.length >= 32);
  if (customCustSecrets.length > 0) {
    return crypto.createHmac("sha256", customCustSecrets[0]).update("kased_karim_customer_jwt_domain_v2").digest();
  }
  const master = getMasterJwtSecret();
  if (!master) return null;
  return crypto.createHmac("sha256", master).update("kased_karim_customer_jwt_domain_v2").digest();
}

export function getCustomerSigningKeys() {
  const customCustSecrets = (process.env.CUSTOMER_JWT_SECRET || "").split(",").map(s => s.trim()).filter(s => s.length >= 32);
  if (customCustSecrets.length > 0) {
    return customCustSecrets.map(sec => crypto.createHmac("sha256", sec).update("kased_karim_customer_jwt_domain_v2").digest());
  }
  const secrets = getMasterJwtSecrets();
  return secrets.map(sec => crypto.createHmac("sha256", sec).update("kased_karim_customer_jwt_domain_v2").digest());
}

// Constant for backward-compatible internal reference
const JWT_SECRET = getMasterJwtSecret() || "UNCONFIGURED_FAIL_CLOSED_SECRET";

// Allowed server-side admin passwords (strictly from environment variable or memory-hard hash)
const CONFIGURED_ADMIN_PASSWORDS = [
  process.env.ADMIN_PASSWORD
].filter(Boolean);

// Strict Fail-Closed: No hardcoded fallback passwords in source code
const ALLOWED_ADMIN_PASSWORDS = CONFIGURED_ADMIN_PASSWORDS;
const ADMIN_PASSWORD_HASH = (process.env.ADMIN_PASSWORD_HASH || "").trim();
const ADMIN_PASSWORD_SALT = (process.env.ADMIN_PASSWORD_SALT || "").trim();

// -----------------------------------------------------------------------------
// CORS & HTTP SECURITY HEADERS ENGINE (OWASP ASVS V14.5, CWE-942, CWE-346, CWE-352)
// -----------------------------------------------------------------------------

// Sanitizes and strictly normalizes an Origin string (CWE-113 & CWE-942)
export function normalizeExactOrigin(rawOrigin) {
  if (typeof rawOrigin !== "string") return null;
  const trimmed = rawOrigin.trim();
  if (!trimmed || trimmed.length > 256) return null;

  // Strict CRLF & Whitespace / Control-Char injection check (CWE-113)
  if (/[\r\n\0\s]/.test(trimmed)) return null;

  // Strict ban on "null" string origin (CWE-942)
  if (trimmed.toLowerCase() === "null") return null;

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }

  // Protocol must strictly be https: or http:
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return null;
  }

  // Origin headers must not contain path (except root /), search query, or hash fragment
  if ((parsed.pathname !== "/" && parsed.pathname !== "") || parsed.search || parsed.hash) {
    return null;
  }

  // Must not contain credentials (user:pass@host)
  if (parsed.username || parsed.password) {
    return null;
  }

  // Hostname must be valid
  if (!parsed.hostname || parsed.hostname.length > 253) {
    return null;
  }

  return parsed.origin.toLowerCase();
}

// Builds the authoritative Exact-Match Origin Set based on runtime environment (Axis 1 & 2)
export function getAllowedOrigins() {
  const allowed = new Set([
    "https://kasedkarim.com",
    "https://www.kasedkarim.com"
  ]);

  const isProd = process.env.VERCEL_ENV === "production" || process.env.NODE_ENV === "production";
  const isPreview = process.env.VERCEL_ENV === "preview";

  // Support official Vercel preview deployment URL (strictly in preview environment only)
  if (isPreview && process.env.VERCEL_URL) {
    const rawPreviewUrl = `https://${process.env.VERCEL_URL.trim()}`;
    const normPreview = normalizeExactOrigin(rawPreviewUrl);
    if (normPreview) {
      allowed.add(normPreview);
    }
  }

  // Support additional environment-configured origins (ASVS 14.5.1)
  if (process.env.ALLOWED_ORIGINS) {
    const customList = process.env.ALLOWED_ORIGINS.split(",");
    for (const raw of customList) {
      const norm = normalizeExactOrigin(raw);
      if (norm) {
        // In production, reject non-HTTPS entries
        if (isProd && !norm.startsWith("https://")) {
          continue;
        }
        allowed.add(norm);
      }
    }
  }

  return allowed;
}

// Strictly checks if a given origin is authorized (Exact Match & Environment Isolation)
export function isAllowedOrigin(rawOrigin) {
  const normalized = normalizeExactOrigin(rawOrigin);
  if (!normalized) return false;

  const isProd = process.env.VERCEL_ENV === "production" || process.env.NODE_ENV === "production";

  // In production, strictly reject any non-HTTPS origin (mitigates MITM / protocol downgrade)
  if (isProd && !normalized.startsWith("https://")) {
    return false;
  }

  const allowedSet = getAllowedOrigins();
  if (allowedSet.has(normalized)) {
    return true;
  }

  // In non-production (local dev / test), permit loopback localhost / 127.0.0.1 on any port
  if (!isProd) {
    try {
      const u = new URL(normalized);
      if (u.hostname === "localhost" || u.hostname === "127.0.0.1") {
        return true;
      }
    } catch {}
  }

  return false;
}

// Safely appends fields to the HTTP Vary header without duplication or overwriting (Axis 3)
export function appendVaryHeader(res, field) {
  if (!res || typeof res.setHeader !== "function" || typeof res.getHeader !== "function") return;
  const existing = res.getHeader("Vary");
  if (!existing) {
    res.setHeader("Vary", field);
    return;
  }

  const existingStr = Array.isArray(existing) ? existing.join(", ") : String(existing);
  const currentTokens = existingStr.split(",").map(t => t.trim().toLowerCase());
  const newFields = field.split(",").map(f => f.trim());

  const toAdd = [];
  for (const f of newFields) {
    if (!currentTokens.includes(f.toLowerCase())) {
      toAdd.push(f);
      currentTokens.push(f.toLowerCase());
    }
  }

  if (toAdd.length > 0) {
    res.setHeader("Vary", `${existingStr}, ${toAdd.join(", ")}`);
  }
}

// Central API Security & CORS Guard (ASVS Level 3, CWE-942, CWE-346, CWE-352)
export function setSecurityHeaders(req, res, options = {}) {
  let actualRes = res;
  let actualReq = req;
  if (!actualRes && actualReq && typeof actualReq.setHeader === "function") {
    actualRes = actualReq;
    actualReq = { headers: {} };
  }
  if (!actualRes || typeof actualRes.setHeader !== "function") return false;

  // 1. Mandatory Core Security & Anti-Caching Headers for JSON APIs (ASVS Level 3 & CWE-525)
  const cacheControl = options.cacheControl || "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0";
  actualRes.setHeader("Cache-Control", cacheControl);
  actualRes.setHeader("Pragma", "no-cache");
  actualRes.setHeader("Expires", "0");
  actualRes.setHeader("X-Content-Type-Options", "nosniff");
  actualRes.setHeader("X-Frame-Options", "DENY");
  actualRes.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  actualRes.setHeader("Referrer-Policy", "no-referrer");
  actualRes.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  actualRes.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
  actualRes.setHeader("X-XSS-Protection", "1; mode=block");

  // 2. Intelligent Vary Header merging (Prevents Vercel Edge / Proxy Cache Poisoning)
  appendVaryHeader(actualRes, "Origin");

  // 3. Extract and inspect Origin & Fetch Metadata
  const rawOrigin = (actualReq?.headers && (actualReq.headers["origin"] || actualReq.headers["Origin"])) || "";
  const secFetchSite = (actualReq?.headers && (actualReq.headers["sec-fetch-site"] || actualReq.headers["Sec-Fetch-Site"])) || "";
  const method = (actualReq?.method || "").toUpperCase();

  let originAllowed = false;
  let normalizedOrigin = null;

  if (rawOrigin) {
    normalizedOrigin = normalizeExactOrigin(rawOrigin);
    if (normalizedOrigin && isAllowedOrigin(normalizedOrigin)) {
      originAllowed = true;
    }
  }

  const allowedMethodsList = options.allowedMethods || ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
  const allowedMethodsStr = allowedMethodsList.join(", ");
  const allowedHeadersStr = "Content-Type, Authorization, x-admin-token, x-customer-token, Cache-Control, Pragma, X-Requested-With, Idempotency-Key, x-destructive-confirm";

  // 4. Strict Preflight OPTIONS Lifecycle Handling (Axis 4)
  if (method === "OPTIONS") {
    appendVaryHeader(actualRes, "Access-Control-Request-Method, Access-Control-Request-Headers");
    actualRes.setHeader("Allow", allowedMethodsStr);

    if (rawOrigin) {
      if (originAllowed && normalizedOrigin) {
        // Preflight Accepted -> 204 No Content with exact origin
        actualRes.setHeader("Access-Control-Allow-Origin", normalizedOrigin);
        actualRes.setHeader("Access-Control-Allow-Credentials", "true");
        actualRes.setHeader("Access-Control-Allow-Methods", allowedMethodsStr);
        actualRes.setHeader("Access-Control-Allow-Headers", allowedHeadersStr);
        actualRes.setHeader("Access-Control-Max-Age", "600");
        actualRes.setHeader("Access-Control-Expose-Headers", "Retry-After, X-Request-Id");
        actualRes.statusCode = 204;
        if (typeof actualRes.end === "function") actualRes.end();
        return true;
      } else {
        // Preflight Rejected -> 403 Forbidden with zero Access-Control-Allow-Origin (Axis 1 & 4)
        actualRes.statusCode = 403;
        const errPayload = { ok: false, success: false, error: "النطاق الأصلي غير مصرح له بالوصول (Origin Forbidden)." };
        if (typeof actualRes.json === "function") {
          actualRes.json(errPayload);
        } else if (typeof actualRes.end === "function") {
          actualRes.setHeader("Content-Type", "application/json; charset=utf-8");
          actualRes.end(JSON.stringify(errPayload));
        }
        return true;
      }
    }

    // Direct OPTIONS without Origin header (e.g. CLI curl test)
    actualRes.statusCode = 204;
    if (typeof actualRes.end === "function") actualRes.end();
    return true;
  }

  // 5. Normal Request Handling (GET, POST, PUT, PATCH, DELETE)
  if (rawOrigin) {
    if (originAllowed && normalizedOrigin) {
      actualRes.setHeader("Access-Control-Allow-Origin", normalizedOrigin);
      actualRes.setHeader("Access-Control-Allow-Credentials", "true");
      actualRes.setHeader("Access-Control-Expose-Headers", "Retry-After, X-Request-Id");
    } else {
      // Active Origin Rejection: Never process state-changing methods from unauthorized origins (Axis 6)
      const isMutating = ["POST", "PUT", "PATCH", "DELETE"].includes(method);
      if (isMutating || options.strictOrigin) {
        actualRes.statusCode = 403;
        const errPayload = { ok: false, success: false, error: "النطاق الأصلي غير مصرح له بتنفيذ هذه العملية (Origin Forbidden)." };
        if (typeof actualRes.json === "function") {
          actualRes.json(errPayload);
        } else if (typeof actualRes.end === "function") {
          actualRes.setHeader("Content-Type", "application/json; charset=utf-8");
          actualRes.end(JSON.stringify(errPayload));
        }
        return true;
      }
    }
  }

  // 6. Fetch Metadata (Sec-Fetch-Site) Defense-in-Depth against Cross-Site Attacks (CSRF)
  if (secFetchSite && typeof secFetchSite === "string") {
    const site = secFetchSite.trim().toLowerCase();
    const isMutating = ["POST", "PUT", "PATCH", "DELETE"].includes(method);
    if (site === "cross-site" && isMutating) {
      actualRes.statusCode = 403;
      const errPayload = { ok: false, success: false, error: "تم رفض الطلب العابر للمواقع لحماية النظام (Cross-Site Request Rejected)." };
      if (typeof actualRes.json === "function") {
        actualRes.json(errPayload);
      } else if (typeof actualRes.end === "function") {
        actualRes.setHeader("Content-Type", "application/json; charset=utf-8");
        actualRes.end(JSON.stringify(errPayload));
      }
      return true;
    }
  }

  // 7. Referer Header Defense if Origin is absent on mutating request
  if (!rawOrigin && ["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    const referer = (actualReq?.headers && (actualReq.headers["referer"] || actualReq.headers["Referer"])) || "";
    if (referer && typeof referer === "string") {
      try {
        const refUrl = new URL(referer);
        const refOrigin = refUrl.origin.toLowerCase();
        if (!isAllowedOrigin(refOrigin)) {
          actualRes.statusCode = 403;
          const errPayload = { ok: false, success: false, error: "المصدر المرجعي للطلب غير مصرح به (Referer Forbidden)." };
          if (typeof actualRes.json === "function") {
            actualRes.json(errPayload);
          } else if (typeof actualRes.end === "function") {
            actualRes.setHeader("Content-Type", "application/json; charset=utf-8");
            actualRes.end(JSON.stringify(errPayload));
          }
          return true;
        }
      } catch {
        actualRes.statusCode = 403;
        const errPayload = { ok: false, success: false, error: "المصدر المرجعي للطلب غير صالح (Invalid Referer)." };
        if (typeof actualRes.json === "function") {
          actualRes.json(errPayload);
        } else if (typeof actualRes.end === "function") {
          actualRes.setHeader("Content-Type", "application/json; charset=utf-8");
          actualRes.end(JSON.stringify(errPayload));
        }
        return true;
      }
    }
  }

  return false;
}

// -----------------------------------------------------------------------------
// SECURE CLOUD DATABASE (FIREBASE RTDB) ACCESS & SECRETS VAULT (ASVS L3 & F-01)
// -----------------------------------------------------------------------------

// Sanitizes and redacts secrets from URLs, messages, and error stacks (ASVS 7.1.1 & CWE-532)
export function redactSecretUrl(text) {
  if (typeof text !== "string") return "";
  let clean = text;
  const secret = (process.env.FIREBASE_DB_SECRET || process.env.FIREBASE_AUTH_TOKEN || "").trim();
  if (secret && secret.length >= 4) {
    clean = clean.split(secret).join("[REDACTED_SECRET]");
  }
  // Mask any ?auth=... or &auth=... in query strings
  clean = clean.replace(/([?&]auth=)[^&\s"'`#]+/gi, "$1[REDACTED]");
  return clean;
}

// Whitelist of valid, safe Firebase RTDB query parameters
const ALLOWED_FIREBASE_PARAMS = new Set([
  "auth",
  "shallow",
  "orderBy",
  "equalTo",
  "startAt",
  "endAt",
  "limitToFirst",
  "limitToLast",
  "t",
  "format",
  "print",
  "download"
]);

// Fail-Closed & SSRF-Hardened Firebase RTDB URL Constructor (ASVS 2.10.3, 12.6.1 & RFC 8725)
export function getFirebaseUrl(path = "", queryParams = {}) {
  // 1. Strict Fail-Closed Check on Database Configuration (Zero-Tolerance SQLite Fallback on Vercel)
  const isVercel = process.env.VERCEL === "1" || Boolean(process.env.VERCEL);
  const rawEnvUrl = (process.env.FIREBASE_DB_URL || "").trim();
  const secret = (process.env.FIREBASE_DB_SECRET || process.env.FIREBASE_AUTH_TOKEN || "").trim();

  if (!rawEnvUrl) {
    throw new Error(
      isVercel
        ? "Fail-Closed Critical: FIREBASE_DB_URL is missing in Vercel environment. Silent fallback to local SQLite is strictly prohibited on serverless to prevent order data loss."
        : "Cryptographic Fail-Closed: FIREBASE_DB_URL is not configured."
    );
  }
  if (!secret) {
    throw new Error(
      isVercel
        ? "Fail-Closed Critical: FIREBASE_DB_SECRET is missing in Vercel environment. Silent fallback to local SQLite is strictly prohibited on serverless to prevent order data loss."
        : "Cryptographic Fail-Closed: FIREBASE_DB_SECRET is missing or empty."
    );
  }

  // 2. Strict Protocol & Official Firebase Domain Validation
  let parsedBase;
  try {
    parsedBase = new URL(rawEnvUrl);
  } catch {
    throw new Error("Cryptographic Fail-Closed: FIREBASE_DB_URL is malformed.");
  }

  if (parsedBase.protocol !== "https:") {
    throw new Error("Cryptographic Fail-Closed: FIREBASE_DB_URL must strictly use HTTPS protocol.");
  }

  const hostname = parsedBase.hostname.toLowerCase();
  const isFirebaseHost =
    /^[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)*\.(firebaseio\.com|firebasedatabase\.app)$/.test(hostname);
  if (!isFirebaseHost) {
    throw new Error("Cryptographic Fail-Closed: FIREBASE_DB_URL must point to an official Firebase domain.");
  }

  // 3. SSRF & Path Traversal Validation on path argument
  if (typeof path !== "string") {
    throw new Error("Security Alert: Firebase path must be a string.");
  }

  const rawPath = path.trim();

  // Block dangerous SSRF and Traversal patterns
  if (
    rawPath.includes("://") ||
    rawPath.startsWith("//") ||
    rawPath.startsWith("/\\") ||
    rawPath.startsWith("\\") ||
    rawPath.includes("@") ||
    rawPath.includes("#") ||
    rawPath.includes("\\") ||
    /[\x00-\x1F\x7F]/.test(rawPath) ||
    /%2[eE]|%00/i.test(rawPath) ||
    /(^|\/)\.\.(\/|$)/.test(rawPath)
  ) {
    throw new Error("Security Alert: Malicious or illegal path supplied to Firebase URL builder.");
  }

  // Parse path and separate any inline query parameters safely
  let pathOnly = rawPath;
  let inlineQuery = "";
  const qIdx = rawPath.indexOf("?");
  if (qIdx !== -1) {
    pathOnly = rawPath.slice(0, qIdx);
    inlineQuery = rawPath.slice(qIdx + 1);
  }

  const cleanPath = pathOnly ? (pathOnly.startsWith("/") ? pathOnly : `/${pathOnly}`) : "/";
  const targetUrl = new URL(cleanPath, parsedBase.origin);

  // Defense-in-Depth: Enforce exact origin match
  if (targetUrl.origin !== parsedBase.origin) {
    throw new Error("Security Alert: Target origin mismatch detected in Firebase URL builder.");
  }

  // 4. Set Protected Server Secret Auth Parameter
  targetUrl.searchParams.set("auth", secret);

  // 5. Whitelist and sanitize inline query params
  if (inlineQuery) {
    const inlineParams = new URLSearchParams(inlineQuery);
    for (const [key, value] of inlineParams.entries()) {
      if (key !== "auth" && ALLOWED_FIREBASE_PARAMS.has(key)) {
        targetUrl.searchParams.set(key, value);
      }
    }
  }

  // 6. Whitelist and sanitize queryParams argument
  if (queryParams && typeof queryParams === "object" && !Array.isArray(queryParams)) {
    for (const [key, value] of Object.entries(queryParams)) {
      if (
        key !== "auth" &&
        key !== "__proto__" &&
        key !== "constructor" &&
        key !== "prototype" &&
        ALLOWED_FIREBASE_PARAMS.has(key) &&
        value !== undefined &&
        value !== null
      ) {
        targetUrl.searchParams.set(key, String(value));
      }
    }
  }

  return targetUrl.toString();
}

// Centralized Secure Firebase HTTP Client with Timeout, Redirect Protection & Secret Redaction
export async function firebaseFetch(path = "", options = {}, queryParams = {}) {
  const url = getFirebaseUrl(path, queryParams);
  const controller = new AbortController();
  const timeoutMs = typeof options.timeoutMs === "number" ? options.timeoutMs : 5000;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  const fetchOptions = {
    ...options,
    redirect: "error", // Strictly block redirects (Prevents credential leakage)
    signal: options.signal || controller.signal,
    headers: {
      "Accept": "application/json",
      ...(options.headers || {})
    }
  };
  delete fetchOptions.timeoutMs;

  try {
    const res = await fetch(url, fetchOptions);
    return res;
  } catch (err) {
    const safeErrorMsg = redactSecretUrl(err?.message || "Firebase Network Request Failed");
    const sanitizedError = new Error(safeErrorMsg);
    if (err?.name) sanitizedError.name = err.name;
    throw sanitizedError;
  } finally {
    clearTimeout(timeoutId);
  }
}

// Atomic Compare-And-Swap (CAS) via Firebase RTDB ETag Header (Concurrency & Race Condition Mitigation)
export async function firebaseCas(path, updateFn, maxRetries = 3) {
  let attempt = 0;
  while (attempt < maxRetries) {
    attempt++;
    const fetchRes = await firebaseFetch(path, {
      cache: "no-store",
      headers: {
        "Accept": "application/json",
        "X-Firebase-ETag": "true"
      }
    }, { t: Date.now() });

    if (!fetchRes.ok) {
      if (fetchRes.status === 404) {
        await fetchRes.body?.cancel?.().catch(() => {});
        const updated = await updateFn(null);
        if (updated === undefined || updated === false) return { success: false, reason: "aborted" };
        const putRes = await firebaseFetch(path, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(updated)
        });
        if (putRes.ok) {
          await putRes.body?.cancel?.().catch(() => {});
          return { success: true, data: updated };
        }
        await putRes.body?.cancel?.().catch(() => {});
        return { success: false, reason: "put_failed", status: putRes.status };
      }
      await fetchRes.body?.cancel?.().catch(() => {});
      return { success: false, reason: "fetch_failed", status: fetchRes.status };
    }

    let currentData;
    try {
      currentData = await fetchRes.json();
    } catch {
      await fetchRes.body?.cancel?.().catch(() => {});
      return { success: false, reason: "invalid_json", status: fetchRes.status };
    }
    const etag = fetchRes.headers.get("etag") || fetchRes.headers.get("ETag");

    const updatedData = await updateFn(currentData);
    if (updatedData === undefined || updatedData === false) {
      return { success: false, reason: "aborted", data: currentData };
    }

    const putHeaders = { "Content-Type": "application/json" };
    if (etag) {
      putHeaders["If-Match"] = etag;
    }

    const putRes = await firebaseFetch(path, {
      method: "PUT",
      cache: "no-store",
      headers: putHeaders,
      body: JSON.stringify(updatedData)
    });

    if (putRes.ok) {
      await putRes.body?.cancel?.().catch(() => {});
      return { success: true, data: updatedData };
    }

    if (putRes.status === 412) {
      await putRes.body?.cancel?.().catch(() => {});
      // Precondition Failed (CAS conflict) - Wait jittered backoff and retry
      await new Promise(r => setTimeout(r, 40 + Math.random() * 50));
      continue;
    }

    await putRes.body?.cancel?.().catch(() => {});
    return { success: false, reason: "cas_put_failed", status: putRes.status };
  }
  return { success: false, reason: "max_retries_exceeded" };
}

// -----------------------------------------------------------------------------
// INPUT VALIDATION, NOSQL DEFENSE & SAFE PATH BUILDER (ASVS L3, CWE-22, CWE-943, CWE-915)
// -----------------------------------------------------------------------------

// Forbidden reserved keywords and sensitive collection nodes
const RESERVED_PATH_NAMES = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "tostring",
  "valueof",
  "_server_vault",
  "backups",
  "auth_2fa_otp",
  "rate_limits",
  "undefined",
  "null",
  "nan",
  "true",
  "false",
  "root"
]);

// Allowed primary Firebase RTDB collections
const ALLOWED_RTDB_COLLECTIONS = new Set([
  "orders",
  "products",
  "customers",
  "reviews",
  "categories",
  "coupons",
  "settings",
  "sync_meta",
  "backups",
  "_server_vault"
]);

// Strict Path Identifier Allowlist (Strict string type, rejects traversal, control chars, reserved names)
export function sanitizePathId(id) {
  if (typeof id !== "string") return null;
  const clean = id.trim();
  // Strictly enforce safe identifier format (alphanumeric, underscores, hyphens, 1-64 chars)
  if (!/^[a-zA-Z0-9_\-]{1,64}$/.test(clean)) {
    return null;
  }
  // Reject reserved names, prototype pollution keys & internal vault collections
  if (RESERVED_PATH_NAMES.has(clean.toLowerCase())) {
    return null;
  }
  return clean;
}

// Canonical RTDB Path Constructor (Guarantees .json suffix, prevents empty-ID collection wipe)
export function buildSafeRtdbPath(collection, id) {
  if (typeof collection !== "string" || !ALLOWED_RTDB_COLLECTIONS.has(collection.trim())) {
    throw new Error(`Security Alert: Invalid or unauthorized RTDB collection '${collection}'`);
  }
  const cleanCollection = collection.trim();

  // If only 1 argument was passed (e.g. buildSafeRtdbPath("orders")), return collection root
  if (arguments.length === 1) {
    return `${cleanCollection}.json`;
  }

  // If 2 arguments were passed, single-item ID is REQUIRED and must be a valid non-empty string
  if (typeof id !== "string" || !id.trim()) {
    throw new Error(`Security Alert: Empty, null, or undefined identifier supplied for collection '${cleanCollection}'.`);
  }

  // Handle nested sub-collections inside backups or _server_vault (e.g. _server_vault/otp_challenges/ID)
  if (cleanCollection === "_server_vault" || cleanCollection === "backups") {
    const parts = id.trim().split("/");
    if (parts.length === 1) {
      const safeId = sanitizePathId(parts[0]);
      if (!safeId) throw new Error(`Security Alert: Illegal identifier '${parts[0]}' in '${cleanCollection}'.`);
      return `${cleanCollection}/${safeId}.json`;
    } else if (parts.length === 2) {
      const safeSub = sanitizePathId(parts[0]);
      const safeSubId = sanitizePathId(parts[1]);
      if (!safeSub || !safeSubId) {
        throw new Error(`Security Alert: Illegal sub-path in '${cleanCollection}'.`);
      }
      return `${cleanCollection}/${safeSub}/${safeSubId}.json`;
    } else {
      throw new Error(`Security Alert: Excessive path depth in '${cleanCollection}'.`);
    }
  }

  const safeId = sanitizePathId(id);
  if (!safeId) {
    throw new Error(`Security Alert: Illegal item identifier '${id}' in collection '${cleanCollection}'.`);
  }

  return `${cleanCollection}/${safeId}.json`;
}

// Recursive Payload Validator & Mass Assignment Defense (ASVS 5.1.4, CWE-915 & CWE-943)
export function assertSafeRtdbPayload(obj, { allowedKeys = null, maxDepth = 6, allowNull = false } = {}) {
  if (obj === null || obj === undefined) {
    if (!allowNull) throw new Error("Security Alert: Null or undefined payload is not permitted.");
    return null;
  }
  if (typeof obj !== "object") {
    return obj; // Primitive value
  }

  function validateRecursive(current, depth) {
    if (depth > maxDepth) {
      throw new Error(`Security Alert: Maximum payload nesting depth exceeded (${maxDepth}).`);
    }
    if (current === null) {
      if (!allowNull) throw new Error("Security Alert: Null value detected in payload (prevents silent deletion).");
      return;
    }
    if (typeof current !== "object") {
      return;
    }

    if (Array.isArray(current)) {
      for (const item of current) {
        validateRecursive(item, depth + 1);
      }
      return;
    }

    const keys = Object.keys(current);
    for (const key of keys) {
      // 1. Prototype pollution defense
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        throw new Error(`Security Alert: Prototype pollution key '${key}' detected.`);
      }

      // 2. Reject Firebase RTDB special keys (.sv, .priority, .value, etc.)
      if (key.startsWith(".")) {
        throw new Error(`Security Alert: Prohibited Firebase RTDB special key '${key}'.`);
      }

      // 3. Multi-location update & traversal prevention (keys with /, \, .., ., $, #, [, ])
      if (/[.\#\$\[\]\/\\%]/.test(key) || key.includes("..")) {
        throw new Error(`Security Alert: Path traversal or multi-location update delimiter detected in key '${key}'.`);
      }

      // 4. Top-level whitelist enforcement if allowedKeys is defined
      if (depth === 1 && allowedKeys && !allowedKeys.includes(key)) {
        throw new Error(`Security Alert: Unauthorized field '${key}' in payload.`);
      }

      const val = current[key];
      // 5. ServerValue injection check on nested object values
      if (val && typeof val === "object" && !Array.isArray(val)) {
        if (Object.keys(val).some(k => k.startsWith("."))) {
          throw new Error(`Security Alert: Firebase ServerValue injection detected inside '${key}'.`);
        }
      }

      validateRecursive(val, depth + 1);
    }
  }

  validateRecursive(obj, 1);
  return obj;
}

// -----------------------------------------------------------------------------
// SECURE IMAGE & MEDIA URL VALIDATOR & SSRF DEFENSE (OWASP API7:2023 & CWE-918)
// -----------------------------------------------------------------------------
function isPrivateIpv4Octets(b1, b2, b3, b4) {
  if (b1 === 127) return true; // Loopback
  if (b1 === 0) return true;   // Current network
  if (b1 === 10) return true;  // Private Class A
  if (b1 === 172 && b2 >= 16 && b2 <= 31) return true; // Private Class B
  if (b1 === 192 && b2 === 168) return true; // Private Class C
  if (b1 === 169 && b2 === 254) return true; // Link-Local & Cloud Metadata (169.254.169.254)
  if (b1 === 100 && b2 >= 64 && b2 <= 127) return true; // Carrier-Grade NAT
  if (b1 === 192 && b2 === 0 && b3 === 0) return true; // IETF Protocol Assignments
  if (b1 === 192 && b2 === 0 && b3 === 2) return true; // TEST-NET-1
  if (b1 === 198 && b2 === 51 && b3 === 100) return true; // TEST-NET-2
  if (b1 === 203 && b2 === 0 && b3 === 113) return true; // TEST-NET-3
  if (b1 >= 224 && b1 <= 239) return true; // Multicast
  if (b1 >= 240) return true; // Reserved / Future Use
  return false;
}

function isPrivateOrReservedHostIp(hostStr) {
  const clean = hostStr.trim().toLowerCase();

  // Decimal, octal, hex 32-bit single integer representation (e.g. 2130706433 = 127.0.0.1)
  if (/^(0x[0-9a-f]+|\d+)$/i.test(clean)) {
    const num = clean.startsWith("0x") ? parseInt(clean, 16) : parseInt(clean, 10);
    if (!isNaN(num) && num >= 0 && num <= 0xFFFFFFFF) {
      const b1 = (num >>> 24) & 0xff;
      const b2 = (num >>> 16) & 0xff;
      const b3 = (num >>> 8) & 0xff;
      const b4 = num & 0xff;
      return isPrivateIpv4Octets(b1, b2, b3, b4);
    }
  }

  // Dotted decimal/octal/hex IP representation (e.g. 127.0.0.1, 0177.0.0.1, 0x7f.0.0.1, 127.1)
  const parts = clean.split(".");
  if (parts.length >= 2 && parts.length <= 4) {
    const octets = [];
    for (const part of parts) {
      if (/^0x[0-9a-f]+$/i.test(part)) {
        octets.push(parseInt(part, 16));
      } else if (/^0[0-7]+$/.test(part)) {
        octets.push(parseInt(part, 8));
      } else if (/^\d+$/.test(part)) {
        octets.push(parseInt(part, 10));
      } else {
        return false;
      }
    }
    if (octets.some(o => isNaN(o) || o < 0)) return false;

    let b1 = 0, b2 = 0, b3 = 0, b4 = 0;
    if (octets.length === 4) {
      if (octets.some(o => o > 255)) return true; // Malformed / overflow octet
      [b1, b2, b3, b4] = octets;
    } else if (octets.length === 2) {
      b1 = octets[0];
      const rest = octets[1];
      b2 = (rest >>> 16) & 0xff;
      b3 = (rest >>> 8) & 0xff;
      b4 = rest & 0xff;
    } else if (octets.length === 3) {
      b1 = octets[0];
      b2 = octets[1];
      const rest = octets[2];
      b3 = (rest >>> 8) & 0xff;
      b4 = rest & 0xff;
    }
    return isPrivateIpv4Octets(b1, b2, b3, b4);
  }

  // IPv6 checks
  let v6Clean = clean;
  if (v6Clean.startsWith("[") && v6Clean.endsWith("]")) {
    v6Clean = v6Clean.slice(1, -1);
  }
  if (v6Clean.includes(":") || v6Clean === "localhost") {
    if (v6Clean === "::1" || v6Clean === "::" || v6Clean === "0:0:0:0:0:0:0:1" || v6Clean === "0:0:0:0:0:0:0:0") return true;
    if (v6Clean.startsWith("fc") || v6Clean.startsWith("fd")) return true; // Unique local (fc00::/7)
    if (/^fe[89ab]/i.test(v6Clean)) return true; // Link-local (fe80::/10)
    if (v6Clean.includes("::ffff:")) {
      const v4Part = v6Clean.split("::ffff:")[1];
      if (v4Part && isPrivateOrReservedHostIp(v4Part)) return true;
      return true; // Any IPv4-mapped IPv6 is prohibited for external image URLs
    }
  }

  return false;
}

// Strict Binary Magic Bytes & MIME Validator for Base64 Data URI Image Uploads
// Mitigates: File Upload Abuse, MIME Spoofing, Stored XSS via SVG/HTML, Large Payload DoS (CWE-434, CWE-79, CWE-400)
export function validateImageDataUri(dataUri, maxBytes = 5 * 1024 * 1024) {
  if (typeof dataUri !== "string" || !dataUri.startsWith("data:")) {
    return { valid: false, error: "صيغة بيانات الصورة غير صالحة." };
  }

  // Max length check: 5MB binary is ~6.7MB base64
  const maxBase64Len = Math.ceil((maxBytes * 4) / 3) + 128;
  if (dataUri.length > maxBase64Len) {
    return { valid: false, error: `حجم الصورة المشفرة يتجاوز الحد الأقصى المسموح به (${Math.round(maxBytes / (1024 * 1024))} ميجابايت).` };
  }

  // Ban SVG data URIs to prevent Stored XSS via script execution or XML entities
  if (dataUri.toLowerCase().includes("image/svg") || dataUri.toLowerCase().includes("svg+xml")) {
    return { valid: false, error: "تحميل صور SVG عبر data URI محظور أمنياً لمنع هجمات حقن الشيفرات (Stored XSS)." };
  }

  // Strictly allow only safe raster image mime types: jpeg, png, webp, avif
  const match = dataUri.match(/^data:(image\/(jpeg|jpg|png|webp|avif));base64,([A-Za-z0-9+/=]+)$/);
  if (!match) {
    return { valid: false, error: "نوع وسائط الصورة غير مدعوم أو غير صالح (يسمح فقط بـ JPEG, PNG, WEBP, AVIF)." };
  }

  const declaredMime = match[1].toLowerCase();
  const base64Data = match[3];

  // Decode first 48 base64 characters (~36 bytes) to inspect Magic Bytes
  let headerBuffer;
  try {
    const chunkToDecode = base64Data.slice(0, 48);
    headerBuffer = Buffer.from(chunkToDecode, "base64");
  } catch (e) {
    return { valid: false, error: "فشل فك تشفير بيانات الصورة Base64." };
  }

  if (headerBuffer.length < 8) {
    return { valid: false, error: "ملف الصورة تالف أو قصير جداً." };
  }

  // Magic Bytes Detection:
  // PNG: 89 50 4E 47 0D 0A 1A 0A
  const isPng = headerBuffer[0] === 0x89 && headerBuffer[1] === 0x50 && headerBuffer[2] === 0x4e && headerBuffer[3] === 0x47;
  // JPEG: FF D8 FF
  const isJpeg = headerBuffer[0] === 0xff && headerBuffer[1] === 0xd8 && headerBuffer[2] === 0xff;
  // WebP: RIFF (bytes 0-3) and WEBP (bytes 8-11)
  const isWebp = headerBuffer.length >= 12 &&
                 headerBuffer.toString("ascii", 0, 4) === "RIFF" &&
                 headerBuffer.toString("ascii", 8, 12) === "WEBP";
  // AVIF: ftypavif or ftypavis
  const isAvif = headerBuffer.length >= 12 &&
                 headerBuffer.toString("ascii", 4, 12).includes("avif");

  let detectedMime = null;
  if (isPng) detectedMime = "image/png";
  else if (isJpeg) detectedMime = "image/jpeg";
  else if (isWebp) detectedMime = "image/webp";
  else if (isAvif) detectedMime = "image/avif";

  if (!detectedMime) {
    return { valid: false, error: "التوقيع الثنائي للملف (Magic Bytes) لا يتطابق مع أي صيغة صور معتمدة (فشل التحقق الأمني من المحتوى الحقيقي للملف)." };
  }

  const normalizedDeclared = declaredMime === "image/jpg" ? "image/jpeg" : declaredMime;
  if (detectedMime !== normalizedDeclared) {
    return { valid: false, error: `تزييف نوع الملف (MIME Spoofing): النوع المعلن هو '${declaredMime}' بينما المحتوى الحقيقي هو '${detectedMime}'.` };
  }

  return { valid: true, sanitizedUrl: dataUri };
}

export function validateSafeImageUrl(urlStr) {
  if (typeof urlStr !== "string") {
    return { valid: false, error: "رابط الصورة يجب أن يكون نصاً صالحاً." };
  }

  // Control characters prevention (CWE-150 / Null Byte & Whitespace Injection)
  if (/[\x00-\x1F\x7F]/.test(urlStr)) {
    return { valid: false, error: "رابط الصورة يحتوي على أحرف تحكم غير مسموح بها." };
  }

  const trimmed = urlStr.trim();
  if (!trimmed) {
    return { valid: false, error: "رابط الصورة لا يمكن أن يكون فارغاً." };
  }

  // Case 0: Data URI Upload with strict binary Magic Bytes inspection
  if (trimmed.startsWith("data:")) {
    return validateImageDataUri(trimmed);
  }

  if (trimmed.length > 2048) {
    return { valid: false, error: "طول رابط الصورة يتجاوز الحد المسموح به (2048 حرفاً)." };
  }

  // Case 1: Local site assets (e.g. /assets/images/chandelier1.webp)
  if (trimmed.startsWith("/")) {
    if (trimmed.startsWith("//")) {
      return { valid: false, error: "الروابط النسبية للبروتوكول (//) محظورة لمنع هجمات التوجيه المفتوح وحقن النطاقات." };
    }
    if (
      trimmed.includes("..") ||
      trimmed.includes("\\") ||
      /%2e/i.test(trimmed) ||
      /%2f/i.test(trimmed) ||
      trimmed.includes("?") ||
      trimmed.includes("#")
    ) {
      return { valid: false, error: "مسار الصورة المحلي يحتوي على أحرف غير آمنة أو محاولات تخطي مسار." };
    }
    const validExts = [".jpg", ".jpeg", ".png", ".webp", ".avif", ".svg"];
    const lowerPath = trimmed.toLowerCase();
    const hasValidExt = validExts.some(ext => lowerPath.endsWith(ext));
    if (!hasValidExt) {
      return { valid: false, error: "امتداد الصورة المحلي غير معتمد (يجب أن ينتهي بـ .jpg, .png, .webp, .avif, .svg)." };
    }
    return { valid: true, sanitizedUrl: trimmed };
  }

  // Case 2: Absolute URL (Must strictly be HTTPS)
  let parsed = null;
  try {
    parsed = new URL(trimmed);
  } catch (e) {
    return { valid: false, error: "صيغة رابط الصورة غير صالحة." };
  }

  if (parsed.protocol !== "https:") {
    return { valid: false, error: `البروتوكول '${parsed.protocol}' غير مسموح به. يجب أن يبدأ الرابط حصراً بـ https://` };
  }

  if (parsed.username || parsed.password) {
    return { valid: false, error: "تضمين بيانات الاعتماد (اسم المستخدم أو كلمة المرور) في رابط الصورة محظور تماماً." };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return { valid: false, error: "نطاق الرابط غير صالح." };
  }

  // SSRF Protection: Loopback, Link-Local, Metadata, and Internal TLDs
  if (
    hostname === "localhost" ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".lan") ||
    hostname.endsWith(".home")
  ) {
    return { valid: false, error: "استهداف النطاقات الداخلية والمحلية (SSRF) محظور أمنياً." };
  }

  if (isPrivateOrReservedHostIp(hostname)) {
    return { valid: false, error: "استهداف عناوين IP المحجوزة أو الخاصة أو بيانات السحابة (SSRF) محظور." };
  }

  // Optional Whitelist Enforcment via ALLOWED_IMAGE_HOSTS
  const allowedHostsEnv = process.env.ALLOWED_IMAGE_HOSTS;
  if (allowedHostsEnv && typeof allowedHostsEnv === "string" && allowedHostsEnv.trim()) {
    const allowedList = allowedHostsEnv.split(",").map(h => h.trim().toLowerCase()).filter(Boolean);
    if (allowedList.length > 0) {
      const isAllowed = allowedList.some(allowed => hostname === allowed || hostname.endsWith("." + allowed));
      if (!isAllowed) {
        return { valid: false, error: `استضافة الصور على النطاق '${hostname}' غير مصرح بها وفق سياسة الأمان المعتمدة.` };
      }
    }
  }

  return { valid: true, sanitizedUrl: parsed.href };
}

// Centralized Safe RTDB Request Helper
export async function rtdbRequest(method, collection, id = null, options = {}) {
  const upperMethod = (method || "GET").toUpperCase();
  if (!["GET", "PUT", "PATCH", "DELETE"].includes(upperMethod)) {
    throw new Error(`Security Alert: Unsupported HTTP method '${upperMethod}' for RTDB.`);
  }

  // Prevent catastrophic accidental empty-ID wipe
  if ((upperMethod === "DELETE" || upperMethod === "PUT") && (id === null || id === undefined)) {
    if (!options.allowBulk) {
      throw new Error(`Security Alert: Bulk ${upperMethod} on root collection '${collection}' is strictly prohibited without allowBulk.`);
    }
  }

  const safePath = buildSafeRtdbPath(collection, id);

  const fetchOptions = {
    method: upperMethod,
    cache: "no-store",
    headers: { ...(options.headers || {}) }
  };

  if (options.timeoutMs) {
    fetchOptions.timeoutMs = options.timeoutMs;
  }

  if (options.body !== undefined) {
    assertSafeRtdbPayload(options.body, {
      allowedKeys: options.allowedKeys || null,
      maxDepth: options.maxDepth || 6,
      allowNull: options.allowNull || false
    });
    fetchOptions.headers["Content-Type"] = "application/json";
    fetchOptions.body = JSON.stringify(options.body);
  }

  const queryParams = options.queryParams || {};
  const res = await firebaseFetch(safePath, fetchOptions, queryParams);
  return res;
}

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// DISTRIBUTED SERVERLESS RATE LIMITER (RE-EXPORTED FROM DEDICATED ENGINE)
// -----------------------------------------------------------------------------
export {
  getClientIp,
  normalizeIpForRateLimit,
  getRateLimitKey,
  checkRateLimitDistributed,
  recordFailedAttemptDistributed,
  resetRateLimitDistributed,
  checkDualLayerRateLimit
} from "./_ratelimit.js";

import {
  normalizeIpForRateLimit,
  checkRateLimitDistributed,
  recordFailedAttemptDistributed,
  resetRateLimitDistributed
} from "./_ratelimit.js";

// Backward-compatible wrappers for existing code
export async function checkDistributedRateLimit(clientIp, action = "login", maxAttempts = 5, windowMs = 15 * 60 * 1000, options = {}) {
  const normalized = normalizeIpForRateLimit(clientIp);
  return checkRateLimitDistributed(action, normalized, maxAttempts, windowMs, options);
}

export async function recordFailedRateLimitAttempt(clientIp, action = "login", maxAttempts = 5, windowMs = 15 * 60 * 1000) {
  const normalized = normalizeIpForRateLimit(clientIp);
  return recordFailedAttemptDistributed(action, normalized, maxAttempts, windowMs);
}

export async function resetDistributedRateLimit(clientIp, action = "login") {
  const normalized = normalizeIpForRateLimit(clientIp);
  return resetRateLimitDistributed(action, normalized);
}

// -----------------------------------------------------------------------------
// SECURE JWT ENGINE & TOKEN EXTRACTION (RFC 7519, RFC 8725 & ASVS LEVEL 3)
// -----------------------------------------------------------------------------
export function extractCookie(cookieHeader, cookieName) {
  if (!cookieHeader || typeof cookieHeader !== "string") return null;
  const items = cookieHeader.split(";");
  for (const item of items) {
    const eqIdx = item.indexOf("=");
    if (eqIdx !== -1) {
      const name = item.slice(0, eqIdx).trim();
      const val = item.slice(eqIdx + 1).trim();
      if (name === cookieName && val) {
        return val;
      }
    }
  }
  return null;
}

export function extractBearerToken(authHeader) {
  if (!authHeader || typeof authHeader !== "string") return null;
  const clean = authHeader.trim();
  const match = clean.match(/^Bearer\s+([A-Za-z0-9\-_.]+)$/i);
  return match && match[1] ? match[1].trim() : null;
}

// -----------------------------------------------------------------------------
// TOKEN REVOCATION & BLACKLIST VAULT (RFC 7009 / ASVS 3.3.1 & 3.5.3)
// -----------------------------------------------------------------------------
const inMemoryRevokedTokens = new Map();

export function isTokenRevoked(jti) {
  if (!jti || typeof jti !== "string") return false;
  const safeJti = sanitizePathId(jti);
  if (!safeJti) return false;
  const expiresAt = inMemoryRevokedTokens.get(safeJti);
  if (!expiresAt) return false;
  if (Date.now() > expiresAt) {
    inMemoryRevokedTokens.delete(safeJti);
    return false;
  }
  return true;
}

export async function isTokenRevokedAsync(jti) {
  if (!jti || typeof jti !== "string") return false;
  const safeJti = sanitizePathId(jti);
  if (!safeJti) return false;
  if (isTokenRevoked(safeJti)) return true;
  try {
    const res = await firebaseFetch(`_server_vault/revoked_tokens/${safeJti}.json`, { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      if (data && data.exp && Date.now() < Number(data.exp)) {
        inMemoryRevokedTokens.set(safeJti, Number(data.exp));
        return true;
      }
    }
  } catch (e) {}
  return false;
}

export async function revokeToken(rawTokenOrPayload) {
  if (!rawTokenOrPayload) return false;
  let jti = null;
  let exp = Date.now() + 24 * 60 * 60 * 1000;

  if (typeof rawTokenOrPayload === "string") {
    const clean = rawTokenOrPayload.trim();
    const parts = clean.split(".");
    if (parts.length === 3) {
      try {
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf-8"));
        if (payload && payload.jti) {
          jti = payload.jti;
          if (payload.exp) {
            exp = payload.exp > 1e11 ? payload.exp : payload.exp * 1000;
          }
        }
      } catch {}
    }
  } else if (typeof rawTokenOrPayload === "object" && rawTokenOrPayload.jti) {
    jti = rawTokenOrPayload.jti;
    if (rawTokenOrPayload.exp) {
      exp = rawTokenOrPayload.exp > 1e11 ? rawTokenOrPayload.exp : rawTokenOrPayload.exp * 1000;
    }
  }

  if (jti) {
    const safeJti = sanitizePathId(jti);
    if (safeJti) {
      inMemoryRevokedTokens.set(safeJti, exp);
      try {
        await firebaseFetch(`_server_vault/revoked_tokens/${safeJti}.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ jti: safeJti, exp, revokedAt: Date.now() })
        });
      } catch (e) {}
      return true;
    }
  }
  return false;
}

// Low-level Strict JWT Signer
export function signJwt({ payload = {}, key, role, aud, maxTtlSec }) {
  if (!key || !Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error("Cryptographic Fail-Closed: Invalid or missing 32-byte signing key (ADMIN_JWT_SECRET unconfigured or < 32 chars).");
  }

  const nowMs = Date.now();

  let expMs = nowMs + maxTtlSec * 1000;
  if (typeof payload.expiresInMs === "number" && payload.expiresInMs > 0) {
    expMs = nowMs + Math.min(payload.expiresInMs, maxTtlSec * 1000);
  }

  const jti = crypto.randomUUID();

  // Whitelist safe custom payload fields (Prevent prototype pollution & claim overwriting)
  const safePayload = {};
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    for (const [k, v] of Object.entries(payload)) {
      if (
        !["role", "iss", "aud", "iat", "exp", "nbf", "jti", "expiresInMs"].includes(k) &&
        !["__proto__", "constructor", "prototype"].includes(k)
      ) {
        safePayload[k] = v;
      }
    }
  }

  // Enforced security attributes MUST supersede any custom fields
  const finalPayload = {
    ...safePayload,
    role,
    iss: "kased-karim-api",
    aud,
    jti,
    iat: nowMs,
    exp: expMs
  };

  const headerObj = { alg: "HS256", typ: "JWT" };
  const encodedHeader = Buffer.from(JSON.stringify(headerObj), "utf-8").toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(finalPayload), "utf-8").toString("base64url");

  const signature = crypto
    .createHmac("sha256", key)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("base64url");

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

// Low-level Strict JWT Verifier
export function verifyJwt({ token, key, keys, expectedRole, expectedAud, maxTtlSec }) {
  // 1. Structural & DoS Validation (CWE-400)
  if (!token || typeof token !== "string") return null;
  const cleanToken = token.trim();
  if (cleanToken.length < 20 || cleanToken.length > 2048) return null;

  const parts = cleanToken.split(".");
  if (parts.length !== 3) return null;
  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  // Strict Base64URL character checks
  if (
    !/^[A-Za-z0-9\-_]+$/.test(encodedHeader) ||
    !/^[A-Za-z0-9\-_]+$/.test(encodedPayload) ||
    !/^[A-Za-z0-9\-_]{43}$/.test(encodedSignature)
  ) {
    return null;
  }

  // 2. Secret Fail-Closed Check (RFC 8725 §3.2) with Key Rotation Support
  const candidateKeys = Array.isArray(keys) ? keys : (key ? [key] : []);
  const validKeys = candidateKeys.filter(k => Buffer.isBuffer(k) && k.length === 32);
  if (validKeys.length === 0) {
    return null;
  }

  // 3. Cryptographic Signature Verification (Verify BEFORE trusting payload)
  const sigBuf = Buffer.from(encodedSignature, "utf-8");
  let validSig = false;

  for (const k of validKeys) {
    const expectedSig = crypto
      .createHmac("sha256", k)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest("base64url");

    const expBuf = Buffer.from(expectedSig, "utf-8");
    if (sigBuf.length === 43 && expBuf.length === 43 && crypto.timingSafeEqual(sigBuf, expBuf)) {
      validSig = true;
      break;
    }
  }

  if (!validSig) {
    return null;
  }

  // 4. Safe JSON Parsing & Header Hardening with Prototype Pollution Defense (ASVS 5.1.4)
  let header = null;
  let payload = null;
  try {
    const reviver = (key, value) => {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        throw new Error("Prototype pollution key detected in JWT");
      }
      return value;
    };
    header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf-8"), reviver);
    payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf-8"), reviver);
  } catch (err) {
    return null;
  }

  // Check plain object & prototype pollution (ASVS 5.1.4)
  if (typeof header !== "object" || header === null || Array.isArray(header)) return null;
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return null;

  if (
    Object.hasOwn(header, "__proto__") || Object.hasOwn(header, "constructor") || Object.hasOwn(header, "prototype") ||
    Object.hasOwn(payload, "__proto__") || Object.hasOwn(payload, "constructor") || Object.hasOwn(payload, "prototype")
  ) {
    return null;
  }

  // Strict Algorithm Pinning & Header Checks (RFC 8725 §3.1)
  if (header.alg !== "HS256" || header.typ !== "JWT") return null;
  const DANGEROUS_HEADERS = ["crit", "jku", "jwk", "x5u", "x5c", "kid"];
  for (const dh of DANGEROUS_HEADERS) {
    if (Object.hasOwn(header, dh)) return null;
  }

  // 5. Mandatory Claims Verification (exp, iat, role, aud, iss)
  if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) return null;
  if (typeof payload.iat !== "number" || !Number.isFinite(payload.iat)) return null;

  const nowMs = Date.now();
  const nowSec = Math.floor(nowMs / 1000);

  // Normalize exp and iat (handle both ms and s gracefully)
  const expSec = payload.exp > 1e11 ? Math.floor(payload.exp / 1000) : payload.exp;
  const iatSec = payload.iat > 1e11 ? Math.floor(payload.iat / 1000) : payload.iat;

  // Enforce active expiration (RFC 7519 §4.1.4)
  if (expSec <= nowSec) {
    return null; // Expired
  }

  // Enforce sensible iat (allow 30s clock skew)
  if (iatSec > nowSec + 30) {
    return null; // Future iat
  }

  // Enforce Max-TTL ceiling upon verification (Prevents ancient 30-day tokens)
  if (expSec - iatSec > maxTtlSec + 30) {
    return null;
  }

  // Check optional nbf
  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== "number" || !Number.isFinite(payload.nbf)) return null;
    const nbfSec = payload.nbf > 1e11 ? Math.floor(payload.nbf / 1000) : payload.nbf;
    if (nbfSec > nowSec + 30) return null;
  }

  // Enforce Contextual Claims & Role Isolation
  if (payload.iss !== "kased-karim-api") return null;
  if (expectedRole && payload.role !== expectedRole) return null;
  if (expectedAud && payload.aud !== expectedAud) return null;

  // Active Token Revocation Check (RFC 7009 / ASVS 3.3.1)
  if (payload.jti && isTokenRevoked(payload.jti)) {
    return null;
  }

  return payload;
}

// -----------------------------------------------------------------------------
// ADMIN TOKEN ENGINE (SHORT-LIVED JWT + HTTPONLY COOKIE SUPPORT) (F-10)
// -----------------------------------------------------------------------------
export function signAdminToken(payload = {}, expiresInMs = 2 * 60 * 60 * 1000) {
  const key = getAdminSigningKey();
  return signJwt({ payload, key, role: "admin", aud: "admin", maxTtlSec: 7200 });
}

export function createAdminToken(payload = {}, expiresInMs = 2 * 60 * 60 * 1000) {
  return signAdminToken(payload, expiresInMs);
}

export function verifyAdminToken(token) {
  const keys = getAdminSigningKeys();
  const payload = verifyJwt({ token, keys, expectedRole: "admin", expectedAud: "admin", maxTtlSec: 7200 });
  if (!payload) return null;

  // Strict 2FA Enforcement Gate (NIST SP 800-63B / OWASP ASVS 2.8)
  // All privileged admin sessions MUST strictly have verified2FA: true
  if (payload.verified2FA !== true) {
    return null;
  }

  return payload;
}

// Backward-compatible legacy aliases
export const createToken = createAdminToken;
export const verifyToken = verifyAdminToken;

export function verifyAdminRequest(req) {
  if (!req || !req.headers) return null;

  // 1. Authorization Header (Bearer <token>)
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  const bearerToken = extractBearerToken(authHeader);
  if (bearerToken) {
    const verified = verifyAdminToken(bearerToken);
    if (verified) return verified;
  }

  // 2. HttpOnly Secure Cookie (Strict exact cookie match, zero prefix collisions)
  const cookieHeader = req.headers["cookie"];
  const cookieToken = extractCookie(cookieHeader, "kk_admin_token");
  if (cookieToken) {
    const verified = verifyAdminToken(cookieToken);
    if (verified) return verified;
  }

  // 3. Custom Admin Header
  const customHeader = req.headers["x-admin-token"];
  if (customHeader && typeof customHeader === "string") {
    const verified = verifyAdminToken(customHeader.trim());
    if (verified) return verified;
  }

  return null;
}

// Timing-safe constant-length digest comparison (Zero Timing Leak on input length)
export function timingSafeStringCompare(secretA, secretB) {
  if (typeof secretA !== "string" || typeof secretB !== "string") return false;
  const hashA = crypto.createHash("sha256").update(secretA).digest();
  const hashB = crypto.createHash("sha256").update(secretB).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

// Memory-Hard KDF & Constant-Time Admin Password Verification (ASVS 2.4.1 & NIST SP 800-63B)
export async function verifyAdminPassword(inputPassword) {
  if (!inputPassword || typeof inputPassword !== "string") return false;
  const cleanInput = inputPassword.normalize("NFKC").trim().slice(0, 128);

  // 1. Preferred Memory-Hard non-blocking scrypt Verification (OWASP ASVS Level 2/3)
  if (ADMIN_PASSWORD_HASH && ADMIN_PASSWORD_SALT) {
    try {
      const derived = await scryptAsync(cleanInput, ADMIN_PASSWORD_SALT, 64, {
        N: 16384,
        r: 8,
        p: 1,
        maxmem: 64 * 1024 * 1024
      });
      const derivedHex = derived.toString("hex");
      const a = Buffer.from(derivedHex, "hex");
      const b = Buffer.from(ADMIN_PASSWORD_HASH, "hex");
      if (a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b)) {
        return true;
      }
    } catch (e) {}
  }

  // 2. Strict Constant-Time SHA-256 Digest Verification (Zero Length Leakage)
  for (const allowed of ALLOWED_ADMIN_PASSWORDS) {
    if (typeof allowed === "string" && allowed.trim()) {
      if (timingSafeStringCompare(cleanInput, allowed.trim())) {
        return true;
      }
    }
  }
  return false;
}



// -----------------------------------------------------------------------------
// TWO-FACTOR AUTHENTICATION (2FA) & EMAIL OTP ENGINE (F-02, F-15, F-18, ASVS 2.8, NIST SP 800-63B)
// -----------------------------------------------------------------------------
// Admin emails read strictly from environment variable (Zero Hardcoded Personal Emails)
export const ADMIN_2FA_EMAILS = (process.env.ADMIN_2FA_EMAILS || process.env.ADMIN_2FA_EMAIL || "")
  .split(",")
  .map(e => e.trim().toLowerCase())
  .filter(e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e));

export const ADMIN_2FA_EMAIL = ADMIN_2FA_EMAILS[0] || "";

// Fail-Closed Validation of Required Server Configuration for Privileged Access
export function checkAdminAuthConfigured() {
  const hasPassword = Boolean(
    (process.env.ADMIN_PASSWORD && process.env.ADMIN_PASSWORD.trim().length >= 8) ||
    (ADMIN_PASSWORD_HASH && ADMIN_PASSWORD_SALT)
  );
  const hasJwtSecret = Boolean(
    (process.env.ADMIN_JWT_SECRET && process.env.ADMIN_JWT_SECRET.trim().length >= 32) ||
    (process.env.ADMIN_SECRET && process.env.ADMIN_SECRET.trim().length >= 32)
  );
  const has2FAEmail = ADMIN_2FA_EMAILS.length > 0;
  const hasDbSecret = Boolean(
    (process.env.FIREBASE_DB_SECRET && process.env.FIREBASE_DB_SECRET.trim().length > 0) ||
    (process.env.FIREBASE_AUTH_TOKEN && process.env.FIREBASE_AUTH_TOKEN.trim().length > 0)
  );

  return {
    configured: hasPassword && hasJwtSecret && has2FAEmail && hasDbSecret,
    missing: [
      !hasPassword && "ADMIN_PASSWORD / ADMIN_PASSWORD_HASH",
      !hasJwtSecret && "ADMIN_JWT_SECRET (>= 32 chars)",
      !has2FAEmail && "ADMIN_2FA_EMAILS",
      !hasDbSecret && "FIREBASE_DB_SECRET"
    ].filter(Boolean)
  };
}

// Mask email for public display or logs (e.g. k***@gmail.com) (F-15)
export function maskEmail(email) {
  if (!email || !email.includes("@")) return "a***@kasedkarim.com";
  const [user, domain] = email.split("@");
  const masked = user.length > 2 ? user[0] + "***" + user[user.length - 1] : user[0] + "***";
  return `${masked}@${domain}`;
}

// In-Memory Secure OTP & Challenge Cache per Serverless Instance
const inMemoryChallenges = new Map();
const inMemoryCooldown = new Map();

// Generate high-entropy 6-digit cryptographic PIN (Uniform distribution, zero modulo bias)
export function generate6DigitOTP() {
  return crypto.randomInt(100000, 1000000).toString();
}

// Keyed Salted HMAC-SHA256 with Domain Separation (NIST SP 800-63B / ASVS 2.8.4)
export function hashOTP(code, salt, challengeId = "") {
  const otpKey = crypto
    .createHmac("sha256", JWT_SECRET)
    .update("kased_karim_admin_otp_domain_v1")
    .digest();

  return crypto
    .createHmac("sha256", otpKey)
    .update(`admin-otp-v1:${code}:${salt}:${challengeId}`)
    .digest("hex");
}

// Burn and delete challenge from all layers (Fail-Safe Cleanup)
export async function burnChallenge(challengeId) {
  const safeId = sanitizePathId(challengeId);
  if (!safeId) return;
  inMemoryChallenges.delete(safeId);
  try {
    await firebaseFetch(`_server_vault/otp_challenges/${safeId}.json`, { method: "DELETE", cache: "no-store" });
  } catch (e) {}
}

async function burnChallengeWithEtag(safeId, etag) {
  inMemoryChallenges.delete(safeId);
  try {
    const headers = etag ? { "If-Match": etag } : {};
    await firebaseFetch(`_server_vault/otp_challenges/${safeId}.json`, { method: "DELETE", cache: "no-store", headers });
  } catch (e) {}
}

// Create Challenge-Bound 2FA OTP with IP Binding & 60-Second Cooldown (NIST SP 800-63B Compliant)
export async function create2FAChallenge(clientIp = null) {
  const now = Date.now();
  const cooldownKey = clientIp || "admin_global";
  const lastCreated = inMemoryCooldown.get(cooldownKey) || 0;
  const COOLDOWN_MS = 60 * 1000; // 60 seconds mandatory resend cooldown

  if (now - lastCreated < COOLDOWN_MS) {
    const remainingSec = Math.ceil((COOLDOWN_MS - (now - lastCreated)) / 1000);
    return { error: "cooldown", remainingSec };
  }

  const challengeId = crypto.randomBytes(32).toString("hex");
  const otpCode = generate6DigitOTP();
  const salt = crypto.randomBytes(16).toString("hex");
  const expiresAt = now + 5 * 60 * 1000; // 5 minutes TTL
  const codeHash = hashOTP(otpCode, salt, challengeId);

  const record = {
    challengeId,
    codeHash,
    salt,
    expiresAt,
    attempts: 0,
    createdAt: now,
    boundIp: clientIp || null
  };

  inMemoryCooldown.set(cooldownKey, now);
  inMemoryChallenges.set(challengeId, record);

  try {
    await firebaseFetch(`_server_vault/otp_challenges/${challengeId}.json`, {
      method: "PUT",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(record)
    });
  } catch (e) {
    console.warn("Server vault challenge persistence note:", redactSecretUrl(e.message));
  }

  return { challengeId, otpCode };
}

// Verify Challenge-Bound OTP with Atomic ETag Compare-And-Swap (TOCTOU & Concurrency Proof - CWE-362)
export async function verify2FAChallenge(challengeId, inputCode, clientIp = null) {
  if (typeof inputCode !== "string") {
    return { valid: false, error: "invalid_type" };
  }
  const cleanCode = inputCode.trim();
  if (!/^\d{6}$/.test(cleanCode)) {
    return { valid: false, error: "invalid_format" };
  }

  const safeId = sanitizePathId(challengeId);
  if (!safeId) {
    return { valid: false, error: "invalid_challenge" };
  }

  let record = null;
  let etag = null;

  // 1. Fetch challenge with X-Firebase-ETag for Atomic Optimistic Locking
  try {
    const res = await firebaseFetch(`_server_vault/otp_challenges/${safeId}.json`, {
      cache: "no-store",
      headers: {
        "Accept": "application/json",
        "X-Firebase-ETag": "true"
      }
    }, { t: Date.now() });
    if (res.ok) {
      record = await res.json();
      etag = res.headers.get("etag") || res.headers.get("ETag");
    }
  } catch (e) {}

  if (!record) {
    record = inMemoryChallenges.get(safeId);
  }

  // Strict Fail-Closed: Challenge must exist in vault and have valid properties
  if (!record || typeof record !== "object" || !record.codeHash || !record.salt || !record.expiresAt) {
    return { valid: false, error: "not_found" };
  }

  const now = Date.now();

  // 2. Enforce TTL Expiry (5 minutes)
  if (now > record.expiresAt) {
    await burnChallengeWithEtag(safeId, etag);
    return { valid: false, error: "expired" };
  }

  // 3. Enforce Attempt Threshold (Max 3 attempts)
  if (record.attempts && record.attempts >= 3) {
    await burnChallengeWithEtag(safeId, etag);
    return { valid: false, error: "max_attempts" };
  }

  // 4. Verify Origin IP Binding
  if (record.boundIp && clientIp && record.boundIp !== clientIp) {
    console.warn("Security Alert: 2FA OTP verification attempted from mismatched origin IP.");
    return { valid: false, error: "ip_mismatch" };
  }

  // 5. Hex Format Validation & RangeError-Safe Constant-Time Comparison
  if (!/^[0-9a-fA-F]{64}$/.test(record.codeHash) || !/^[0-9a-fA-F]{32}$/.test(record.salt)) {
    return { valid: false, error: "corrupt_record" };
  }

  const expectedHash = hashOTP(cleanCode, record.salt, safeId);
  const a = Buffer.from(expectedHash, "hex");
  const b = Buffer.from(record.codeHash, "hex");

  if (a.length !== 32 || b.length !== 32 || a.length !== b.length) {
    return { valid: false, error: "length_mismatch" };
  }

  const isMatch = crypto.timingSafeEqual(a, b);

  // 6. Execution Branch
  if (isMatch) {
    // ATOMIC CONDITIONAL BURN via Firebase ETag (Prevents Multi-Session Replay - CWE-362)
    inMemoryChallenges.delete(safeId);

    if (etag) {
      try {
        const delRes = await firebaseFetch(`_server_vault/otp_challenges/${safeId}.json`, {
          method: "DELETE",
          cache: "no-store",
          headers: { "If-Match": etag }
        });
        if (delRes.status === 412 || delRes.status === 404) {
          // Precondition Failed or Already Deleted: Another concurrent instance already burned or modified this OTP
          console.warn("Security Alert: Concurrency conflict (412/404) on OTP burn. Blocking token issuance.");
          return { valid: false, error: "concurrency_detected" };
        }
        if (!delRes.ok) {
          console.error("Server vault OTP atomic deletion failed:", delRes.status);
          return { valid: false, error: "burn_failed" };
        }
      } catch (err) {
        console.error("Network error during atomic OTP burn:", redactSecretUrl(err.message));
        return { valid: false, error: "burn_failed" };
      }
    } else {
      await firebaseFetch(`_server_vault/otp_challenges/${safeId}.json`, { method: "DELETE", cache: "no-store" }).catch(() => {});
    }

    return { valid: true };
  } else {
    // FAILED ATTEMPT: Conditional CAS Update or Lockout
    const newAttempts = (record.attempts || 0) + 1;
    record.attempts = newAttempts;
    record.lastAttempt = now;
    inMemoryChallenges.set(safeId, record);

    if (newAttempts >= 3) {
      // Burn immediately on 3rd failure to prevent brute force
      await burnChallengeWithEtag(safeId, etag);
      return { valid: false, error: "max_attempts", attempts: newAttempts, locked: true };
    } else {
      // Conditional CAS Update of attempts counter using ETag
      if (etag) {
        try {
          await firebaseFetch(`_server_vault/otp_challenges/${safeId}.json`, {
            method: "PUT",
            cache: "no-store",
            headers: {
              "Content-Type": "application/json",
              "If-Match": etag
            },
            body: JSON.stringify(record)
          });
        } catch (e) {}
      } else {
        try {
          await firebaseFetch(`_server_vault/otp_challenges/${safeId}.json`, {
            method: "PUT",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(record)
          });
        } catch (e) {}
      }
      return { valid: false, error: "invalid_code", attempts: newAttempts, locked: false };
    }
  }
}

// Deprecated legacy stubs (strictly for backward compatibility)
export async function save2FAOTP(code) { return null; }
export async function verify2FAOTP(inputCode) { return false; }

// Dispatch Email to Admin using Resend, Brevo, Webhook or Cloud Notification
export async function send2FAEmail(otpCode, targetEmails = ADMIN_2FA_EMAILS) {
  let emailDispatched = false;
  const recipients = (Array.isArray(targetEmails) ? targetEmails : [targetEmails])
    .map(e => String(e || "").trim().toLowerCase())
    .filter(Boolean);

  if (recipients.length === 0) {
    console.warn("No ADMIN_2FA_EMAILS configured in environment!");
    return { dispatched: false, emails: [] };
  }

  const emailHtml = `
    <div dir="rtl" style="font-family: Arial, -apple-system, BlinkMacSystemFont, sans-serif; background-color: #0A0F1D; color: #FFFFFF; padding: 40px 24px; border-radius: 16px; max-width: 520px; margin: 0 auto; text-align: center; border: 1.5px solid #C5A059; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
      <div style="font-size: 28px; margin-bottom: 8px;">💎</div>
      <h2 style="color: #C5A059; font-size: 22px; font-weight: 800; margin: 0 0 6px 0; letter-spacing: 0.5px;">معرض قاصد كريم للإضاءة الفاخرة</h2>
      <div style="font-size: 13px; color: #94A3B8; margin-bottom: 24px; font-weight: 600;">بوابة الإدارة التنفيذية • فرع الشيخ زايد</div>
      
      <div style="background: rgba(255,255,255,0.04); border-radius: 12px; padding: 20px; margin-bottom: 24px; border: 1px solid rgba(255,255,255,0.08);">
        <p style="font-size: 15px; color: #E2E8F0; line-height: 1.6; margin: 0 0 16px 0;">
          تم رصد طلب دخول إلى لوحة تحكم المعرض. رمز التحقق السداسي (2FA) الخاص بالمسؤول هو:
        </p>
        <div style="background: linear-gradient(135deg, rgba(197, 160, 89, 0.2), rgba(197, 160, 89, 0.05)); border: 2px dashed #C5A059; color: #F59E0B; font-size: 38px; font-weight: 900; letter-spacing: 12px; padding: 18px; border-radius: 10px; margin: 12px 0; font-family: monospace;">
          ${otpCode}
        </div>
        <div style="font-size: 12px; color: #CBD5E1; margin-top: 10px;">
          ⏱️ صلاحية هذا الرمز <strong>5 دقائق</strong> فقط للاستخدام لمرة واحدة (حد أقصى 3 محاولات).
        </div>
      </div>

      <p style="font-size: 12px; color: #64748B; line-height: 1.5; margin: 0;">
        إذا لم تكن أنت من طلب هذا الرمز، يُرجى فحص أمان حسابك وتغيير كلمة المرور فوراً.
      </p>
    </div>
  `;

  // Option A: Resend API (Strict Fail-Closed: Zero hardcoded fallback keys)
  const resendApiKey = process.env.RESEND_API_KEY ? process.env.RESEND_API_KEY.trim() : null;
  if (resendApiKey) {
    try {
      const fromEmail = process.env.RESEND_FROM || "Kased Karim Security <onboarding@resend.dev>";
      const results = await Promise.allSettled(
        recipients.map(async (email) => {
          const res = await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${resendApiKey}`,
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              from: fromEmail,
              to: [email],
              subject: `🔐 رمز التحقق السري لدخول لوحة تحكم قاصد كريم: ${otpCode}`,
              html: emailHtml
            })
          });
          const resData = await res.json().catch(() => ({}));
          return { email, ok: res.ok, data: resData };
        })
      );
      if (results.some(r => r.status === "fulfilled" && r.value?.ok)) {
        emailDispatched = true;
      }
    } catch (e) {
      console.warn("Resend email dispatch note:", e.message);
    }
  }

  // Option B: Brevo API
  const brevoApiKey = process.env.BREVO_API_KEY;
  if (!emailDispatched && brevoApiKey) {
    try {
      const brevoRecipients = recipients.map(email => ({ email, name: "Admin" }));
      const res = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
          "api-key": brevoApiKey,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          sender: { name: "Kased Karim Security", email: process.env.BREVO_SENDER || "security@kasedkarim.com" },
          to: brevoRecipients,
          subject: `🔐 كود التحقق السري لدخول لوحة تحكم قاصد كريم: ${otpCode}`,
          htmlContent: emailHtml
        })
      });
      if (res.ok) emailDispatched = true;
    } catch (e) {
      console.warn("Brevo email dispatch note:", e.message);
    }
  }

  // Option C: Webhook Dispatcher
  const webhookUrl = process.env.OTP_WEBHOOK_URL || process.env.ADMIN_ALERT_WEBHOOK;
  if (!emailDispatched && webhookUrl) {
    try {
      const res = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "admin_2fa_otp",
          emails: recipients.map(maskEmail),
          code: otpCode,
          timestamp: Date.now()
        })
      });
      if (res.ok) emailDispatched = true;
    } catch (e) {}
  }

  return { dispatched: emailDispatched, emails: recipients.map(maskEmail) };
}

// -----------------------------------------------------------------------------
// CUSTOMER AUTHENTICATION ENGINE (F-05, F-10, ASVS 2.4.1, NIST SP 800-63B)
// -----------------------------------------------------------------------------
// Pre-calculated deterministic dummy hash for constant CPU timing against user enumeration (ASVS 2.2.4)
export const DUMMY_PASSWORD_SALT = "0123456789abcdef0123456789abcdef";
// Precomputed Scrypt hash (N=16384, r=8, p=1, keylen=64) to eliminate synchronous startup Event-Loop blocking (ASVS 2.2.4 / CWE-400)
export const DUMMY_PASSWORD_HASH = "2bbdb280d57c0a3db26026c95be1cdd2f9499b98b64cb1a4b08a7dc3803e76862ccbe6ad7a400765a7f79a7c89e0cd374d7a0fc8f4be52547ea6a07e25ffcdb4";

// Sanitize & Normalize Password: Enforces String type, rejects null bytes, Unicode NFKC, length bounds (CWE-400, CWE-176)
export function sanitizeAndNormalizePassword(rawPassword, minLength = 8, maxLength = 128) {
  if (typeof rawPassword !== "string") return null;
  if (rawPassword.includes("\0")) return null; // Reject null bytes
  const normalized = rawPassword.normalize("NFKC").trim();
  if (normalized.length < minLength || normalized.length > maxLength) {
    return null;
  }
  return normalized;
}

// Non-blocking Asynchronous Scrypt KDF (Event-Loop Safe - RFC 7914 / ASVS 2.4.1)
export async function hashCustomerPassword(password, salt = null) {
  if (typeof password !== "string") return null;
  if (password.includes("\0")) return null;
  const clean = password.normalize("NFKC").slice(0, 128);
  const usedSalt = salt || crypto.randomBytes(16).toString("hex");

  // Non-blocking asynchronous scrypt running on libuv threadpool
  const derivedBuffer = await scryptAsync(clean, usedSalt, 64, {
    N: 16384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024
  });

  return {
    hash: derivedBuffer.toString("hex"),
    salt: usedSalt,
    alg: "scrypt",
    N: 16384,
    r: 8,
    p: 1,
    keylen: 64
  };
}

// Non-blocking Constant-Time Scrypt Verification (RangeError & Timing Safe - ASVS 2.10.3)
export async function verifyCustomerPassword(inputPassword, storedHash, storedSalt) {
  if (typeof inputPassword !== "string" || typeof storedHash !== "string" || typeof storedSalt !== "string") {
    return false;
  }
  if (inputPassword.includes("\0")) return false;

  // Validate that storedHash and storedSalt are valid hexadecimal strings
  if (!/^[a-fA-F0-9]{64,128}$/.test(storedHash) || !/^[a-fA-F0-9]{32,64}$/.test(storedSalt)) {
    return false;
  }

  try {
    const clean = inputPassword.normalize("NFKC").slice(0, 128);
    const derivedBuffer = await scryptAsync(clean, storedSalt, 64, {
      N: 16384,
      r: 8,
      p: 1,
      maxmem: 64 * 1024 * 1024
    });

    const b = Buffer.from(storedHash, "hex");
    return derivedBuffer.length === b.length && crypto.timingSafeEqual(derivedBuffer, b);
  } catch (e) {
    return false;
  }
}

// -----------------------------------------------------------------------------
// CUSTOMER TOKEN ENGINE (SEPARATE KEY & AUDIENCE ISOLATION) (F-10)
// -----------------------------------------------------------------------------
export function signCustomerToken(payload = {}, expiresInMs = 24 * 60 * 60 * 1000) {
  const key = getCustomerSigningKey();
  const isVerified = Boolean(payload.email_verified || payload.emailVerified);
  const normalizedPayload = {
    ...payload,
    email_verified: isVerified,
    emailVerified: isVerified
  };
  return signJwt({ payload: normalizedPayload, key, role: "customer", aud: "customer", maxTtlSec: 86400 });
}

export function createCustomerToken(payload = {}, expiresInMs = 24 * 60 * 60 * 1000) {
  return signCustomerToken(payload, expiresInMs);
}

export function verifyCustomerToken(token) {
  const keys = getCustomerSigningKeys();
  return verifyJwt({ token, keys, expectedRole: "customer", expectedAud: "customer", maxTtlSec: 86400 });
}

export function verifyCustomerRequest(req) {
  if (!req || !req.headers) return null;

  // 1. Authorization Header (Bearer <token>)
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  const bearerToken = extractBearerToken(authHeader);
  if (bearerToken) {
    const verified = verifyCustomerToken(bearerToken);
    if (verified && verified.sub) {
      const safeSub = sanitizePathId(verified.sub);
      if (safeSub) return { ...verified, sub: safeSub };
    }
  }

  // 2. HttpOnly Secure Cookie (Strict exact cookie match, zero prefix collisions)
  const cookieHeader = req.headers["cookie"];
  const cookieToken = extractCookie(cookieHeader, "kk_customer_token");
  if (cookieToken) {
    const verified = verifyCustomerToken(cookieToken);
    if (verified && verified.sub) {
      const safeSub = sanitizePathId(verified.sub);
      if (safeSub) return { ...verified, sub: safeSub };
    }
  }

  // 3. Custom Customer Header
  const customHeader = req.headers["x-customer-token"];
  if (customHeader && typeof customHeader === "string") {
    const verified = verifyCustomerToken(customHeader.trim());
    if (verified && verified.sub) {
      const safeSub = sanitizePathId(verified.sub);
      if (safeSub) return { ...verified, sub: safeSub };
    }
  }

  return null;
}

/**
 * Server Middleware Guard: Enforces that customer is authenticated AND has verified email.
 * Returns 403 Forbidden if email is not verified (email_verified === false).
 * Returns customerAuth payload if verified, or sends response and returns null if rejected.
 */
export async function requireVerifiedCustomer(req, res) {
  const customerAuth = verifyCustomerRequest(req);
  if (!customerAuth || !customerAuth.sub) {
    res.status(401).json({
      success: false,
      error: "يجب تسجيل الدخول أولاً للمتابعة (401 Unauthorized)."
    });
    return null;
  }

  // 1. Direct JWT Claim Check
  if (customerAuth.email_verified === true || customerAuth.emailVerified === true) {
    return customerAuth;
  }

  // 2. Fail-Safe Live Database Lookup (in case user just verified their email)
  try {
    const safeSub = sanitizePathId(customerAuth.sub);
    const custRes = await firebaseFetch(buildSafeRtdbPath("customers", safeSub), { cache: "no-store" });
    if (custRes.ok) {
      const liveCust = await custRes.json();
      if (liveCust && (liveCust.emailVerified === true || liveCust.email_verified === true)) {
        return {
          ...customerAuth,
          email_verified: true,
          emailVerified: true
        };
      }
    }
  } catch (err) {}

  res.status(403).json({
    success: false,
    forbidden: true,
    error: "تم رفض الوصول: يتطلب إتمام هذه العملية تفعيل البريد الإلكتروني للحساب (403 Forbidden)."
  });
  return null;
}

/**
 * Dispatches a customer email verification message via Resend, Brevo, or Transactional Webhook.
 */
export async function sendCustomerVerificationEmail(email, name, verificationToken, verificationCode = null) {
  if (!email || typeof email !== "string") return false;
  const cleanEmail = email.trim().toLowerCase();
  const cleanName = typeof name === "string" ? name.trim() : "عميلنا العزيز";

  const appUrl = (process.env.APP_URL || (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "https://kasedkarim.com")).replace(/\/+$/, "");
  const verifyLink = `${appUrl}/?verify_email=${verificationToken}&email=${encodeURIComponent(cleanEmail)}`;

  const emailHtml = `
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head><meta charset="UTF-8"><title>تفعيل حسابك - معرض قاصد كريم</title></head>
    <body style="font-family: Arial, sans-serif; background-color: #f8fafc; padding: 20px; direction: rtl; text-align: right;">
      <div style="max-width: 580px; margin: 0 auto; background: #ffffff; border-radius: 12px; padding: 30px; border: 1px solid #e2e8f0;">
        <h2 style="color: #0F172A; margin-top: 0;">مرحباً ${cleanName}،</h2>
        <p style="color: #334155; font-size: 15px; line-height: 1.6;">
          شكراً لتسجيلك في معرض قاصد كريم لوحدات الإضاءة الفاخرة بالشيخ زايد.<br>
          لتأكيد بريدك الإلكتروني وتفعيل حسابك بشكل كامل، يرجى الضغط على زر التفعيل أدناه:
        </p>
        <div style="text-align: center; margin: 25px 0;">
          <a href="${verifyLink}" style="background-color: #D97706; color: #ffffff; padding: 12px 28px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">
            تفعيل الحساب الآن
          </a>
        </div>
        ${verificationCode ? `<p style="text-align: center; font-size: 14px; color: #64748B;">أو استخدم رمز التحقق التالي: <strong style="font-size: 18px; color: #0F172A; letter-spacing: 3px;">${verificationCode}</strong></p>` : ""}
        <p style="color: #64748B; font-size: 13px; line-height: 1.5; margin-top: 30px; border-top: 1px solid #e2e8f0; padding-top: 15px;">
          ملاحظة: هذا الرابط صالح لمدة 24 ساعة فقط. في حال لم تقم بإنشاء هذا الحساب، يمكنك تجاهل هذه الرسالة بأمان وسيتم حذف الحساب تلقائياً.
        </p>
      </div>
    </body>
    </html>
  `;

  // Option A: Resend
  const resendApiKey = process.env.RESEND_API_KEY;
  if (resendApiKey) {
    try {
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${resendApiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: process.env.RESEND_FROM || "Kased Karim Security <security@kasedkarim.com>",
          to: [cleanEmail],
          subject: "✉️ تفعيل بريدك الإلكتروني - معرض قاصد كريم للإضاءة الفاخرة",
          html: emailHtml
        })
      });
      if (res.ok) return true;
    } catch (e) {
      console.warn("[EmailDispatch] Resend error:", e.message);
    }
  }

  // Option B: Brevo
  const brevoApiKey = process.env.BREVO_API_KEY;
  if (brevoApiKey) {
    try {
      const res = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
          "api-key": brevoApiKey,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          sender: { name: "Kased Karim Lighting", email: process.env.BREVO_SENDER || "security@kasedkarim.com" },
          to: [{ email: cleanEmail, name: cleanName }],
          subject: "✉️ تفعيل بريدك الإلكتروني - معرض قاصد كريم للإضاءة الفاخرة",
          htmlContent: emailHtml
        })
      });
      if (res.ok) return true;
    } catch (e) {
      console.warn("[EmailDispatch] Brevo error:", e.message);
    }
  }

  return false;
}

// -----------------------------------------------------------------------------
// GOOGLE ID TOKEN CRYPTOGRAPHIC VERIFICATION (F-03, ASVS 3.8, RFC 8725 & OIDC Core 1.0)
// -----------------------------------------------------------------------------
export async function verifyGoogleIdToken(idToken) {
  // 1. Strict Input Validation & Length Limits (DoS & Injection Mitigation)
  if (!idToken || typeof idToken !== "string") return null;
  const cleanToken = idToken.trim();
  if (cleanToken.length < 50 || cleanToken.length > 4096) return null;
  if (!/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/.test(cleanToken)) {
    return null;
  }

  // 2. Strict Fail-Closed: Require configured Google Client ID in server environment (Confused Deputy Prevention)
  const configuredAud = (process.env.GOOGLE_CLIENT_ID || process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || "").trim();
  if (!configuredAud) {
    console.error("CRITICAL SECURITY ALERT: GOOGLE_CLIENT_ID is not configured in server environment. Blocking OAuth authentication (Fail-Closed).");
    return null;
  }

  // 3. Outbound Fetch with AbortSignal Timeout (5 Seconds) & URL Parameter Safety
  try {
    const tokenUrl = new URL("https://oauth2.googleapis.com/tokeninfo");
    tokenUrl.searchParams.set("id_token", cleanToken);

    const res = await fetch(tokenUrl.toString(), {
      method: "GET",
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
      headers: { "Accept": "application/json" }
    });

    if (!res.ok || res.status !== 200) {
      return null;
    }

    const payload = await res.json();
    if (!payload || typeof payload !== "object") return null;

    // 4. Strict Issuer Verification (Exact match, accounts.google.com or https://accounts.google.com)
    if (payload.iss !== "accounts.google.com" && payload.iss !== "https://accounts.google.com") {
      return null;
    }

    // 5. Strict Audience Verification (aud must exactly equal configured Google Client ID)
    if (payload.aud !== configuredAud) {
      console.warn("Security Alert: Google ID Token audience mismatch. Expected:", configuredAud, "Received:", payload.aud);
      return null;
    }

    // 6. Time Claims Verification (exp, iat, nbf)
    const nowSec = Math.floor(Date.now() / 1000);
    const expSec = Number(payload.exp);
    if (!Number.isFinite(expSec) || expSec <= nowSec) {
      return null; // Expired token
    }

    const iatSec = Number(payload.iat);
    if (!Number.isFinite(iatSec) || iatSec > nowSec + 60 || (nowSec - iatSec) > 86400) {
      return null; // Future timestamp or token older than 24h
    }

    if (payload.nbf) {
      const nbfSec = Number(payload.nbf);
      if (Number.isFinite(nbfSec) && nbfSec > nowSec + 60) {
        return null;
      }
    }

    // 7. Strict Email Verification Enforcement (Prevent Truthy String Bug on "false")
    if (payload.email_verified !== "true" && payload.email_verified !== true) {
      return null;
    }

    // 8. Identity Claims Extraction & Sanitization (sub, email, name, picture)
    if (typeof payload.sub !== "string" || !/^[a-zA-Z0-9_\-]{1,255}$/.test(payload.sub.trim())) {
      return null;
    }
    const cleanSub = payload.sub.trim();

    if (typeof payload.email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email.trim())) {
      return null;
    }
    const cleanEmail = payload.email.trim().toLowerCase();

    const rawName = typeof payload.name === "string" ? payload.name : (typeof payload.given_name === "string" ? payload.given_name : "عميل Google");
    const cleanName = rawName.normalize("NFKC").trim().replace(/[\x00-\x1F\x7F]/g, "").slice(0, 100) || "عميل Google";

    let cleanPicture = "";
    if (typeof payload.picture === "string" && payload.picture.trim().length > 0 && payload.picture.length <= 1024) {
      const p = payload.picture.trim();
      try {
        const parsedPic = new URL(p);
        if (
          parsedPic.protocol === "https:" &&
          (parsedPic.hostname.endsWith(".googleusercontent.com") || parsedPic.hostname.endsWith(".google.com"))
        ) {
          cleanPicture = p;
        }
      } catch (e) {}
    }

    return {
      sub: cleanSub,
      googleId: cleanSub,
      email: cleanEmail,
      emailVerified: true,
      name: cleanName,
      picture: cleanPicture
    };
  } catch (e) {
    if (typeof timeoutId !== "undefined") clearTimeout(timeoutId);
    return null;
  }
}

// -----------------------------------------------------------------------------
// SENSITIVE DATA MINIMIZATION (F-04, F-05)
// -----------------------------------------------------------------------------
// Strictly Allowlist-based customer sanitization (OWASP API3: BOPLA, ASVS Level 3 & CWE-200)
// Internal security fields (passwordHash, passwordSalt, passwordAlg, tokenVersion, resetOtpHash, etc.) are NEVER returned.
export function sanitizeCustomer(customer, options = { forAdmin: false }) {
  if (!customer || typeof customer !== "object" || Array.isArray(customer)) {
    return null;
  }

  const isGoogle = customer.authProvider === "google" || !!customer.googleId || !!customer.googleSub;

  const sanitized = {
    id: typeof customer.id === "string" ? customer.id : "",
    name: typeof customer.name === "string" ? customer.name : "",
    email: customer.email ? String(customer.email).toLowerCase().trim() : null,
    phone: typeof customer.phone === "string" ? customer.phone : "",
    address: typeof customer.address === "string" ? customer.address : "",
    city: typeof customer.city === "string" ? customer.city : "",
    avatar: typeof customer.avatar === "string" ? customer.avatar : (typeof customer.picture === "string" ? customer.picture : ""),
    authProvider: customer.authProvider === "google" ? "google" : "local",
    emailVerified: Boolean(customer.emailVerified),
    createdAt: typeof customer.createdAt === "number" ? customer.createdAt : (typeof customer.createdAt === "string" ? Number(customer.createdAt) || 0 : 0),
    updatedAt: typeof customer.updatedAt === "number" ? customer.updatedAt : (typeof customer.updatedAt === "string" ? Number(customer.updatedAt) || 0 : 0)
  };

  // Safe UI flag for Google authentication badge without exposing raw googleSub
  if (isGoogle) {
    sanitized.googleId = true;
  }

  // Admin-specific safe display fields
  if (options && options.forAdmin) {
    sanitized.role = customer.role === "admin" ? "admin" : "customer";
    sanitized.status = typeof customer.status === "string" ? customer.status : (customer.disabled || customer.isBlocked ? "disabled" : "active");
    sanitized.disabled = Boolean(customer.disabled || customer.isBlocked || customer.status === "disabled" || customer.status === "suspended");
  } else {
    // Client-specific safe profile fields
    if (typeof customer.deliveryArea === "string") {
      sanitized.deliveryArea = customer.deliveryArea;
    }
    if (typeof customer.deliveryAreaName === "string") {
      sanitized.deliveryAreaName = customer.deliveryAreaName;
    }
  }

  return Object.freeze(sanitized);
}

// -----------------------------------------------------------------------------
// ORDER IDENTIFIERS & PHONE NUMBER VERIFICATION (F-08, ASVS Level 3)
// -----------------------------------------------------------------------------

// Cryptographically Unguessable High-Entropy Order Reference (>= 64 bits entropy)
// Generates 8 cryptographically secure random bytes (64 bits of CSPRNG entropy)
// formatted as 16 uppercase hex characters: ORD-XXXX-XXXX-XXXX-XXXX
export function generateOrderId() {
  const bytes = crypto.randomBytes(8);
  const hex = bytes.toString("hex").toUpperCase();
  return `ORD-${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}`;
}

// Strict Phone Number Normalizer (Handles Eastern Arabic digits, international codes & Egyptian standard)
export function normalizePhoneNumber(rawPhone) {
  if (!rawPhone || typeof rawPhone !== "string") return "";

  // 1. Convert Eastern Arabic (٠-٩) and Persian (۰-۹) digits to standard Western Arabic (0-9)
  let normalized = rawPhone
    .replace(/[٠۰]/g, "0")
    .replace(/[١۱]/g, "1")
    .replace(/[٢۲]/g, "2")
    .replace(/[٣۳]/g, "3")
    .replace(/[٤۴]/g, "4")
    .replace(/[٥۵]/g, "5")
    .replace(/[٦۶]/g, "6")
    .replace(/[٧۷]/g, "7")
    .replace(/[٨۸]/g, "8")
    .replace(/[٩۹]/g, "9");

  // 2. Strip all non-digit characters
  normalized = normalized.replace(/[^0-9]/g, "");

  // 3. Handle Egyptian dial codes (+20, 0020, 20)
  if (normalized.startsWith("002001") && normalized.length === 15) {
    normalized = normalized.slice(4);
  } else if (normalized.startsWith("00201") && normalized.length === 14) {
    normalized = "0" + normalized.slice(4);
  } else if (normalized.startsWith("2001") && normalized.length === 13) {
    normalized = normalized.slice(2);
  } else if (normalized.startsWith("201") && normalized.length === 12) {
    normalized = "0" + normalized.slice(2);
  } else if (normalized.startsWith("00")) {
    normalized = normalized.slice(2);
  }

  // 4. Ensure leading zero for 10-digit Egyptian mobile (10xxxxxxxx -> 010xxxxxxxx)
  if (normalized.length === 10 && normalized.startsWith("1")) {
    normalized = "0" + normalized;
  }

  return normalized.slice(0, 20);
}

// Timing-Safe Constant-Time Phone Comparison (CWE-208 & ASVS Level 3)
// Hashes normalized phone numbers using SHA-256 and compares the 32-byte digests via crypto.timingSafeEqual.
// Explicitly rejects partial / suffix matches (e.g. 4-digit suffix).
export function timingSafePhoneCompare(storedPhone, inputPhone) {
  const normA = normalizePhoneNumber(storedPhone);
  const normB = normalizePhoneNumber(inputPhone);

  // If either is empty or under 8 digits, fail closed with constant-time dummy operation
  if (!normA || !normB || normA.length < 8 || normB.length < 8) {
    const dummyA = crypto.createHash("sha256").update("invalid_dummy_salt_a").digest();
    const dummyB = crypto.createHash("sha256").update("invalid_dummy_salt_b").digest();
    crypto.timingSafeEqual(dummyA, dummyB);
    return false;
  }

  // Reject partial / length mismatches with dummy comparison to maintain constant time
  if (normA.length !== normB.length) {
    const dummyA = crypto.createHash("sha256").update(normA).digest();
    const dummyB = crypto.createHash("sha256").update(normB).digest();
    crypto.timingSafeEqual(dummyA, dummyB);
    return false;
  }

  const hashA = crypto.createHash("sha256").update(normA).digest();
  const hashB = crypto.createHash("sha256").update(normB).digest();

  return crypto.timingSafeEqual(hashA, hashB);
}

// -----------------------------------------------------------------------------
// BACKUP SECURITY, SETTINGS SANITIZATION & REVIEWS VALIDATION (ASVS Level 3)
// -----------------------------------------------------------------------------

export const ALLOWED_BACKUP_COLLECTIONS = Object.freeze([
  "products",
  "categories",
  "settings",
  "orders",
  "reviews"
]);

// Deep Recursive Validator to strictly prevent Prototype Pollution, RTDB reserved keys & injection
export function assertSafeBackupPayload(data, depth = 0) {
  if (depth > 8) {
    throw new Error("Security Alert: Backup payload exceeds maximum allowable nesting depth (8).");
  }
  if (data === null || data === undefined) return;

  if (typeof data === "object") {
    if (Array.isArray(data)) {
      if (data.length > 50000) {
        throw new Error("Security Alert: Backup array exceeds maximum allowable elements limit (50,000).");
      }
      for (let i = 0; i < data.length; i++) {
        assertSafeBackupPayload(data[i], depth + 1);
      }
    } else {
      const keys = Object.keys(data);
      if (keys.length > 10000) {
        throw new Error("Security Alert: Backup object exceeds maximum allowable keys limit (10,000).");
      }

      for (const key of keys) {
        // 1. Prototype Pollution Defense
        if (
          key === "__proto__" ||
          key === "constructor" ||
          key === "prototype" ||
          key === "toString" ||
          key === "valueOf"
        ) {
          throw new Error(`Security Violation: Prototype pollution key '${key}' detected in backup payload.`);
        }

        // 2. Firebase RTDB Reserved Keys and Prohibited Characters
        if (
          key.startsWith(".") ||
          key.includes("/") ||
          key.includes(".") ||
          key.includes("#") ||
          key.includes("$") ||
          key.includes("[") ||
          key.includes("]") ||
          /[\x00-\x1F\x7F]/.test(key) ||
          key.length === 0 ||
          key.length > 128
        ) {
          throw new Error(`Security Violation: Illegal RTDB key name '${key}' detected in backup payload.`);
        }

        // 3. Vault & Internal System Node Isolation
        if (
          key === "_server_vault" ||
          key === "auth_2fa_otp" ||
          key === "rate_limits" ||
          key === "tokens" ||
          key === "backups"
        ) {
          throw new Error(`Security Violation: Attempt to access privileged internal key '${key}' in backup.`);
        }

        const val = data[key];

        // 4. Dangerous Protocol Check in String Values
        if (typeof val === "string") {
          const lower = val.toLowerCase().trim();
          if (
            lower.startsWith("javascript:") ||
            lower.startsWith("vbscript:") ||
            lower.startsWith("data:text/html")
          ) {
            throw new Error(`Security Violation: Dangerous URI scheme detected in key '${key}'.`);
          }
        }

        assertSafeBackupPayload(val, depth + 1);
      }
    }
  }
}

// Strictly Allowlist-based Public Showroom Settings Sanitizer (ASVS 13.1 & CWE-200)
// Internal secrets, notification webhooks, supplier data, and margin notes are NEVER leaked.
export function sanitizePublicSettings(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return Object.freeze({});
  }

  const phone = typeof raw.phone === "string" ? raw.phone.replace(/[<>]/g, "").trim().slice(0, 25) : "";
  const whatsapp = typeof raw.whatsapp === "string" ? raw.whatsapp.replace(/[^0-9]/g, "").trim().slice(0, 20) : "";
  const email = typeof raw.email === "string" ? raw.email.replace(/[<>]/g, "").trim().toLowerCase().slice(0, 100) : "";
  const addressAr = typeof raw.addressAr === "string" ? raw.addressAr.replace(/[<>]/g, "").trim().slice(0, 200) : "";
  const addressEn = typeof raw.addressEn === "string" ? raw.addressEn.replace(/[<>]/g, "").trim().slice(0, 200) : "";
  const workingHoursAr = typeof raw.workingHoursAr === "string" ? raw.workingHoursAr.replace(/[<>]/g, "").trim().slice(0, 100) : (typeof raw.workingHours === "string" ? raw.workingHours.replace(/[<>]/g, "").trim().slice(0, 100) : "");
  const workingHoursEn = typeof raw.workingHoursEn === "string" ? raw.workingHoursEn.replace(/[<>]/g, "").trim().slice(0, 100) : "";
  const storeNameAr = typeof raw.storeNameAr === "string" ? raw.storeNameAr.replace(/[<>]/g, "").trim().slice(0, 100) : "معرض قاصد كريم";
  const storeNameEn = typeof raw.storeNameEn === "string" ? raw.storeNameEn.replace(/[<>]/g, "").trim().slice(0, 100) : "Kased Karim Showroom";
  const announcement = typeof raw.announcement === "string" ? raw.announcement.replace(/[<>]/g, "").trim().slice(0, 200) : "";

  // Public Google OAuth Client ID (Client-side identifier, strictly not secret)
  const googleClientId = typeof raw.googleClientId === "string" && raw.googleClientId.trim().endsWith(".apps.googleusercontent.com")
    ? raw.googleClientId.trim().slice(0, 150)
    : "";

  // Safe HTTPS URLs only
  let mapUrl = "";
  if (typeof raw.mapUrl === "string" && raw.mapUrl.trim().startsWith("https://")) {
    mapUrl = raw.mapUrl.trim().slice(0, 500);
  }
  let mapEmbedUrl = "";
  if (typeof raw.mapEmbedUrl === "string" && raw.mapEmbedUrl.trim().startsWith("https://")) {
    mapEmbedUrl = raw.mapEmbedUrl.trim().slice(0, 800);
  }

  const freeShippingThreshold = typeof raw.freeShippingThreshold === "number" && Number.isFinite(raw.freeShippingThreshold)
    ? Math.max(0, Math.min(1000000, raw.freeShippingThreshold))
    : (parseInt(raw.freeShippingThreshold, 10) > 0 ? Math.min(1000000, parseInt(raw.freeShippingThreshold, 10)) : 5000);

  const social = {
    facebook: typeof raw.social?.facebook === "string" && raw.social.facebook.trim().startsWith("https://") ? raw.social.facebook.trim().slice(0, 200) : "",
    instagram: typeof raw.social?.instagram === "string" && raw.social.instagram.trim().startsWith("https://") ? raw.social.instagram.trim().slice(0, 200) : "",
    tiktok: typeof raw.social?.tiktok === "string" && raw.social.tiktok.trim().startsWith("https://") ? raw.social.tiktok.trim().slice(0, 200) : "",
    designerUrl: "https://karimodesign.vercel.app/"
  };

  return Object.freeze({
    phone,
    whatsapp,
    email,
    addressAr,
    addressEn,
    workingHoursAr,
    workingHoursEn,
    storeNameAr,
    storeNameEn,
    announcement,
    googleClientId,
    mapUrl,
    mapEmbedUrl,
    freeShippingThreshold,
    social,
    updatedAt: typeof raw.updatedAt === "number" ? raw.updatedAt : Date.now()
  });
}

// Strictly Allowlist-based Review Sanitizer (OWASP API3: BOPLA & ASVS Level 3)
export function sanitizeReview(review, options = { forAdmin: false }) {
  if (!review || typeof review !== "object" || Array.isArray(review)) return null;

  const id = typeof review.id === "string" ? review.id.slice(0, 64) : "";
  const productId = typeof review.productId === "string" ? review.productId.slice(0, 64) : "";
  const productName = typeof review.productName === "string" ? review.productName.replace(/[<>]/g, "").trim().slice(0, 100) : "";
  const author = typeof review.author === "string" ? review.author.replace(/[<>]/g, "").trim().slice(0, 60) : (typeof review.name === "string" ? review.name.replace(/[<>]/g, "").trim().slice(0, 60) : "عميل المعرض");
  const rating = Number.isInteger(review.rating) && review.rating >= 1 && review.rating <= 5 ? review.rating : 5;
  const comment = typeof review.comment === "string" ? review.comment.replace(/[<>]/g, "").trim().slice(0, 1000) : "";
  const adminReply = typeof review.adminReply === "string" ? review.adminReply.replace(/[<>]/g, "").trim().slice(0, 500) : "";
  const timestamp = typeof review.timestamp === "number" ? review.timestamp : (typeof review.createdAt === "number" ? review.createdAt : Date.now());
  const status = typeof review.status === "string" && ["approved", "pending", "rejected"].includes(review.status) ? review.status : "pending";

  const publicReview = {
    id,
    productId,
    productName,
    author,
    rating,
    comment,
    adminReply,
    status,
    timestamp
  };

  if (options && options.forAdmin) {
    publicReview.status = status;
    publicReview.approved = status === "approved";
    publicReview.moderatedAt = typeof review.moderatedAt === "number" ? review.moderatedAt : null;
    publicReview.moderatedBy = typeof review.moderatedBy === "string" ? review.moderatedBy.slice(0, 50) : null;
    publicReview.customerId = typeof review.customerId === "string" ? review.customerId.slice(0, 50) : null;
  }

  return Object.freeze(publicReview);
}

// -----------------------------------------------------------------------------
// CENTRAL RESILIENCE ENGINE RE-EXPORTS (Unit 3B-3 / OWASP API4 & API8)
// -----------------------------------------------------------------------------
export {
  HttpError,
  redactSecrets,
  safeLogError,
  SAFE_REGEX,
  testSafeRegex,
  safeSanitizeString,
  validateJsonStructureIterative,
  readSafeJsonBody,
  safeFetchWithTimeout,
  safeReadResponseJson,
  cancelResponseBody,
  withApiHardening
} from "./_resilience.js";
