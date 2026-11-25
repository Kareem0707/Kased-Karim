// =============================================================================
// FILE: api/_resilience.js
// CENTRAL RUNTIME SECURITY, RESILIENCE & ERROR BOUNDARY MODULE
// OWASP API Security Top 10 (API4, API8), OWASP ASVS Level 3, CWE-209, CWE-400, CWE-1333
// =============================================================================

import crypto from "crypto";
import { setSecurityHeaders } from "./_auth.js";

// -----------------------------------------------------------------------------
// 1. HTTP ERROR CLASS (Semantic HTTP Status & Safe Message)
// -----------------------------------------------------------------------------
export class HttpError extends Error {
  constructor(statusCode, message, extra = {}) {
    super(message);
    this.name = "HttpError";
    this.statusCode = statusCode;
    this.isHttpError = true;
    this.extra = extra;
  }
}

// -----------------------------------------------------------------------------
// 2. SECRET REDACTION & ZERO-LEAKAGE LOG HYGIENE (CWE-209, CWE-532)
// -----------------------------------------------------------------------------
const SENSITIVE_PATTERNS = [
  /([?&]auth=)[^&\s"'`#]+/gi,
  /(Bearer\s+)[A-Za-z0-9\-_.]+/gi,
  /(admin_token|customer_token)=[^;\s]+/gi,
  /(xkeysib-[a-zA-Z0-9_-]+)/gi,
  /(re_[a-zA-Z0-9_]{20,})/gi,
  /(AIza[0-9A-Za-z-_]{35})/gi,
  /("password"\s*:\s*")[^"]+(")/gi,
  /("otp"\s*:\s*")[^"]+(")/gi
];

export function redactSecrets(val) {
  if (typeof val !== "string") {
    if (val === null || val === undefined) return "";
    try {
      val = String(val);
    } catch {
      return "[Unserializable Value]";
    }
  }

  let sanitized = val;

  // Redact known environment secrets if present in runtime
  const dbSecret = process.env.FIREBASE_DB_SECRET;
  if (dbSecret && dbSecret.length >= 8) {
    sanitized = sanitized.split(dbSecret).join("[REDACTED_DB_SECRET]");
  }
  const jwtSecrets = [
    process.env.ADMIN_JWT_SECRET,
    process.env.CUSTOMER_JWT_SECRET,
    process.env.MASTER_JWT_SECRET
  ];
  for (const s of jwtSecrets) {
    if (s && s.length >= 8) {
      sanitized = sanitized.split(s).join("[REDACTED_JWT_SECRET]");
    }
  }
  const admin2faSecret = process.env.ADMIN_2FA_SECRET;
  if (admin2faSecret && admin2faSecret.length >= 8) {
    sanitized = sanitized.split(admin2faSecret).join("[REDACTED_2FA_SECRET]");
  }
  const resendKey = process.env.RESEND_API_KEY;
  if (resendKey && resendKey.length >= 8) {
    sanitized = sanitized.split(resendKey).join("[REDACTED_RESEND_KEY]");
  }
  const brevoKey = process.env.BREVO_API_KEY;
  if (brevoKey && brevoKey.length >= 8) {
    sanitized = sanitized.split(brevoKey).join("[REDACTED_BREVO_KEY]");
  }

  // Redact regex patterns
  for (const pattern of SENSITIVE_PATTERNS) {
    sanitized = sanitized.replace(pattern, (match, p1, p2) => {
      if (match.includes("[REDACTED")) return match;
      if (p2) return `${p1}[REDACTED]${p2}`;
      if (p1) return `${p1}[REDACTED]`;
      return "[REDACTED]";
    });
  }

  return sanitized;
}

export function safeLogError(context, requestId, err) {
  const timestamp = new Date().toISOString();
  const safeContext = typeof context === "string" ? context.slice(0, 80) : "ApiServerless";
  const safeReqId = typeof requestId === "string" ? requestId.slice(0, 32) : "unknown-req";

  const rawMessage = err?.message || String(err || "Unknown server error");
  const sanitizedMessage = redactSecrets(rawMessage);

  // Redact stack trace if present
  let sanitizedStack = "";
  if (err?.stack && typeof err.stack === "string") {
    sanitizedStack = redactSecrets(err.stack);
  }

  console.error(
    `[${timestamp}] [ReqId: ${safeReqId}] [Context: ${safeContext}] ERROR: ${sanitizedMessage}`,
    sanitizedStack ? `\nStack:\n${sanitizedStack}` : ""
  );
}

// -----------------------------------------------------------------------------
// 3. CERTIFIED LINEAR ReDoS-SAFE REGEX ENGINE (CWE-1333)
// -----------------------------------------------------------------------------
export const SAFE_REGEX = Object.freeze({
  EMAIL: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$/,
  EGYPT_PHONE: /^01[0125][0-9]{8}$/,
  SAFE_ID: /^[a-zA-Z0-9_\-]{1,64}$/,
  ORDER_ID: /^ORD-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/,
  DIGITS_ONLY: /^\d+$/,
  HEX: /^[a-fA-F0-9]+$/,
  HEX_32_64: /^[a-fA-F0-9]{32,64}$/,
  HEX_64_128: /^[a-fA-F0-9]{64,128}$/,
  BEARER: /^Bearer\s+([A-Za-z0-9\-_.]+)$/i,
  IP_CANDIDATE: /^[a-fA-F0-9:.]+$/,
  IPV4_QUAD: /^\d{1,3}(\.\d{1,3}){3}$/
});

// Length-bounded regex tester: Enforces strict length ceiling BEFORE running regex
export function testSafeRegex(regex, value, maxLength = 255) {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > maxLength) return false;
  return regex.test(value);
}

// Linear ReDoS-safe string sanitizer
export function safeSanitizeString(val, maxLength = 255) {
  if (typeof val !== "string") return "";
  // Axis 4: Bound length FIRST to guarantee O(n) execution with zero backtracking
  const bounded = val.slice(0, maxLength);
  return bounded
    .replace(/[\x00-\x1F\x7F]/g, "") // Strip control characters
    .replace(/[<>]/g, "")            // Strip HTML tag delimiters
    .replace(/javascript\s*:/gi, "") // Neutralize javascript pseudo-protocol
    .trim();
}

// -----------------------------------------------------------------------------
// 4. ITERATIVE STRUCTURAL JSON VALIDATOR (Anti-JSON Bomb & Prototype Pollution)
// -----------------------------------------------------------------------------
export function validateJsonStructureIterative(root, { maxDepth = 6, maxKeys = 200, isArrayAllowed = false } = {}) {
  if (root === null || typeof root !== "object") {
    throw new HttpError(400, "جسم الطلب يجب أن يكون كائناً أو مصفوفة بصيغة JSON صالحة.");
  }

  if (!isArrayAllowed && Array.isArray(root)) {
    throw new HttpError(400, "جسم الطلب يجب أن يكون كائناً بصيغة JSON وليس مصفوفة.");
  }

  // Iterative stack-based walk (Immune to RangeError: Maximum call stack size exceeded)
  const stack = [{ node: root, depth: 1 }];
  let totalKeys = 0;
  const visited = new Set();

  while (stack.length > 0) {
    const { node, depth } = stack.pop();

    if (depth > maxDepth) {
      throw new HttpError(400, `مستوى تداخل البيانات (${depth}) يتجاوز الحد الأقصى المسموح به (${maxDepth}).`);
    }

    if (node === null || typeof node !== "object") {
      continue;
    }

    if (visited.has(node)) {
      throw new HttpError(400, "تم رصد إشارة مرجعية دائرية غير صالحة في البيانات.");
    }
    visited.add(node);

    // Prototype pollution verification
    const proto = Object.getPrototypeOf(node);
    if (proto !== Object.prototype && proto !== Array.prototype && proto !== null) {
      throw new HttpError(400, "كائن غير صالح أمنياً (تم رصد تلاعب في النموذج الأولي Prototype Pollution).");
    }

    // Inspect own keys
    const keys = Object.getOwnPropertyNames(node);
    totalKeys += keys.length;
    if (totalKeys > maxKeys) {
      throw new HttpError(400, `عدد حقول البيانات الكلي (${totalKeys}) يتجاوز الحد الأقصى المسموح به (${maxKeys}).`);
    }

    for (const key of keys) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        throw new HttpError(400, `مفتاح محظور أمنياً في جسم الطلب (${key}).`);
      }

      const val = node[key];
      if (val !== null && typeof val === "object") {
        stack.push({ node: val, depth: depth + 1 });
      }
    }
  }

  return true;
}

// -----------------------------------------------------------------------------
// 5. SECURE STREAM & BODY READER (Per-Route Byte Ceiling & Content-Type 415)
// -----------------------------------------------------------------------------
export async function readSafeJsonBody(req, {
  maxBytes = 64 * 1024,
  maxDepth = 6,
  maxKeys = 200,
  isArrayAllowed = false,
  requireBody = true
} = {}) {
  // 1. Content-Type Header Verification (Simple CSRF & Media Type defense)
  const rawContentType = (req.headers && (req.headers["content-type"] || req.headers["Content-Type"])) || "";
  const isWriteMethod = ["POST", "PUT", "PATCH"].includes((req.method || "").toUpperCase());

  if (isWriteMethod) {
    if (rawContentType) {
      if (!rawContentType.toLowerCase().includes("application/json")) {
        throw new HttpError(415, "نوع المحتوى غير مدعوم (Unsupported Media Type). يجب أن يكون Content-Type: application/json.");
      }
    } else {
      // If Content-Type is omitted on a real stream or non-object body, require application/json
      if (typeof req.body !== "object" || req.body === null) {
        if ((req && typeof req[Symbol.asyncIterator] === "function" && !req._readableState?.ended) || typeof req.body === "string" || Buffer.isBuffer(req.body)) {
          throw new HttpError(415, "نوع المحتوى غير مدعوم (Unsupported Media Type). يجب تحديد Content-Type: application/json.");
        }
      }
    }
  }

  // 2. Early Content-Length Header Check
  const contentLengthHeader = req.headers && (req.headers["content-length"] || req.headers["Content-Length"]);
  if (contentLengthHeader) {
    const declaredLength = parseInt(contentLengthHeader, 10);
    if (!isNaN(declaredLength) && declaredLength > maxBytes) {
      throw new HttpError(413, `حجم الطلب (${declaredLength} بايت) يتجاوز الحد الأقصى المسموح به لهذا المسار (${maxBytes} بايت).`);
    }
  }

  // 3. Obtain Raw String / Object
  let rawBody = null;

  // Case A: Stream body (when bodyParser is disabled or raw stream is active)
  if (req && typeof req[Symbol.asyncIterator] === "function" && !req._readableState?.ended && !req.body) {
    let bytesRead = 0;
    const chunks = [];

    for await (const chunk of req) {
      bytesRead += chunk.length;
      if (bytesRead > maxBytes) {
        throw new HttpError(413, `حجم تدفق الطلب يتجاوز الحد الأقصى المسموح به (${maxBytes} بايت).`);
      }
      chunks.push(chunk);
    }

    if (chunks.length > 0) {
      rawBody = Buffer.concat(chunks).toString("utf8");
    }
  } else if (req.body !== undefined && req.body !== null) {
    // Case B: Pre-parsed by Vercel or middleware
    if (Buffer.isBuffer(req.body)) {
      if (req.body.length > maxBytes) {
        throw new HttpError(413, `حجم الطلب (${req.body.length} بايت) يتجاوز الحد الأقصى المسموح به (${maxBytes} بايت).`);
      }
      rawBody = req.body.toString("utf8");
    } else if (typeof req.body === "string") {
      const byteLen = Buffer.byteLength(req.body, "utf8");
      if (byteLen > maxBytes) {
        throw new HttpError(413, `حجم الطلب (${byteLen} بايت) يتجاوز الحد الأقصى المسموح به (${maxBytes} بايت).`);
      }
      rawBody = req.body;
    } else if (typeof req.body === "object") {
      // Body is already a parsed JS object
      try {
        const estimatedBytes = Buffer.byteLength(JSON.stringify(req.body), "utf8");
        if (estimatedBytes > maxBytes) {
          throw new HttpError(413, `حجم الطلب المتوقع (${estimatedBytes} بايت) يتجاوز الحد الأقصى (${maxBytes} بايت).`);
        }
      } catch {
        // Continue to iterative validation
      }
      rawBody = req.body;
    }
  }

  // Check for empty body on required write operations
  if (rawBody === null || rawBody === "" || (typeof rawBody === "string" && rawBody.trim().length === 0)) {
    if (requireBody && isWriteMethod) {
      throw new HttpError(400, "جسم الطلب مطلوب ولا يمكن أن يكون فارغاً.");
    }
    return null;
  }

  // 4. Safe JSON Parsing
  let parsedJson;
  if (typeof rawBody === "object" && rawBody !== null) {
    parsedJson = rawBody;
  } else {
    try {
      parsedJson = JSON.parse(rawBody);
    } catch (parseErr) {
      throw new HttpError(400, "صيغة JSON غير صالحة (Malformed JSON Body).");
    }
  }

  // 5. Iterative Structure & Prototype Validation
  validateJsonStructureIterative(parsedJson, { maxDepth, maxKeys, isArrayAllowed });

  return parsedJson;
}

// -----------------------------------------------------------------------------
// 6. SAFE OUTBOUND FETCH WITH TIMEOUT & SOCKET DRAIN (CWE-400 / Socket Leaks)
// -----------------------------------------------------------------------------
export async function safeFetchWithTimeout(url, options = {}, timeoutMs = 7000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort(new Error(`Outbound network request timed out after ${timeoutMs}ms`));
  }, timeoutMs);

  const fetchOptions = {
    ...options,
    redirect: "error", // Never follow redirects blindly (SSRF and credential safety)
    signal: options.signal || controller.signal,
    headers: {
      "Accept": "application/json",
      ...(options.headers || {})
    }
  };

  try {
    const res = await fetch(url, fetchOptions);
    return res;
  } catch (err) {
    const safeMsg = redactSecrets(err?.message || "Outbound Fetch Request Failed");
    const sanitizedError = new Error(safeMsg);
    if (err?.name) sanitizedError.name = err.name;
    throw sanitizedError;
  } finally {
    clearTimeout(timeoutId);
  }
}

// Safely consume or drain response JSON without socket leakage
export async function safeReadResponseJson(res) {
  if (!res) return null;
  try {
    const text = await res.text();
    if (!text || text.trim().length === 0) return null;
    return JSON.parse(text);
  } catch (err) {
    // If upstream returned HTML (e.g. 502/503) or malformed payload
    const snippet = (await res.text?.().catch(() => "")) || "";
    throw new Error(`Upstream returned non-JSON response (Status: ${res.status}). Body snippet: ${redactSecrets(snippet).slice(0, 80)}`);
  }
}

// Safely cancel unread body stream to prevent socket pool exhaustion
export async function cancelResponseBody(res) {
  if (!res || !res.body) return;
  try {
    if (typeof res.body.cancel === "function") {
      await res.body.cancel();
    } else if (typeof res.body.destroy === "function") {
      res.body.destroy();
    }
  } catch {
    // Ignore cleanup errors
  }
}

// -----------------------------------------------------------------------------
// 7. UNIFIED TOP-LEVEL ERROR BOUNDARY & HARDENING WRAPPER
// -----------------------------------------------------------------------------
export function withApiHardening(handler, options = {}) {
  let allowedMethods = options.allowedMethods ? [...options.allowedMethods] : ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
  if (allowedMethods.includes("GET") && !allowedMethods.includes("HEAD")) {
    allowedMethods.push("HEAD");
  }
  const maxBodyBytes = options.maxBodyBytes || 64 * 1024;
  const maxDepth = options.maxDepth || 6;
  const maxKeys = options.maxKeys || 200;
  const isArrayAllowed = Boolean(options.isArrayAllowed);
  const context = options.context || "ApiEndpoint";
  const requireJsonBody = options.requireJsonBody !== false;

  return async function wrappedApiHandler(req, res) {
    const requestId = crypto.randomUUID().slice(0, 8);

    // Strict Security & Content-Type Headers on all responses (including errors)
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("X-Request-Id", requestId);

    // 0. Active CORS, Security Headers & Preflight Gate (Unit 5A-1 / ASVS V14.5)
    if (setSecurityHeaders(req, res, { allowedMethods })) {
      return;
    }

    // 1. HTTP Method Whitelist Check
    const method = (req.method || "").toUpperCase();
    if (!allowedMethods.includes(method)) {
      res.setHeader("Allow", allowedMethods.join(", "));
      return res.status(405).json({
        ok: false,
        success: false,
        error: `طريقة الطلب ${method} غير مسموحة لهذا المسار. الطرق المسموحة: ${allowedMethods.join(", ")}`,
        requestId
      });
    }

    try {
      // 2. Body Parsing & Byte-level validation for write methods
      let parsedBody = null;
      if (["POST", "PUT", "PATCH"].includes(method)) {
        parsedBody = await readSafeJsonBody(req, {
          maxBytes: maxBodyBytes,
          maxDepth,
          maxKeys,
          isArrayAllowed,
          requireBody: requireJsonBody
        });
        req.safeBody = parsedBody;
        if (parsedBody !== null) {
          req.body = parsedBody;
        }
      }

      // 4. Invoke Core Business Logic
      return await handler(req, res, { requestId, safeBody: parsedBody });
    } catch (err) {
      // Prevent Double-Send / ERR_HTTP_HEADERS_SENT
      if (res.headersSent) {
        safeLogError(context, requestId, new Error(`Response already sent before error handler: ${err?.message}`));
        return;
      }

      // Semantic HTTP Error (400, 401, 403, 405, 413, 415, 429)
      if (err?.isHttpError) {
        return res.status(err.statusCode).json({
          ok: false,
          success: false,
          error: err.message,
          requestId,
          ...(err.extra || {})
        });
      }

      // Internal Unexpected Server Error (500) - Never leak stack or internal details
      safeLogError(context, requestId, err);
      return res.status(500).json({
        ok: false,
        success: false,
        error: "حدث خطأ داخلي في الخادم.",
        requestId
      });
    }
  };
}
