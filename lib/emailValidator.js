/**
 * lib/emailValidator.js
 * High-Security Email Validation Engine for Node.js Runtime (Vercel Serverless & Node.js 18+)
 * 
 * Capabilities:
 * 1. Strict RFC 5321/5322 Syntax Validation & Normalization (Trim, Unicode NFKC, Lowercase, Length Bounds).
 * 2. Disposable / Temporary Email Blocking via `disposable-email-domains` using an O(1) Set lookup
 *    with subdomain traversal and supplemental high-risk burner domain lists.
 * 3. Real DNS MX Record Verification via `node:dns/promises` with a strict fail-safe timeout (max 3 seconds)
 *    and RFC 7505 Null-MX rejection.
 */

import { createRequire } from "node:module";
import { Resolver } from "node:dns/promises";

// 1. Load disposable email domains list safely in ESM environment
const require = createRequire(import.meta.url);
let rawDisposableList = [];
try {
  rawDisposableList = require("disposable-email-domains");
} catch (err) {
  console.warn("[emailValidator] Warning: Could not load disposable-email-domains package:", err.message);
}

// 2. Supplemental Burner & Disposable Domains (covering newly emerging and localized temp-mail providers)
const SUPPLEMENTAL_DISPOSABLE_DOMAINS = [
  "tempmail.com",
  "temp-mail.org",
  "temp-mail.io",
  "tempmail.net",
  "10minutemail.com",
  "10minutemail.net",
  "10minutemail.org",
  "guerrillamail.com",
  "guerrillamail.net",
  "guerrillamail.org",
  "guerrillamailblock.com",
  "sharklasers.com",
  "grr.la",
  "mailinator.com",
  "mailinator2.com",
  "yopmail.com",
  "yopmail.fr",
  "yopmail.net",
  "cool.fr.nf",
  "jetable.fr.nf",
  "trashmail.com",
  "trashmail.net",
  "trashmail.org",
  "throwawaymail.com",
  "getnada.com",
  "nada.ltd",
  "abovedad.me",
  "mohmal.com",
  "mohmal.im",
  "mohmal.in",
  "fakemailgenerator.com",
  "burnermail.io",
  "crazymailing.com",
  "dispostable.com",
  "inboxkitten.com",
  "maildrop.cc",
  "tempail.com",
  "minutemailbox.com",
  "emailondeck.com",
  "fakeinbox.com",
  "generator.email",
  "mytemp.email",
  "dropmail.me",
  "10mail.org",
  "trash-mail.at",
  "armyspy.com",
  "cuvox.de",
  "dayrep.com",
  "einrot.com",
  "fleckens.hu",
  "gustr.com",
  "jourrapide.com",
  "rhyta.com",
  "superrito.com",
  "teleworm.us"
];

// O(1) Set Construction for instant high-throughput lookup
export const DISPOSABLE_DOMAINS_SET = new Set([
  ...rawDisposableList,
  ...SUPPLEMENTAL_DISPOSABLE_DOMAINS
].map(d => String(d).trim().toLowerCase()));

// 3. Strict RFC 5322 Compliant Email Regex (Prevents CRLF Injection, ReDoS & Invalid Characters)
const EMAIL_SYNTAX_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

// 4. DNS Resolver Configuration with Public Fallback (ensures reliability in local dev & serverless containers)
const resolver = new Resolver({ timeout: 3000 });
try {
  const currentServers = resolver.getServers();
  if (!currentServers || currentServers.length === 0 || (currentServers.length === 1 && currentServers[0] === "127.0.0.1")) {
    resolver.setServers(["8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1"]);
  }
} catch (e) {
  try {
    resolver.setServers(["8.8.8.8", "1.1.1.1"]);
  } catch (_) {}
}

/**
 * Normalizes an email address (Trims whitespace, applies NFKC unicode normalization, and lowercases).
 * @param {string} rawEmail
 * @returns {string} Normalized email
 */
export function normalizeEmail(rawEmail) {
  if (typeof rawEmail !== "string") return "";
  return rawEmail
    .normalize("NFKC")
    .replace(/[\u200B-\u200D\uFEFF]/g, "") // Strip zero-width chars
    .trim()
    .toLowerCase();
}

/**
 * Validates the syntax and length boundaries of an email string.
 * @param {string} email
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateEmailSyntax(email) {
  if (!email || typeof email !== "string") {
    return { valid: false, error: "البريد الإلكتروني مطلوب وغير صالح" };
  }

  // RFC 5321 length limits: Total <= 254 chars, Local-part <= 64 chars, Domain <= 253 chars
  if (email.length > 254) {
    return { valid: false, error: "طول البريد الإلكتروني يتجاوز الحد الأقصى المسموح (254 حرفاً)" };
  }

  if (email.includes("\0") || email.includes("\r") || email.includes("\n")) {
    return { valid: false, error: "البريد الإلكتروني يحتوي على محارف غير مسموح بها (Null byte or CRLF injection)" };
  }

  const atIndex = email.lastIndexOf("@");
  if (atIndex <= 0 || atIndex === email.length - 1) {
    return { valid: false, error: "صيغة البريد الإلكتروني غير صحيحة (مفقود أو غير مكتمل)" };
  }

  const localPart = email.slice(0, atIndex);
  const domainPart = email.slice(atIndex + 1);

  if (localPart.length > 64) {
    return { valid: false, error: "اسم المستخدم بالبريد يتجاوز 64 حرفاً" };
  }

  if (domainPart.length > 253) {
    return { valid: false, error: "نطاق البريد يتجاوز 253 حرفاً" };
  }

  if (localPart.startsWith(".") || localPart.endsWith(".") || localPart.includes("..")) {
    return { valid: false, error: "البريد الإلكتروني يحتوي على نقاط متتالية أو غير صالحة" };
  }

  if (!EMAIL_SYNTAX_REGEX.test(email)) {
    return { valid: false, error: "صيغة البريد الإلكتروني غير مطابقة للمعايير القياسية (RFC 5322)" };
  }

  return { valid: true };
}

/**
 * Checks whether an email domain or any of its parent domains is a known disposable/temporary domain.
 * Supports subdomain traversal: e.g. "user@sub.mailinator.com" -> checks "sub.mailinator.com" then "mailinator.com".
 * @param {string} domain
 * @returns {boolean} True if disposable
 */
export function isDisposableDomain(domain) {
  if (!domain || typeof domain !== "string") return false;
  const cleanDomain = domain.trim().toLowerCase();

  // 1. Direct O(1) Set lookup
  if (DISPOSABLE_DOMAINS_SET.has(cleanDomain)) {
    return true;
  }

  // 2. Subdomain traversal check
  const parts = cleanDomain.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    const parentDomain = parts.slice(i).join(".");
    if (DISPOSABLE_DOMAINS_SET.has(parentDomain)) {
      return true;
    }
  }

  // 3. Keyword heuristic on known temp-mail patterns
  if (
    cleanDomain.startsWith("tempmail") ||
    cleanDomain.startsWith("temp-mail") ||
    cleanDomain.startsWith("guerrillamail") ||
    cleanDomain.startsWith("10minutemail") ||
    cleanDomain.includes("disposable") ||
    cleanDomain.includes("throwaway") ||
    cleanDomain.includes("fakeinbox")
  ) {
    return true;
  }

  return false;
}

/**
 * Verifies existence of real MX records for the domain via dns/promises with strict timeout (<= 3s).
 * Rejects RFC 7505 Null-MX records (exchange === "." or empty).
 * @param {string} domain
 * @param {number} timeoutMs Max timeout in milliseconds (default: 3000ms)
 * @returns {Promise<{ hasMx: boolean, error?: string, mxRecords?: Array }>}
 */
export async function checkMxRecords(domain, timeoutMs = 3000) {
  if (!domain || typeof domain !== "string") {
    return { hasMx: false, error: "اسم النطاق غير صالح" };
  }

  const cleanDomain = domain.trim().toLowerCase();

  // Fail-fast for localhost, loopback, or invalid TLD
  if (
    cleanDomain === "localhost" ||
    cleanDomain.endsWith(".local") ||
    cleanDomain.endsWith(".internal") ||
    cleanDomain.endsWith(".test") ||
    cleanDomain.endsWith(".invalid")
  ) {
    return { hasMx: false, error: "النطاق المحلي أو الداخلي غير صالح للاستخدام" };
  }

  let timerHandle;
  const timeoutPromise = new Promise((_, reject) => {
    timerHandle = setTimeout(() => {
      const err = new Error(`DNS MX lookup timed out after ${timeoutMs}ms`);
      err.code = "ETIMEDOUT";
      reject(err);
    }, timeoutMs);
  });

  try {
    const mxRecords = await Promise.race([
      resolver.resolveMx(cleanDomain),
      timeoutPromise
    ]);

    if (!Array.isArray(mxRecords) || mxRecords.length === 0) {
      return { hasMx: false, error: "لا توجد سجلات بريد (MX Records) مسجلة لهذا النطاق" };
    }

    // RFC 7505 Null MX Detection: If only record has priority 0 and exchange "." it explicitly refuses emails!
    const validRecords = mxRecords.filter(record => {
      if (!record || !record.exchange) return false;
      const ex = String(record.exchange).trim().toLowerCase();
      return ex !== "." && ex !== "localhost" && ex !== "0.0.0.0" && ex.length > 0;
    });

    if (validRecords.length === 0) {
      return { hasMx: false, error: "نطاق البريد يرفض استلام الرسائل وفق المعيار RFC 7505 (Null MX)" };
    }

    return { hasMx: true, mxRecords: validRecords };
  } catch (err) {
    if (err.code === "ETIMEDOUT") {
      return { hasMx: false, error: `استغرق فحص سجلات النطاق وقتاً أطول من المسموح (${timeoutMs / 1000} ثوانٍ)` };
    }
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      return { hasMx: false, error: "النطاق غير موجود أو لا يحتوي على سجلات بريد نشطة (MX Records)" };
    }
    return { hasMx: false, error: `تعذر التحقق من نطاق البريد عبر DNS: ${err.code || err.message}` };
  } finally {
    if (timerHandle) clearTimeout(timerHandle);
  }
}

/**
 * Full Email Validator: Performs Syntax, Disposable Domain & DNS MX verification.
 * 
 * @param {string} rawEmail The email to validate
 * @param {object} options Options { checkMx: true, timeoutMs: 3000 }
 * @returns {Promise<{ valid: boolean, normalizedEmail?: string, domain?: string, reason?: string, error?: string }>}
 */
export async function validateEmail(rawEmail, options = {}) {
  const { checkMx = true, timeoutMs = 3000 } = options;

  // 1. Normalize
  const normalized = normalizeEmail(rawEmail);
  if (!normalized) {
    return {
      valid: false,
      reason: "EMPTY_EMAIL",
      error: "يرجى إدخال البريد الإلكتروني"
    };
  }

  // 2. Syntax Validation
  const syntaxCheck = validateEmailSyntax(normalized);
  if (!syntaxCheck.valid) {
    return {
      valid: false,
      reason: "INVALID_SYNTAX",
      error: syntaxCheck.error
    };
  }

  const atIndex = normalized.lastIndexOf("@");
  const domain = normalized.slice(atIndex + 1);

  // 3. Disposable Domain Blocking (O(1) Set)
  if (isDisposableDomain(domain)) {
    return {
      valid: false,
      normalizedEmail: normalized,
      domain,
      reason: "DISPOSABLE_EMAIL",
      error: "غير مسموح بالتسجيل باستخدام بريد إلكتروني مؤقت أو وهمي (Disposable Email Blocked). يرجى استخدام بريد شخصي أو عمل حقيقي."
    };
  }

  // 4. DNS MX Record Verification (Max 3s timeout)
  if (checkMx) {
    const mxResult = await checkMxRecords(domain, timeoutMs);
    if (!mxResult.hasMx) {
      return {
        valid: false,
        normalizedEmail: normalized,
        domain,
        reason: "NO_MX_RECORDS",
        error: `نطاق البريد الإلكتروني (${domain}) غير صالح أو لا يستقبل رسائل بريدية حقيقية (Missing MX Records).`
      };
    }
  }

  return {
    valid: true,
    normalizedEmail: normalized,
    domain,
    reason: "VALID"
  };
}

export default validateEmail;
