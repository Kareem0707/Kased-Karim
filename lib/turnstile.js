/**
 * lib/turnstile.js
 * Cloudflare Turnstile Server-Side Verification Engine
 * 
 * Securely verifies Turnstile challenge response tokens against:
 * https://challenges.cloudflare.com/turnstile/v0/siteverify
 * Complies with OWASP Automated Threats (OAT-007 Credential Stuffing, OAT-019 Account Creation Flooding)
 */

const TURNSTILE_VERIFY_ENDPOINT = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const TIMEOUT_MS = 5000;

/**
 * Extracts Cloudflare Turnstile token from request body, query or headers.
 * @param {object} req Incoming HTTP request
 * @param {object} [parsedBody] Optional pre-parsed body object
 * @returns {string|null}
 */
export function extractTurnstileToken(req, parsedBody = null) {
  if (parsedBody && typeof parsedBody === "object") {
    if (typeof parsedBody.turnstileToken === "string" && parsedBody.turnstileToken.trim()) {
      return parsedBody.turnstileToken.trim();
    }
    if (typeof parsedBody["cf-turnstile-response"] === "string" && parsedBody["cf-turnstile-response"].trim()) {
      return parsedBody["cf-turnstile-response"].trim();
    }
    if (typeof parsedBody.turnstile === "string" && parsedBody.turnstile.trim()) {
      return parsedBody.turnstile.trim();
    }
  }

  if (req && req.body && typeof req.body === "object") {
    if (typeof req.body.turnstileToken === "string" && req.body.turnstileToken.trim()) {
      return req.body.turnstileToken.trim();
    }
    if (typeof req.body["cf-turnstile-response"] === "string" && req.body["cf-turnstile-response"].trim()) {
      return req.body["cf-turnstile-response"].trim();
    }
  }

  if (req && req.headers) {
    const headerToken = req.headers["cf-turnstile-response"] || req.headers["x-turnstile-token"];
    if (typeof headerToken === "string" && headerToken.trim()) {
      return headerToken.trim();
    }
  }

  return null;
}

/**
 * Verifies Turnstile token with Cloudflare API using process.env.TURNSTILE_SECRET_KEY.
 * 
 * @param {string} token The turnstile challenge response token from client
 * @param {string} [remoteIp] Optional client IP address
 * @returns {Promise<{ success: boolean, error?: string, errorCodes?: string[], hostname?: string }>}
 */
export async function verifyTurnstile(token, remoteIp = null) {
  const secretKey = process.env.TURNSTILE_SECRET_KEY;

  // Fail-Closed enforcement in production
  if (!secretKey) {
    if (process.env.NODE_ENV === "production") {
      console.error("[Turnstile] CRITICAL: TURNSTILE_SECRET_KEY environment variable is missing (Fail-Closed).");
      return {
        success: false,
        error: "حماية مكافحة الروبوتات غير مهيأة على الخادم (Fail-Closed)."
      };
    }
    console.warn("[Turnstile] WARNING: TURNSTILE_SECRET_KEY is not configured in local environment.");
    // In local non-production, if test token or dummy token provided with no secret configured, allow bypass only if explicitly enabled
    if (process.env.SKIP_TURNSTILE === "true") {
      return { success: true, bypass: true };
    }
  }

  // Cloudflare always-pass testing secret fallback if testing in development
  const effectiveSecret = secretKey || "1x0000000000000000000000000000000AA";

  if (!token || typeof token !== "string" || !token.trim()) {
    return {
      success: false,
      error: "رمز التحقق الأمني (Turnstile Token) مطلوب لإتمام العملية والتحقق من أنك لست روبوت."
    };
  }

  const cleanToken = token.trim();
  if (cleanToken.length < 10 || cleanToken.length > 2048) {
    return {
      success: false,
      error: "رمز التحقق الأمني غير صالح أو تالف."
    };
  }

  const formData = new URLSearchParams();
  formData.append("secret", effectiveSecret);
  formData.append("response", cleanToken);
  if (remoteIp && typeof remoteIp === "string") {
    formData.append("remoteip", remoteIp.trim());
  }

  try {
    const res = await fetch(TURNSTILE_VERIFY_ENDPOINT, {
      method: "POST",
      body: formData,
      headers: {
        "Accept": "application/json"
      },
      signal: AbortSignal.timeout(TIMEOUT_MS)
    });

    if (!res.ok) {
      console.warn(`[Turnstile] Cloudflare API responded with HTTP status ${res.status}`);
      return {
        success: false,
        error: "تعذر الاتصال بخدمة التحقق الأمني من Cloudflare حالياً."
      };
    }

    const data = await res.json();
    if (data && data.success === true) {
      return {
        success: true,
        hostname: data.hostname,
        challengeTs: data.challenge_ts
      };
    }

    const errorCodes = Array.isArray(data["error-codes"]) ? data["error-codes"] : [];
    console.warn("[Turnstile] Verification failed with codes:", errorCodes);

    return {
      success: false,
      errorCodes,
      error: "فشل التحقق من اختبار مكافحة الروبوتات (Cloudflare Turnstile). يرجى إعادة المحاولة."
    };
  } catch (err) {
    console.error("[Turnstile] Error during verification:", err.message);
    if (err.name === "TimeoutError") {
      return {
        success: false,
        error: "استغرق التحقق الأمني وقتاً أطول من المتوقع. يرجى إعادة المحاولة."
      };
    }
    return {
      success: false,
      error: "حدث خطأ أثناء فحص رمز التحقق الأمني."
    };
  }
}

export default verifyTurnstile;
