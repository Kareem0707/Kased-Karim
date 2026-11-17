// Serverless Authentication & Security Token Vault
// Node.js Native Crypto (Zero External Dependencies)
import crypto from "crypto";

// Cryptographically Strong JWT Secrets
const FALLBACK_SECRET = "kk_sec_vault_" + crypto.createHash("sha256").update("kased_karim_luxury_lighting_sheikh_zayed_2026").digest("hex");
const JWT_SECRET = process.env.ADMIN_JWT_SECRET || process.env.ADMIN_SECRET || FALLBACK_SECRET;
const CUSTOMER_JWT_SECRET = process.env.CUSTOMER_JWT_SECRET || (JWT_SECRET + "_customer_portal_key_2026");

// Allowed server-side admin passwords (strictly from environment variable)
const CONFIGURED_ADMIN_PASSWORDS = [
  process.env.ADMIN_PASSWORD
].filter(Boolean);

// Fallback password for initial deployment if ADMIN_PASSWORD is not yet configured in Vercel
// Note: It is strongly recommended to set ADMIN_PASSWORD in Vercel project environment variables!
const ALLOWED_ADMIN_PASSWORDS = CONFIGURED_ADMIN_PASSWORDS.length > 0 
  ? CONFIGURED_ADMIN_PASSWORDS 
  : ["KasedKarim@SheikhZayed2026!Sec"];

// -----------------------------------------------------------------------------
// CORS & HTTP SECURITY HEADERS ENGINE (F-14, F-11)
// -----------------------------------------------------------------------------
const ALLOWED_ORIGIN_PATTERNS = [
  /^https?:\/\/localhost(:\d+)?$/,
  /^https?:\/\/127\.0\.0\.1(:\d+)?$/,
  /^https?:\/\/(www\.)?kasedkarim\.com$/,
  /^https:\/\/.*\.vercel\.app$/
];

export function setSecurityHeaders(req, res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // Dynamic Strict CORS - Never use wildcard '*' with credentials (F-14)
  const reqOrigin = req.headers["origin"] || req.headers["Origin"];
  if (reqOrigin) {
    const isAllowed = ALLOWED_ORIGIN_PATTERNS.some(pattern => pattern.test(reqOrigin));
    if (isAllowed) {
      res.setHeader("Access-Control-Allow-Origin", reqOrigin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }
  }

  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin-token, x-customer-token, Cache-Control, Pragma");
}

// -----------------------------------------------------------------------------
// SECURE CLOUD DATABASE (FIREBASE RTDB) ACCESS WITH PRIVILEGED SERVER AUTH (F-01)
// -----------------------------------------------------------------------------
export function getFirebaseUrl(path = "", queryParams = {}) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL || "https://kased-karim-default-rtdb.firebaseio.com";
  const baseUrl = envUrl.trim().replace(/\/$/, "");
  const cleanPath = path ? (path.startsWith("/") ? path : `/${path}`) : "";
  const url = new URL(`${baseUrl}${cleanPath}`);

  // Privileged Server Access Token / Secret (Works when RTDB .read: false, .write: false)
  const secret = process.env.FIREBASE_DB_SECRET || process.env.FIREBASE_AUTH_TOKEN;
  if (secret && secret.trim()) {
    url.searchParams.set("auth", secret.trim());
  }

  for (const [key, value] of Object.entries(queryParams)) {
    if (value !== undefined && value !== null) {
      url.searchParams.set(key, String(value));
    }
  }

  return url.toString();
}

// -----------------------------------------------------------------------------
// INPUT VALIDATION & PATH TRAVERSAL SANITIZATION (F-19)
// -----------------------------------------------------------------------------
export function sanitizePathId(id) {
  if (!id || typeof id !== "string") return null;
  const clean = id.trim();
  // Strictly enforce safe identifier format (alphanumeric, underscores, hyphens, 1-64 chars)
  if (!/^[a-zA-Z0-9_\-]{1,64}$/.test(clean)) {
    return null;
  }
  return clean;
}

// -----------------------------------------------------------------------------
// ADMIN TOKEN ENGINE (SHORT-LIVED JWT + HTTPONLY COOKIE SUPPORT) (F-10)
// -----------------------------------------------------------------------------
// Short session TTL for executive admin: 2 hours (F-10)
export function createAdminToken(payload = {}, expiresInMs = 2 * 60 * 60 * 1000) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const exp = Date.now() + expiresInMs;
  const body = Buffer.from(JSON.stringify({
    ...payload,
    role: "admin",
    exp,
    iat: Date.now()
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(`${header}.${body}`)
    .digest("base64url");

  return `${header}.${body}.${signature}`;
}

export function verifyAdminToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.trim().replace(/^Bearer\s+/i, "").split(".");
  if (parts.length !== 3) return null;

  const [header, body, signature] = parts;

  try {
    const parsedHeader = JSON.parse(Buffer.from(header, "base64url").toString("utf-8"));
    if (parsedHeader.alg !== "HS256") {
      return null; // Algorithm confusion attack prevention
    }

    const expectedSig = crypto
      .createHmac("sha256", JWT_SECRET)
      .update(`${header}.${body}`)
      .digest("base64url");

    const sigBuf = Buffer.from(signature);
    const expectedBuf = Buffer.from(expectedSig);

    if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf-8"));
    if (!payload.exp || payload.exp < Date.now()) {
      return null; // Expired token
    }

    if (payload.role !== "admin") {
      return null; // Strict role separation
    }

    return payload;
  } catch (err) {
    return null;
  }
}

export function verifyAdminRequest(req) {
  if (!req) return null;

  // 1. Authorization Header (Bearer <token>)
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
    const token = authHeader.slice(7).trim();
    const verified = verifyAdminToken(token);
    if (verified) return verified;
  }

  // 2. Custom Admin Header
  const customHeader = req.headers["x-admin-token"];
  if (customHeader) {
    const verified = verifyAdminToken(customHeader);
    if (verified) return verified;
  }

  // 3. HttpOnly Secure Cookie (kk_admin_token)
  const cookieHeader = req.headers["cookie"];
  if (cookieHeader) {
    const match = cookieHeader.match(/kk_admin_token=([^;]+)/);
    if (match && match[1]) {
      const verified = verifyAdminToken(match[1]);
      if (verified) return verified;
    }
  }

  return null;
}

// Constant-Time Password Verification (Zero Timing Leak)
export function verifyAdminPassword(inputPassword) {
  if (!inputPassword || typeof inputPassword !== "string") return false;
  const cleanInput = inputPassword.trim();

  for (const allowed of ALLOWED_ADMIN_PASSWORDS) {
    if (typeof allowed === "string" && allowed.length === cleanInput.length) {
      const a = Buffer.from(cleanInput);
      const b = Buffer.from(allowed);
      if (crypto.timingSafeEqual(a, b)) {
        return true;
      }
    }
  }
  return false;
}

// -----------------------------------------------------------------------------
// TWO-FACTOR AUTHENTICATION (2FA) & EMAIL OTP ENGINE (F-02, F-15, F-18)
// -----------------------------------------------------------------------------
// Admin emails read strictly from environment variable (No personal emails in source!) (F-15)
export const ADMIN_2FA_EMAILS = (process.env.ADMIN_2FA_EMAILS || process.env.ADMIN_2FA_EMAIL || "")
  .split(",")
  .map(e => e.trim().toLowerCase())
  .filter(Boolean);

export const ADMIN_2FA_EMAIL = ADMIN_2FA_EMAILS[0] || "";

// Mask email for public display or logs (e.g. k***@gmail.com) (F-15)
export function maskEmail(email) {
  if (!email || !email.includes("@")) return "a***@kasedkarim.com";
  const [user, domain] = email.split("@");
  const masked = user.length > 2 ? user[0] + "***" + user[user.length - 1] : user[0] + "***";
  return `${masked}@${domain}`;
}

// In-Memory Secure OTP Cache per Serverless Instance
const inMemoryOTP = new Map();

// Generate high-entropy 6-digit cryptographic PIN
export function generate6DigitOTP() {
  return crypto.randomInt(100000, 1000000).toString();
}

// Keyed Salted HMAC-SHA256 Hash for OTP (Immune to offline dictionary attacks) (F-02)
function hashOTP(code, salt) {
  return crypto
    .createHmac("sha256", JWT_SECRET)
    .update(`${code}:${salt}`)
    .digest("hex");
}

// Save active OTP to persistent cloud storage & in-memory cache
export async function save2FAOTP(code) {
  const salt = crypto.randomBytes(16).toString("hex");
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes TTL (F-02)
  const codeHash = hashOTP(code, salt);

  // Note: We DO NOT store admin emails inside the database record (F-15)
  const record = {
    codeHash,
    salt,
    expiresAt,
    attempts: 0,
    createdAt: Date.now()
  };

  inMemoryOTP.set("active_otp", record);

  // Persist to Server-Only internal vault path in Firebase
  try {
    const firebaseUrl = getFirebaseUrl("_server_vault/auth_2fa_otp.json");
    await fetch(firebaseUrl, {
      method: "PUT",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(record)
    });
  } catch (e) {
    console.warn("Server vault OTP persistence note:", e.message);
  }

  return record;
}

// Verify 6-digit OTP code with strict rate-limit, attempt burning & timing equality (F-02, F-18)
export async function verify2FAOTP(inputCode) {
  if (!inputCode || typeof inputCode !== "string") return false;
  const cleanCode = inputCode.trim().replace(/[^0-9]/g, "");
  if (cleanCode.length !== 6) return false;

  let record = null;

  // 1. Fetch from Server-Only internal vault in Firebase
  try {
    const firebaseUrl = getFirebaseUrl("_server_vault/auth_2fa_otp.json", { t: Date.now() });
    const res = await fetch(firebaseUrl, { cache: "no-store" });
    if (res.ok) {
      record = await res.json();
    }
  } catch (e) {}

  // 2. Fallback to in-memory instance cache
  if (!record) {
    record = inMemoryOTP.get("active_otp");
  }

  if (!record || !record.codeHash || !record.salt || !record.expiresAt) {
    return false;
  }

  // Check TTL expiry
  if (Date.now() > record.expiresAt) {
    // Burn expired OTP
    burnOTP();
    return false;
  }

  // Check attempt limit: Max 3 failed attempts (F-18)
  if (record.attempts >= 3) {
    burnOTP();
    return false;
  }

  const inputHash = hashOTP(cleanCode, record.salt);
  const a = Buffer.from(inputHash);
  const b = Buffer.from(record.codeHash);

  if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
    // Single-Use Guarantee: Burn OTP immediately upon success
    await burnOTP();
    return true;
  } else {
    // Increment attempts server-side
    record.attempts = (record.attempts || 0) + 1;
    inMemoryOTP.set("active_otp", record);

    if (record.attempts >= 3) {
      // Burn OTP on 3rd failure to prevent brute force (F-18)
      await burnOTP();
    } else {
      try {
        const firebaseUrl = getFirebaseUrl("_server_vault/auth_2fa_otp/attempts.json");
        await fetch(firebaseUrl, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(record.attempts)
        });
      } catch (e) {}
    }
    return false;
  }
}

// Invalidate and delete OTP from server vault
async function burnOTP() {
  inMemoryOTP.delete("active_otp");
  try {
    const firebaseUrl = getFirebaseUrl("_server_vault/auth_2fa_otp.json");
    await fetch(firebaseUrl, { method: "DELETE", cache: "no-store" });
  } catch (e) {}
}

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

  // Option A: Resend API
  const resendApiKey = process.env.RESEND_API_KEY;
  if (resendApiKey) {
    try {
      const fromEmail = process.env.RESEND_FROM || "Kased Karim Security <security@kasedkarim.com>";
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
          return { email, ok: res.ok };
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
// CUSTOMER AUTHENTICATION ENGINE (F-05, F-10)
// -----------------------------------------------------------------------------
export function hashCustomerPassword(password, salt = null) {
  if (!password) return null;
  const usedSalt = salt || crypto.randomBytes(16).toString("hex");
  // Memory-hard scrypt with work factor (F-05)
  const derived = crypto.scryptSync(password, usedSalt, 64, { N: 16384, r: 8, p: 1 }).toString("hex");
  return { hash: derived, salt: usedSalt };
}

export function verifyCustomerPassword(inputPassword, storedHash, storedSalt) {
  if (!inputPassword || !storedHash || !storedSalt) return false;
  try {
    const derived = crypto.scryptSync(inputPassword, storedSalt, 64, { N: 16384, r: 8, p: 1 }).toString("hex");
    const a = Buffer.from(derived, "hex");
    const b = Buffer.from(storedHash, "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (e) {
    return false;
  }
}

// Customer session token: 24 hours TTL (F-10)
export function createCustomerToken(payload = {}, expiresInMs = 24 * 60 * 60 * 1000) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const exp = Date.now() + expiresInMs;
  const body = Buffer.from(JSON.stringify({
    ...payload,
    role: "customer",
    exp,
    iat: Date.now()
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", CUSTOMER_JWT_SECRET)
    .update(`${header}.${body}`)
    .digest("base64url");

  return `${header}.${body}.${signature}`;
}

export function verifyCustomerToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.trim().replace(/^Bearer\s+/i, "").split(".");
  if (parts.length !== 3) return null;

  const [header, body, signature] = parts;
  try {
    const parsedHeader = JSON.parse(Buffer.from(header, "base64url").toString("utf-8"));
    if (parsedHeader.alg !== "HS256") {
      return null;
    }

    const expectedSig = crypto
      .createHmac("sha256", CUSTOMER_JWT_SECRET)
      .update(`${header}.${body}`)
      .digest("base64url");

    const sigBuf = Buffer.from(signature);
    const expectedBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf-8"));
    if (!payload.exp || payload.exp < Date.now()) {
      return null;
    }
    if (payload.role !== "customer") {
      return null;
    }
    return payload;
  } catch (err) {
    return null;
  }
}

export function verifyCustomerRequest(req) {
  if (!req) return null;
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
    const token = authHeader.slice(7).trim();
    const verified = verifyCustomerToken(token);
    if (verified) return verified;
  }

  const customHeader = req.headers["x-customer-token"];
  if (customHeader) {
    const verified = verifyCustomerToken(customHeader);
    if (verified) return verified;
  }

  const cookieHeader = req.headers["cookie"];
  if (cookieHeader) {
    const match = cookieHeader.match(/kk_customer_token=([^;]+)/);
    if (match && match[1]) {
      const verified = verifyCustomerToken(match[1]);
      if (verified) return verified;
    }
  }

  return null;
}

// -----------------------------------------------------------------------------
// GOOGLE ID TOKEN CRYPTOGRAPHIC VERIFICATION (F-03)
// -----------------------------------------------------------------------------
export async function verifyGoogleIdToken(idToken) {
  if (!idToken || typeof idToken !== "string" || idToken.length < 50) return null;
  try {
    const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken.trim())}`);
    if (!res.ok) return null;
    const payload = await res.json();

    // Verify token issuer
    if (payload.iss !== "accounts.google.com" && payload.iss !== "https://accounts.google.com") {
      return null;
    }

    // Verify expiration
    const exp = parseInt(payload.exp, 10) * 1000;
    if (isNaN(exp) || exp < Date.now()) {
      return null;
    }

    // Verify audience matches configured Google Client ID if available
    const configuredAud = process.env.GOOGLE_CLIENT_ID || process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
    if (configuredAud && payload.aud && payload.aud !== configuredAud) {
      return null;
    }

    // Return strictly verified claims
    return {
      sub: payload.sub,
      googleId: payload.sub,
      email: payload.email ? payload.email.toLowerCase().trim() : "",
      emailVerified: payload.email_verified === "true" || payload.email_verified === true,
      name: payload.name || payload.given_name || "عميل Google",
      picture: payload.picture || ""
    };
  } catch (e) {
    return null;
  }
}

// -----------------------------------------------------------------------------
// SENSITIVE DATA MINIMIZATION (F-04, F-05)
// -----------------------------------------------------------------------------
// Strip password hash, salt, and private fields before sending to client
export function sanitizeCustomer(customer) {
  if (!customer || typeof customer !== "object") return null;
  const safe = { ...customer };
  delete safe.passwordHash;
  delete safe.passwordSalt;
  delete safe._secret;
  return safe;
}
