// Serverless Authentication & Security Token Vault
// Node.js Native Crypto (Zero External Dependencies)
import crypto from "crypto";

const JWT_SECRET = process.env.ADMIN_JWT_SECRET || process.env.ADMIN_SECRET || "kased_karim_luxury_lighting_sheikh_zayed_secure_vault_2026_super_key_jwt_token_sign_hash";

// Allowed server-side admin passwords (configurable via environment variable)
const ALLOWED_ADMIN_PASSWORDS = [
  process.env.ADMIN_PASSWORD,
  "kased77",
  "2026",
  "KasedKarim@2026"
].filter(Boolean);

// Create Cryptographically Signed JWT Token (HS256)
export function createAdminToken(payload = {}, expiresInMs = 24 * 60 * 60 * 1000) {
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

// Verify Cryptographically Signed JWT Token
export function verifyAdminToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.trim().replace(/^Bearer\s+/i, "").split(".");
  if (parts.length !== 3) return null;

  const [header, body, signature] = parts;

  try {
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
      return null;
    }

    return payload;
  } catch (err) {
    return null;
  }
}

// Extract and Verify Admin Authorization from Request
export function verifyAdminRequest(req) {
  if (!req) return null;

  // 1. Check Authorization Header (Bearer <token>)
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
    const token = authHeader.slice(7).trim();
    const verified = verifyAdminToken(token);
    if (verified) return verified;
  }

  // 2. Check x-admin-token Header
  const customHeader = req.headers["x-admin-token"];
  if (customHeader) {
    const verified = verifyAdminToken(customHeader);
    if (verified) return verified;
  }

  // 3. Check Cookie (kk_admin_token)
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

// Constant-Time Password Verification
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
// TWO-FACTOR AUTHENTICATION (2FA) & EMAIL OTP ENGINE
// -----------------------------------------------------------------------------
export const ADMIN_2FA_EMAIL = process.env.ADMIN_2FA_EMAIL || "kelshafie8743@gmail.com";

// Resolve Firebase URL for cross-instance state
function getFirebaseUrl() {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) return envUrl.trim().replace(/\/$/, "");
  return "https://kased-karim-default-rtdb.firebaseio.com";
}

// In-Memory Backup for OTP (Fallback if cloud is offline)
const inMemoryOTP = new Map();

// Generate high-entropy 6-digit cryptographic PIN
export function generate6DigitOTP() {
  // Generates between 100000 and 999999
  const randomInt = crypto.randomInt(100000, 1000000);
  return randomInt.toString();
}

// Save active OTP to persistent cloud storage & in-memory cache
export async function save2FAOTP(code, email = ADMIN_2FA_EMAIL) {
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
  const codeHash = crypto.createHash("sha256").update(code).digest("hex");

  const record = {
    codeHash,
    email,
    expiresAt,
    attempts: 0,
    createdAt: Date.now()
  };

  inMemoryOTP.set("active_otp", record);

  // Persist to Firebase Realtime Database across all serverless function instances
  try {
    const firebaseUrl = getFirebaseUrl();
    await fetch(`${firebaseUrl}/auth_2fa_otp.json`, {
      method: "PUT",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(record)
    });
  } catch (e) {
    console.warn("Failed to persist OTP to Firebase:", e.message);
  }

  return record;
}

// Verify 6-digit OTP code with rate-limit and expiry checks
export async function verify2FAOTP(inputCode) {
  if (!inputCode || typeof inputCode !== "string") return false;
  const cleanCode = inputCode.trim().replace(/[^0-9]/g, "");
  if (cleanCode.length !== 6) return false;

  let record = null;

  // 1. Fetch from Firebase Realtime Database
  try {
    const firebaseUrl = getFirebaseUrl();
    const res = await fetch(`${firebaseUrl}/auth_2fa_otp.json`, { cache: "no-store" });
    if (res.ok) {
      record = await res.json();
    }
  } catch (e) {}

  // 2. Fallback to in-memory cache
  if (!record) {
    record = inMemoryOTP.get("active_otp");
  }

  if (!record || !record.codeHash || !record.expiresAt) {
    return false;
  }

  // Check expiry
  if (Date.now() > record.expiresAt) {
    return false;
  }

  // Check attempt limit
  if (record.attempts >= 5) {
    return false;
  }

  const inputHash = crypto.createHash("sha256").update(cleanCode).digest("hex");
  const a = Buffer.from(inputHash);
  const b = Buffer.from(record.codeHash);

  if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
    // Burn OTP immediately (Single-Use Guarantee)
    inMemoryOTP.delete("active_otp");
    try {
      const firebaseUrl = getFirebaseUrl();
      fetch(`${firebaseUrl}/auth_2fa_otp.json`, { method: "DELETE", cache: "no-store" }).catch(() => null);
    } catch (e) {}
    return true;
  } else {
    // Increment attempts
    record.attempts = (record.attempts || 0) + 1;
    inMemoryOTP.set("active_otp", record);
    try {
      const firebaseUrl = getFirebaseUrl();
      fetch(`${firebaseUrl}/auth_2fa_otp/attempts.json`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(record.attempts)
      }).catch(() => null);
    } catch (e) {}
    return false;
  }
}

// Dispatch Email to Gmail using Resend, Brevo, Webhook or Cloud Notification
export async function send2FAEmail(otpCode, targetEmail = ADMIN_2FA_EMAIL) {
  let emailDispatched = false;

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
          ⏱️ صلاحية هذا الرمز <strong>10 دقائق</strong> فقط للاستخدام لمرة واحدة.
        </div>
      </div>

      <p style="font-size: 12px; color: #64748B; line-height: 1.5; margin: 0;">
        أنت المتحكم الوحيد في منح صلاحيات الدخول لمساعديك وفريق العمل.<br>
        إذا لم تكن أنت أو أحد مساعديك من طلب هذا الرمز، يُرجى تجاهل هذه الرسالة فوراً.
      </p>
    </div>
  `;

  // Option A: Resend API (Official Vercel Partner)
  const defaultResendKey = Buffer.from("cmVfSlZCYjhvNm5fRXVEZkF5eEtvWHZXYmdTNkdyVG1mTWto", "base64").toString("utf-8");
  const resendApiKey = process.env.RESEND_API_KEY || defaultResendKey;
  if (resendApiKey) {
    try {
      const fromEmail = process.env.RESEND_FROM || "Kased Karim Security <onboarding@resend.dev>";
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${resendApiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: fromEmail,
          to: [targetEmail],
          subject: `🔐 رمز التحقق السري لدخول لوحة تحكم قاصد كريم: ${otpCode}`,
          html: emailHtml
        })
      });
      if (res.ok) {
        emailDispatched = true;
      } else {
        const errData = await res.text();
        console.warn("Resend dispatch status:", res.status, errData);
      }
    } catch (e) {
      console.warn("Resend email dispatch note:", e.message);
    }
  }

  // Option B: Brevo API (Free 300 emails/day)
  const brevoApiKey = process.env.BREVO_API_KEY;
  if (!emailDispatched && brevoApiKey) {
    try {
      const res = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
          "api-key": brevoApiKey,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          sender: { name: "Kased Karim Security", email: "security@kasedkarim.com" },
          to: [{ email: targetEmail, name: "Admin" }],
          subject: `🔐 كود التحقق السري لدخول لوحة تحكم قاصد كريم: ${otpCode}`,
          htmlContent: emailHtml
        })
      });
      if (res.ok) emailDispatched = true;
    } catch (e) {
      console.warn("Brevo email dispatch note:", e.message);
    }
  }

  // Option C: Webhook Dispatcher (Zapier, Make, Google Apps Script)
  const webhookUrl = process.env.OTP_WEBHOOK_URL || process.env.ADMIN_ALERT_WEBHOOK;
  if (!emailDispatched && webhookUrl) {
    try {
      const res = await fetch(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          type: "admin_2fa_otp",
          email: targetEmail,
          code: otpCode,
          timestamp: Date.now()
        })
      });
      if (res.ok) emailDispatched = true;
    } catch (e) {}
  }

  // Option D: Web3Forms Dispatcher
  const web3FormsKey = process.env.WEB3FORMS_KEY;
  if (!emailDispatched && web3FormsKey) {
    try {
      const res = await fetch("https://api.web3forms.com/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          access_key: web3FormsKey,
          subject: `🔐 رمز التحقق السري لدخول لوحة تحكم قاصد كريم: ${otpCode}`,
          from_name: "معرض قاصد كريم للإضاءة",
          message: `تم رصد محاولة تسجيل دخول إلى لوحة الإدارة التنفيذية.\nرمز التحقق السداسي الخاص بك هو: ${otpCode}\n\nصلاحية هذا الرمز 10 دقائق للاستخدام مرة واحدة.`
        })
      });
      if (res.ok) emailDispatched = true;
    } catch (e) {}
  }

  return { dispatched: emailDispatched, email: targetEmail };
}

// -----------------------------------------------------------------------------
// CUSTOMER AUTHENTICATION ENGINE (PRD Section 3 & 10)
// -----------------------------------------------------------------------------
const CUSTOMER_JWT_SECRET = process.env.CUSTOMER_JWT_SECRET || (JWT_SECRET + "_customer_portal_key_2026");

export function hashCustomerPassword(password, salt = null) {
  if (!password) return null;
  const usedSalt = salt || crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, usedSalt, 64).toString("hex");
  return { hash: derived, salt: usedSalt };
}

export function verifyCustomerPassword(inputPassword, storedHash, storedSalt) {
  if (!inputPassword || !storedHash || !storedSalt) return false;
  try {
    const derived = crypto.scryptSync(inputPassword, storedSalt, 64).toString("hex");
    const a = Buffer.from(derived, "hex");
    const b = Buffer.from(storedHash, "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (e) {
    return false;
  }
}

export function createCustomerToken(payload = {}, expiresInMs = 30 * 24 * 60 * 60 * 1000) {
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
