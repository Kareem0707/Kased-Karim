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
    <div dir="rtl" style="font-family: Arial, sans-serif; background-color: #0F172A; color: #FFFFFF; padding: 30px; border-radius: 12px; max-width: 520px; margin: 0 auto; text-align: center; border: 1px solid #C5A059;">
      <h2 style="color: #C5A059; margin-bottom: 8px;">معرض قاصد كريم للإضاءة الفاخرة</h2>
      <div style="font-size: 13px; color: #94A3B8; margin-bottom: 24px;">الفرع الرئيسي • الشيخ زايد</div>
      <p style="font-size: 15px; color: #E2E8F0; line-height: 1.6; margin-bottom: 20px;">
        تم رصد محاولة تسجيل دخول إلى لوحة الإدارة التنفيذية. رمز التحقق السداسي المؤقت الخاص بك هو:
      </p>
      <div style="background: rgba(197, 160, 89, 0.15); border: 2px dashed #C5A059; color: #F59E0B; font-size: 34px; font-weight: 800; letter-spacing: 8px; padding: 16px; border-radius: 8px; margin: 20px 0; font-family: monospace;">
        ${otpCode}
      </div>
      <p style="font-size: 13px; color: #94A3B8; margin-top: 20px;">
        ⏱️ هذا الرمز صالح للاستخدام مرة واحدة فقط ولمدة <strong>10 دقائق</strong>.<br>
        تم إرسال هذا الرمز إلى: <span style="color: #C5A059;">${targetEmail}</span><br>
        إذا لم تكن أنت من طلب هذا الرمز، يُرجى تجاهل هذه الرسالة فوراً.
      </p>
    </div>
  `;

  // Option A: Resend API (Official Vercel Partner)
  const resendApiKey = process.env.RESEND_API_KEY;
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

  return { dispatched: emailDispatched, email: targetEmail };
}
