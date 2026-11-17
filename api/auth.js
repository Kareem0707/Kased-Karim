// Vercel Serverless Function: /api/auth
// Executive Admin Authentication Gate & Token Issuance with Mandatory 2-Factor Authentication (2FA OTP)
import {
  createAdminToken,
  verifyAdminRequest,
  verifyAdminPassword,
  generate6DigitOTP,
  save2FAOTP,
  verify2FAOTP,
  send2FAEmail,
  ADMIN_2FA_EMAILS,
  maskEmail,
  setSecurityHeaders
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// In-Memory Brute-Force Rate Limiter (per serverless instance) (F-18)
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

function checkRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record) return { allowed: true };

  if (record.lockedUntil && record.lockedUntil > now) {
    const remainingSec = Math.ceil((record.lockedUntil - now) / 1000);
    return { allowed: false, remainingSec };
  }

  if (now - record.firstAttempt > LOCKOUT_MS) {
    loginAttempts.delete(ip);
    return { allowed: true };
  }

  if (record.count >= MAX_ATTEMPTS) {
    record.lockedUntil = now + LOCKOUT_MS;
    return { allowed: false, remainingSec: Math.ceil(LOCKOUT_MS / 1000) };
  }

  return { allowed: true };
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, firstAttempt: now };
  record.count += 1;
  loginAttempts.set(ip, record);
}

function resetAttempts(ip) {
  loginAttempts.delete(ip);
}

export default async function handler(req, res) {
  setSecurityHeaders(req, res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const clientIp = req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown_ip";

  try {
    // 1. GET: Verify active session token
    if (req.method === "GET") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ authenticated: false, error: "جلسة الدخول غير صالحة أو منتهية" });
      }
      return res.status(200).json({
        authenticated: true,
        user: { role: "admin", name: "Kased Karim Admin" },
        expiresAt: admin.exp
      });
    }

    // 2. POST: 2-Step Authentication (Password -> 6-Digit Email OTP -> Token)
    if (req.method === "POST") {
      const rateCheck = checkRateLimit(clientIp);
      if (!rateCheck.allowed) {
        return res.status(429).json({
          success: false,
          error: `تم تجاوز الحد الأقصى للمحاولات الخاطئة. يرجى الانتظار ${rateCheck.remainingSec} ثانية قبل إعادة المحاولة.`
        });
      }

      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      body = body || {};

      // =======================================================================
      // STEP 2: VERIFY 6-DIGIT EMAIL OTP (MANDATORY MFA)
      // =======================================================================
      if (body.action === "verify_otp" || (body.otp && !body.password)) {
        const inputOtp = String(body.otp || "").trim().replace(/[^0-9]/g, "");
        if (!inputOtp || inputOtp.length !== 6) {
          return res.status(400).json({ success: false, error: "يرجى إدخال رمز التحقق السداسي المكون من 6 أرقام" });
        }

        const isOtpValid = await verify2FAOTP(inputOtp);
        if (!isOtpValid) {
          recordFailedAttempt(clientIp);
          await new Promise(r => setTimeout(r, 600)); // Constant delay against timing analysis
          return res.status(401).json({
            success: false,
            error: "رمز التحقق السداسي غير صحيح أو انتهت صلاحيته (5 دقائق - حد أقصى 3 محاولات)"
          });
        }

        // OTP Verified: Reset limits and issue short-lived JWT session token (2 hours) (F-10)
        resetAttempts(clientIp);
        const token = createAdminToken({ sub: "executive-admin", ip: clientIp, verified2FA: true }, 2 * 60 * 60 * 1000);
        
        // Secure HttpOnly Cookie (F-10)
        res.setHeader("Set-Cookie", `kk_admin_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=7200; Secure`);

        return res.status(200).json({
          success: true,
          token,
          user: { role: "admin", name: "Kased Karim Admin" },
          message: "تم التحقق الأمني بنجاح ومصادقة هذا الجهاز كجهاز إدارة معتمد"
        });
      }

      // =======================================================================
      // STEP 1: VERIFY PASSWORD & DISPATCH 6-DIGIT EMAIL OTP
      // =======================================================================
      const password = (body.password || body.pin || body.key || "").trim();

      if (!password) {
        return res.status(400).json({ success: false, error: "يرجى إدخال رمز الدخول السري" });
      }

      const isValid = verifyAdminPassword(password);
      if (!isValid) {
        recordFailedAttempt(clientIp);
        await new Promise(r => setTimeout(r, 600));
        return res.status(401).json({
          success: false,
          error: "رمز الدخول السري غير صحيح"
        });
      }

      // MANDATORY 2FA ENFORCEMENT: All password entries require OTP verification (F-13: NO BYPASSES)
      const otpCode = generate6DigitOTP();
      await save2FAOTP(otpCode);
      const emailResult = await send2FAEmail(otpCode, ADMIN_2FA_EMAILS);

      return res.status(200).json({
        success: true,
        step: "otp_required",
        message: "تم إرسال كود التحقق الأمني السداسي إلى البريد المعتمد للإدارة الرئيسية.",
        emailDispatched: emailResult.dispatched,
        maskedEmails: ADMIN_2FA_EMAILS.map(maskEmail)
      });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
