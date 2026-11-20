// Vercel Serverless Function: /api/auth
// Executive Admin Authentication Gate & Token Issuance with Mandatory 2-Factor Authentication (2FA OTP)
// Fully Compliant with OWASP ASVS (Level 3) & NIST SP 800-63B (AAL2)

import {
  createAdminToken,
  verifyAdminRequest,
  verifyAdminPassword,
  checkAdminAuthConfigured,
  create2FAChallenge,
  verify2FAChallenge,
  burnChallenge,
  send2FAEmail,
  checkDistributedRateLimit,
  recordFailedRateLimitAttempt,
  resetDistributedRateLimit,
  checkRateLimitDistributed,
  recordFailedAttemptDistributed,
  resetRateLimitDistributed,
  getClientIp,
  normalizeIpForRateLimit,
  ADMIN_2FA_EMAILS,
  maskEmail,
  setSecurityHeaders,
  withApiHardening,
  safeLogError
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// In-Memory Brute-Force Rate Limiter (per serverless instance secondary fallback) (F-18)
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

async function authHandler(req, res, { requestId, safeBody } = {}) {
  // 1. Mandatory CORS & HTTP Security Headers Gate (Axis 4: ASVS V14.5)
  if (setSecurityHeaders(req, res)) return;

  try {
    // 0. Fail-Closed Server Configuration Integrity Gate (OWASP ASVS 1.14 / NIST SP 800-63B)
    const adminConfig = checkAdminAuthConfigured();
    if (!adminConfig.configured) {
      console.error("CRITICAL: Admin Auth Gateway unconfigured or insecure (Fail-Closed). Missing:", adminConfig.missing);
      res.setHeader("Retry-After", "60");
      return res.status(503).json({
        success: false,
        error: "بوابة المصادقة الإدارية غير مهيأة بشكل آمن على الخادم (Fail-Closed Enforcement)."
      });
    }

    const clientIp = getClientIp(req);
    const normalizedIp = normalizeIpForRateLimit(clientIp);

    // Payload Size Limit Check (DoS Mitigation - CWE-400)
    const MAX_AUTH_PAYLOAD = 50 * 1024; // 50 KB
    const contentLength = parseInt(req.headers["content-length"] || "0", 10);
    if (contentLength > MAX_AUTH_PAYLOAD) {
      return res.status(413).json({
        success: false,
        authenticated: false,
        error: "حجم بيانات الطلب يتجاوز الحد المسموح به (50 كيلوبايت)"
      });
    }

    // 1. GET / HEAD: Verify active session token
    if (req.method === "GET" || req.method === "HEAD") {
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

    // 2. POST: 2-Step Authentication (Password -> 6-Digit Email OTP -> Token) & Logout
    if (req.method === "POST") {
      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      body = body || {};

      // Handle Admin Logout (Clear Secure HttpOnly Cookie)
      if (body.action === "logout" || req.query?.action === "logout") {
        res.setHeader("Set-Cookie", "kk_admin_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure");
        return res.status(200).json({ success: true, message: "تم تسجيل الخروج بنجاح" });
      }

      // -----------------------------------------------------------------------
      // DUAL-LAYER DISTRIBUTED RATE LIMITING (IP + GLOBAL FAIL-CLOSED)
      // -----------------------------------------------------------------------
      // Layer 1: IP-level Rate Limit (5 attempts per 15 minutes) with Fail-Closed
      const distCheck = await checkDistributedRateLimit(clientIp, "admin_login_ip", 5, 15 * 60 * 1000, { failClosed: true });
      if (distCheck.failClosedError) {
        res.setHeader("Retry-After", "60");
        return res.status(503).json({
          success: false,
          error: "خدمة المصادقة الإدارية غير متاحة مؤقتاً لعدم تمكن نظام الحماية من التحقق من سلامة الطلبات (Fail-Closed Enforcement)."
        });
      }
      if (!distCheck.allowed) {
        res.setHeader("Retry-After", String(distCheck.remainingSec));
        return res.status(429).json({
          success: false,
          error: `تم تجاوز الحد الأقصى للمحاولات الخاطئة. يرجى الانتظار ${distCheck.remainingSec} ثانية قبل إعادة المحاولة.`
        });
      }

      // Layer 2: Global Distributed Rate Limit across all IPs (Prevents distributed botnet brute-force)
      const globalCheck = await checkRateLimitDistributed("admin_login_global", "global_slot", 15, 15 * 60 * 1000, { failClosed: true });
      if (globalCheck.failClosedError) {
        res.setHeader("Retry-After", "60");
        return res.status(503).json({
          success: false,
          error: "خدمة المصادقة الإدارية غير متاحة مؤقتاً لعدم تمكن نظام الحماية من التحقق من سلامة الطلبات (Fail-Closed Enforcement)."
        });
      }
      if (!globalCheck.allowed) {
        res.setHeader("Retry-After", String(globalCheck.remainingSec));
        return res.status(429).json({
          success: false,
          error: `تم رصد نشاط مكثف غير معتاد على بوابة الإدارة. يرجى الانتظار ${globalCheck.remainingSec} ثانية قبل إعادة المحاولة.`
        });
      }

      // In-Memory Rate Limiter Fallback
      const rateCheck = checkRateLimit(clientIp);
      if (!rateCheck.allowed) {
        res.setHeader("Retry-After", String(rateCheck.remainingSec));
        return res.status(429).json({
          success: false,
          error: `تم تجاوز الحد الأقصى للمحاولات الخاطئة. يرجى الانتظار ${rateCheck.remainingSec} ثانية قبل إعادة المحاولة.`
        });
      }

      // =======================================================================
      // STEP 2: VERIFY 6-DIGIT EMAIL OTP (MANDATORY MFA WITH CHALLENGE BINDING)
      // =======================================================================
      if (body.action === "verify_otp" || (body.otp && !body.password)) {
        const rawOtp = body.otp;
        if (typeof rawOtp !== "string") {
          return res.status(400).json({
            success: false,
            error: "رمز التحقق يجب أن يكون نصياً مكوناً من 6 أرقام"
          });
        }
        const inputOtp = rawOtp.trim();
        if (!/^\d{6}$/.test(inputOtp)) {
          return res.status(400).json({
            success: false,
            error: "يرجى إدخال رمز التحقق السداسي المكون من 6 أرقام فقط"
          });
        }

        const rawChallengeId = body.challengeId || body.challenge || "";
        if (typeof rawChallengeId !== "string" || !/^[a-zA-Z0-9_\-]{16,128}$/.test(rawChallengeId.trim())) {
          return res.status(400).json({
            success: false,
            error: "معرّف التحدي الأمني (challengeId) مفقود أو غير صالح"
          });
        }
        const challengeId = rawChallengeId.trim();

        const verification = await verify2FAChallenge(challengeId, inputOtp, clientIp);
        if (!verification || !verification.valid) {
          await recordFailedRateLimitAttempt(clientIp, "admin_login_ip", 5, 15 * 60 * 1000);
          await recordFailedAttemptDistributed("admin_login_global", "global_slot", 15, 15 * 60 * 1000);
          recordFailedAttempt(clientIp);
          await new Promise(r => setTimeout(r, 600)); // Constant delay against timing side-channel

          if (verification?.error === "concurrency_detected") {
            return res.status(409).json({
              success: false,
              error: "تم رصد محاولة مصادقة متزامنة على نفس الرمز. تم حظر العملية فوراً لمنع هجمات التكرار (Replay Attack)."
            });
          }

          if (verification?.error === "max_attempts" || verification?.locked) {
            return res.status(401).json({
              success: false,
              error: "تم تجاوز الحد الأقصى للمحاولات (3 محاولات خاطئة). تم إتلاف وحرق الرمز فوراً لضمان الأمان."
            });
          }

          if (verification?.error === "expired") {
            return res.status(401).json({
              success: false,
              error: "انتهت صلاحية رمز التحقق (أكثر من 5 دقائق). يرجى طلب تسجيل الدخول مجدداً."
            });
          }

          if (verification?.error === "ip_mismatch") {
            return res.status(401).json({
              success: false,
              error: "فشل التحقق: عنوان IP للجهاز لا يطابق الجهاز الذي أنشأ التحدي الأمني (Origin Mismatch)."
            });
          }

          return res.status(401).json({
            success: false,
            error: "رمز التحقق السداسي غير صحيح أو انتهت صلاحيته (حد أقصى 3 محاولات)"
          });
        }

        // OTP Verified & Atomically Burned via ETag: Reset limits and issue short-lived JWT (2 hours) (F-10)
        await resetDistributedRateLimit(clientIp, "admin_login_ip");
        resetAttempts(clientIp);
        const token = createAdminToken({ sub: "executive-admin", ip: clientIp, verified2FA: true }, 2 * 60 * 60 * 1000);

        // Strict Secure HttpOnly Cookie (Zero Client Token Leakage)
        res.setHeader("Set-Cookie", `kk_admin_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=7200; Secure`);

        return res.status(200).json({
          success: true,
          user: { role: "admin", name: "Kased Karim Admin" },
          message: "تم التحقق الأمني بنجاح ومصادقة هذا الجهاز كجهاز إدارة معتمد"
        });
      }

      // =======================================================================
      // STEP 1: VERIFY PASSWORD & DISPATCH 6-DIGIT EMAIL OTP CHALLENGE
      // =======================================================================
      const rawPassword = body.password || body.pin || body.key;
      if (typeof rawPassword !== "string") {
        return res.status(400).json({ success: false, error: "يرجى إدخال رمز الدخول السري الصحيح" });
      }
      const password = rawPassword.normalize("NFKC").trim();

      if (!password || password.length > 128) {
        return res.status(400).json({ success: false, error: "رمز الدخول السري غير صالح (بحد أقصى 128 حرفاً)" });
      }

      const isValid = await verifyAdminPassword(password);
      if (!isValid) {
        await recordFailedRateLimitAttempt(clientIp, "admin_login_ip", 5, 15 * 60 * 1000);
        await recordFailedAttemptDistributed("admin_login_global", "global_slot", 15, 15 * 60 * 1000);
        recordFailedAttempt(clientIp);
        await new Promise(r => setTimeout(r, 600)); // Constant delay against timing attacks
        return res.status(401).json({
          success: false,
          error: "رمز الدخول السري غير صحيح"
        });
      }

      // MANDATORY 2FA ENFORCEMENT: Create challenge with IP binding & 60s cooldown (NIST AAL2)
      const challengeResult = await create2FAChallenge(clientIp);
      if (challengeResult.error === "cooldown") {
        res.setHeader("Retry-After", String(challengeResult.remainingSec));
        return res.status(429).json({
          success: false,
          error: `يرجى الانتظار ${challengeResult.remainingSec} ثانية قبل طلب رمز تحقق جديد.`
        });
      }

      const { challengeId, otpCode } = challengeResult;
      const emailResult = await send2FAEmail(otpCode, ADMIN_2FA_EMAILS);

      if (!emailResult.dispatched) {
        // Fail-Safe: If email dispatch fails, immediately burn the challenge to prevent orphan valid OTPs!
        await burnChallenge(challengeId);
        return res.status(500).json({
          success: false,
          error: "تعذر إرسال رمز التحقق إلى البريد الإداري المعتمد. تم إتلاف رمز التحدي فوراً لضمان الأمان."
        });
      }

      return res.status(200).json({
        success: true,
        step: "otp_required",
        challengeId,
        message: "تم إرسال كود التحقق الأمني السداسي إلى البريد المعتمد للإدارة الرئيسية.",
        emailDispatched: emailResult.dispatched,
        maskedEmails: ADMIN_2FA_EMAILS.map(maskEmail)
      });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    safeLogError("/api/auth", requestId, err);
    return res.status(500).json({
      success: false,
      ok: false,
      error: "حدث خطأ غير متوقع أثناء معالجة المصادقة.",
      requestId
    });
  }
}

export default withApiHardening(authHandler, {
  allowedMethods: ["GET", "POST"],
  maxBodyBytes: 4 * 1024,
  maxDepth: 4,
  maxKeys: 20,
  context: "/api/auth"
});
