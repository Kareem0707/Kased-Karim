// Vercel Serverless Function: /api/auth
// Executive Admin Authentication Gate & Token Issuance
import { createAdminToken, verifyAdminRequest, verifyAdminPassword } from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// In-Memory Brute-Force Rate Limiter (per serverless instance)
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
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin-token");

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

    // 2. POST: Authenticate with PIN / Password
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

      const password = (body && (body.password || body.pin || body.key)) || "";

      if (!password || typeof password !== "string") {
        return res.status(400).json({ success: false, error: "يرجى إدخال رمز الدخول" });
      }

      const isValid = verifyAdminPassword(password);

      if (!isValid) {
        recordFailedAttempt(clientIp);
        // Delay to prevent rapid-fire brute-force timing attacks
        await new Promise(r => setTimeout(r, 600));
        return res.status(401).json({
          success: false,
          error: "رمز الدخول السري غير صحيح"
        });
      }

      // Success: Reset rate limit and issue JWT token
      resetAttempts(clientIp);
      const token = createAdminToken({ sub: "executive-admin", ip: clientIp });

      // Return token in payload and HttpOnly cookie
      res.setHeader("Set-Cookie", `kk_admin_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Secure`);

      return res.status(200).json({
        success: true,
        token,
        user: { role: "admin", name: "Kased Karim Admin" },
        message: "تم تسجيل الدخول بنجاح"
      });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
