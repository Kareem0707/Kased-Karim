// Vercel Serverless Function: /api/customer
// Hardened Customer Account Management, Authentication & Isolated Order History
// Implements OWASP ASVS (Level 3), OWASP API Security Top 10 (API1: BOLA, API3: BOPLA, API5: BFLA)
// Strict Zero Cross-Account Access Guarantee & NIST SP 800-63B Compliance

import crypto from "crypto";
import { validateEmail } from "../lib/emailValidator.js";
import { verifyTurnstile, extractTurnstileToken } from "../lib/turnstile.js";
import { enforceRateLimit, getClientIp } from "../lib/rateLimit.js";
import {
  hashCustomerPassword,
  verifyCustomerPassword,
  sanitizeAndNormalizePassword,
  DUMMY_PASSWORD_HASH,
  DUMMY_PASSWORD_SALT,
  createCustomerToken,
  verifyCustomerRequest,
  requireVerifiedCustomer,
  sendCustomerVerificationEmail,
  verifyAdminRequest,
  verifyGoogleIdToken,
  sanitizeCustomer,
  sanitizePathId,
  getFirebaseUrl,
  firebaseFetch,
  buildSafeRtdbPath,
  assertSafeRtdbPayload,
  checkDistributedRateLimit,
  recordFailedRateLimitAttempt,
  resetDistributedRateLimit,
  checkRateLimitDistributed,
  recordFailedAttemptDistributed,
  resetRateLimitDistributed,
  normalizeIpForRateLimit,
  setSecurityHeaders,
  withApiHardening,
  safeLogError
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Whitelist of valid, permissible actions (ASVS 5.1.4)
const ALLOWED_ACTIONS = Object.freeze(new Set([
  "register",
  "login",
  "google",
  "google-login",
  "logout",
  "me",
  "orders",
  "update",
  "update_profile",
  "list",
  "verify_email",
  "resend_verification"
]));

/**
 * Fetches all customer records from Firebase RTDB safely
 */
async function fetchCustomers() {
  try {
    const res = await firebaseFetch(buildSafeRtdbPath("customers"), { cache: "no-store" }, { t: Date.now() });
    if (res.ok) {
      const data = await res.json();
      if (data && typeof data === "object") {
        return Object.values(data).filter(Boolean);
      }
    }
  } catch (e) {}
  return [];
}

/**
 * Persists a new customer record to Firebase RTDB using PUT
 */
async function saveCustomer(customer) {
  const safeId = sanitizePathId(customer.id);
  if (!safeId) return false;
  try {
    assertSafeRtdbPayload(customer);
    const res = await firebaseFetch(buildSafeRtdbPath("customers", safeId), {
      method: "PUT",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(customer)
    });
    return res.ok;
  } catch (err) {
    return false;
  }
}

/**
 * Performs a safe partial update (PATCH) on an existing customer record (ASVS L3)
 * Guarantees that unmentioned fields (passwordHash, role, createdAt) are NEVER wiped out.
 */
async function patchCustomer(safeId, patchPayload) {
  const cleanId = sanitizePathId(safeId);
  if (!cleanId) return false;
  try {
    assertSafeRtdbPayload(patchPayload);
    const res = await firebaseFetch(buildSafeRtdbPath("customers", cleanId), {
      method: "PATCH",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patchPayload)
    });
    return res.ok;
  } catch (err) {
    return false;
  }
}

async function customerHandler(req, res, { requestId, safeBody } = {}) {
  // 1. Mandatory CORS & Security Headers Gate (ASVS 14.4 & 14.5)
  if (setSecurityHeaders(req, res, { cacheControl: "no-store, no-cache, must-revalidate" })) return;

  // 2. HTTP Parameter Pollution Defense on action parameter (CWE-235)
  let rawAction = req.query?.action;
  if (Array.isArray(rawAction)) {
    return res.status(400).json({
      success: false,
      error: "طلب غير صالح: تكرار غير مسموح لمعامل الإجراء (HTTP Parameter Pollution Detected)"
    });
  }

  // Safe JSON Body Parsing
  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch (e) {
      return res.status(400).json({ success: false, error: "صيغة بيانات JSON غير صحيحة" });
    }
  }
  body = (body && typeof body === "object" && !Array.isArray(body)) ? body : {};

  if (!rawAction && typeof body.action === "string") {
    rawAction = body.action;
  }

  const normalizedAction = (rawAction || "").trim().toLowerCase();
  const effectiveAction = normalizedAction || (req.method === "GET" || req.method === "HEAD" ? "me" : "");

  // Fail-Closed Action Validation
  if (!effectiveAction || !ALLOWED_ACTIONS.has(effectiveAction)) {
    return res.status(400).json({ success: false, error: "إجراء غير معروف أو غير مصرح به" });
  }

  const clientIp = getClientIp(req);

  // Rate Limiting for Public / Customer Read Operations (60 requests per minute)
  if (req.method === "GET" || req.method === "HEAD") {
    const allowed = await enforceRateLimit(req, res, "read");
    if (!allowed) return;
  }

  try {
    // Payload Size Limit Check (DoS Mitigation - CWE-400)
    const MAX_CUSTOMER_PAYLOAD = 50 * 1024; // 50 KB
    const contentLength = parseInt(req.headers["content-length"] || "0", 10);
    if (contentLength > MAX_CUSTOMER_PAYLOAD) {
      return res.status(413).json({
        success: false,
        error: "حجم بيانات الطلب يتجاوز الحد الأقصى المسموح به (50 كيلوبايت) - 413 Payload Too Large"
      });
    }

    // -------------------------------------------------------------------------
    // 0. CUSTOMER LOGOUT (CLEAR SECURE HTTPONLY COOKIE)
    // -------------------------------------------------------------------------
    if (effectiveAction === "logout") {
      if (req.method !== "POST") {
        return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها. استخدم POST لتسجيل الخروج." });
      }
      res.setHeader("Set-Cookie", "kk_customer_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure");
      return res.status(200).json({ success: true, message: "تم تسجيل خروج العميل بنجاح" });
    }

    // -------------------------------------------------------------------------
    // 1. REGISTER NEW CUSTOMER ACCOUNT (ASVS 2.1, 2.4 & NIST SP 800-63B)
    // -------------------------------------------------------------------------
    if (effectiveAction === "register") {
      if (req.method !== "POST") {
        return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها. استخدم POST لإنشاء الحساب." });
      }

      // Sliding Window Rate Limit: 3 attempts per 1 hour per IP
      const allowed = await enforceRateLimit(req, res, "register");
      if (!allowed) return;

      // Mandatory Cloudflare Turnstile Bot Gate (Anti-Automation & Flooding)
      const turnstileToken = extractTurnstileToken(req, body);
      const turnstileRes = await verifyTurnstile(turnstileToken, clientIp);
      if (!turnstileRes.success) {
        return res.status(400).json({
          success: false,
          error: turnstileRes.error || "فشل التحقق الأمني من اختبار مكافحة الروبوتات (Turnstile)."
        });
      }

      // Input Validation & Normalization (ReDoS Safe & Strict Bounds)
      const rawName = typeof body.name === "string" ? body.name : "";
      const rawPhone = typeof body.phone === "string" ? body.phone : "";
      const rawEmail = typeof body.email === "string" ? body.email : "";

      const name = rawName.trim().replace(/[<>]/g, "").slice(0, 100);
      const phone = rawPhone.replace(/[^0-9]/g, "");
      const email = rawEmail.trim().toLowerCase().slice(0, 254);
      const cleanPassword = sanitizeAndNormalizePassword(body.password, 8, 128);

      if (!name || name.length < 2) {
        return res.status(400).json({ success: false, error: "يرجى كتابة اسم العميل بشكل صحيح (حرفين على الأقل)" });
      }

      // Validate standard Egyptian mobile number format (010, 011, 012, 015 - exactly 11 digits)
      if (!phone || !/^01[0125][0-9]{8}$/.test(phone)) {
        return res.status(400).json({ success: false, error: "يرجى إدخال رقم هاتف مصري صحيح مكون من 11 رقماً يبدأ بـ 01" });
      }

      // Deep Email Validation: Syntax, Disposable/Temp Domains & DNS MX Records
      if (email) {
        const emailValidation = await validateEmail(email, { checkMx: true, timeoutMs: 3000 });
        if (!emailValidation.valid) {
          return res.status(400).json({
            success: false,
            reason: emailValidation.reason,
            error: emailValidation.error
          });
        }
      }

      if (!cleanPassword) {
        return res.status(400).json({
          success: false,
          error: "كلمة المرور يجب أن تكون بين 8 و 128 حرفاً أو رقماً وخالية من الرموز غير الصالحة."
        });
      }

      const allCustomers = await fetchCustomers();
      const existing = allCustomers.find(c =>
        (c.phone && c.phone === phone) ||
        (email && c.email && c.email.toLowerCase() === email)
      );

      // Balanced generic conflict response: Prevents account overwrite and mitigates detailed enumeration
      if (existing) {
        return res.status(409).json({
          success: false,
          error: "بيانات التسجيل (رقم الهاتف أو البريد الإلكتروني) مسجلة بالفعل. يرجى تسجيل الدخول مباشرة."
        });
      }

      // Cryptographically random, collision-resistant customer identifier
      const customerId = "CUST-" + crypto.randomBytes(8).toString("hex").toUpperCase();
      const pwdData = await hashCustomerPassword(cleanPassword);

      // Generate 24-hour Email Verification Token & 6-digit Code (if email provided)
      let verificationToken = null;
      let verificationCode = null;
      let verificationTokenHash = null;
      let verificationCodeHash = null;
      let verificationExpiresAt = null;

      if (email) {
        verificationToken = crypto.randomBytes(32).toString("hex");
        verificationCode = String(crypto.randomInt(100000, 999999));
        verificationTokenHash = crypto.createHash("sha256").update(verificationToken).digest("hex");
        verificationCodeHash = crypto.createHash("sha256").update(verificationCode).digest("hex");
        verificationExpiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24 hours TTL
      }

      // Mass Assignment Protection: Whitelist only safe attributes, enforce customer role
      const newCustomer = {
        id: customerId,
        name,
        phone,
        email: email || null,
        role: "customer",
        authProvider: "local",
        emailVerified: false,
        email_verified: false,
        verificationTokenHash,
        verificationCodeHash,
        verificationExpiresAt,
        passwordHash: pwdData.hash,
        passwordSalt: pwdData.salt,
        passwordAlg: pwdData.alg || "scrypt",
        createdAt: Date.now(),
        updatedAt: Date.now()
      };

      await saveCustomer(newCustomer);

      // Dispatch Email Verification Message asynchronously
      if (email && verificationToken) {
        sendCustomerVerificationEmail(email, name, verificationToken, verificationCode).catch(e => {
          console.warn("[CustomerRegister] Error sending verification email:", e.message);
        });
      }

      const token = createCustomerToken({
        sub: customerId,
        phone,
        name,
        email: newCustomer.email,
        email_verified: false,
        emailVerified: false
      });

      // Secure HttpOnly Cookie for customer session (Zero Client-Side Token Storage)
      res.setHeader("Set-Cookie", `kk_customer_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Secure`);

      return res.status(201).json({
        success: true,
        message: email
          ? "تم إنشاء حساب العميل بنجاح. تم إرسال رابط تأكيد وتفعيل الحساب إلى بريدك الإلكتروني (صالح لمدة 24 ساعة)."
          : "تم إنشاء حساب العميل بنجاح.",
        emailVerificationRequired: Boolean(email),
        customer: sanitizeCustomer(newCustomer)
      });
    }

    // -------------------------------------------------------------------------
    // 1.5 AUTHENTIC GOOGLE OAUTH SIGN-IN WITH SERVER-SIDE TOKEN VERIFICATION (F-03, ASVS 3.8, OIDC Core 1.0)
    // -------------------------------------------------------------------------
    if (effectiveAction === "google" || effectiveAction === "google-login") {
      if (req.method !== "POST") {
        return res.status(405).json({ success: false, error: "Method not allowed. Use POST for Google authentication." });
      }

      // Sliding Window Rate Limit: 5 attempts per 15 minutes per IP
      const allowed = await enforceRateLimit(req, res, "auth");
      if (!allowed) return;

      const rawCredential = body.credential || body.idToken || body.token;
      if (!rawCredential || typeof rawCredential !== "string") {
        return res.status(400).json({
          success: false,
          error: "رمز توثيق Google غير موجود أو غير صالح. يلزم إرسال رمز الاعتماد المشفر (credential)."
        });
      }

      const verifiedProfile = await verifyGoogleIdToken(rawCredential);
      if (!verifiedProfile || !verifiedProfile.email || !verifiedProfile.sub) {
        return res.status(401).json({
          success: false,
          error: "فشل التحقق الأمني من صحة رمز Google. الرمز مزيف أو منتهي الصلاحية أو غير مخصص لهذا الموقع."
        });
      }

      const googleSub = verifiedProfile.sub;
      const email = verifiedProfile.email;
      const name = verifiedProfile.name;
      const avatar = verifiedProfile.picture;
      const rawPhone = typeof body.phone === "string" ? body.phone.trim() : "";
      const clientPhone = rawPhone.replace(/[^0-9+]/g, "").slice(0, 20);

      const allCustomers = await fetchCustomers();

      // 1. Primary Identifier Lookup: Google immutable sub (ASVS 3.8.4)
      let customer = allCustomers.find(c => c.googleSub === googleSub || c.googleId === googleSub);

      if (customer) {
        if (customer.status === "disabled" || customer.status === "suspended" || customer.isBlocked === true || customer.disabled === true) {
          return res.status(403).json({ success: false, error: "تم تعطيل هذا الحساب. يرجى التواصل مع إدارة المعرض." });
        }

        if (customer.email && customer.email.toLowerCase() !== email) {
          const emailCollision = allCustomers.find(c => c.id !== customer.id && c.email && c.email.toLowerCase() === email);
          if (!emailCollision) {
            customer.email = email;
          }
        }

        customer.name = name || customer.name;
        customer.googleSub = googleSub;
        customer.googleId = googleSub;
        customer.emailVerified = true;
        if (avatar) customer.avatar = avatar;
        if (clientPhone && (!customer.phone || customer.phone.length === 0)) customer.phone = clientPhone;
        customer.authProvider = "google";
        customer.role = "customer";
        customer.updatedAt = Date.now();
        await saveCustomer(customer);
      } else {
        // 2. Secondary Lookup by Email: Safe Account Linking & Pre-Account Takeover Mitigation
        const existingByEmail = allCustomers.find(c => c.email && c.email.toLowerCase() === email);
        if (existingByEmail) {
          if (existingByEmail.status === "disabled" || existingByEmail.status === "suspended" || existingByEmail.isBlocked === true || existingByEmail.disabled === true) {
            return res.status(403).json({ success: false, error: "تم تعطيل هذا الحساب. يرجى التواصل مع إدارة المعرض." });
          }

          if (existingByEmail.passwordHash && !existingByEmail.emailVerified) {
            delete existingByEmail.passwordHash;
            delete existingByEmail.passwordSalt;
            existingByEmail.passwordResetRequired = true;
          }

          customer = existingByEmail;
          customer.googleSub = googleSub;
          customer.googleId = googleSub;
          customer.emailVerified = true;
          customer.authProvider = "google";
          customer.role = "customer";
          if (name && (!customer.name || customer.name === "عميل Google")) customer.name = name;
          if (avatar) customer.avatar = avatar;
          if (clientPhone && (!customer.phone || customer.phone.length === 0)) customer.phone = clientPhone;
          customer.updatedAt = Date.now();
          await saveCustomer(customer);
        } else {
          // 3. Create fresh Google-verified customer with deterministic ID derived from googleSub
          const deterministicHash = crypto.createHash("sha256").update(googleSub).digest("hex").slice(0, 12).toUpperCase();
          const customerId = `CUST-G-${deterministicHash}`;

          customer = {
            id: customerId,
            googleSub,
            googleId: googleSub,
            name: name || "عميل Google",
            email,
            phone: clientPhone || "",
            avatar: avatar || "",
            authProvider: "google",
            role: "customer",
            emailVerified: true,
            createdAt: Date.now(),
            updatedAt: Date.now()
          };
          await saveCustomer(customer);
        }
      }

      const token = createCustomerToken({
        sub: customer.id,
        role: "customer",
        phone: customer.phone || "",
        name: customer.name,
        email: customer.email
      });

      res.setHeader("Set-Cookie", `kk_customer_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Secure`);

      return res.status(200).json({
        success: true,
        message: "تم تسجيل الدخول بواسطة Google بنجاح وتوثيق الهوية رسمياً",
        customer: sanitizeCustomer(customer)
      });
    }

    // -------------------------------------------------------------------------
    // 2. SIGN IN / LOGIN CUSTOMER (WITH DUAL-LAYER DISTRIBUTED RATE LIMITING)
    // -------------------------------------------------------------------------
    if (effectiveAction === "login") {
      if (req.method !== "POST") {
        return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها. استخدم POST لتسجيل الدخول." });
      }

      if (typeof body.password !== "string" || !body.password || body.password.includes("\0")) {
        return res.status(400).json({ success: false, error: "يرجى إدخال كلمة المرور بصيغة صحيحة" });
      }

      const rawIdentifier = (body.identifier || body.phone || body.email || "");
      if (typeof rawIdentifier !== "string" || !rawIdentifier.trim()) {
        return res.status(400).json({ success: false, error: "يرجى إدخال رقم الهاتف/البريد وكلمة المرور" });
      }
      const identifier = rawIdentifier.trim().toLowerCase();
      const password = body.password.normalize("NFKC").trim().slice(0, 128);

      if (!password) {
        return res.status(400).json({ success: false, error: "يرجى إدخال كلمة المرور" });
      }

      // Sliding Window Rate Limiting (5 attempts per 15 minutes per IP)
      const allowed = await enforceRateLimit(req, res, "auth");
      if (!allowed) return;

      const cleanPhone = identifier.replace(/[^0-9]/g, "");
      const allCustomers = await fetchCustomers();

      const customer = allCustomers.find(c =>
        (cleanPhone && cleanPhone.length === 11 && c.phone === cleanPhone) ||
        (c.email && c.email.toLowerCase() === identifier)
      );

      const hasStoredPassword = customer && typeof customer.passwordHash === "string" && typeof customer.passwordSalt === "string";
      const targetHash = hasStoredPassword ? customer.passwordHash : DUMMY_PASSWORD_HASH;
      const targetSalt = hasStoredPassword ? customer.passwordSalt : DUMMY_PASSWORD_SALT;

      const isMatch = await verifyCustomerPassword(password, targetHash, targetSalt);

      if (!customer || !hasStoredPassword || !isMatch) {
        await recordFailedRateLimitAttempt(clientIp, "customer_login_ip", 10, 15 * 60 * 1000);
        await recordFailedAttemptDistributed("customer_login_pair", pairKey, 5, 15 * 60 * 1000);
        return res.status(401).json({ success: false, error: "بيانات الدخول غير صحيحة" });
      }

      if (customer.status === "disabled" || customer.status === "suspended" || customer.isBlocked === true || customer.disabled === true) {
        return res.status(403).json({ success: false, error: "تم تعطيل هذا الحساب. يرجى التواصل مع إدارة المعرض." });
      }

      await resetRateLimitDistributed("customer_login_pair", pairKey);

      const isVerified = Boolean(customer.emailVerified || customer.email_verified);
      const token = createCustomerToken({
        sub: customer.id,
        phone: customer.phone,
        name: customer.name,
        email: customer.email,
        email_verified: isVerified,
        emailVerified: isVerified
      });

      res.setHeader("Set-Cookie", `kk_customer_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Secure`);

      return res.status(200).json({
        success: true,
        message: "تم تسجيل الدخول بنجاح",
        customer: sanitizeCustomer(customer)
      });
    }

    // -------------------------------------------------------------------------
    // 3. GET CURRENT PROFILE (AUTHENTICATED CUSTOMER — BOLA/IDOR PROTECTED)
    // -------------------------------------------------------------------------
    if (effectiveAction === "me") {
      if (req.method !== "GET") {
        return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها. استخدم GET لاستعراض الملف الشخصي." });
      }

      const auth = verifyCustomerRequest(req);
      if (!auth || !auth.sub) {
        return res.status(401).json({ success: false, error: "جلسة الدخول غير صالحة أو منتهية" });
      }

      const customerId = sanitizePathId(auth.sub);
      if (!customerId) {
        return res.status(401).json({ success: false, error: "معرّف الحساب غير صالح" });
      }

      // BOLA/IDOR Detection: Reject any mismatched ID parameters sent by client
      const requestedId = req.query?.id || body?.id || body?.customerId;
      if (requestedId && typeof requestedId === "string" && sanitizePathId(requestedId) !== customerId) {
        return res.status(403).json({
          success: false,
          error: "محاولة وصول غير مصرح بها لمعرّف حساب آخر (BOLA/IDOR Blocked)"
        });
      }

      // Direct O(1) Firebase RTDB lookup for isolated record
      const custRes = await firebaseFetch(buildSafeRtdbPath("customers", customerId), { cache: "no-store" });
      if (!custRes.ok) {
        return res.status(404).json({ success: false, error: "لم يتم العثور على حساب العميل" });
      }

      const customer = await custRes.json();
      if (!customer || typeof customer !== "object" || !customer.id) {
        return res.status(404).json({ success: false, error: "لم يتم العثور على حساب العميل" });
      }

      // Live Account Status Check
      if (customer.disabled || customer.isBlocked || customer.status === "disabled" || customer.status === "suspended") {
        return res.status(403).json({ success: false, error: "تم تعطيل هذا الحساب. يرجى التواصل مع إدارة المعرض." });
      }

      return res.status(200).json({
        success: true,
        customer: sanitizeCustomer(customer)
      });
    }

    // -------------------------------------------------------------------------
    // 4. GET CUSTOMER ORDERS HISTORY (STRICT ZERO-LEAKAGE: ONLY USER'S OWN ORDERS)
    // SENSITIVE OPERATION: Enforces email_verified === true (403 Forbidden for unverified)
    // -------------------------------------------------------------------------
    if (effectiveAction === "orders") {
      if (req.method !== "GET") {
        return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها. استخدم GET لعرض الطلبات." });
      }

      const auth = await requireVerifiedCustomer(req, res);
      if (!auth || !auth.sub) return;

      const customerId = sanitizePathId(auth.sub);
      if (!customerId) {
        return res.status(401).json({ success: false, error: "معرّف الحساب غير صالح" });
      }

      // Fetch orders using secure authenticated server-side endpoint
      const ordRes = await firebaseFetch(buildSafeRtdbPath("orders"), { cache: "no-store" }, { t: Date.now() });
      let allOrders = [];
      if (ordRes.ok) {
        const raw = await ordRes.json();
        if (raw && typeof raw === "object") {
          allOrders = Object.values(raw).filter(Boolean);
        }
      }

      // STRICT ISOLATION FILTER: Match strictly by verified token claims
      const customerPhone = auth.phone ? String(auth.phone).replace(/[^0-9]/g, "") : "";
      const customerEmail = (auth.email || "").trim().toLowerCase();

      const myOrders = allOrders.filter(o => {
        if (!o || !o.id) return false;
        if (customerId && o.customerId && o.customerId === customerId) return true;

        if (customerEmail && customerEmail.length > 3) {
          const ordEmail = (o.customer?.email || o.email || "").trim().toLowerCase();
          if (ordEmail && ordEmail === customerEmail) return true;
        }

        if (customerPhone && customerPhone.length === 11) {
          const ordPhone = (o.customer?.phone || "").replace(/[^0-9]/g, "");
          if (ordPhone === customerPhone) return true;
        }

        return false;
      });

      myOrders.sort((a, b) => (Number(b.timestamp) || 0) - (Number(a.timestamp) || 0));

      const localizedOrders = myOrders.map(o => {
        if (!o.timestamp) return o;
        const d = new Date(o.timestamp);
        return {
          ...o,
          dateFormatted: d.toLocaleDateString("ar-EG", {
            timeZone: "Africa/Cairo",
            year: "numeric",
            month: "short",
            day: "numeric"
          }),
          timeFormatted: d.toLocaleTimeString("ar-EG", {
            timeZone: "Africa/Cairo",
            hour: "2-digit",
            minute: "2-digit"
          })
        };
      });

      const rawPage = parseInt(req.query?.page || "1", 10);
      const rawLimit = parseInt(req.query?.limit || "50", 10);
      const page = Number.isInteger(rawPage) && rawPage >= 1 ? rawPage : 1;
      const limit = Number.isInteger(rawLimit) && rawLimit >= 1 ? Math.min(rawLimit, 50) : 50;
      const total = localizedOrders.length;
      const totalPages = Math.ceil(total / limit) || 1;
      const startIndex = (page - 1) * limit;
      const paginatedOrders = localizedOrders.slice(startIndex, startIndex + limit);

      return res.status(200).json({
        success: true,
        count: paginatedOrders.length,
        total,
        page,
        limit,
        totalPages,
        orders: paginatedOrders
      });
    }

    // -------------------------------------------------------------------------
    // 5. UPDATE PROFILE / PASSWORD (STRICT MASS ASSIGNMENT & BOLA PREVENTION)
    // -------------------------------------------------------------------------
    if (effectiveAction === "update" || effectiveAction === "update_profile") {
      if (req.method !== "POST" && req.method !== "PATCH" && req.method !== "PUT") {
        return res.status(405).json({
          success: false,
          error: "طريقة الطلب غير مسموح بها. استخدم POST أو PATCH لتعديل البيانات."
        });
      }

      // Abuse Prevention / Rate Limiting (15 updates / 15 mins)
      const updateLimit = await checkDistributedRateLimit(clientIp, "customer_update", 15, 15 * 60 * 1000);
      if (!updateLimit.allowed) {
        res.setHeader("Retry-After", String(updateLimit.remainingSec));
        return res.status(429).json({
          success: false,
          error: `تم تجاوز الحد الأقصى لمحاولات التعديل. يرجى الانتظار ${updateLimit.remainingSec} ثانية.`
        });
      }

      // SENSITIVE OPERATION: Enforces email_verified === true (403 Forbidden for unverified)
      const auth = await requireVerifiedCustomer(req, res);
      if (!auth || !auth.sub) return;

      const customerId = sanitizePathId(auth.sub);
      if (!customerId) {
        return res.status(401).json({ success: false, error: "معرّف الحساب غير صالح" });
      }

      // BOLA/IDOR Tamper Detection
      const requestedId = req.query?.id || body?.id || body?.customerId;
      if (requestedId && typeof requestedId === "string" && sanitizePathId(requestedId) !== customerId) {
        return res.status(403).json({
          success: false,
          error: "محاولة تعديل غير مصرح بها لحساب آخر (BOLA/IDOR Blocked)"
        });
      }

      // 1. Fail-Fast Structural & Malformed Input Verification (ASVS 5.1 & CWE-20)
      // Reject objects, arrays, nulls, and prototype pollution before any database operations
      for (const [k, v] of Object.entries(body)) {
        if (k === "__proto__" || k === "constructor" || k === "prototype") {
          return res.status(400).json({ success: false, error: "طلب غير صالح: حقول غير مسموح بها" });
        }
        if (v !== null && typeof v === "object") {
          return res.status(400).json({ success: false, error: `طلب غير صالح: الحقل '${k}' لا يمكن أن يكون كائناً أو مصفوفة` });
        }
        if (v === null) {
          return res.status(400).json({ success: false, error: `طلب غير صالح: الحذف الصامت للحقول عبر null غير مسموح` });
        }
      }

      // Check that at least one valid update candidate field is present
      const hasPermissibleField =
        typeof body.name === "string" ||
        typeof body.phone === "string" ||
        typeof body.email === "string" ||
        typeof body.address === "string" ||
        typeof body.city === "string" ||
        typeof body.deliveryArea === "string" ||
        typeof body.deliveryAreaName === "string" ||
        typeof body.avatar === "string" ||
        typeof (body.newPassword || body.password) === "string";

      if (!hasPermissibleField) {
        return res.status(400).json({
          success: false,
          error: "لم يتم تقديم أي حقول صالحة للتعديل (Empty or Invalid DTO)"
        });
      }

      // Fetch live customer record
      const custRes = await firebaseFetch(buildSafeRtdbPath("customers", customerId), { cache: "no-store" });
      if (!custRes.ok) {
        return res.status(404).json({ success: false, error: "حساب العميل غير موجود" });
      }
      const existingCustomer = await custRes.json();
      if (!existingCustomer || typeof existingCustomer !== "object" || !existingCustomer.id) {
        return res.status(404).json({ success: false, error: "حساب العميل غير موجود" });
      }

      // Live Account Status Check
      if (existingCustomer.disabled || existingCustomer.isBlocked || existingCustomer.status === "disabled" || existingCustomer.status === "suspended") {
        return res.status(403).json({ success: false, error: "تم تعطيل هذا الحساب. يرجى التواصل مع إدارة المعرض." });
      }

      // Strict Allowlist DTO Construction for PATCH
      const patchData = {};

      // 1. Name
      if (typeof body.name === "string") {
        const cleanName = body.name.replace(/[\0\r\n<>]/g, "").trim().slice(0, 100);
        if (cleanName.length < 2) {
          return res.status(400).json({ success: false, error: "الاسم يجب أن يتكون من حرفين على الأقل" });
        }
        patchData.name = cleanName;
      }

      // 2. Phone
      if (typeof body.phone === "string") {
        const cleanPhone = body.phone.replace(/[^0-9]/g, "");
        if (!/^01[0125][0-9]{8}$/.test(cleanPhone)) {
          return res.status(400).json({ success: false, error: "يرجى إدخال رقم هاتف مصري صحيح مكون من 11 رقماً يبدأ بـ 01" });
        }
        if (cleanPhone !== existingCustomer.phone) {
          const allCust = await fetchCustomers();
          const phoneConflict = allCust.find(c => c && c.id !== customerId && c.phone === cleanPhone);
          if (phoneConflict) {
            return res.status(409).json({ success: false, error: "رقم الهاتف مسجل بالفعل لحساب آخر" });
          }
          patchData.phone = cleanPhone;
        }
      }

      // 3. Email
      if (typeof body.email === "string") {
        const cleanEmail = body.email.trim().toLowerCase().slice(0, 100);
        if (cleanEmail !== (existingCustomer.email || "").toLowerCase()) {
          // Deep Email Validation: Syntax, Disposable Domains & DNS MX Records
          const emailValidation = await validateEmail(cleanEmail, { checkMx: true, timeoutMs: 3000 });
          if (!emailValidation.valid) {
            return res.status(400).json({
              success: false,
              reason: emailValidation.reason,
              error: emailValidation.error
            });
          }

          // Reject changing email on Google-authenticated accounts
          if (existingCustomer.authProvider === "google") {
            return res.status(400).json({
              success: false,
              error: "لا يمكن تعديل البريد الإلكتروني للحسابات المرتبطة بتسجيل الدخول عبر Google"
            });
          }
          const allCust = await fetchCustomers();
          const emailConflict = allCust.find(c => c && c.id !== customerId && c.email && c.email.toLowerCase() === cleanEmail);
          if (emailConflict) {
            return res.status(409).json({ success: false, error: "البريد الإلكتروني مسجل بالفعل لحساب آخر" });
          }

          const newVerToken = crypto.randomBytes(32).toString("hex");
          const newVerCode = String(crypto.randomInt(100000, 999999));

          patchData.email = cleanEmail;
          patchData.emailVerified = false;
          patchData.email_verified = false;
          patchData.verificationTokenHash = crypto.createHash("sha256").update(newVerToken).digest("hex");
          patchData.verificationCodeHash = crypto.createHash("sha256").update(newVerCode).digest("hex");
          patchData.verificationExpiresAt = Date.now() + (24 * 60 * 60 * 1000);

          sendCustomerVerificationEmail(cleanEmail, existingCustomer.name, newVerToken, newVerCode).catch(e => {
            console.warn("[CustomerUpdate] Error sending verification email:", e.message);
          });
        }
      }

      // 4. Address & City & Delivery Areas
      if (typeof body.address === "string") {
        patchData.address = body.address.replace(/[\0\r\n<>]/g, "").trim().slice(0, 300);
      }
      if (typeof body.city === "string") {
        patchData.city = body.city.replace(/[\0\r\n<>]/g, "").trim().slice(0, 80);
      }
      if (typeof body.deliveryArea === "string") {
        patchData.deliveryArea = body.deliveryArea.replace(/[\0\r\n<>]/g, "").trim().slice(0, 80);
      }
      if (typeof body.deliveryAreaName === "string") {
        patchData.deliveryAreaName = body.deliveryAreaName.replace(/[\0\r\n<>]/g, "").trim().slice(0, 80);
      }

      // 5. Avatar
      if (typeof body.avatar === "string") {
        const cleanAvatar = body.avatar.trim();
        if (cleanAvatar && !/^https?:\/\//i.test(cleanAvatar)) {
          return res.status(400).json({ success: false, error: "رابط الصورة الشخصية غير صالح" });
        }
        patchData.avatar = cleanAvatar.slice(0, 500);
      }

      // 6. Password Change
      const newPassRaw = body.newPassword || body.password;
      if (typeof newPassRaw === "string" && newPassRaw.length > 0) {
        const cleanNewPass = sanitizeAndNormalizePassword(newPassRaw, 8, 128);
        if (!cleanNewPass) {
          return res.status(400).json({
            success: false,
            error: "كلمة المرور الجديدة يجب أن تكون بين 8 و 128 حرفاً وخالية من الرموز غير الصالحة."
          });
        }

        // Strict Re-Authentication: If account already has a password, verify current password first (ASVS 2.1.8)
        if (existingCustomer.passwordHash && existingCustomer.passwordSalt) {
          const rawCurrent = typeof body.currentPassword === "string" ? body.currentPassword : "";
          const currentPass = rawCurrent.normalize("NFKC").trim();
          if (!currentPass) {
            return res.status(400).json({
              success: false,
              error: "يلزم إدخال كلمة المرور الحالية لتأكيد التغيير."
            });
          }
          const valid = await verifyCustomerPassword(currentPass, existingCustomer.passwordHash, existingCustomer.passwordSalt);
          if (!valid) {
            return res.status(401).json({ success: false, error: "كلمة المرور الحالية غير صحيحة." });
          }
        }

        const pwdData = await hashCustomerPassword(cleanNewPass);
        patchData.passwordHash = pwdData.hash;
        patchData.passwordSalt = pwdData.salt;
        patchData.passwordAlg = pwdData.alg || "scrypt";
        patchData.passwordChangedAt = Date.now();
        patchData.tokenVersion = (existingCustomer.tokenVersion || 1) + 1;
      }

      // Reject empty updates (Axis 5)
      if (Object.keys(patchData).length === 0) {
        return res.status(400).json({ success: false, error: "لم يتم تقديم أي حقول صالحة للتعديل" });
      }

      // Server-generated timestamp
      patchData.updatedAt = Date.now();

      // Execute safe partial update via PATCH (NEVER PUT - ASVS L3)
      const ok = await patchCustomer(customerId, patchData);
      if (!ok) {
        return res.status(500).json({ success: false, error: "فشل حفظ التعديلات في قاعدة البيانات" });
      }

      const updatedCustomer = {
        ...existingCustomer,
        ...patchData
      };

      return res.status(200).json({
        success: true,
        message: "تم تحديث البيانات بنجاح",
        customer: sanitizeCustomer(updatedCustomer)
      });
    }

    // -------------------------------------------------------------------------
    // 6. GET ALL REGISTERED CUSTOMERS (ADMIN DIRECTORY — STRICT ADMIN AUTH & BFLA DEFENSE)
    // -------------------------------------------------------------------------
    if (effectiveAction === "list") {
      if (req.method !== "GET") {
        return res.status(405).json({
          success: false,
          error: "طريقة الطلب غير مسموح بها. استخدم GET لاستعراض قائمة العملاء."
        });
      }

      // Mandatory Admin Authorization Check (BFLA Defense - ASVS 4.1.1)
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({
          success: false,
          error: "غير مصرح بالوصول. استعراض سجل العملاء يتطلب صلاحيات الإدارة العليا المعتمدة."
        });
      }

      // Safe pagination limit (min 1, max 50, default 50)
      const rawPage = parseInt(req.query?.page || "1", 10);
      const rawLimit = parseInt(req.query?.limit || "50", 10);
      const page = Number.isInteger(rawPage) && rawPage >= 1 ? rawPage : 1;
      const limit = Number.isInteger(rawLimit) && rawLimit >= 1 ? Math.min(rawLimit, 50) : 50;

      const allCustomers = await fetchCustomers();
      allCustomers.sort((a, b) => (Number(b.createdAt) || Number(b.updatedAt) || 0) - (Number(a.createdAt) || Number(a.updatedAt) || 0));

      const total = allCustomers.length;
      const totalPages = Math.ceil(total / limit) || 1;
      const startIndex = (page - 1) * limit;
      const pagedCustomers = allCustomers.slice(startIndex, startIndex + limit);

      return res.status(200).json({
        success: true,
        count: pagedCustomers.length,
        total,
        page,
        limit,
        totalPages,
        customers: pagedCustomers.map(c => sanitizeCustomer(c, { forAdmin: true }))
      });
    }

    // -------------------------------------------------------------------------
    // 7. VERIFY CUSTOMER EMAIL (AUTHENTICATE CODE OR TOKEN)
    // -------------------------------------------------------------------------
    if (effectiveAction === "verify_email") {
      if (req.method !== "POST" && req.method !== "GET") {
        return res.status(405).json({ success: false, error: "Method not allowed. Use GET or POST for verification." });
      }

      const rawToken = body?.token || req.query?.token || "";
      const rawCode = body?.code || req.query?.code || "";
      const rawEmail = body?.email || req.query?.email || "";

      const inputToken = typeof rawToken === "string" ? rawToken.trim() : "";
      const inputCode = typeof rawCode === "string" ? rawCode.trim() : "";
      const cleanEmail = typeof rawEmail === "string" ? rawEmail.trim().toLowerCase() : "";

      if (!inputToken && (!inputCode || !cleanEmail)) {
        return res.status(400).json({
          success: false,
          error: "يرجى إرسال رابط التفعيل أو كود التحقق والبريد الإلكتروني المرتبط به."
        });
      }

      const allCustomers = await fetchCustomers();
      let targetCustomer = null;

      if (inputToken) {
        const tokenHash = crypto.createHash("sha256").update(inputToken).digest("hex");
        targetCustomer = allCustomers.find(c => c && c.verificationTokenHash === tokenHash);
      } else if (inputCode && cleanEmail) {
        const codeHash = crypto.createHash("sha256").update(inputCode).digest("hex");
        targetCustomer = allCustomers.find(c => c && c.email && c.email.toLowerCase() === cleanEmail && c.verificationCodeHash === codeHash);
      }

      if (!targetCustomer) {
        return res.status(400).json({
          success: false,
          error: "رمز أو رابط تفعيل البريد الإلكتروني غير صحيح أو انتهت صلاحيته."
        });
      }

      if (targetCustomer.verificationExpiresAt && Date.now() > Number(targetCustomer.verificationExpiresAt)) {
        return res.status(400).json({
          success: false,
          error: "انتهت صلاحية رمز التفعيل (صلاحية الرمز 24 ساعة فقط). يرجى طلب رمز تفعيل جديد."
        });
      }

      // Mark customer verified atomically
      const patchData = {
        emailVerified: true,
        email_verified: true,
        verifiedAt: Date.now(),
        verificationTokenHash: null,
        verificationCodeHash: null,
        verificationExpiresAt: null,
        updatedAt: Date.now()
      };

      await patchCustomer(targetCustomer.id, patchData);

      const verifiedCust = { ...targetCustomer, ...patchData };

      const token = createCustomerToken({
        sub: targetCustomer.id,
        phone: targetCustomer.phone,
        name: targetCustomer.name,
        email: targetCustomer.email,
        email_verified: true,
        emailVerified: true
      });

      res.setHeader("Set-Cookie", `kk_customer_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Secure`);

      return res.status(200).json({
        success: true,
        message: "تم تفعيل البريد الإلكتروني بنجاح ومصادقة حسابك رسمياً.",
        customer: sanitizeCustomer(verifiedCust)
      });
    }

    // -------------------------------------------------------------------------
    // 8. RESEND EMAIL VERIFICATION MESSAGE
    // -------------------------------------------------------------------------
    if (effectiveAction === "resend_verification") {
      if (req.method !== "POST") {
        return res.status(405).json({ success: false, error: "Method not allowed. Use POST to resend verification." });
      }

      // Sliding Window Rate Limit: 3 requests per 10 minutes per IP or Email
      const allowed = await enforceRateLimit(req, res, "emails", body.email || null);
      if (!allowed) return;

      // Cloudflare Turnstile Verification
      const turnstileToken = extractTurnstileToken(req, body);
      const turnstileRes = await verifyTurnstile(turnstileToken, clientIp);
      if (!turnstileRes.success) {
        return res.status(400).json({
          success: false,
          error: turnstileRes.error || "فشل التحقق الأمني من اختبار مكافحة الروبوتات."
        });
      }

      const rawEmail = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
      if (!rawEmail) {
        return res.status(400).json({ success: false, error: "يرجى تحديد البريد الإلكتروني المطلوب تفعيله." });
      }

      const allCustomers = await fetchCustomers();
      const targetCustomer = allCustomers.find(c => c && c.email && c.email.toLowerCase() === rawEmail);

      // Generic success response even if not found to prevent user enumeration
      if (!targetCustomer) {
        return res.status(200).json({
          success: true,
          message: "إذا كان هذا البريد مسجلاً لدينا، فقد تم إرسال رابط التفعيل إليه."
        });
      }

      if (targetCustomer.emailVerified || targetCustomer.email_verified) {
        return res.status(200).json({
          success: true,
          message: "هذا الحساب مفعّل بالفعل مسبقاً."
        });
      }

      const newVerToken = crypto.randomBytes(32).toString("hex");
      const newVerCode = String(crypto.randomInt(100000, 999999));

      const patchData = {
        verificationTokenHash: crypto.createHash("sha256").update(newVerToken).digest("hex"),
        verificationCodeHash: crypto.createHash("sha256").update(newVerCode).digest("hex"),
        verificationExpiresAt: Date.now() + (24 * 60 * 60 * 1000),
        updatedAt: Date.now()
      };

      await patchCustomer(targetCustomer.id, patchData);
      await sendCustomerVerificationEmail(targetCustomer.email, targetCustomer.name, newVerToken, newVerCode);

      return res.status(200).json({
        success: true,
        message: "تم إرسال رابط وكود تفعيل جديد إلى بريدك الإلكتروني بنجاح (صالح لمدة 24 ساعة)."
      });
    }

    return res.status(400).json({ success: false, error: "إجراء غير معروف" });
  } catch (err) {
    // Log hygiene: Never print request body, customer PII, or secret URLs (CWE-532)
    safeLogError("/api/customer", requestId, err);
    return res.status(500).json({
      success: false,
      ok: false,
      error: "حدث خطأ غير متوقع في معالجة حساب العميل.",
      requestId
    });
  }
}

export default withApiHardening(customerHandler, {
  allowedMethods: ["GET", "POST", "PATCH", "PUT", "DELETE"],
  maxBodyBytes: 16 * 1024,
  maxDepth: 6,
  maxKeys: 50,
  context: "/api/customer"
});
