// Vercel Serverless Function: /api/customer
// Hardened Customer Account Management, Authentication & Isolated Order History
// Implements OWASP ASVS (Level 3), OWASP API Security Top 10 (API1: BOLA, API3: BOPLA, API5: BFLA)
// Strict Zero Cross-Account Access Guarantee & NIST SP 800-63B Compliance

import crypto from "crypto";
import {
  hashCustomerPassword,
  verifyCustomerPassword,
  sanitizeAndNormalizePassword,
  DUMMY_PASSWORD_HASH,
  DUMMY_PASSWORD_SALT,
  createCustomerToken,
  verifyCustomerRequest,
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
  getClientIp,
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
  "list"
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

  try {
    // Payload Size Limit Check (DoS Mitigation - CWE-400)
    const MAX_CUSTOMER_PAYLOAD = 100 * 1024; // 100 KB
    const contentLength = parseInt(req.headers["content-length"] || "0", 10);
    if (contentLength > MAX_CUSTOMER_PAYLOAD) {
      return res.status(413).json({
        success: false,
        error: "حجم بيانات الطلب يتجاوز الحد المسموح به (100 كيلوبايت)"
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

      const regLimit = await checkDistributedRateLimit(clientIp, "customer_register", 5, 15 * 60 * 1000);
      if (!regLimit.allowed) {
        res.setHeader("Retry-After", String(regLimit.remainingSec));
        return res.status(429).json({
          success: false,
          error: `تم تجاوز الحد الأقصى لمحاولات التسجيل. يرجى الانتظار ${regLimit.remainingSec} ثانية.`
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

      // Validate RFC-compliant email if provided
      if (email && !/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email)) {
        return res.status(400).json({ success: false, error: "صيغة البريد الإلكتروني غير صحيحة" });
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

      // Mass Assignment Protection: Whitelist only safe attributes, enforce customer role
      const newCustomer = {
        id: customerId,
        name,
        phone,
        email: email || null,
        role: "customer",
        authProvider: "local",
        emailVerified: false,
        passwordHash: pwdData.hash,
        passwordSalt: pwdData.salt,
        passwordAlg: pwdData.alg || "scrypt",
        createdAt: Date.now(),
        updatedAt: Date.now()
      };

      await saveCustomer(newCustomer);

      const token = createCustomerToken({
        sub: customerId,
        phone,
        name,
        email: newCustomer.email
      });

      // Secure HttpOnly Cookie for customer session (Zero Client-Side Token Storage)
      res.setHeader("Set-Cookie", `kk_customer_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Secure`);

      return res.status(201).json({
        success: true,
        message: "تم إنشاء حساب العميل بنجاح",
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

      const gLimit = await checkDistributedRateLimit(clientIp, "customer_google", 10, 15 * 60 * 1000);
      if (!gLimit.allowed) {
        res.setHeader("Retry-After", String(gLimit.remainingSec));
        return res.status(429).json({ success: false, error: "تم تجاوز عدد محاولات الدخول عبر Google. يرجى المحاولة لاحقاً." });
      }

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

      // Dual-Layer Rate Limiting:
      const ipLimit = await checkDistributedRateLimit(clientIp, "customer_login_ip", 10, 15 * 60 * 1000);
      if (!ipLimit.allowed) {
        res.setHeader("Retry-After", String(ipLimit.remainingSec));
        return res.status(429).json({
          success: false,
          error: `تم تجاوز الحد الأقصى للمحاولات من هذا الجهاز. يرجى الانتظار ${ipLimit.remainingSec} ثانية.`
        });
      }

      const pairKey = `${normalizeIpForRateLimit(clientIp)}:${identifier}`;
      const pairLimit = await checkRateLimitDistributed("customer_login_pair", pairKey, 5, 15 * 60 * 1000);
      if (!pairLimit.allowed) {
        res.setHeader("Retry-After", String(pairLimit.remainingSec));
        return res.status(429).json({
          success: false,
          error: `تم تجاوز الحد الأقصى للمحاولات لهذا الحساب. يرجى الانتظار ${pairLimit.remainingSec} ثانية قبل إعادة المحاولة.`
        });
      }

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

      const token = createCustomerToken({
        sub: customer.id,
        phone: customer.phone,
        name: customer.name,
        email: customer.email
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
    // -------------------------------------------------------------------------
    if (effectiveAction === "orders") {
      if (req.method !== "GET") {
        return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها. استخدم GET لعرض الطلبات." });
      }

      const auth = verifyCustomerRequest(req);
      if (!auth || !auth.sub) {
        return res.status(401).json({ success: false, error: "يجب تسجيل الدخول لعرض سجل طلباتك" });
      }

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

      return res.status(200).json({
        success: true,
        count: localizedOrders.length,
        orders: localizedOrders
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

      const auth = verifyCustomerRequest(req);
      if (!auth || !auth.sub) {
        return res.status(401).json({ success: false, error: "غير مصرح. يرجى تسجيل الدخول أولاً." });
      }

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
        if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(cleanEmail)) {
          return res.status(400).json({ success: false, error: "صيغة البريد الإلكتروني غير صحيحة" });
        }
        if (cleanEmail !== (existingCustomer.email || "").toLowerCase()) {
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
          patchData.email = cleanEmail;
          patchData.emailVerified = false; // Require re-verification if email changes
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

      // Safe pagination limit (min 1, max 500, default 200)
      const limitParam = parseInt(req.query?.limit, 10);
      const maxLimit = (!isNaN(limitParam) && limitParam > 0) ? Math.min(limitParam, 500) : 200;

      const allCustomers = await fetchCustomers();
      allCustomers.sort((a, b) => (Number(b.createdAt) || Number(b.updatedAt) || 0) - (Number(a.createdAt) || Number(a.updatedAt) || 0));

      const pagedCustomers = allCustomers.slice(0, maxLimit);

      return res.status(200).json({
        success: true,
        count: pagedCustomers.length,
        total: allCustomers.length,
        customers: pagedCustomers.map(c => sanitizeCustomer(c, { forAdmin: true }))
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
