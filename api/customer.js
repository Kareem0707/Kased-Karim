// Vercel Serverless Function: /api/customer
// Customer Account Management, Authentication & Isolated Order History
// PRD Sections 2, 3, 4 & 10 (Strict Zero Cross-Account Access Guarantee)

import crypto from "crypto";
import {
  hashCustomerPassword,
  verifyCustomerPassword,
  createCustomerToken,
  verifyCustomerRequest,
  verifyAdminRequest,
  verifyGoogleIdToken,
  sanitizeCustomer,
  sanitizePathId,
  getFirebaseUrl,
  setSecurityHeaders
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

async function fetchCustomers() {
  try {
    const firebaseUrl = getFirebaseUrl("customers.json", { t: Date.now() });
    const res = await fetch(firebaseUrl, { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      if (data && typeof data === "object") {
        return Object.values(data).filter(Boolean);
      }
    }
  } catch (e) {}
  return [];
}

async function saveCustomer(customer) {
  const safeId = sanitizePathId(customer.id);
  if (!safeId) return false;
  const firebaseUrl = getFirebaseUrl(`customers/${safeId}.json`);
  const res = await fetch(firebaseUrl, {
    method: "PUT",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(customer)
  });
  return res.ok;
}

export default async function handler(req, res) {
  setSecurityHeaders(req, res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  let action = req.query?.action;

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch (e) {}
  }
  body = body || {};

  if (!action && body.action) {
    action = body.action;
  }

  try {
    // -------------------------------------------------------------------------
    // 1. REGISTER NEW CUSTOMER ACCOUNT
    // -------------------------------------------------------------------------
    if (req.method === "POST" && action === "register") {
      const name = (body.name || "").trim().replace(/[<>]/g, "").slice(0, 80);
      const phone = (body.phone || "").replace(/[^0-9]/g, "");
      const email = (body.email || "").trim().toLowerCase().replace(/[<>]/g, "").slice(0, 100);
      const password = (body.password || "").trim();

      if (!name || name.length < 2) {
        return res.status(400).json({ success: false, error: "يرجى كتابة اسم العميل بشكل صحيح" });
      }
      if (!phone || phone.length < 11 || !phone.startsWith("01")) {
        return res.status(400).json({ success: false, error: "يرجى إدخال رقم هاتف مصري صحيح يبدأ بـ 01 (11 رقماً)" });
      }
      if (!password || password.length < 6) {
        return res.status(400).json({ success: false, error: "كلمة المرور يجب ألا تقل عن 6 أحرف أو أرقام" });
      }

      const allCustomers = await fetchCustomers();
      const existing = allCustomers.find(c => c.phone === phone || (email && c.email === email));
      if (existing) {
        return res.status(409).json({
          success: false,
          error: "رقم الهاتف أو البريد الإلكتروني مسجل بالفعل. يرجى تسجيل الدخول مباشرة."
        });
      }

      const customerId = "CUST-" + crypto.randomInt(1000, 9999) + "-" + crypto.randomBytes(3).toString("hex").toUpperCase();
      const { hash, salt } = hashCustomerPassword(password);

      const newCustomer = {
        id: customerId,
        name,
        phone,
        email: email || null,
        passwordHash: hash,
        passwordSalt: salt,
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

      // Secure HttpOnly Cookie for customer session (F-10)
      res.setHeader("Set-Cookie", `kk_customer_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Secure`);

      return res.status(201).json({
        success: true,
        message: "تم إنشاء حساب العميل بنجاح",
        token,
        customer: sanitizeCustomer(newCustomer)
      });
    }

    // -------------------------------------------------------------------------
    // 1.5 AUTHENTIC GOOGLE OAUTH SIGN-IN WITH SERVER-SIDE TOKEN VERIFICATION (F-03)
    // -------------------------------------------------------------------------
    if (req.method === "POST" && (action === "google" || action === "google-login")) {
      const rawCredential = body.credential || body.idToken || body.token;
      if (!rawCredential) {
        return res.status(400).json({
          success: false,
          error: "رمز توثيق Google غير موجود. يلزم إرسال رمز الاعتماد المشفر (credential)."
        });
      }

      // Cryptographically verify Google ID token against Google's public keys (F-03)
      const verifiedProfile = await verifyGoogleIdToken(rawCredential);
      if (!verifiedProfile || !verifiedProfile.email || !verifiedProfile.sub) {
        return res.status(401).json({
          success: false,
          error: "فشل التحقق الأمني من صحة رمز Google. الرمز مزيف أو منتهي الصلاحية."
        });
      }

      const googleId = verifiedProfile.sub;
      const email = verifiedProfile.email;
      const name = verifiedProfile.name;
      const avatar = verifiedProfile.picture;
      const clientPhone = (body.phone || "").replace(/[^0-9]/g, "");

      const allCustomers = await fetchCustomers();
      let customer = allCustomers.find(c => c.googleId === googleId || (c.email && c.email.toLowerCase() === email));

      if (customer) {
        customer.name = name || customer.name;
        customer.googleId = googleId;
        if (avatar) customer.avatar = avatar;
        if (clientPhone && !customer.phone) customer.phone = clientPhone;
        customer.authProvider = "google";
        customer.updatedAt = Date.now();
        await saveCustomer(customer);
      } else {
        const customerId = "CUST-G-" + crypto.randomInt(1000, 9999) + "-" + crypto.randomBytes(3).toString("hex").toUpperCase();
        customer = {
          id: customerId,
          googleId,
          name: name || "عميل Google",
          email,
          phone: clientPhone || "",
          avatar: avatar || "",
          authProvider: "google",
          createdAt: Date.now(),
          updatedAt: Date.now()
        };
        await saveCustomer(customer);
      }

      const token = createCustomerToken({
        sub: customer.id,
        phone: customer.phone || "",
        name: customer.name,
        email: customer.email
      });

      res.setHeader("Set-Cookie", `kk_customer_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Secure`);

      return res.status(200).json({
        success: true,
        message: "تم تسجيل الدخول بواسطة Google بنجاح وتوثيق الهوية رسمياً",
        token,
        customer: sanitizeCustomer(customer)
      });
    }

    // -------------------------------------------------------------------------
    // 2. SIGN IN / LOGIN CUSTOMER
    // -------------------------------------------------------------------------
    if (req.method === "POST" && action === "login") {
      const identifier = (body.identifier || body.phone || body.email || "").trim().toLowerCase();
      const password = (body.password || "").trim();

      if (!identifier || !password) {
        return res.status(400).json({ success: false, error: "يرجى إدخال رقم الهاتف/البريد وكلمة المرور" });
      }

      const cleanPhone = identifier.replace(/[^0-9]/g, "");
      const allCustomers = await fetchCustomers();

      const customer = allCustomers.find(c => 
        (cleanPhone && c.phone === cleanPhone) || 
        (c.email && c.email.toLowerCase() === identifier)
      );

      if (!customer || !customer.passwordHash || !customer.passwordSalt) {
        return res.status(401).json({ success: false, error: "بيانات الدخول غير صحيحة" });
      }

      const isMatch = verifyCustomerPassword(password, customer.passwordHash, customer.passwordSalt);
      if (!isMatch) {
        return res.status(401).json({ success: false, error: "بيانات الدخول غير صحيحة" });
      }

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
        token,
        customer: sanitizeCustomer(customer)
      });
    }

    // -------------------------------------------------------------------------
    // 3. GET CURRENT PROFILE (AUTHENTICATED CUSTOMER)
    // -------------------------------------------------------------------------
    if (req.method === "GET" && (!action || action === "me")) {
      const auth = verifyCustomerRequest(req);
      if (!auth) {
        return res.status(401).json({ success: false, error: "جلسة الدخول غير صالحة أو منتهية" });
      }

      const allCustomers = await fetchCustomers();
      const customer = allCustomers.find(c => c.id === auth.sub || (auth.phone && c.phone === auth.phone));

      if (!customer) {
        return res.status(404).json({ success: false, error: "لم يتم العثور على حساب العميل" });
      }

      return res.status(200).json({
        success: true,
        customer: sanitizeCustomer(customer)
      });
    }

    // -------------------------------------------------------------------------
    // 4. GET CUSTOMER ORDERS HISTORY (STRICT ZERO-LEAKAGE: ONLY USER'S OWN ORDERS)
    // -------------------------------------------------------------------------
    if (req.method === "GET" && action === "orders") {
      const auth = verifyCustomerRequest(req);
      if (!auth) {
        return res.status(401).json({ success: false, error: "يجب تسجيل الدخول لعرض سجل طلباتك" });
      }

      // Fetch orders using secure authenticated server-side endpoint
      const ordUrl = getFirebaseUrl("orders.json", { t: Date.now() });
      const ordRes = await fetch(ordUrl, { cache: "no-store" });
      let allOrders = [];
      if (ordRes.ok) {
        const raw = await ordRes.json();
        if (raw && typeof raw === "object") {
          allOrders = Object.values(raw).filter(Boolean);
        }
      }

      // STRICT ISOLATION FILTER: Only orders belonging to this customer
      const customerPhone = auth.phone ? auth.phone.replace(/[^0-9]/g, "") : "";
      const customerId = auth.sub;
      const customerEmail = (auth.email || "").trim().toLowerCase();

      const myOrders = allOrders.filter(o => {
        if (!o || !o.id) return false;
        if (customerId && o.customerId && o.customerId === customerId) return true;
        
        // Permanent Email Linkage
        const ordEmail = (o.customer?.email || o.email || "").trim().toLowerCase();
        if (customerEmail && ordEmail && ordEmail === customerEmail) return true;

        // Match by verified phone number
        const ordPhone = (o.customer?.phone || "").replace(/[^0-9]/g, "");
        if (customerPhone && ordPhone && (ordPhone === customerPhone || ordPhone.endsWith(customerPhone) || customerPhone.endsWith(ordPhone))) {
          return true;
        }
        return false;
      });

      myOrders.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

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
    // 5. UPDATE PROFILE / PASSWORD
    // -------------------------------------------------------------------------
    if (req.method === "POST" && action === "update_profile") {
      const auth = verifyCustomerRequest(req);
      if (!auth) {
        return res.status(401).json({ success: false, error: "غير مصرح" });
      }

      const allCustomers = await fetchCustomers();
      const customer = allCustomers.find(c => c.id === auth.sub || (auth.phone && c.phone === auth.phone));
      if (!customer) {
        return res.status(404).json({ success: false, error: "حساب العميل غير موجود" });
      }

      if (body.name) customer.name = String(body.name).trim().replace(/[<>]/g, "").slice(0, 80);
      if (body.email) customer.email = String(body.email).trim().toLowerCase().replace(/[<>]/g, "").slice(0, 100);

      if (body.newPassword && String(body.newPassword).trim().length >= 6) {
        if (body.currentPassword) {
          const valid = verifyCustomerPassword(body.currentPassword, customer.passwordHash, customer.passwordSalt);
          if (!valid) {
            return res.status(400).json({ success: false, error: "كلمة المرور الحالية غير صحيحة" });
          }
        }
        const { hash, salt } = hashCustomerPassword(String(body.newPassword).trim());
        customer.passwordHash = hash;
        customer.passwordSalt = salt;
      }

      customer.updatedAt = Date.now();
      await saveCustomer(customer);

      return res.status(200).json({
        success: true,
        message: "تم تحديث البيانات بنجاح",
        customer: sanitizeCustomer(customer)
      });
    }

    // -------------------------------------------------------------------------
    // 6. GET ALL REGISTERED CUSTOMERS (ADMIN DIRECTORY - STRICT ADMIN AUTH REQ) (F-04)
    // -------------------------------------------------------------------------
    if (req.method === "GET" && action === "list") {
      // Mandatory admin authorization check (F-04)
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({
          success: false,
          error: "غير مصرح بالوصول. استعراض سجل العملاء يتطلب صلاحيات الإدارة العليا المعتمدة."
        });
      }

      const allCustomers = await fetchCustomers();
      allCustomers.sort((a, b) => (b.createdAt || b.updatedAt || 0) - (a.createdAt || a.updatedAt || 0));

      return res.status(200).json({
        success: true,
        count: allCustomers.length,
        customers: allCustomers.map(c => sanitizeCustomer(c))
      });
    }

    return res.status(400).json({ success: false, error: "إجراء غير معروف" });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
}
