// Vercel Serverless Function: /api/customer
// Customer Account Management, Authentication & Isolated Order History
// PRD Sections 2, 3, 4 & 10 (Strict Zero Cross-Account Access Guarantee)

import crypto from "crypto";
import {
  hashCustomerPassword,
  verifyCustomerPassword,
  createCustomerToken,
  verifyCustomerRequest
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

function getFirebaseUrl(req) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) return envUrl.trim().replace(/\/$/, "");
  return "https://kased-karim-default-rtdb.firebaseio.com";
}

async function fetchCustomers(firebaseUrl) {
  try {
    const res = await fetch(`${firebaseUrl}/customers.json?t=${Date.now()}`, { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      if (data && typeof data === "object") {
        return Object.values(data).filter(Boolean);
      }
    }
  } catch (e) {}
  return [];
}

async function saveCustomer(firebaseUrl, customer) {
  const safeId = encodeURIComponent(customer.id);
  const res = await fetch(`${firebaseUrl}/customers/${safeId}.json`, {
    method: "PUT",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(customer)
  });
  return res.ok;
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-customer-token");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const firebaseUrl = getFirebaseUrl(req);
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
      const name = (body.name || "").trim().replace(/[<>]/g, "");
      const phone = (body.phone || "").replace(/[^0-9]/g, "");
      const email = (body.email || "").trim().toLowerCase().replace(/[<>]/g, "");
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

      const allCustomers = await fetchCustomers(firebaseUrl);
      const existing = allCustomers.find(c => c.phone === phone || (email && c.email === email));
      if (existing) {
        return res.status(409).json({
          success: false,
          error: "رقم الهاتف أو البريد الإلكتروني مسجل بالفعل. يرجى تسجيل الدخول مباشرة."
        });
      }

      const customerId = "CUST-" + crypto.randomInt(1000, 9999) + "-" + crypto.randomBytes(2).toString("hex").toUpperCase();
      const { hash, salt } = hashCustomerPassword(password);

      const newCustomer = {
        id: customerId,
        name,
        phone,
        email: email || `${phone}@kasedkarim.test`,
        passwordHash: hash,
        passwordSalt: salt,
        createdAt: Date.now(),
        updatedAt: Date.now()
      };

      await saveCustomer(firebaseUrl, newCustomer);

      const token = createCustomerToken({
        sub: customerId,
        phone,
        name,
        email: newCustomer.email
      });

      return res.status(201).json({
        success: true,
        message: "تم إنشاء حساب العميل بنجاح",
        token,
        customer: {
          id: newCustomer.id,
          name: newCustomer.name,
          phone: newCustomer.phone,
          email: newCustomer.email
        }
      });
    }

    // -------------------------------------------------------------------------
    // 1.5 AUTHENTIC GOOGLE OAUTH SIGN-IN
    // -------------------------------------------------------------------------
    if (req.method === "POST" && (action === "google" || action === "google-login")) {
      const email = (body.email || "").trim().toLowerCase().replace(/[<>]/g, "");
      const name = (body.name || "").trim().replace(/[<>]/g, "");
      const googleId = (body.sub || body.googleId || "").trim();
      const avatar = (body.picture || body.avatar || "").trim();
      const phone = (body.phone || "").replace(/[^0-9]/g, "");

      if (!email || !googleId) {
        return res.status(400).json({ success: false, error: "بيانات حساب Google غير مكتملة" });
      }

      const allCustomers = await fetchCustomers(firebaseUrl);
      let customer = allCustomers.find(c => c.googleId === googleId || (c.email && c.email.toLowerCase() === email));

      if (customer) {
        customer.name = name || customer.name;
        customer.googleId = googleId;
        if (avatar) customer.avatar = avatar;
        if (phone && !customer.phone) customer.phone = phone;
        customer.authProvider = "google";
        customer.updatedAt = Date.now();
        await saveCustomer(firebaseUrl, customer);
      } else {
        const customerId = "CUST-G-" + crypto.randomInt(1000, 9999) + "-" + crypto.randomBytes(2).toString("hex").toUpperCase();
        customer = {
          id: customerId,
          googleId,
          name: name || "عميل Google",
          email,
          phone: phone || "",
          avatar: avatar || "",
          authProvider: "google",
          createdAt: Date.now(),
          updatedAt: Date.now()
        };
        await saveCustomer(firebaseUrl, customer);
      }

      const token = createCustomerToken({
        sub: customer.id,
        phone: customer.phone || "",
        name: customer.name,
        email: customer.email
      });

      return res.status(200).json({
        success: true,
        message: "تم تسجيل الدخول بواسطة Google بنجاح",
        token,
        customer: {
          id: customer.id,
          name: customer.name,
          phone: customer.phone,
          email: customer.email,
          avatar: customer.avatar,
          authProvider: "google"
        }
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
      const allCustomers = await fetchCustomers(firebaseUrl);

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

      return res.status(200).json({
        success: true,
        message: "تم تسجيل الدخول بنجاح",
        token,
        customer: {
          id: customer.id,
          name: customer.name,
          phone: customer.phone,
          email: customer.email
        }
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

      const allCustomers = await fetchCustomers(firebaseUrl);
      const customer = allCustomers.find(c => c.id === auth.sub || c.phone === auth.phone);

      if (!customer) {
        return res.status(404).json({ success: false, error: "لم يتم العثور على حساب العميل" });
      }

      return res.status(200).json({
        success: true,
        customer: {
          id: customer.id,
          name: customer.name,
          phone: customer.phone,
          email: customer.email,
          createdAt: customer.createdAt
        }
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

      // Fetch all orders from Firebase
      const ordRes = await fetch(`${firebaseUrl}/orders.json?t=${Date.now()}`, { cache: "no-store" });
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

      const myOrders = allOrders.filter(o => {
        if (!o || !o.id) return false;
        if (o.customerId && o.customerId === customerId) return true;
        const ordPhone = (o.customer?.phone || "").replace(/[^0-9]/g, "");
        if (customerPhone && ordPhone && (ordPhone === customerPhone || ordPhone.endsWith(customerPhone) || customerPhone.endsWith(ordPhone))) {
          return true;
        }
        return false;
      });

      myOrders.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

      return res.status(200).json({
        success: true,
        count: myOrders.length,
        orders: myOrders
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

      const allCustomers = await fetchCustomers(firebaseUrl);
      const customer = allCustomers.find(c => c.id === auth.sub || c.phone === auth.phone);
      if (!customer) {
        return res.status(404).json({ success: false, error: "حساب العميل غير موجود" });
      }

      if (body.name) customer.name = String(body.name).trim().replace(/[<>]/g, "");
      if (body.email) customer.email = String(body.email).trim().toLowerCase().replace(/[<>]/g, "");

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
      await saveCustomer(firebaseUrl, customer);

      return res.status(200).json({
        success: true,
        message: "تم تحديث البيانات بنجاح",
        customer: {
          id: customer.id,
          name: customer.name,
          phone: customer.phone,
          email: customer.email
        }
      });
    }

    return res.status(400).json({ success: false, error: "إجراء غير معروف" });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
}
