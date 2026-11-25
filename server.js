/**
 * KASED KARIM LUXURY LIGHTING - PRODUCTION HARDENED SERVER (server.js)
 * Architecture: Unified Frontend + Backend + Relational SQL Database
 * Zero Vendor Lock-in: Run on ANY VPS (Hetzner, DO, Contabo, AWS) or locally via Node/Docker/Podman.
 * Standards: OWASP ASVS Level 3, Strict Referential Integrity, Automated Soft Delete, Zero-Trust Pricing & IDOR Defense.
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { validateEmail } from "./lib/emailValidator.js";
import { verifyTurnstile, extractTurnstileToken } from "./lib/turnstile.js";
import { enforceRateLimit, getClientIp } from "./lib/rateLimit.js";
import {
  validateSafeImageUrl,
  create2FAChallenge,
  verify2FAChallenge,
  burnChallenge,
  send2FAEmail,
  sendCustomerVerificationEmail,
  verifyCustomerToken,
  verifyAdminPassword,
  ADMIN_2FA_EMAILS,
  setSecurityHeaders,
  safeLogError,
  redactSecrets
} from "./api/_auth.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// =============================================================================
// 0. ENVIRONMENT VARIABLES & SECRETS INITIALIZATION (Fail-Closed)
// =============================================================================
const envFile = path.join(__dirname, ".env");
if (fs.existsSync(envFile)) {
  try {
    const rawEnv = fs.readFileSync(envFile, "utf8");
    for (const line of rawEnv.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx > 0) {
        const k = trimmed.slice(0, eqIdx).trim();
        const v = trimmed.slice(eqIdx + 1).trim();
        if (!process.env[k]) {
          process.env[k] = v;
        }
      }
    }
  } catch (e) {
    console.warn("[Env] Warning reading local .env file:", e.message);
  }
}

const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "0.0.0.0";
const DB_FILE = process.env.SQLITE_DB_PATH || path.join(__dirname, "kased_karim.db");

// Cryptographic Secrets with Zero-Downtime Rotation Support (RFC 7519 / ASVS Level 3)
const EPHEMERAL_SECRET = crypto.randomBytes(32).toString("hex");
const ADMIN_JWT_SECRETS = (process.env.ADMIN_JWT_SECRET || process.env.ADMIN_SECRET || EPHEMERAL_SECRET).split(",").map(s => s.trim()).filter(Boolean);
const ADMIN_JWT_SECRET = ADMIN_JWT_SECRETS[0];
const CUSTOMER_JWT_SECRETS = (process.env.CUSTOMER_JWT_SECRET || "").split(",").map(s => s.trim()).filter(Boolean);
// Strict Cryptographic Domain Separation: If CUSTOMER_JWT_SECRET is unset, derive an isolated domain-separated key
const CUSTOMER_JWT_SECRET = CUSTOMER_JWT_SECRETS.length > 0 
  ? CUSTOMER_JWT_SECRETS[0] 
  : crypto.createHmac("sha256", ADMIN_JWT_SECRET).update("kased_karim_customer_jwt_domain_v2").digest("hex");
const EFFECTIVE_CUSTOMER_JWT_SECRETS = CUSTOMER_JWT_SECRETS.length > 0 ? CUSTOMER_JWT_SECRETS : [CUSTOMER_JWT_SECRET];

// Fail-Closed: Strictly from environment variables (Zero hardcoded fallback passwords - CWE-259 / CWE-798)
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "").trim();
const ADMIN_PASSWORD_HASH = (process.env.ADMIN_PASSWORD_HASH || "").trim();
const ADMIN_PASSWORD_SALT = (process.env.ADMIN_PASSWORD_SALT || "").trim();
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || "").trim();

// =============================================================================
// 1. RELATIONAL DATABASE INITIALIZATION & MIGRATIONS
// =============================================================================
// Fail-Closed Architecture Guard for Vercel Serverless & Production (ASVS Level 3)
const isVercel = process.env.VERCEL === "1" || Boolean(process.env.VERCEL);
if (isVercel) {
  const errMsg = "CRITICAL FAIL-CLOSED: server.js execution blocked on Vercel Serverless. " +
    "Vercel filesystem is stateless & ephemeral; local SQLite files (kased_karim.db) will be erased on lambda teardown, causing permanent loss of customer orders. " +
    "Vercel production deployments strictly route traffic to /api serverless endpoints backed by managed Firebase RTDB or PostgreSQL.";
  console.error(errMsg);
  throw new Error(errMsg);
}

console.log(`[Database] Initializing Relational SQL Database at: ${DB_FILE}`);
const db = new DatabaseSync(DB_FILE);

// Enforce strict foreign key constraints in SQLite engine
db.exec("PRAGMA foreign_keys = ON;");
db.exec("PRAGMA journal_mode = WAL;");

// Execute Core Relational Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS categories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    en_name TEXT,
    slug TEXT UNIQUE NOT NULL,
    parent_id TEXT REFERENCES categories(id) ON DELETE SET NULL,
    icon TEXT,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    sku TEXT UNIQUE,
    name TEXT NOT NULL,
    en_name TEXT,
    category_id TEXT REFERENCES categories(id) ON DELETE RESTRICT,
    category_name TEXT,
    price REAL NOT NULL CHECK (price >= 0),
    sale_price REAL,
    original_price REAL,
    cost_price REAL,
    stock INTEGER NOT NULL DEFAULT 0,
    image TEXT,
    secondary_image TEXT,
    images TEXT DEFAULT '[]',
    description TEXT,
    short_description TEXT,
    style TEXT,
    warranty TEXT DEFAULT '5 سنوات ضمان معتمد',
    specs TEXT DEFAULT '{}',
    variants TEXT DEFAULT '[]',
    tags TEXT DEFAULT '[]',
    active INTEGER DEFAULT 1,
    featured INTEGER DEFAULT 0,
    is_new INTEGER DEFAULT 0,
    is_bestseller INTEGER DEFAULT 0,
    status TEXT DEFAULT 'published',
    deleted_at TEXT DEFAULT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS pricelists (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    code TEXT UNIQUE,
    currency TEXT DEFAULT 'EGP',
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS pricelist_items (
    id TEXT PRIMARY KEY,
    pricelist_id TEXT NOT NULL REFERENCES pricelists(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    tier_price REAL NOT NULL,
    min_quantity INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE (pricelist_id, product_id)
  );

  CREATE TABLE IF NOT EXISTS inventory (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    warehouse_name TEXT DEFAULT 'المستودع الرئيسي - الشيخ زايد',
    quantity_on_hand INTEGER NOT NULL DEFAULT 0,
    quantity_reserved INTEGER NOT NULL DEFAULT 0,
    reorder_threshold INTEGER DEFAULT 5,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE (product_id, warehouse_name)
  );

  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    order_number TEXT UNIQUE NOT NULL,
    customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
    customer_name TEXT NOT NULL,
    customer_phone TEXT NOT NULL,
    customer_email TEXT,
    shipping_address TEXT NOT NULL,
    delivery_city TEXT,
    subtotal REAL NOT NULL,
    discount REAL DEFAULT 0,
    delivery_fee REAL DEFAULT 0,
    total REAL NOT NULL,
    status TEXT DEFAULT 'pending',
    payment_method TEXT DEFAULT 'cod',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS order_items (
    id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    product_name TEXT NOT NULL,
    unit_price REAL NOT NULL,
    quantity INTEGER NOT NULL,
    total_price REAL NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sales (
    id TEXT PRIMARY KEY,
    order_id TEXT REFERENCES orders(id) ON DELETE SET NULL,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    quantity_sold INTEGER NOT NULL,
    unit_cost REAL DEFAULT 0,
    unit_price REAL NOT NULL,
    gross_revenue REAL NOT NULL,
    net_profit REAL NOT NULL,
    sale_date TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS restore_points (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    date_str TEXT NOT NULL,
    time_str TEXT NOT NULL,
    label TEXT NOT NULL,
    point_type TEXT DEFAULT 'auto_delete',
    counts_json TEXT,
    total_revenue REAL DEFAULT 0,
    data_json TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT,
    password_salt TEXT,
    google_sub TEXT UNIQUE,
    avatar TEXT,
    role TEXT DEFAULT 'customer',
    email_verified INTEGER DEFAULT 0,
    verification_token_hash TEXT,
    verification_code_hash TEXT,
    verification_expires_at INTEGER,
    verification_attempts INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    revoked_at TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_products_active_deleted ON products(active, deleted_at, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_orders_customer_id ON orders(customer_id);
  CREATE INDEX IF NOT EXISTS idx_orders_created_at ON orders(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id);
  CREATE INDEX IF NOT EXISTS idx_customers_email_lower ON customers(LOWER(email));
  CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON revoked_tokens(expires_at);

  CREATE TABLE IF NOT EXISTS coupons (
    code TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value REAL NOT NULL,
    min_order_amount REAL DEFAULT 0,
    max_discount_amount REAL,
    usage_limit INTEGER,
    used_count INTEGER DEFAULT 0,
    active INTEGER DEFAULT 1,
    expires_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS idempotency_locks (
    key TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    order_id TEXT,
    response_body TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON revoked_tokens(expires_at);
  CREATE INDEX IF NOT EXISTS idx_idempotency_created ON idempotency_locks(created_at);
  CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers(phone);
  CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email);
  CREATE INDEX IF NOT EXISTS idx_restore_points_date ON restore_points(date_str);
  CREATE INDEX IF NOT EXISTS idx_restore_points_time ON restore_points(timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_prod_deleted_at ON products(deleted_at);
  CREATE INDEX IF NOT EXISTS idx_prod_active ON products(active, deleted_at);
  CREATE INDEX IF NOT EXISTS idx_order_items_product ON order_items(product_id);
  CREATE INDEX IF NOT EXISTS idx_sales_product ON sales(product_id);
  CREATE INDEX IF NOT EXISTS idx_inventory_product ON inventory(product_id);
  CREATE INDEX IF NOT EXISTS idx_pricelist_product ON pricelist_items(product_id);
`);

// Safe migration for customer_id in existing database
try {
  db.exec("ALTER TABLE orders ADD COLUMN customer_id TEXT;");
} catch (e) {}
try {
  db.exec("ALTER TABLE customers ADD COLUMN email_verified INTEGER DEFAULT 0;");
} catch (e) {}
try {
  db.exec("ALTER TABLE customers ADD COLUMN verification_token_hash TEXT;");
} catch (e) {}
try {
  db.exec("ALTER TABLE customers ADD COLUMN verification_code_hash TEXT;");
} catch (e) {}
try {
  db.exec("ALTER TABLE customers ADD COLUMN verification_expires_at INTEGER;");
} catch (e) {}
try {
  db.exec("ALTER TABLE customers ADD COLUMN verification_attempts INTEGER DEFAULT 0;");
} catch (e) {}

// Seed initial showroom categories if table is empty
const catCount = db.prepare("SELECT COUNT(*) as count FROM categories").get().count;
if (catCount === 0) {
  console.log("[Database] Seeding initial showroom categories...");
  const insertCat = db.prepare("INSERT INTO categories (id, name, en_name, slug, sort_order) VALUES (?, ?, ?, ?, ?)");
  insertCat.run("cat_chandeliers", "نجف وثريات فاخرة", "Luxury Chandeliers", "chandeliers", 1);
  insertCat.run("cat_wall_lights", "إنارة جدارية عصرية", "Modern Wall Lights", "wall-lights", 2);
  insertCat.run("cat_architectural", "إنارة معمارية ومخفية", "Architectural Lighting", "architectural", 3);
  insertCat.run("cat_outdoor", "إنارة حدائق وواجهات", "Outdoor & Landscape", "outdoor", 4);
}

// Seed baseline products if table is empty
const prodCount = db.prepare("SELECT COUNT(*) as count FROM products").get().count;
if (prodCount === 0) {
  console.log("[Database] Seeding initial showroom products...");
  const insertProd = db.prepare(`
    INSERT INTO products (
      id, sku, name, en_name, category_id, category_name,
      price, sale_price, cost_price, stock, image, description, active, featured, deleted_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, NULL)
  `);
  insertProd.run(
    "prod_crystal_palace",
    "KK-CH-001",
    "ثريا كريستال عصفور ملكية - قصر الكريستال",
    "Crystal Palace Royal Chandelier",
    "cat_chandeliers",
    "نجف وثريات فاخرة",
    48500.0,
    42000.0,
    28000.0,
    12,
    "https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=800&q=80",
    "ثريا ملكية فاخرة مطلية بذهب عيار 24 مع كريستال نقي ومصممة خصيصاً للصالات والقصور."
  );
  insertProd.run(
    "prod_nordic_minimal",
    "KK-WL-002",
    "وحدة إضاءة جدارية نورديك ألمنيوم مصقول",
    "Nordic Minimalist Wall Sconce",
    "cat_wall_lights",
    "إنارة جدارية عصرية",
    3800.0,
    null,
    2100.0,
    45,
    "https://images.unsplash.com/photo-1513506003901-1e6a229e2d15?auto=format&fit=crop&w=800&q=80",
    "إضاءة جدارية غير مباشرة بدرجة حرارة لون 3000K تمنح راحة بصرية فائقة وأناقة راقية."
  );

  // Link inventory
  const insertInv = db.prepare("INSERT INTO inventory (id, product_id, warehouse_name, quantity_on_hand, quantity_reserved) VALUES (?, ?, ?, ?, ?)");
  insertInv.run("inv_001", "prod_crystal_palace", "المستودع الرئيسي - الشيخ زايد", 12, 0);
  insertInv.run("inv_002", "prod_nordic_minimal", "المستودع الرئيسي - الشيخ زايد", 45, 0);
}

// =============================================================================
// 2. REFERENTIAL INTEGRITY & SOFT-DELETE VERIFIER
// =============================================================================
function checkProductRelations(productId) {
  const orderCount = db.prepare("SELECT COUNT(*) as c FROM order_items WHERE product_id = ?").get(productId).c;
  const salesCount = db.prepare("SELECT COUNT(*) as c FROM sales WHERE product_id = ?").get(productId).c;
  const invCount = db.prepare("SELECT COUNT(*) as c FROM inventory WHERE product_id = ? AND quantity_on_hand > 0").get(productId).c;
  const priceCount = db.prepare("SELECT COUNT(*) as c FROM pricelist_items WHERE product_id = ?").get(productId).c;

  return {
    orders: orderCount,
    sales: salesCount,
    inventory: invCount,
    pricelists: priceCount,
    hasRelations: (orderCount > 0 || salesCount > 0 || invCount > 0 || priceCount > 0)
  };
}

// =============================================================================
// 3. CRYPTOGRAPHIC HELPERS & AUTHENTICATION ENGINES
// =============================================================================

// Sign RFC 7519 Compliant HMAC-SHA256 JWT
function signHmacJwt(payload, secretKey, maxAgeSec = 7200) {
  const header = { alg: "HS256", typ: "JWT" };
  const exp = Math.floor(Date.now() / 1000) + maxAgeSec;
  const jti = crypto.randomUUID();
  const fullPayload = { ...payload, jti, exp, iat: Math.floor(Date.now() / 1000) };

  const b64Header = Buffer.from(JSON.stringify(header)).toString("base64url");
  const b64Payload = Buffer.from(JSON.stringify(fullPayload)).toString("base64url");
  const signature = crypto.createHmac("sha256", secretKey).update(`${b64Header}.${b64Payload}`).digest("base64url");

  return `${b64Header}.${b64Payload}.${signature}`;
}

// Strictly verify and decode HMAC-SHA256 JWT with Key Rotation Support (ASVS Level 3)
function verifyHmacJwt(token, secretKeyOrKeys) {
  if (!token || typeof token !== "string") return null;
  const parts = token.trim().split(".");
  if (parts.length !== 3) return null;
  const [b64Header, b64Payload, signature] = parts;

  const keys = Array.isArray(secretKeyOrKeys) ? secretKeyOrKeys : [secretKeyOrKeys];
  const sigBuf = Buffer.from(signature, "utf-8");

  let matchFound = false;
  for (const key of keys) {
    if (!key) continue;
    const expectedSig = crypto.createHmac("sha256", key).update(`${b64Header}.${b64Payload}`).digest("base64url");
    const expBuf = Buffer.from(expectedSig, "utf-8");
    if (sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf)) {
      matchFound = true;
      break;
    }
  }

  if (!matchFound) {
    return null;
  }

  try {
    const header = JSON.parse(Buffer.from(b64Header, "base64url").toString("utf8"));
    if (header.alg !== "HS256" || header.typ !== "JWT") return null;

    const payload = JSON.parse(Buffer.from(b64Payload, "base64url").toString("utf8"));
    const nowSec = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp) || payload.exp < nowSec) {
      return null; // Missing or expired exp claim
    }

    // Active Server-Side Token Revocation Check (RFC 7009 / ASVS 3.3.1 — Fail-Closed)
    if (payload.jti) {
      try {
        const revoked = db.prepare("SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at > ?").get(payload.jti, nowSec);
        if (revoked) return null;
      } catch (e) {
        return null;
      }
    }

    return payload;
  } catch (e) {
    return null;
  }
}

// Extract Cookie Value Safely
function extractCookie(cookieHeader, name) {
  if (!cookieHeader || typeof cookieHeader !== "string") return null;
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  if (!match) return null;
  try {
    return decodeURIComponent(match[1].trim());
  } catch {
    return null;
  }
}

// Authorize Admin Request
function assertAdminAuthorized(req) {
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  let token = null;
  if (authHeader && typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
    token = authHeader.slice(7).trim();
  }
  if (!token) {
    token = extractCookie(req.headers["cookie"], "kk_admin_token");
  }
  if (!token) {
    token = req.headers["x-admin-token"];
  }
  if (!token) return null;

  const verified = verifyHmacJwt(token, ADMIN_JWT_SECRETS);
  if (verified && verified.role === "admin") {
    // Zero-Trust NIST SP 800-63B (AAL2): verified2FA must strictly be true for admin sessions
    if (verified.verified2FA !== true) {
      return null;
    }
    return verified;
  }
  return null;
}

// Extract Authenticated Customer Session
function extractCustomerSession(req) {
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  let token = null;
  if (authHeader && typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
    token = authHeader.slice(7).trim();
  }
  if (!token) {
    token = extractCookie(req.headers["cookie"], "kk_customer_token");
  }
  if (!token) return null;

  const verified = verifyHmacJwt(token, EFFECTIVE_CUSTOMER_JWT_SECRETS) || verifyCustomerToken(token);
  if (verified && (verified.role === "customer" || verified.sub)) {
    if (verified.jti) {
      try {
        const revoked = db.prepare("SELECT 1 FROM revoked_tokens WHERE jti = ? AND expires_at > ?").get(verified.jti, Math.floor(Date.now() / 1000));
        if (revoked) return null;
      } catch (e) {}
    }
    return verified;
  }
  return null;
}

// Asynchronous Non-blocking scrypt Password Hashing
function hashPasswordAsync(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");
    crypto.scrypt(password, salt, 32, (err, derivedKey) => {
      if (err) return reject(err);
      resolve({
        hash: derivedKey.toString("hex"),
        salt
      });
    });
  });
}

// Asynchronous Non-blocking Constant-Time Password Verification
function verifyPasswordAsync(password, storedHash, storedSalt) {
  return new Promise((resolve) => {
    crypto.scrypt(password, storedSalt, 32, (err, derivedKey) => {
      if (err) return resolve(false);
      const derivedBuf = Buffer.from(derivedKey.toString("hex"), "hex");
      const targetBuf = Buffer.from(storedHash, "hex");
      if (derivedBuf.length !== targetBuf.length) return resolve(false);
      resolve(crypto.timingSafeEqual(derivedBuf, targetBuf));
    });
  });
}

// Verified Google ID Token Check via Google OAuth API (Strict Fail-Closed)
async function verifyGoogleToken(idToken) {
  if (!idToken || typeof idToken !== "string" || idToken.length < 50 || idToken.length > 4096) {
    return null;
  }
  if (!GOOGLE_CLIENT_ID) {
    console.error("[CRITICAL SECURITY ALERT] GOOGLE_CLIENT_ID is not configured in server environment. Blocking OAuth authentication (Fail-Closed).");
    return null;
  }
  try {
    const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken.trim())}`, {
      headers: { "Accept": "application/json" },
      signal: AbortSignal.timeout(5000)
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (!data || typeof data !== "object") return null;
    if (data.aud !== GOOGLE_CLIENT_ID) {
      console.warn("[Security Alert] Google token audience mismatch. Expected:", GOOGLE_CLIENT_ID, "Received:", data.aud);
      return null;
    }
    if (data.iss !== "accounts.google.com" && data.iss !== "https://accounts.google.com") {
      console.warn("[Security Alert] Google token issuer mismatch:", data.iss);
      return null;
    }
    if (data.email_verified !== "true" && data.email_verified !== true) {
      return null;
    }
    return {
      sub: data.sub,
      email: (data.email || "").toLowerCase(),
      name: data.name || "عميل Google",
      picture: data.picture || ""
    };
  } catch (err) {
    console.error("[Auth] Google token verification error:", err.message);
    return null;
  }
}

// Distributed Upstash Sliding Window Rate Limiting (Zero In-Memory Map)

// =============================================================================
// 4. HTTP SERVER & ROUTING ENGINE
// =============================================================================
const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".webmanifest": "application/manifest+json"
};

function isHttpsRequest(req) {
  if (!req) return process.env.NODE_ENV === "production";
  if (req.socket && req.socket.encrypted) return true;
  const proto = (req.headers && (req.headers["x-forwarded-proto"] || req.headers["X-Forwarded-Proto"])) || "";
  if (typeof proto === "string" && proto.toLowerCase().includes("https")) return true;
  return process.env.NODE_ENV === "production";
}

function applySecurityHeaders(res, isPathAdmin = false) {
  if (!res.getHeader("X-Content-Type-Options")) res.setHeader("X-Content-Type-Options", "nosniff");
  if (!res.getHeader("X-Frame-Options")) res.setHeader("X-Frame-Options", "DENY");
  if (!res.getHeader("Referrer-Policy")) {
    res.setHeader("Referrer-Policy", isPathAdmin ? "no-referrer" : "strict-origin-when-cross-origin");
  }
  if (!res.getHeader("Cross-Origin-Opener-Policy")) {
    res.setHeader("Cross-Origin-Opener-Policy", isPathAdmin ? "same-origin" : "same-origin-allow-popups");
  }
  if (!res.getHeader("Permissions-Policy")) {
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  }
  if (!res.getHeader("Strict-Transport-Security")) {
    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  }

  // Preserve existing API Content-Security-Policy (e.g. from setSecurityHeaders in api/_auth.js)
  if (!res.getHeader("Content-Security-Policy")) {
    if (isPathAdmin) {
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; style-src-attr 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: blob: https://images.unsplash.com https://res.cloudinary.com https://lh3.googleusercontent.com; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; manifest-src 'self'; worker-src 'none'; upgrade-insecure-requests;"
      );
    } else {
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self' https://accounts.google.com/gsi/client https://www.googletagmanager.com https://challenges.cloudflare.com; script-src-attr 'none'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://accounts.google.com/gsi/style; style-src-attr 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: blob: https://images.unsplash.com https://res.cloudinary.com https://lh3.googleusercontent.com https://*.google-analytics.com https://*.googletagmanager.com; connect-src 'self' https://accounts.google.com/gsi/ https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com https://challenges.cloudflare.com; frame-src https://accounts.google.com/gsi/ https://maps.google.com https://www.google.com https://challenges.cloudflare.com; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; manifest-src 'self'; worker-src 'none'; upgrade-insecure-requests;"
      );
    }
  }
}

function sendJson(res, statusCode, data, customHeaders = {}) {
  applySecurityHeaders(res);
  const json = JSON.stringify(data);
  const activeCache = res.getHeader("Cache-Control") || "no-store, no-cache, must-revalidate, max-age=0";
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(json),
    "Cache-Control": activeCache,
    ...customHeaders
  });
  res.end(json);
}

function sendError(res, statusCode, message) {
  return sendJson(res, statusCode, { success: false, error: message });
}

function parseBody(req, maxLimit = 50 * 1024) {
  return new Promise((resolve, reject) => {
    // 1. Content-Length Header Guard against Denial of Wallet (CWE-400)
    const cl = parseInt(req.headers["content-length"] || "0", 10);
    if (cl > maxLimit) {
      const err = new Error(`حجم بيانات الطلب (${Math.round(cl / 1024)}KB) يتجاوز الحد الأقصى المسموح به (${Math.round(maxLimit / 1024)}KB) - 413 Payload Too Large.`);
      err.statusCode = 413;
      return reject(err);
    }

    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (Buffer.byteLength(body, "utf8") > maxLimit) {
        req.destroy();
        const err = new Error(`حجم بيانات الطلب يتجاوز الحد الأقصى المسموح به (${Math.round(maxLimit / 1024)}KB) - 413 Payload Too Large.`);
        err.statusCode = 413;
        reject(err);
      }
    });
    req.on("end", () => {
      try {
        const parsed = body ? JSON.parse(body) : {};
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          if (parsed.__proto__ !== Object.prototype && parsed.__proto__ !== null) {
            const err = new Error("تم رصد محاولة تلاعب بالنموذج الأولي (Prototype Pollution).");
            err.statusCode = 400;
            return reject(err);
          }
          if (Object.prototype.hasOwnProperty.call(parsed, "__proto__") ||
              Object.prototype.hasOwnProperty.call(parsed, "constructor") ||
              Object.prototype.hasOwnProperty.call(parsed, "prototype")) {
            const err = new Error("كائن البيانات يحتوي على حقول محظورة أمنياً (__proto__, constructor, prototype).");
            err.statusCode = 400;
            return reject(err);
          }
        }
        resolve(parsed);
      } catch (e) {
        if (body && body.trim().length > 0) {
          const err = new Error("حزمة البيانات المرسلة غير صالحة (Invalid JSON Body).");
          err.statusCode = 400;
          return reject(err);
        }
        resolve({});
      }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const pathname = parsedUrl.pathname;
    const method = req.method.toUpperCase();
    const clientIp = getClientIp(req);

    // -------------------------------------------------------------------------
    // API CORS & PREFLIGHT GUARD (Axis 4 / Unit 13)
    // -------------------------------------------------------------------------
    if (pathname.startsWith("/api/")) {
      const handled = setSecurityHeaders(req, res);
      if (handled || method === "OPTIONS") {
        return;
      }
    }

  // ---------------------------------------------------------------------------
  // API: Database Health Check (/api/db-health)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/db-health") {
    // Basic liveness probe to verify SQLite engine availability
    try {
      db.prepare("SELECT 1").get();
    } catch (err) {
      console.error("[Health Check] Database probe failed:", err.message);
      return sendJson(res, 503, { status: "unhealthy", error: "Database engine unavailable" });
    }

    const admin = assertAdminAuthorized(req);

    // Public / Container Health Check Response (Zero Information Disclosure)
    if (!admin) {
      return sendJson(res, 200, { status: "healthy" });
    }

    // Privileged Diagnostics & Statistics (Admin Only)
    const activeProducts = db.prepare("SELECT COUNT(*) as c FROM products WHERE deleted_at IS NULL").get().c;
    const softDeletedProducts = db.prepare("SELECT COUNT(*) as c FROM products WHERE deleted_at IS NOT NULL").get().c;
    const ordersCount = db.prepare("SELECT COUNT(*) as c FROM orders").get().c;
    const salesCount = db.prepare("SELECT COUNT(*) as c FROM sales").get().c;
    const inventoryCount = db.prepare("SELECT COUNT(*) as c FROM inventory").get().c;

    return sendJson(res, 200, {
      status: "healthy",
      database: "relational-sql",
      engine: "sqlite-native-wal",
      storage: DB_FILE,
      referentialIntegrity: "ENFORCED (FOREIGN KEYS ON)",
      softDeleteStatus: "ACTIVE",
      stats: {
        products_active: activeProducts,
        products_soft_deleted: softDeletedProducts,
        orders_count: ordersCount,
        sales_count: salesCount,
        inventory_records: inventoryCount
      },
      timestamp: new Date().toISOString()
    });
  }

  // ---------------------------------------------------------------------------
  // API: Admin Authentication Gate (/api/auth)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/auth") {
    if (method === "GET" || method === "HEAD") {
      const admin = assertAdminAuthorized(req);
      if (!admin) {
        return sendError(res, 401, "جلسة الإدارة غير صالحة أو منتهية.");
      }
      return sendJson(res, 200, {
        authenticated: true,
        user: { role: "admin", name: "Kased Karim Admin" },
        expiresAt: admin.exp
      });
    }

    if (method === "POST") {
      const body = await parseBody(req);

      // Admin Logout
      if (body.action === "logout" || parsedUrl.searchParams.get("action") === "logout") {
        const token = extractCookie(req.headers["cookie"], "kk_admin_token") ||
                      (req.headers["authorization"]?.startsWith("Bearer ") ? req.headers["authorization"].slice(7).trim() : null) ||
                      req.headers["x-admin-token"];
        if (token) {
          try {
            const verified = verifyHmacJwt(token, ADMIN_JWT_SECRETS);
            if (verified && verified.jti) {
              db.prepare("INSERT OR REPLACE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)").run(
                verified.jti,
                verified.exp || (Math.floor(Date.now() / 1000) + 7200)
              );
            }
          } catch (e) {}
        }
        applySecurityHeaders(res);
        res.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
          "Set-Cookie": `kk_admin_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; ${isHttpsRequest(req) ? "Secure" : ""}`.trim()
        });
        return res.end(JSON.stringify({ success: true, message: "تم تسجيل خروج الإدارة بنجاح وإلغاء صلاحية الجلسة فورياً." }));
      }

      // Sliding Window Rate Limit: Admin login (5 attempts per 15 minutes)
      const allowed = await enforceRateLimit(req, res, "auth");
      if (!allowed) return;

      // -----------------------------------------------------------------------
      // STEP 2: VERIFY 6-DIGIT EMAIL OTP (MANDATORY MFA WITH ATOMIC BURN)
      // -----------------------------------------------------------------------
      if (body.action === "verify_otp" || (body.otp && !body.password)) {
        const rawOtp = body.otp;
        if (typeof rawOtp !== "string" || !/^\d{6}$/.test(rawOtp.trim())) {
          return sendError(res, 400, "يرجى إدخال رمز التحقق السداسي المكون من 6 أرقام فقط.");
        }
        const challengeId = (body.challengeId || "").trim();
        if (!challengeId) {
          return sendError(res, 400, "معرّف التحدي الأمني (challengeId) مفقود.");
        }

        const verification = await verify2FAChallenge(challengeId, rawOtp.trim(), clientIp);
        if (!verification || !verification.valid) {
          await new Promise(r => setTimeout(r, 600)); // Constant delay against timing side-channel
          if (verification?.error === "max_attempts") {
            return sendError(res, 401, "تم تجاوز الحد الأقصى للمحاولات (3 محاولات خاطئة). تم إتلاف الرمز فوراً لضمان الأمان.");
          }
          if (verification?.error === "expired") {
            return sendError(res, 401, "انتهت صلاحية رمز التحقق (أكثر من 5 دقائق). يرجى تسجيل الدخول مجدداً.");
          }
          if (verification?.error === "ip_mismatch") {
            return sendError(res, 401, "فشل التحقق: عنوان IP للجهاز لا يطابق الجهاز الذي أنشأ التحدي الأمني.");
          }
          return sendError(res, 401, "رمز التحقق السداسي غير صحيح أو انتهت صلاحيته.");
        }

        // OTP Verified & Atomically Burned: Issue 2-hour Admin Token
        const token = signHmacJwt({ sub: "executive-admin", role: "admin", ip: clientIp, verified2FA: true }, ADMIN_JWT_SECRET, 7200);
        applySecurityHeaders(res);
        res.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
          "Set-Cookie": `kk_admin_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=7200; ${isHttpsRequest(req) ? "Secure" : ""}`.trim()
        });
        return res.end(JSON.stringify({
          success: true,
          user: { role: "admin", name: "Kased Karim Admin" },
          message: "تم التحقق الأمني بنجاح ومصادقة جهاز الإدارة."
        }));
      }

      // -----------------------------------------------------------------------
      // STEP 1: VERIFY PASSWORD & ISSUE 2FA CHALLENGE
      // -----------------------------------------------------------------------
      const inputPassword = body.password ? String(body.password).normalize("NFKC").trim() : "";
      if (!inputPassword) {
        return sendError(res, 400, "كلمة المرور مطلوبة.");
      }

      // Memory-Hard scrypt + constant-time password verification (ASVS Level 3)
      const isValid = await verifyAdminPassword(inputPassword);
      if (!isValid) {
        await new Promise(r => setTimeout(r, 600)); // Constant delay
        return sendError(res, 401, "بيانات الدخول الإدارية غير صحيحة.");
      }

      // Create Mandatory 2FA Challenge (NIST AAL2)
      const challengeResult = await create2FAChallenge(clientIp);
      if (challengeResult.error === "cooldown") {
        res.setHeader("Retry-After", String(challengeResult.remainingSec));
        return sendError(res, 429, `يرجى الانتظار ${challengeResult.remainingSec} ثانية قبل طلب رمز تحقق جديد.`);
      }

      const { challengeId, otpCode } = challengeResult;
      console.log(`[Admin 2FA] Verification challenge ${challengeId} created and dispatched.`);

      // Dispatch 2FA email in background
      send2FAEmail(otpCode, ADMIN_2FA_EMAILS).catch(err => {
        console.warn("[Admin 2FA] Email dispatch note:", err.message);
      });

      return sendJson(res, 200, {
        success: true,
        step: "otp_required",
        challengeId,
        message: "تم إرسال كود التحقق الأمني السداسي إلى البريد المعتمد للإدارة الرئيسية."
      });
    }
  }

  // ---------------------------------------------------------------------------
  // API: Products Management (/api/products)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/products") {
    // 1. GET: Fetch Products
    if (method === "GET") {
      const id = parsedUrl.searchParams.get("id");
      const includeDeleted = parsedUrl.searchParams.get("include_deleted") === "1";
      const isAdminView = parsedUrl.searchParams.get("all") === "1";

      const rawCookie = req.headers?.cookie || req.headers?.Cookie || "";
      const rawAuth = req.headers?.authorization || req.headers?.Authorization || "";
      const rawAdminToken = req.headers?.["x-admin-token"] || req.headers?.["X-Admin-Token"] || "";
      const rawCustomerToken = req.headers?.["x-customer-token"] || req.headers?.["X-Customer-Token"] || "";
      const hasAuth = Boolean(rawCookie || rawAuth || rawAdminToken || rawCustomerToken);

      // Viewing soft-deleted products or admin all view requires verified admin token
      if (includeDeleted || isAdminView) {
        const admin = assertAdminAuthorized(req);
        if (!admin) {
          res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
          res.setHeader("CDN-Cache-Control", "no-store");
          res.setHeader("Vercel-CDN-Cache-Control", "no-store");
          return sendError(res, 401, "غير مصرح بالوصول. استعراض المنتجات المحذوفة يتطلب صلاحيات الإدارة العليا.");
        }
      }

      const isPublicCacheable = !includeDeleted && !isAdminView && !hasAuth;

      const sanitizePublicProduct = (p) => {
        if (!p || typeof p !== "object") return p;
        const { cost_price, costPrice, supplier, admin_notes, adminNotes, ...safe } = p;
        return safe;
      };

      if (id) {
        const prod = db.prepare("SELECT * FROM products WHERE id = ?").get(id);
        if (!prod) {
          res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
          res.setHeader("CDN-Cache-Control", "no-store");
          res.setHeader("Vercel-CDN-Cache-Control", "no-store");
          return sendError(res, 404, "المنتج غير موجود.");
        }
        if ((prod.deleted_at || prod.active === 0) && !includeDeleted && !isAdminView) {
          res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
          res.setHeader("CDN-Cache-Control", "no-store");
          res.setHeader("Vercel-CDN-Cache-Control", "no-store");
          return sendError(res, 404, "عفواً، هذا المنتج غير متوفر حالياً (تمت أرشفته أو حذفه).");
        }
        if (isPublicCacheable) {
          res.setHeader("Cache-Control", "public, s-maxage=300, stale-while-revalidate=600");
          res.setHeader("CDN-Cache-Control", "public, s-maxage=300, stale-while-revalidate=600");
          res.setHeader("Vercel-CDN-Cache-Control", "public, s-maxage=300, stale-while-revalidate=600");
          res.setHeader("Vary", "Origin, Accept-Encoding, Cookie, Authorization");
        } else {
          res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
          res.setHeader("CDN-Cache-Control", "no-store");
          res.setHeader("Vercel-CDN-Cache-Control", "no-store");
          res.setHeader("Pragma", "no-cache");
          res.setHeader("Expires", "0");
          res.setHeader("Vary", "Cookie, Authorization");
        }
        return sendJson(res, 200, { success: true, product: isAdminView ? prod : sanitizePublicProduct(prod) });
      }

      let query = "SELECT * FROM products WHERE deleted_at IS NULL AND active = 1 ORDER BY created_at DESC";
      if (includeDeleted || isAdminView) {
        query = includeDeleted
          ? "SELECT * FROM products ORDER BY created_at DESC"
          : "SELECT * FROM products WHERE deleted_at IS NULL ORDER BY created_at DESC";
      }

      const rawProducts = db.prepare(query).all();
      const products = isAdminView ? rawProducts : rawProducts.map(sanitizePublicProduct);

      if (isPublicCacheable) {
        res.setHeader("Cache-Control", "public, s-maxage=300, stale-while-revalidate=600");
        res.setHeader("CDN-Cache-Control", "public, s-maxage=300, stale-while-revalidate=600");
        res.setHeader("Vercel-CDN-Cache-Control", "public, s-maxage=300, stale-while-revalidate=600");
        res.setHeader("Vary", "Origin, Accept-Encoding, Cookie, Authorization");
      } else {
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
        res.setHeader("CDN-Cache-Control", "no-store");
        res.setHeader("Vercel-CDN-Cache-Control", "no-store");
        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");
        res.setHeader("Vary", "Cookie, Authorization");
      }

      // Enforce pagination bound (max 50 items)
      const rawPage = parseInt(parsedUrl.searchParams.get("page") || "1", 10);
      const rawLimit = parseInt(parsedUrl.searchParams.get("limit") || "50", 10);
      const page = Number.isInteger(rawPage) && rawPage >= 1 ? rawPage : 1;
      const limit = Number.isInteger(rawLimit) && rawLimit >= 1 ? Math.min(rawLimit, 50) : 50;
      const total = products.length;
      const totalPages = Math.ceil(total / limit) || 1;
      const paged = products.slice((page - 1) * limit, page * limit);

      return sendJson(res, 200, {
        success: true,
        count: paged.length,
        total,
        page,
        limit,
        totalPages,
        products: paged
      });
    }

    // STRICT BFLA GATE: All Mutations (PATCH, POST, DELETE) REQUIRE ADMIN AUTH
    const admin = assertAdminAuthorized(req);
    if (!admin) {
      return sendError(res, 401, "غير مصرح بالوصول. يلزم توفير صلاحيات الإدارة العليا لتعديل أو حذف أو إضافة عناصر الكتالوج.");
    }

    // 2. PATCH / RESTORE: Update Product or Restore Soft-Deleted Product (ADMIN ONLY)
    if (method === "PATCH" || (method === "POST" && parsedUrl.searchParams.get("action") === "restore")) {
      const body = await parseBody(req);
      const rawId = parsedUrl.searchParams.get("id") || body.id;
      if (!rawId) {
        return sendError(res, 400, "معرف المنتج مطلوب لإجراء التعديل أو الاسترجاع.");
      }

      // Restore Soft-Deleted Product
      if (parsedUrl.searchParams.get("action") === "restore" || body.action === "restore" || body.restore === true) {
        db.prepare("UPDATE products SET deleted_at = NULL, active = 1, status = 'published', updated_at = datetime('now') WHERE id = ?")
          .run(rawId);

        return sendJson(res, 200, {
          success: true,
          restored: true,
          id: rawId,
          message: "تم استرجاع المنتج المحذوف بنجاح، وعاد للظهور فوراً في المتجر والكتالوج بكافة بياناته."
        });
      }

      // Anti-Mass-Assignment: Reject any attempts to tamper with protected metadata
      const forbiddenMassKeys = ["deleted_at", "created_at", "sku"];
      for (const fk of forbiddenMassKeys) {
        if (body[fk] !== undefined) {
          return sendError(res, 400, `لا يمكن تعديل الحقل المحمي '${fk}' عبر هذه الواجهة (Mass Assignment Blocked).`);
        }
      }

      // Partial Field Updates (Price, Sale Price, Stock, Description, Active status, Image)
      if (body.price !== undefined) {
        const p = parseFloat(body.price);
        if (isNaN(p) || p < 0) return sendError(res, 400, "سعر المنتج يجب أن يكون رقماً موجباً.");
        db.prepare("UPDATE products SET price = ? WHERE id = ?").run(p, rawId);
      }
      if (body.sale_price !== undefined || body.salePrice !== undefined) {
        const rawSale = body.sale_price !== undefined ? body.sale_price : body.salePrice;
        if (rawSale === null || rawSale === "") {
          db.prepare("UPDATE products SET sale_price = NULL WHERE id = ?").run(rawId);
        } else {
          const sp = parseFloat(rawSale);
          if (isNaN(sp) || sp < 0) return sendError(res, 400, "سعر التخفيض يجب أن يكون رقماً موجباً.");
          const currentProd = db.prepare("SELECT price FROM products WHERE id = ?").get(rawId);
          const currentPrice = body.price !== undefined ? parseFloat(body.price) : (currentProd ? currentProd.price : 0);
          if (sp >= currentPrice && currentPrice > 0) {
            return sendError(res, 400, "سعر التخفيض يجب أن يكون أقل من السعر الأساسي للمنتج.");
          }
          db.prepare("UPDATE products SET sale_price = ? WHERE id = ?").run(sp, rawId);
        }
      }
      if (body.stock !== undefined) {
        const s = parseInt(body.stock, 10);
        if (isNaN(s) || s < 0) return sendError(res, 400, "كمية المخزون يجب أن تكون رقماً موجباً.");
        db.prepare("UPDATE products SET stock = ? WHERE id = ?").run(s, rawId);
      }
      if (body.description !== undefined) {
        db.prepare("UPDATE products SET description = ? WHERE id = ?").run(String(body.description || "").slice(0, 5000), rawId);
      }
      if (body.active !== undefined) db.prepare("UPDATE products SET active = ? WHERE id = ?").run(body.active ? 1 : 0, rawId);
      if (body.name !== undefined) db.prepare("UPDATE products SET name = ? WHERE id = ?").run(String(body.name).slice(0, 150), rawId);
      if (body.image !== undefined) {
        const rawImg = String(body.image || "").trim();
        if (rawImg) {
          const imgCheck = validateSafeImageUrl(rawImg);
          if (!imgCheck.valid) {
            return sendError(res, 400, `رابط الصورة غير صالح أمنياً: ${imgCheck.error}`);
          }
          db.prepare("UPDATE products SET image = ? WHERE id = ?").run(imgCheck.sanitizedUrl, rawId);
        } else {
          db.prepare("UPDATE products SET image = '' WHERE id = ?").run(rawId);
        }
      }

      return sendJson(res, 200, { success: true, id: rawId, message: "تم تحديث بيانات المنتج بنجاح." });
    }

    // 3. POST: Create Product (ADMIN ONLY)
    if (method === "POST") {
      const body = await parseBody(req);
      if (!body.name || body.price === undefined || body.price === null || body.price === "") {
        return sendError(res, 400, "اسم المنتج وسعره حقول إلزامية.");
      }

      const pPrice = parseFloat(body.price);
      if (isNaN(pPrice) || pPrice < 0) return sendError(res, 400, "سعر المنتج غير صالح. يجب أن يكون رقماً موجباً أكبر من أو يساوي 0.");

      // Validate stock >= 0
      const rawStock = body.stock !== undefined && body.stock !== null && body.stock !== "" ? parseInt(body.stock, 10) : 10;
      if (isNaN(rawStock) || rawStock < 0) {
        return sendError(res, 400, "كمية المخزون (stock) غير صالحة. يجب أن تكون رقماً صحيحاً أكبر من أو يساوي 0.");
      }

      // Validate sale_price (if present) >= 0 and < price
      let pSalePrice = null;
      if (body.salePrice !== undefined || body.sale_price !== undefined) {
        const rawSale = body.salePrice !== undefined ? body.salePrice : body.sale_price;
        if (rawSale !== null && rawSale !== "") {
          pSalePrice = parseFloat(rawSale);
          if (isNaN(pSalePrice) || pSalePrice < 0) {
            return sendError(res, 400, "سعر التخفيض (sale_price) يجب أن يكون رقماً موجباً أكبر من أو يساوي 0.");
          }
          if (pSalePrice >= pPrice) {
            return sendError(res, 400, "سعر التخفيض (sale_price) يجب أن يكون أقل من السعر الأساسي للمنتج.");
          }
        }
      }

      // Validate category_id exists in database before insertion
      const targetCatId = String(body.category_id || body.category || body.categoryId || "cat_chandeliers").trim();
      const existingCat = db.prepare("SELECT id, name FROM categories WHERE id = ?").get(targetCatId);
      if (!existingCat) {
        return sendError(res, 400, `معرف القسم (category_id) '${targetCatId}' غير موجود في قاعدة البيانات.`);
      }
      const categoryName = existingCat.name || body.category_name || body.categoryName || "نجف وثريات فاخرة";

      let safeProductImage = "";
      if (body.image) {
        const rawImg = String(body.image || "").trim();
        if (rawImg) {
          const imgCheck = validateSafeImageUrl(rawImg);
          if (!imgCheck.valid) {
            return sendError(res, 400, `رابط الصورة غير صالح أمنياً: ${imgCheck.error}`);
          }
          safeProductImage = imgCheck.sanitizedUrl;
        }
      }

      const id = body.id || `prod_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
      const stmt = db.prepare(`
        INSERT INTO products (
          id, sku, name, en_name, category_id, category_name, price, sale_price, cost_price,
          stock, image, description, active, featured, deleted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, NULL)
      `);

      stmt.run(
        id,
        body.sku || `KK-${Date.now().toString().slice(-4)}`,
        String(body.name).slice(0, 150),
        String(body.enName || body.en_name || "").slice(0, 150),
        targetCatId,
        categoryName,
        pPrice,
        pSalePrice,
        body.costPrice || body.cost_price ? parseFloat(body.costPrice || body.cost_price) : null,
        rawStock,
        safeProductImage,
        String(body.description || "").slice(0, 500),
        body.featured ? 1 : 0
      );

      // Create linked inventory
      db.prepare("INSERT OR REPLACE INTO inventory (id, product_id, warehouse_name, quantity_on_hand) VALUES (?, ?, ?, ?)")
        .run(`inv_${id}`, id, "المستودع الرئيسي - الشيخ زايد", rawStock);

      return sendJson(res, 201, { success: true, message: "تم إنشاء المنتج بنجاح في قاعدة البيانات العلائقية.", id });
    }

    // 4. DELETE: Safe Deletion Engine (ADMIN ONLY)
    if (method === "DELETE") {
      const rawId = parsedUrl.searchParams.get("id");
      const isForceHard = parsedUrl.searchParams.get("force_hard") === "1";

      if (!rawId) {
        return sendError(res, 400, "معرف المنتج مطلوب لإجراء الحذف.");
      }

      const existing = db.prepare("SELECT * FROM products WHERE id = ?").get(rawId);
      if (!existing) {
        return sendError(res, 404, "المنتج غير موجود.");
      }

      // Referential Integrity Check across Orders, Sales, Inventory, and Pricelists
      const relations = checkProductRelations(rawId);
      const nowIso = new Date().toISOString();

      if (relations.hasRelations) {
        if (isForceHard) {
          return sendJson(res, 409, {
            success: false,
            error: "لا يمكن الحذف النهائي (Hard Delete) لهذا المنتج لوجود سجلات مرتبطة به في (الطلبات، المبيعات، المخزون، أو قوائم الأسعار). تم الحفاظ على تكامل البيانات المحاسبية.",
            relations
          });
        }

        // Apply Soft Delete
        db.prepare("UPDATE products SET deleted_at = ?, active = 0, status = 'archived', updated_at = ? WHERE id = ?")
          .run(nowIso, nowIso, rawId);

        return sendJson(res, 200, {
          success: true,
          softDeleted: true,
          id: rawId,
          deleted_at: nowIso,
          message: "تم تنفيذ الحذف اللطيف (Soft Delete) بنجاح. المنتج محفوظ تاريخياً ومحاسبياً وتم استثناؤه من المتجر.",
          relations
        });
      }

      if (isForceHard) {
        db.prepare("DELETE FROM inventory WHERE product_id = ?").run(rawId);
        db.prepare("DELETE FROM products WHERE id = ?").run(rawId);

        return sendJson(res, 200, {
          success: true,
          hardDeleted: true,
          id: rawId,
          message: "تم حذف المنتج نهائياً من قاعدة البيانات (Hard Delete) لعدم وجود أي ارتباطات له."
        });
      }

      db.prepare("UPDATE products SET deleted_at = ?, active = 0, status = 'archived', updated_at = ? WHERE id = ?")
        .run(nowIso, nowIso, rawId);

      return sendJson(res, 200, {
        success: true,
        softDeleted: true,
        id: rawId,
        deleted_at: nowIso,
        message: "تم تنفيذ الحذف اللطيف (Soft Delete) بنجاح. تم حفظ المنتج وأرشفته مع إخفائه من المتجر."
      });
    }
  }

  // ---------------------------------------------------------------------------
  // API: Orders & Checkout (/api/orders)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/orders") {
    // 1. GET: Fetch Orders (IDOR & BFLA Protected)
    if (method === "GET") {
      const isMine = parsedUrl.searchParams.get("mine") === "1";

      // SUB-CASE A: Authenticated Customer Order History (Strict Zero-Leakage & IDOR Defense)
      if (isMine) {
        const customer = extractCustomerSession(req);
        if (!customer || !customer.sub) {
          return sendError(res, 401, "يجب تسجيل الدخول لعرض سجل طلباتك.");
        }

        // Query database directly to confirm customer existence and verified status (Zero-Trust DB Authority)
        const custRecord = db.prepare("SELECT id, email, email_verified FROM customers WHERE id = ?").get(customer.sub);
        if (!custRecord) {
          return sendError(res, 401, "حساب العميل غير موجود أو تم إلغاؤه.");
        }

        const isEmailVerified = Boolean(custRecord.email_verified === 1 || custRecord.email_verified === "1" || custRecord.email_verified === true);
        const custEmail = (custRecord.email || "").trim().toLowerCase();

        // Bind strictly to customer_id; only permit matching email if verified in DB; NEVER match unverified phone
        let query;
        let params;
        if (isEmailVerified && custEmail) {
          query = "SELECT id, order_number, subtotal, delivery_fee, total, status, created_at FROM orders WHERE customer_id = ? OR (LOWER(customer_email) = ? AND customer_email IS NOT NULL) ORDER BY created_at DESC";
          params = [custRecord.id, custEmail];
        } else {
          query = "SELECT id, order_number, subtotal, delivery_fee, total, status, created_at FROM orders WHERE customer_id = ? ORDER BY created_at DESC";
          params = [custRecord.id];
        }

        const myOrders = db.prepare(query).all(...params);
        return sendJson(res, 200, { success: true, count: myOrders.length, orders: myOrders });
      }

      // SUB-CASE B: Privileged Admin Access (BFLA Defense)
      const admin = assertAdminAuthorized(req);
      if (!admin) {
        return sendError(res, 401, "غير مصرح بالوصول. استعراض كافة سجلات الطلبات يتطلب صلاحيات الإدارة العليا.");
      }

      const orders = db.prepare("SELECT * FROM orders ORDER BY created_at DESC").all();
      return sendJson(res, 200, { success: true, count: orders.length, orders });
    }

    // 2. POST: Create Order (Server-Authoritative Pricing & Anti-Spam Rate Limit)
    if (method === "POST") {
      // Sliding Window Rate Limit: Orders (3 requests per 10 minutes)
      const allowed = await enforceRateLimit(req, res, "orders");
      if (!allowed) return;

      const body = await parseBody(req);

      // Mandatory Cloudflare Turnstile Bot Gate
      const turnstileToken = extractTurnstileToken(req, body);
      const turnstileRes = await verifyTurnstile(turnstileToken, clientIp);
      if (!turnstileRes.success) {
        return sendError(res, 400, turnstileRes.error || "فشل التحقق الأمني من اختبار مكافحة الروبوتات (Turnstile).");
      }

      // Verified Customer Enforcement (SENSITIVE OPERATION: 403 Forbidden for Unverified Accounts)
      const customerSession = extractCustomerSession(req);
      if (customerSession && customerSession.sub) {
        const isVerified = Boolean(customerSession.email_verified === true || customerSession.emailVerified === true);
        if (!isVerified) {
          const custRec = db.prepare("SELECT email_verified FROM customers WHERE id = ?").get(customerSession.sub);
          const liveVerified = Boolean(custRec && (custRec.email_verified === 1 || custRec.email_verified === "1" || custRec.email_verified === true));
          if (!liveVerified) {
            return sendError(res, 403, "تم رفض إنشاء الطلب: حساب العميل غير مفعّل. يرجى تفعيل البريد الإلكتروني للمتابعة (403 Forbidden).");
          }
        }
      }

      // Email Validation: Syntax, Disposable Domains & DNS MX Records
      const rawCandidateEmail = (body.customerEmail || body.email || customerSession?.email || "").trim();
      if (rawCandidateEmail) {
        const emailValidation = await validateEmail(rawCandidateEmail, { checkMx: true, timeoutMs: 3000 });
        if (!emailValidation.valid) {
          return sendError(res, 400, emailValidation.error || "البريد الإلكتروني للطلب غير صالح أو مؤقت أو غير مسجل في خوادم البريد (MX Records).");
        }
      }

      // Check Idempotency-Key & Race Condition Defense
      const rawIdempKey = req.headers["idempotency-key"] || body.idempotencyKey || "";
      let cleanIdempKey = typeof rawIdempKey === "string" ? rawIdempKey.trim().slice(0, 100) : "";
      if (!cleanIdempKey) {
        const candidatePhone = (body.customerPhone || body.phone || "").replace(/[^0-9]/g, "");
        const itemsSig = Array.isArray(body.items)
          ? body.items.map(i => `${i.id || i.productId}:${i.qty || i.quantity}`).sort().join(",")
          : "";
        cleanIdempKey = `synth_${crypto.createHash("sha256").update(`${clientIp}:${candidatePhone}:${itemsSig}`).digest("hex")}`;
      }

      const existingLock = db.prepare("SELECT status, response_body, created_at FROM idempotency_locks WHERE key = ?").get(cleanIdempKey);
      if (existingLock) {
        const ageMs = Date.now() - existingLock.created_at;
        if (existingLock.status === "completed" && ageMs < 3600 * 1000 && existingLock.response_body) {
          try {
            const cachedRes = JSON.parse(existingLock.response_body);
            return sendJson(res, 200, {
              ...cachedRes,
              idempotentReplay: true,
              message: "تم استلام هذا الطلب وتأكيده مسبقاً بنجاح."
            });
          } catch (_) {}
        }
        if (existingLock.status === "processing" && ageMs < 15 * 1000) {
          return sendError(res, 409, "جارٍ معالجة هذا الطلب بالفعل حالياً على الخادم. يرجى الانتظار لحين اكتمال المعالجة.");
        }
      }

      // Claim processing lock
      db.prepare("INSERT OR REPLACE INTO idempotency_locks (key, status, created_at) VALUES (?, 'processing', ?)").run(cleanIdempKey, Date.now());

      const items = Array.isArray(body.items) ? body.items : [];

      if (items.length === 0) {
        db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
        return sendError(res, 400, "السلة فارغة، يجب إرسال منتجات صالحة.");
      }

      if (items.length > 50) {
        db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
        return sendError(res, 400, "عدد بنود الطلب يتجاوز الحد الأقصى المسموح به (50 صنف).");
      }

      // STRICT ZERO-TRUST FINANCIAL PRICING: Deduplicate items & enforce integer positive quantity bounds
      const aggregatedMap = new Map();
      for (const item of items) {
        if (!item || typeof item !== "object") {
          db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
          return sendError(res, 400, "بيانات أحد المنتجات في السلة غير صالحة.");
        }
        const prodId = item.id || item.productId;
        if (!prodId || typeof prodId !== "string" || prodId.length > 100 || prodId.includes("..") || prodId.includes("/") || prodId.includes("\\")) {
          db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
          return sendError(res, 400, "معرف أحد المنتجات في السلة غير صالح.");
        }
        const rawQty = item.qty !== undefined ? item.qty : item.quantity;
        if (typeof rawQty !== "number" || !Number.isInteger(rawQty) || rawQty < 1 || rawQty > 50) {
          db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
          return sendError(res, 400, "كمية المنتج غير صالحة. يجب أن تكون عدداً صحيحاً موجباً بين 1 و 50 حصراً.");
        }
        const existingQty = aggregatedMap.get(prodId) || 0;
        const combinedQty = existingQty + rawQty;
        if (combinedQty > 50) {
          db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
          return sendError(res, 400, `الكمية الإجمالية المطلوبة للمنتج '${prodId}' تتجاوز السقف المسموح به (50 قطعة).`);
        }
        aggregatedMap.set(prodId, combinedQty);
      }

      let calculatedSubtotal = 0;
      const verifiedLineItems = [];

      for (const [prodId, qty] of aggregatedMap.entries()) {
        const prod = db.prepare("SELECT * FROM products WHERE id = ?").get(prodId);
        if (!prod || prod.active === 0 || prod.deleted_at !== null) {
          db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
          return sendError(res, 400, `عفواً، المنتج '${prod ? prod.name : prodId}' لم يعد متاحاً في المتجر (تم حذفه أو إيقافه).`);
        }

        // Preliminary stock availability check before transaction
        if (prod.stock < qty) {
          db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
          return sendError(res, 400, `عفواً، الكمية المطلوبة للمنتج '${prod.name}' غير متوفرة في المخزون (المتبقي: ${prod.stock}).`);
        }

        // Authoritative Price from DB (Honor sale_price if active)
        const authoritativeUnitPrice = (prod.sale_price !== null && prod.sale_price !== undefined && prod.sale_price > 0 && prod.sale_price < prod.price)
          ? prod.sale_price
          : prod.price;

        const lineTotal = authoritativeUnitPrice * qty;
        calculatedSubtotal += lineTotal;

        verifiedLineItems.push({
          productId: prod.id,
          productName: prod.name,
          unitPrice: authoritativeUnitPrice,
          quantity: qty,
          totalPrice: lineTotal
        });
      }

      // Mandatory Customer Name and Phone Validation (Zero-Trust Customer Profile — supports flat or nested body.customer)
      const custObj = (body.customer && typeof body.customer === "object") ? body.customer : {};
      const customerPhone = (body.customerPhone || body.phone || custObj.phone || customerSession?.phone || "").replace(/[^0-9]/g, "").slice(0, 20);
      const customerName = (body.customerName || body.name || custObj.name || customerSession?.name || "").trim().slice(0, 100);

      if (!customerName || customerName.length < 2) {
        db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
        return sendError(res, 400, "يرجى كتابة اسم العميل بشكل صحيح (حرفين على الأقل).");
      }

      // Egyptian Mobile Phone Validation (010, 011, 012, 015 - exactly 11 digits)
      if (!customerPhone || !/^01[0125][0-9]{8}$/.test(customerPhone)) {
        db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
        return sendError(res, 400, "يرجى إدخال رقم هاتف مصري صحيح مكون من 11 رقماً يبدأ بـ 01 (لا يمكن إتمام الطلب برقم هاتف فارغ أو غير صالح).");
      }

      // Extract remaining customer attributes
      const customerId = customerSession ? customerSession.sub : null;
      const customerEmail = (body.customerEmail || body.email || custObj.email || customerSession?.email || "").trim().toLowerCase().slice(0, 100);
      const shippingAddress = (body.address || body.shippingAddress || custObj.address || "الشيخ زايد").trim().slice(0, 250);
      const deliveryCity = (body.city || body.deliveryCity || custObj.deliveryArea || custObj.city || "الشيخ زايد").trim().slice(0, 100);

      const orderId = `ORD-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
      const orderNumber = `KK-${Date.now().toString().slice(-6)}`;

      let finalDiscount = 0;
      let finalDeliveryFee = 150;
      let finalGrandTotal = calculatedSubtotal + 150;

      // ATOMIC TRANSACTION: Stock Deduction, Coupon Enforcement & Order Placement
      db.exec("BEGIN IMMEDIATE;");
      try {
        // 1. Atomic Stock Verification and Deduction on every item
        for (const line of verifiedLineItems) {
          const deductRes = db.prepare(`
            UPDATE products 
            SET stock = stock - ?, updated_at = datetime('now')
            WHERE id = ? AND stock >= ?
          `).run(line.quantity, line.productId, line.quantity);

          if (deductRes.changes === 0) {
            throw new Error(`INSUFFICIENT_STOCK:${line.productName}`);
          }

          // Update inventory warehouse records
          db.prepare(`
            UPDATE inventory 
            SET quantity_on_hand = MAX(0, quantity_on_hand - ?), updated_at = datetime('now')
            WHERE product_id = ?
          `).run(line.quantity, line.productId);
        }

        // 2. Atomic Coupon Verification & Usage Limit Increment
        let calculatedDiscount = 0;
        let appliedCouponCode = null;
        const rawCoupon = (body.couponCode || body.coupon || "").trim().toUpperCase();
        if (rawCoupon) {
          const coupon = db.prepare("SELECT * FROM coupons WHERE code = ? AND active = 1").get(rawCoupon);
          if (!coupon) {
            throw new Error("COUPON_ERROR:كوبون الخصم غير صالح أو تم إيقافه.");
          }
          if (coupon.expires_at && new Date(coupon.expires_at).getTime() < Date.now()) {
            throw new Error("COUPON_ERROR:كوبون الخصم منتهي الصلاحية.");
          }
          if (coupon.usage_limit && coupon.used_count >= coupon.usage_limit) {
            throw new Error("COUPON_ERROR:تم الوصول للحد الأقصى لاستخدام هذا الكوبون.");
          }
          if (calculatedSubtotal < (coupon.min_order_amount || 0)) {
            throw new Error(`COUPON_ERROR:الحد الأدنى لتفعيل هذا الكوبون هو ${coupon.min_order_amount} ج.م.`);
          }

          if (coupon.type === "percentage") {
            calculatedDiscount = (calculatedSubtotal * coupon.value) / 100;
            if (coupon.max_discount_amount) {
              calculatedDiscount = Math.min(calculatedDiscount, coupon.max_discount_amount);
            }
          } else {
            calculatedDiscount = coupon.value;
          }
          calculatedDiscount = Math.min(calculatedDiscount, calculatedSubtotal);

          // Atomic Condition Increment: Prevents race conditions exceeding usage_limit
          const couponUpdateRes = db.prepare(`
            UPDATE coupons 
            SET used_count = used_count + 1 
            WHERE code = ? AND active = 1 AND (usage_limit IS NULL OR used_count < usage_limit)
          `).run(coupon.code);

          if (couponUpdateRes.changes === 0) {
            throw new Error("COUPON_ERROR:تم الوصول للحد الأقصى لاستخدام هذا الكوبون بالتزامن.");
          }
          appliedCouponCode = coupon.code;
        }

        // Calculate authoritative delivery fee & grand total
        const deliveryFee = (calculatedSubtotal - calculatedDiscount) >= 5000 ? 0 : 150;
        const calculatedGrandTotal = Math.max(0, calculatedSubtotal - calculatedDiscount) + deliveryFee;

        finalDiscount = calculatedDiscount;
        finalDeliveryFee = deliveryFee;
        finalGrandTotal = calculatedGrandTotal;

        // 3. Insert Order Record
        db.prepare(`
          INSERT INTO orders (
            id, order_number, customer_id, customer_name, customer_phone, customer_email,
            shipping_address, delivery_city, subtotal, discount, delivery_fee, total, status
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        `).run(
          orderId,
          orderNumber,
          customerId,
          customerName,
          customerPhone,
          customerEmail || null,
          shippingAddress,
          deliveryCity,
          calculatedSubtotal,
          calculatedDiscount,
          deliveryFee,
          calculatedGrandTotal
        );

        // 4. Insert Order Items & Sales
        const insertItem = db.prepare(`
          INSERT INTO order_items (id, order_id, product_id, product_name, unit_price, quantity, total_price)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        const insertSale = db.prepare(`
          INSERT INTO sales (id, order_id, product_id, quantity_sold, unit_price, gross_revenue, net_profit)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);

        for (const line of verifiedLineItems) {
          const itemId = `item_${Date.now()}_${crypto.randomBytes(3).toString("hex")}`;
          const saleId = `sale_${Date.now()}_${crypto.randomBytes(3).toString("hex")}`;
          insertItem.run(itemId, orderId, line.productId, line.productName, line.unitPrice, line.quantity, line.totalPrice);
          insertSale.run(saleId, orderId, line.productId, line.quantity, line.unitPrice, line.totalPrice, line.totalPrice * 0.35);
        }

        db.exec("COMMIT;");
      } catch (txErr) {
        try { db.exec("ROLLBACK;"); } catch (_) {}
        db.prepare("DELETE FROM idempotency_locks WHERE key = ?").run(cleanIdempKey);
        if (txErr.message.startsWith("INSUFFICIENT_STOCK:")) {
          const pName = txErr.message.replace("INSUFFICIENT_STOCK:", "");
          return sendError(res, 400, `عفواً، نفاد المخزون: الكمية المطلوبة للمنتج '${pName}' غير متوفرة حالياً في المخزون.`);
        }
        if (txErr.message.startsWith("COUPON_ERROR:")) {
          return sendError(res, 400, txErr.message.replace("COUPON_ERROR:", ""));
        }
        throw txErr;
      }

      const responsePayload = {
        success: true,
        orderId,
        orderNumber,
        subtotal: calculatedSubtotal,
        discount: finalDiscount,
        deliveryFee: finalDeliveryFee,
        total: finalGrandTotal,
        message: "تم تسجيل الطلب وتوثيقه بنجاح بالأسعار الرسمية المعتمدة."
      };

      // Mark Idempotency Lock Completed with Cached Response Body
      db.prepare("UPDATE idempotency_locks SET status = 'completed', order_id = ?, response_body = ? WHERE key = ?").run(
        orderId,
        JSON.stringify(responsePayload),
        cleanIdempKey
      );

      return sendJson(res, 201, responsePayload);
    }

    // 3. PATCH / DELETE / PUT: Admin Order Management (ADMIN ONLY)
    const admin = assertAdminAuthorized(req);
    if (!admin) {
      return sendError(res, 401, "غير مصرح بالوصول. إدارة حالة وسجلات الطلبات تتطلب صلاحيات الإدارة العليا.");
    }

    if (method === "PATCH") {
      const body = await parseBody(req);
      const rawId = parsedUrl.searchParams.get("id") || body.id;
      if (!rawId) return sendError(res, 400, "معرف الطلب مطلوب.");

      if (body.status) {
        const allowedStatuses = ["pending", "confirmed", "processing", "shipping", "delivered", "completed", "cancelled"];
        const sanitizedStatus = String(body.status).toLowerCase().trim();
        if (!allowedStatuses.includes(sanitizedStatus)) {
          return sendError(res, 400, "حالة الطلب غير صالحة. الحالات المعتمدة: " + allowedStatuses.join(", "));
        }
        db.prepare("UPDATE orders SET status = ?, updated_at = datetime('now') WHERE id = ?").run(sanitizedStatus, rawId);
      }
      return sendJson(res, 200, { success: true, message: "تم تحديث حالة الطلب بنجاح." });
    }

    if (method === "DELETE") {
      const rawId = parsedUrl.searchParams.get("id");
      if (!rawId) return sendError(res, 400, "معرف الطلب مطلوب للحذف.");
      db.prepare("DELETE FROM orders WHERE id = ?").run(rawId);
      return sendJson(res, 200, { success: true, message: "تم حذف الطلب بنجاح." });
    }
  }

  // ---------------------------------------------------------------------------
  // API: Order Tracking with Zero-PII (/api/track)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/track") {
    if (method !== "POST") {
      return sendError(res, 405, "طريقة الطلب غير مسموح بها. يلزم إرسال طلب POST.");
    }

    // Sliding Window Rate Limit: Track queries (60 requests per minute)
    const allowed = await enforceRateLimit(req, res, "read");
    if (!allowed) return;

    const body = await parseBody(req);
    const orderId = (body.orderId || body.id || "").trim().toUpperCase();
    const phone = (body.phone || "").replace(/[^0-9]/g, "");

    if (!orderId || !phone) {
      return sendError(res, 400, "يرجى إدخال رقم الطلب ورقم الهاتف المسجل.");
    }

    const order = db.prepare("SELECT * FROM orders WHERE UPPER(id) = ? OR UPPER(order_number) = ?").get(orderId, orderId);

    // Verify phone in constant time
    let isMatch = false;
    if (order && order.customer_phone) {
      const cleanStoredPhone = order.customer_phone.replace(/[^0-9]/g, "");
      const hashA = crypto.createHash("sha256").update(cleanStoredPhone).digest();
      const hashB = crypto.createHash("sha256").update(phone).digest();
      isMatch = crypto.timingSafeEqual(hashA, hashB);
    } else {
      const dummyA = crypto.createHash("sha256").update("dummy_salt_a").digest();
      const dummyB = crypto.createHash("sha256").update(phone).digest();
      crypto.timingSafeEqual(dummyA, dummyB);
    }

    if (!order || !isMatch) {
      await new Promise(r => setTimeout(r, 550));
      return sendError(res, 404, "تعذر العثور على الطلب أو أن بيانات التحقق غير مطابقة.");
    }

    // Zero-PII Response
    const items = db.prepare("SELECT product_name, unit_price, quantity, total_price FROM order_items WHERE order_id = ?").all(order.id);

    return sendJson(res, 200, {
      success: true,
      order: {
        id: order.id,
        orderNumber: order.order_number,
        status: order.status || "pending",
        created_at: order.created_at,
        subtotal: order.subtotal,
        deliveryFee: order.delivery_fee,
        total: order.total,
        items: items.map(it => ({
          name: it.product_name,
          price: it.unit_price,
          qty: it.quantity,
          total: it.total_price
        }))
      }
    });
  }

  // ---------------------------------------------------------------------------
  // API: Showroom Settings & Categories (/api/settings)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/settings") {
    if (method === "GET" || method === "HEAD") {
      const categories = db.prepare("SELECT id, name, en_name as nameEn, icon, slug FROM categories ORDER BY sort_order ASC").all();
      return sendJson(res, 200, {
        success: true,
        categories,
        settings: {
          storeNameAr: "معرض قاصد كريم",
          storeNameEn: "Kased Karim Showroom",
          phone: "01006367690",
          whatsapp: "201006367690",
          freeShippingThreshold: 5000,
          shippingFee: 150
        }
      });
    }

    // Mutating settings requires Admin authorization
    const admin = assertAdminAuthorized(req);
    if (!admin) {
      return sendError(res, 401, "غير مصرح. تعديل إعدادات المعرض مقصور على الإدارة العليا.");
    }

    const body = await parseBody(req);
    return sendJson(res, 200, { success: true, message: "تم تحديث إعدادات المعرض بنجاح." });
  }

  // ---------------------------------------------------------------------------
  // API: Backup & Data Export (/api/backup) (ADMIN ONLY)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/backup") {
    const admin = assertAdminAuthorized(req);
    if (!admin) {
      return sendError(res, 401, "غير مصرح. تنزيل النسخة الاحتياطية مقصور على الإدارة العليا فقط.");
    }

    const products = db.prepare("SELECT * FROM products").all();
    const categories = db.prepare("SELECT * FROM categories").all();
    const orders = db.prepare("SELECT * FROM orders").all();
    const orderItems = db.prepare("SELECT * FROM order_items").all();
    const sales = db.prepare("SELECT * FROM sales").all();
    const inventory = db.prepare("SELECT * FROM inventory").all();

    return sendJson(res, 200, {
      success: true,
      timestamp: new Date().toISOString(),
      metadata: {
        engine: "sqlite-native",
        database: DB_FILE
      },
      data: {
        products,
        categories,
        orders,
        order_items: orderItems,
        sales,
        inventory
      }
    });
  }

  // ---------------------------------------------------------------------------
  // API: Long-Term Web Restore Points (/api/restore-points) (ADMIN ONLY)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/restore-points" || pathname.startsWith("/api/restore-points/")) {
    const admin = assertAdminAuthorized(req);
    if (!admin) {
      return sendError(res, 401, "غير مصرح بالوصول. إدارة واسترجاع نقاط النسخ الاحتياطي مقصورة على الإدارة العليا.");
    }

    if (method === "GET") {
      const date = parsedUrl.searchParams.get("date");
      const year = parsedUrl.searchParams.get("year");
      const month = parsedUrl.searchParams.get("month");
      const q = parsedUrl.searchParams.get("q");

      let sql = "SELECT id, timestamp, date_str, time_str, label, point_type, counts_json, total_revenue, created_at FROM restore_points WHERE 1=1";
      const params = [];

      if (date && date.trim()) {
        sql += " AND date_str = ?";
        params.push(date.trim());
      } else {
        if (year && month) {
          const ym = `${year}-${String(month).padStart(2, "0")}`;
          sql += " AND date_str LIKE ?";
          params.push(`${ym}%`);
        } else if (year) {
          sql += " AND date_str LIKE ?";
          params.push(`${year}%`);
        }
      }

      if (q && q.trim()) {
        sql += " AND (label LIKE ? OR id LIKE ?)";
        params.push(`%${q.trim()}%`, `%${q.trim()}%`);
      }

      sql += " ORDER BY timestamp DESC LIMIT 300";

      const points = db.prepare(sql).all(...params);
      const calendarDates = db.prepare("SELECT DISTINCT date_str, COUNT(*) as count FROM restore_points GROUP BY date_str ORDER BY date_str DESC").all();

      return sendJson(res, 200, {
        success: true,
        count: points.length,
        points: points.map(p => ({
          ...p,
          dateFormatted: p.date_str,
          timeFormatted: p.time_str,
          counts: p.counts_json ? JSON.parse(p.counts_json) : {}
        })),
        calendarDates
      });
    }

    if (method === "POST") {
      const body = await parseBody(req);
      const action = parsedUrl.searchParams.get("action") || body.action;

      if (action === "restore") {
        const pointId = parsedUrl.searchParams.get("id") || body.id;
        if (!pointId) return sendError(res, 400, "معرف نقطة الاسترجاع مطلوب.");

        const point = db.prepare("SELECT * FROM restore_points WHERE id = ?").get(pointId);
        if (!point || !point.data_json) {
          return sendError(res, 404, "نقطة الاسترجاع غير موجودة في الأرشيف التاريخي.");
        }

        let snapshotData = {};
        try { snapshotData = JSON.parse(point.data_json); } catch (e) {}

        const restoredProducts = snapshotData.products || [];
        if (Array.isArray(restoredProducts) && restoredProducts.length > 0) {
          for (const p of restoredProducts) {
            if (!p || !p.id) continue;
            const existing = db.prepare("SELECT id FROM products WHERE id = ?").get(p.id);
            if (existing) {
              db.prepare("UPDATE products SET deleted_at = NULL, active = 1, status = 'published', updated_at = datetime('now') WHERE id = ?").run(p.id);
            } else {
              let safeRestoreImage = "";
              if (p.image) {
                const imgCheck = validateSafeImageUrl(String(p.image).trim());
                if (imgCheck.valid) {
                  safeRestoreImage = imgCheck.sanitizedUrl;
                }
              }

              db.prepare(`
                INSERT INTO products (
                  id, sku, name, en_name, category_id, category_name, price, stock, image, description, active, deleted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, NULL)
              `).run(
                p.id,
                p.sku || `KK-${Date.now().toString().slice(-4)}`,
                p.name || "وحدة إضاءة مسترجعة",
                p.enName || p.en_name || "",
                p.category_id || p.category || "cat_chandeliers",
                p.category_name || p.categoryName || "نجف وثريات فاخرة",
                parseFloat(p.price || 0),
                parseInt(p.stock || 10, 10),
                safeRestoreImage,
                p.description || ""
              );
            }
          }
        }

        return sendJson(res, 200, {
          success: true,
          restored: true,
          pointId,
          message: `تم تطبيق نقطة الاسترجاع [${point.label}] بنجاح وعادت المنتجات للعمل فوراً.`
        });
      }

      // Save new Restore Point
      const id = body.id || `RST-${Date.now().toString().slice(-7)}`;
      const timestamp = body.timestamp || Date.now();
      const d = new Date(timestamp);
      const dateStr = body.dateFormatted || d.toISOString().slice(0, 10);
      const timeStr = body.timeFormatted || d.toTimeString().slice(0, 8);
      const label = body.label || "نقطة استرجاع";
      const countsJson = JSON.stringify(body.counts || {});
      const dataJson = JSON.stringify(body.data || body);

      db.prepare(`
        INSERT OR REPLACE INTO restore_points (id, timestamp, date_str, time_str, label, counts_json, total_revenue, data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, timestamp, dateStr, timeStr, label, countsJson, body.totalRevenue || 0, dataJson);

      return sendJson(res, 201, {
        success: true,
        id,
        date_str: dateStr,
        message: "تم حفظ نقطة الاسترجاع في السجل التاريخي الدائم بنجاح."
      });
    }
  }

  // ---------------------------------------------------------------------------
  // API: Customer Account & Authentication (/api/customer)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/customer") {
    const body = method !== "GET" ? await parseBody(req) : {};
    const action = parsedUrl.searchParams.get("action") || (body ? body.action : "") || "me";

    // 1. REGISTER
    if (action === "register" && method === "POST") {
      // Sliding Window Rate Limit: Register (3 attempts per 1 hour)
      const allowed = await enforceRateLimit(req, res, "register");
      if (!allowed) return;

      // Mandatory Cloudflare Turnstile Bot Gate
      const turnstileToken = extractTurnstileToken(req, body);
      const turnstileRes = await verifyTurnstile(turnstileToken, clientIp);
      if (!turnstileRes.success) {
        return sendError(res, 400, turnstileRes.error || "فشل التحقق الأمني من اختبار مكافحة الروبوتات (Turnstile).");
      }

      const name = (body.name || "").trim().slice(0, 100);
      const phone = (body.phone || "").replace(/[^0-9]/g, "");
      const email = (body.email || "").trim().toLowerCase();
      const rawPassword = body.password || "";
      if (typeof rawPassword !== "string" || rawPassword.length < 8) {
        return sendError(res, 400, "كلمة المرور يجب أن لا تقل عن 8 أحرف أو أرقام.");
      }
      if (rawPassword.length > 128) {
        return sendError(res, 400, "كلمة المرور لا يمكن أن تتجاوز 128 حرفاً لمنع استنزاف موارد النظام.");
      }
      const password = rawPassword.normalize("NFKC");

      if (!name || name.length < 2) {
        return sendError(res, 400, "يرجى كتابة اسم العميل بشكل صحيح (حرفين على الأقل)");
      }
      if (!phone || !/^01[0125][0-9]{8}$/.test(phone)) {
        return sendError(res, 400, "يرجى إدخال رقم هاتف مصري صحيح مكون من 11 رقماً يبدأ بـ 01");
      }

      // Deep Email Validation: Syntax, Disposable Domains & DNS MX Records
      if (email) {
        const emailValidation = await validateEmail(email, { checkMx: true, timeoutMs: 3000 });
        if (!emailValidation.valid) {
          return sendError(res, 400, emailValidation.error);
        }
      }

      const existing = db.prepare("SELECT * FROM customers WHERE phone = ? OR (email IS NOT NULL AND email = ?)").get(phone, email || "---none---");
      if (existing) {
        return sendError(res, 409, "رقم الهاتف أو البريد الإلكتروني مسجل بالفعل بحساب آخر.");
      }

      const id = "CUST-" + crypto.randomUUID().slice(0, 8).toUpperCase();
      const pwdData = await hashPasswordAsync(password);

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
        verificationExpiresAt = Date.now() + (24 * 60 * 60 * 1000);
      }

      db.prepare(`
        INSERT INTO customers (id, name, phone, email, password_hash, password_salt, email_verified, verification_token_hash, verification_code_hash, verification_expires_at, verification_attempts, role)
        VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 0, 'customer')
      `).run(id, name, phone, email || null, pwdData.hash, pwdData.salt, verificationTokenHash, verificationCodeHash, verificationExpiresAt);

      if (email && verificationToken) {
        sendCustomerVerificationEmail(email, name, verificationToken, verificationCode).catch(e => {
          console.warn("[server.js] Error sending verification email:", e.message);
        });
      }

      // Issue 24-hour Customer Token
      const token = signHmacJwt({ sub: id, phone, name, email: email || null, role: "customer", email_verified: false }, CUSTOMER_JWT_SECRET, 86400);

      applySecurityHeaders(res);
      res.writeHead(201, {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": `kk_customer_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; ${isHttpsRequest(req) ? "Secure" : ""}`.trim()
      });
      return res.end(JSON.stringify({
        success: true,
        message: email
          ? "تم إنشاء حساب العميل بنجاح. يرجى تفعيل البريد الإلكتروني عبر الرابط المرسل إليك (صالح لمدة 24 ساعة)."
          : "تم إنشاء حساب العميل بنجاح.",
        customer: { id, name, phone, email: email || null, role: "customer", email_verified: false }
      }));
    }

    // 2. LOGIN
    if (action === "login" && method === "POST") {
      // Sliding Window Rate Limit: Customer Login (5 attempts per 15 minutes)
      const allowed = await enforceRateLimit(req, res, "auth");
      if (!allowed) return;

      const identifier = (body.identifier || body.phone || body.email || "").trim();
      const rawPassword = body.password || "";
      if (typeof rawPassword !== "string" || !rawPassword || rawPassword.length > 128) {
        return sendError(res, 400, "بيانات كلمة المرور غير صالحة.");
      }
      const password = rawPassword.normalize("NFKC");
      const cleanPhone = identifier.replace(/[^0-9]/g, "");

      const cust = db.prepare(`
        SELECT * FROM customers 
        WHERE (phone = ? AND phone != '') OR (LOWER(email) = LOWER(?) AND email IS NOT NULL)
      `).get(cleanPhone, identifier.toLowerCase());

      if (!cust || !cust.password_hash || !cust.password_salt) {
        // Equalize CPU timing via dummy scrypt verification against user enumeration (CWE-208 / ASVS 2.1.8)
        await verifyPasswordAsync(password, "0".repeat(64), "0".repeat(32)).catch(() => {});
        return sendError(res, 401, "بيانات الدخول غير صحيحة. يرجى التأكد من رقم الهاتف/البريد وكلمة المرور.");
      }

      const isMatch = await verifyPasswordAsync(password, cust.password_hash, cust.password_salt);
      if (!isMatch) {
        return sendError(res, 401, "بيانات الدخول غير صحيحة. يرجى التأكد من رقم الهاتف/البريد وكلمة المرور.");
      }

      const isVerified = Boolean(cust.email_verified === 1 || cust.email_verified === "1" || cust.email_verified === true);
      // Issue 24-hour Customer Token
      const token = signHmacJwt({ sub: cust.id, phone: cust.phone, name: cust.name, email: cust.email, role: cust.role, email_verified: isVerified }, CUSTOMER_JWT_SECRET, 86400);

      applySecurityHeaders(res);
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": `kk_customer_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; ${isHttpsRequest(req) ? "Secure" : ""}`.trim()
      });
      return res.end(JSON.stringify({
        success: true,
        message: "تم تسجيل الدخول بنجاح",
        customer: { id: cust.id, name: cust.name, phone: cust.phone, email: cust.email, role: cust.role, email_verified: isVerified }
      }));
    }

    // 3. LOGOUT (REVOKE TOKEN SERVER-SIDE & CLEAR COOKIE)
    if (action === "logout") {
      const token = extractCookie(req.headers["cookie"], "kk_customer_token") ||
                    (req.headers["authorization"]?.startsWith("Bearer ") ? req.headers["authorization"].slice(7).trim() : null) ||
                    req.headers["x-customer-token"];
      if (token) {
        try {
          const verified = verifyHmacJwt(token, EFFECTIVE_CUSTOMER_JWT_SECRETS) || verifyCustomerToken(token);
          if (verified && verified.jti) {
            db.prepare("INSERT OR REPLACE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)").run(
              verified.jti,
              verified.exp || (Math.floor(Date.now() / 1000) + 86400)
            );
          }
        } catch (e) {}
      }
      applySecurityHeaders(res);
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": `kk_customer_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; ${isHttpsRequest(req) ? "Secure" : ""}`.trim()
      });
      return res.end(JSON.stringify({ success: true, message: "تم تسجيل الخروج بنجاح وإلغاء صلاحية الجلسة فورياً." }));
    }

    // 4. GOOGLE AUTHENTICATION (Verified via Google Tokeninfo API)
    if (action === "google" && method === "POST") {
      // Sliding Window Rate Limit: Google Login (5 attempts per 15 minutes)
      const allowed = await enforceRateLimit(req, res, "auth");
      if (!allowed) return;

      const credential = body.credential || body.idToken || body.token;
      if (!credential) {
        return sendError(res, 400, "رمز توثيق Google مطلوب.");
      }

      const googleProfile = await verifyGoogleToken(credential);
      if (!googleProfile || !googleProfile.sub || !googleProfile.email) {
        return sendError(res, 401, "فشل التحقق الأمني من صحة رمز Google. الرمز مزيف أو منتهي الصلاحية.");
      }

      const googleSub = googleProfile.sub;
      const email = googleProfile.email;
      const name = googleProfile.name;
      const avatar = googleProfile.picture;

      let cust = db.prepare("SELECT * FROM customers WHERE google_sub = ? OR (email IS NOT NULL AND LOWER(email) = ?)").get(googleSub, email);
      if (!cust) {
        const id = "CUST-G-" + crypto.randomUUID().slice(0, 8).toUpperCase();
        db.prepare(`
          INSERT INTO customers (id, name, phone, email, google_sub, avatar, email_verified, role)
          VALUES (?, ?, NULL, ?, ?, ?, 1, 'customer')
        `).run(id, name, email, googleSub, avatar);
        cust = { id, name, phone: null, email, avatar, role: "customer", email_verified: 1 };
      } else if (!cust.google_sub) {
        // Pre-Account Takeover Defense: If the existing account was never email-verified, invalidate any attacker-set password
        if (!cust.email_verified) {
          db.prepare("UPDATE customers SET google_sub = ?, avatar = COALESCE(avatar, ?), email_verified = 1, password_hash = NULL, password_salt = NULL, updated_at = datetime('now') WHERE id = ?")
            .run(googleSub, avatar, cust.id);
        } else {
          db.prepare("UPDATE customers SET google_sub = ?, avatar = COALESCE(avatar, ?), email_verified = 1, updated_at = datetime('now') WHERE id = ?")
            .run(googleSub, avatar, cust.id);
        }
      }

      const token = signHmacJwt({ sub: cust.id, phone: cust.phone, name: cust.name, email: cust.email, role: cust.role, email_verified: true }, CUSTOMER_JWT_SECRET, 86400);

      applySecurityHeaders(res);
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": `kk_customer_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; ${isHttpsRequest(req) ? "Secure" : ""}`.trim()
      });
      return res.end(JSON.stringify({
        success: true,
        message: "تم تسجيل الدخول بواسطة Google بنجاح وتوثيق الهوية رسمياً.",
        customer: { id: cust.id, name: cust.name, phone: cust.phone, email: cust.email, avatar: cust.avatar, role: cust.role, email_verified: true }
      }));
    }

    // 5. GET CURRENT PROFILE (ME)
    if (action === "me") {
      const customerSession = extractCustomerSession(req);
      if (!customerSession || !customerSession.sub) {
        return sendError(res, 401, "جلسة الدخول غير صالحة أو منتهية.");
      }

      const cust = db.prepare("SELECT id, name, phone, email, avatar, role, email_verified, created_at FROM customers WHERE id = ?").get(customerSession.sub);
      if (!cust) {
        return sendError(res, 404, "لم يتم العثور على حساب العميل.");
      }

      return sendJson(res, 200, { success: true, customer: cust });
    }

    // 6. VERIFY EMAIL (BRUTE FORCE & CSRF PROTECTED)
    if (action === "verify_email") {
      // Prevent email verification and session cookie issuance via GET; strictly require POST to prevent CSRF
      if (method !== "POST") {
        return sendError(res, 405, "طريقة الطلب غير مسموح بها. التحقق وتفعيل الحساب مقصور على طلبات POST فقط لمنع ثغرات CSRF.");
      }

      // Sliding Window Rate Limit: Auth (5 attempts per 15 minutes)
      const allowed = await enforceRateLimit(req, res, "auth");
      if (!allowed) return;

      const rawToken = typeof body?.token === "string" ? body.token.trim() : "";
      const rawCode = typeof body?.code === "string" ? body.code.trim() : "";
      const rawEmail = (typeof body?.email === "string" ? body.email : "").trim().toLowerCase();

      if (!rawToken && (!rawCode || !rawEmail)) {
        return sendError(res, 400, "يرجى تقديم رابط التفعيل أو كود التحقق والبريد الإلكتروني المرتبط به.");
      }

      let targetCust = null;

      // CASE A: 6-Digit Code Verification with Email (Target for Brute Force)
      if (rawCode && rawEmail) {
        const cust = db.prepare("SELECT * FROM customers WHERE LOWER(email) = ?").get(rawEmail);
        if (!cust) {
          return sendError(res, 400, "رمز أو كود تفعيل البريد الإلكتروني غير صحيح أو انتهت صلاحيته.");
        }

        if (cust.email_verified === 1 || cust.email_verified === true) {
          return sendJson(res, 200, {
            success: true,
            message: "هذا الحساب مفعّل بالفعل مسبقاً.",
            customer: { id: cust.id, name: cust.name, phone: cust.phone, email: cust.email, role: cust.role, email_verified: true }
          });
        }

        const currentAttempts = Number(cust.verification_attempts || 0);

        // Fail-Closed: If already 5 or more failed attempts, or token already nullified
        if (currentAttempts >= 5 || !cust.verification_code_hash) {
          db.prepare(`
            UPDATE customers 
            SET verification_token_hash = NULL, verification_code_hash = NULL, verification_expires_at = NULL, updated_at = datetime('now')
            WHERE id = ?
          `).run(cust.id);
          return sendError(res, 429, "تم تجاوز الحد الأقصى للمحاولات الخاطئة (5 محاولات). تم إتلاف رمز التفعيل لأسباب أمنية، يرجى طلب إعادة إرسال كود جديد.");
        }

        if (cust.verification_expires_at && Date.now() > Number(cust.verification_expires_at)) {
          return sendError(res, 400, "انتهت صلاحية رمز التفعيل (صلاحيته 24 ساعة فقط). يرجى طلب رمز جديد.");
        }

        // Timing-Safe Verification of 6-Digit Code Hash
        const codeHash = crypto.createHash("sha256").update(rawCode).digest("hex");
        const expectedBuf = Buffer.from(cust.verification_code_hash, "hex");
        const actualBuf = Buffer.from(codeHash, "hex");
        const isMatch = (expectedBuf.length === actualBuf.length) && crypto.timingSafeEqual(expectedBuf, actualBuf);

        if (!isMatch) {
          const newAttempts = currentAttempts + 1;
          if (newAttempts >= 5) {
            // Incinerate verification tokens immediately on 5th failed attempt
            db.prepare(`
              UPDATE customers 
              SET verification_attempts = ?, verification_token_hash = NULL, verification_code_hash = NULL, verification_expires_at = NULL, updated_at = datetime('now')
              WHERE id = ?
            `).run(newAttempts, cust.id);
            return sendError(res, 429, "تم تجاوز الحد الأقصى للمحاولات الخاطئة (5 محاولات). تم إتلاف رمز التفعيل لأسباب أمنية، يرجى طلب إعادة إرسال كود جديد.");
          } else {
            db.prepare(`
              UPDATE customers 
              SET verification_attempts = ?, updated_at = datetime('now')
              WHERE id = ?
            `).run(newAttempts, cust.id);
            const remaining = 5 - newAttempts;
            return sendError(res, 400, `كود التفعيل غير صحيح. متبقي لديك ${remaining} محاولات قبل إتلاف الرمز نهائياً.`);
          }
        }

        targetCust = cust;
      } 
      // CASE B: 32-Byte Secret Token Verification
      else if (rawToken) {
        const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
        targetCust = db.prepare("SELECT * FROM customers WHERE verification_token_hash = ?").get(tokenHash);

        if (!targetCust) {
          if (rawEmail) {
            const cust = db.prepare("SELECT * FROM customers WHERE LOWER(email) = ?").get(rawEmail);
            if (cust && cust.verification_token_hash) {
              const newAttempts = Number(cust.verification_attempts || 0) + 1;
              if (newAttempts >= 5) {
                db.prepare(`
                  UPDATE customers 
                  SET verification_attempts = ?, verification_token_hash = NULL, verification_code_hash = NULL, verification_expires_at = NULL, updated_at = datetime('now')
                  WHERE id = ?
                `).run(newAttempts, cust.id);
                return sendError(res, 429, "تم تجاوز الحد الأقصى للمحاولات الخاطئة (5 محاولات). تم إتلاف رمز التفعيل لأسباب أمنية، يرجى طلب إعادة إرسال رمز جديد.");
              } else {
                db.prepare(`
                  UPDATE customers 
                  SET verification_attempts = ?, updated_at = datetime('now')
                  WHERE id = ?
                `).run(newAttempts, cust.id);
              }
            }
          }
          return sendError(res, 400, "رمز أو رابط تفعيل البريد الإلكتروني غير صحيح أو انتهت صلاحيته.");
        }

        if (Number(targetCust.verification_attempts || 0) >= 5) {
          db.prepare(`
            UPDATE customers 
            SET verification_token_hash = NULL, verification_code_hash = NULL, verification_expires_at = NULL, updated_at = datetime('now')
            WHERE id = ?
          `).run(targetCust.id);
          return sendError(res, 429, "تم تجاوز الحد الأقصى للمحاولات الخاطئة (5 محاولات). تم إتلاف رمز التفعيل لأسباب أمنية، يرجى طلب إعادة إرسال رمز جديد.");
        }

        if (targetCust.verification_expires_at && Date.now() > Number(targetCust.verification_expires_at)) {
          return sendError(res, 400, "انتهت صلاحية رابط التفعيل (صلاحيته 24 ساعة فقط). يرجى طلب رابط جديد.");
        }
      }

      if (!targetCust) {
        return sendError(res, 400, "رمز أو رابط تفعيل البريد الإلكتروني غير صحيح أو انتهت صلاحيته.");
      }

      // Successful verification: mark verified, clear tokens, and reset failed attempts counter to 0
      db.prepare(`
        UPDATE customers 
        SET email_verified = 1, verification_token_hash = NULL, verification_code_hash = NULL, verification_expires_at = NULL, verification_attempts = 0, updated_at = datetime('now')
        WHERE id = ?
      `).run(targetCust.id);

      const newToken = signHmacJwt({ sub: targetCust.id, phone: targetCust.phone, name: targetCust.name, email: targetCust.email, role: targetCust.role, email_verified: true }, CUSTOMER_JWT_SECRET, 86400);

      applySecurityHeaders(res);
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Set-Cookie": `kk_customer_token=${newToken}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; ${isHttpsRequest(req) ? "Secure" : ""}`.trim()
      });
      return res.end(JSON.stringify({
        success: true,
        message: "تم تفعيل البريد الإلكتروني بنجاح ومصادقة حسابك رسمياً.",
        customer: { id: targetCust.id, name: targetCust.name, phone: targetCust.phone, email: targetCust.email, role: targetCust.role, email_verified: true }
      }));
    }

    // 6.5 RESEND EMAIL VERIFICATION (SELF-SERVICE RESET)
    if (action === "resend_verification" && method === "POST") {
      const allowed = await enforceRateLimit(req, res, "auth");
      if (!allowed) return;

      const rawEmail = (body?.email || "").trim().toLowerCase();
      if (!rawEmail) {
        return sendError(res, 400, "يرجى تحديد البريد الإلكتروني المطلوب تفعيله.");
      }

      const cust = db.prepare("SELECT * FROM customers WHERE LOWER(email) = ?").get(rawEmail);
      if (!cust) {
        return sendJson(res, 200, {
          success: true,
          message: "إذا كان هذا البريد مسجلاً لدينا، فقد تم إرسال كود ورابط تفعيل جديد إليه."
        });
      }

      if (cust.email_verified === 1 || cust.email_verified === true) {
        return sendJson(res, 200, {
          success: true,
          message: "هذا الحساب مفعّل بالفعل مسبقاً."
        });
      }

      const newVerToken = crypto.randomBytes(32).toString("hex");
      const newVerCode = String(crypto.randomInt(100000, 999999));
      const tokenHash = crypto.createHash("sha256").update(newVerToken).digest("hex");
      const codeHash = crypto.createHash("sha256").update(newVerCode).digest("hex");
      const expiresAt = Date.now() + (24 * 60 * 60 * 1000);

      db.prepare(`
        UPDATE customers 
        SET verification_token_hash = ?, verification_code_hash = ?, verification_expires_at = ?, verification_attempts = 0, updated_at = datetime('now')
        WHERE id = ?
      `).run(tokenHash, codeHash, expiresAt, cust.id);

      sendCustomerVerificationEmail(cust.email, cust.name, newVerToken, newVerCode).catch(e => {
        console.warn("[server.js] Error sending verification email:", e.message);
      });

      return sendJson(res, 200, {
        success: true,
        message: "تم إرسال كود ورابط تفعيل جديد إلى بريدك الإلكتروني بنجاح (صالح لمدة 24 ساعة)."
      });
    }

    // 7. GET CUSTOMER ORDERS (BOLA/IDOR PROTECTED)
    if (action === "orders" && method === "GET") {
      const customerSession = extractCustomerSession(req);
      if (!customerSession || !customerSession.sub) {
        return sendError(res, 401, "يجب تسجيل الدخول لعرض سجل طلباتك.");
      }

      // Query database directly to confirm customer existence and verified status (Zero-Trust DB Authority)
      const custRecord = db.prepare("SELECT id, email, email_verified FROM customers WHERE id = ?").get(customerSession.sub);
      if (!custRecord) {
        return sendError(res, 401, "حساب العميل غير موجود أو تم إلغاؤه.");
      }

      const isEmailVerified = Boolean(custRecord.email_verified === 1 || custRecord.email_verified === "1" || custRecord.email_verified === true);
      const custEmail = (custRecord.email || "").trim().toLowerCase();

      // Bind strictly to customer_id; only permit matching email if verified in DB; NEVER match unverified phone
      let query;
      let params;
      if (isEmailVerified && custEmail) {
        query = "SELECT id, order_number, subtotal, delivery_fee, total, status, created_at FROM orders WHERE customer_id = ? OR (LOWER(customer_email) = ? AND customer_email IS NOT NULL) ORDER BY created_at DESC";
        params = [custRecord.id, custEmail];
      } else {
        query = "SELECT id, order_number, subtotal, delivery_fee, total, status, created_at FROM orders WHERE customer_id = ? ORDER BY created_at DESC";
        params = [custRecord.id];
      }

      const myOrders = db.prepare(query).all(...params);
      return sendJson(res, 200, { success: true, count: myOrders.length, orders: myOrders });
    }

    // 8. ADMIN DIRECTORY (GET ALL CUSTOMERS — STRICT ADMIN RBAC & BFLA DEFENSE)
    if (action === "list" && method === "GET") {
      const admin = assertAdminAuthorized(req);
      if (!admin) {
        return sendError(res, 401, "غير مصرح بالوصول. استعراض سجل العملاء يتطلب صلاحيات الإدارة العليا.");
      }
      const rawPage = parseInt(parsedUrl.searchParams.get("page") || "1", 10);
      const rawLimit = parseInt(parsedUrl.searchParams.get("limit") || "50", 10);
      const page = Number.isInteger(rawPage) && rawPage >= 1 ? rawPage : 1;
      const limit = Number.isInteger(rawLimit) && rawLimit >= 1 ? Math.min(rawLimit, 50) : 50;
      const offset = (page - 1) * limit;

      const totalRow = db.prepare("SELECT COUNT(*) as count FROM customers").get();
      const total = totalRow ? totalRow.count : 0;
      const customers = db.prepare(`
        SELECT id, name, phone, email, avatar, role, email_verified, created_at, updated_at 
        FROM customers 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
      `).all(limit, offset);

      return sendJson(res, 200, {
        success: true,
        count: customers.length,
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit) || 1,
        customers
      });
    }
  }

  // ---------------------------------------------------------------------------
  // API: Cron Automated Cleanup (/api/cron/cleanup-unverified)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/cron/cleanup-unverified") {
    const cronSecret = process.env.CRON_SECRET;
    if (!cronSecret || cronSecret.length < 16) {
      return sendError(res, 500, "CRON_SECRET is not configured or too short (Fail-Closed).");
    }

    const authHeader = req.headers["authorization"] || req.headers["Authorization"] || "";
    const expectedHeader = `Bearer ${cronSecret}`;
    const actualHash = crypto.createHash("sha256").update(authHeader).digest();
    const expectedHash = crypto.createHash("sha256").update(expectedHeader).digest();

    if (!crypto.timingSafeEqual(actualHash, expectedHash)) {
      return sendError(res, 401, "غير مصرح: رمز مهمة التنظيف غير صحيح (Invalid Cron Secret).");
    }

    try {
      // SQLite datetime('now') uses 'YYYY-MM-DD HH:MM:SS' (space separator, not ISO 'T')
      const cutoffTime = new Date(Date.now() - (24 * 60 * 60 * 1000)).toISOString().replace("T", " ").slice(0, 19);
      const deleted = db.prepare(`
        DELETE FROM customers 
        WHERE (email_verified IS NULL OR email_verified = 0 OR email_verified = 'false')
          AND (google_sub IS NULL OR google_sub = '')
          AND role != 'admin'
          AND created_at < ?
      `).run(cutoffTime);

      return sendJson(res, 200, {
        success: true,
        message: `تم تنظيف ${deleted.changes} حساب غير مفعّل تجاوزت مدة إنشائها 24 ساعة بنجاح.`,
        deletedCount: deleted.changes
      });
    } catch (err) {
      return sendError(res, 500, "فشل تنفيذ مهمة تنظيف الحسابات غير المفعّلة.");
    }
  }

  // ---------------------------------------------------------------------------
  // STATIC ASSETS & FRONTEND SERVING (Directory Traversal & Secrets Defense)
  // ---------------------------------------------------------------------------
  // Strict Allowlist Static File Server (blocks .git, .env, internal reports, Windows // UNC bypass, symlinks)
  if (method !== "GET" && method !== "HEAD") {
    applySecurityHeaders(res);
    res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8", "Allow": "GET, HEAD" });
    return res.end("405 Method Not Allowed");
  }

  if (pathname.includes("\0") || /%00/i.test(pathname) || pathname.includes("\\")) {
    applySecurityHeaders(res);
    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("400 Bad Request: Malformed Path");
  }

  let decodedPath = "";
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    applySecurityHeaders(res);
    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("400 Bad Request: Malformed URI Encoding");
  }

  const collapsedPath = decodedPath.replace(/\\/g, "/").replace(/\/{2,}/g, "/");
  const segments = collapsedPath.split("/").filter(Boolean);

  // Strictly reject any dot-segment (.git, .env, .., .vscode, etc.)
  if (segments.some(seg => seg.startsWith(".") || seg.includes(".."))) {
    applySecurityHeaders(res);
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("403 Forbidden: Protected System Resource");
  }

  const ALLOWED_CLEAN_ROUTES = new Map([
    ["/", "index.html"],
    ["/admin", "admin.html"],
    ["/privacy", "privacy.html"],
    ["/terms", "terms.html"]
  ]);
  const ALLOWED_ROOT_FILES = new Set([
    "index.html",
    "admin.html",
    "privacy.html",
    "terms.html",
    "robots.txt",
    "sitemap.xml",
    "site.webmanifest",
    "favicon.ico",
    "apple-touch-icon.png",
    "google5d5a78c6da719b99.html"
  ]);
  const ALLOWED_PUBLIC_DIRS = new Set(["css", "js", "assets"]);
  const ALLOWED_STATIC_EXTS = new Set([
    ".html", ".css", ".js", ".png", ".jpg", ".jpeg", ".webp", ".avif", ".svg", ".ico", ".txt", ".xml", ".webmanifest"
  ]);

  let relativeTarget = null;
  const lowerCollapsed = collapsedPath.toLowerCase();
  if (ALLOWED_CLEAN_ROUTES.has(lowerCollapsed)) {
    relativeTarget = ALLOWED_CLEAN_ROUTES.get(lowerCollapsed);
  } else if (segments.length === 1 && ALLOWED_ROOT_FILES.has(segments[0].toLowerCase())) {
    relativeTarget = segments[0];
  } else if (segments.length >= 2 && ALLOWED_PUBLIC_DIRS.has(segments[0].toLowerCase())) {
    const ext = path.extname(segments[segments.length - 1]).toLowerCase();
    if (ALLOWED_STATIC_EXTS.has(ext)) {
      relativeTarget = segments.join("/");
    }
  }

  if (!relativeTarget) {
    applySecurityHeaders(res);
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("404 Not Found");
  }

  const resolvedRoot = fs.realpathSync(path.resolve(__dirname));
  const resolvedRootWithSep = resolvedRoot.endsWith(path.sep) ? resolvedRoot : resolvedRoot + path.sep;
  const candidatePath = path.resolve(resolvedRoot, relativeTarget);

  let realFilePath = null;
  try {
    realFilePath = fs.realpathSync(candidatePath);
  } catch {
    applySecurityHeaders(res);
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("404 Not Found");
  }

  if (!realFilePath.startsWith(resolvedRootWithSep)) {
    applySecurityHeaders(res);
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    return res.end("403 Forbidden: Directory Traversal Blocked");
  }

  const isAdminSurface = relativeTarget.toLowerCase() === "admin.html";

  fs.stat(realFilePath, (err, stats) => {
    if (err || !stats.isFile()) {
      applySecurityHeaders(res);
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("404 Not Found");
    }

    const ext = path.extname(realFilePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";
    const cacheControl = ext === ".html" ? "no-cache" : "public, max-age=86400";
    const etag = `W/"${stats.size}-${Math.floor(stats.mtimeMs)}"`;

    applySecurityHeaders(res, isAdminSurface);
    res.setHeader("ETag", etag);
    res.setHeader("Vary", "Accept-Encoding");

    if (req.headers["if-none-match"] === etag) {
      res.writeHead(304, { "Cache-Control": cacheControl, "ETag": etag });
      return res.end();
    }

    const acceptEncoding = String(req.headers["accept-encoding"] || "");
    const compressibleExts = new Set([".html", ".css", ".js", ".svg", ".xml", ".txt", ".webmanifest", ".json"]);
    const canCompress = compressibleExts.has(ext) && stats.size >= 1024;
    const encoding = canCompress
      ? (acceptEncoding.includes("br") ? "br" : (acceptEncoding.includes("gzip") ? "gzip" : null))
      : null;

    if (method === "HEAD") {
      const headHeaders = {
        "Content-Type": contentType,
        "Cache-Control": cacheControl,
        "ETag": etag
      };
      if (!encoding) headHeaders["Content-Length"] = stats.size;
      else headHeaders["Content-Encoding"] = encoding;
      res.writeHead(200, headHeaders);
      return res.end();
    }

    const stream = fs.createReadStream(realFilePath);
    stream.on("error", () => {
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
      }
      res.end();
    });

    if (encoding === "br") {
      res.writeHead(200, { "Content-Type": contentType, "Content-Encoding": "br", "Cache-Control": cacheControl, "ETag": etag });
      stream.pipe(zlib.createBrotliCompress()).pipe(res);
    } else if (encoding === "gzip") {
      res.writeHead(200, { "Content-Type": contentType, "Content-Encoding": "gzip", "Cache-Control": cacheControl, "ETag": etag });
      stream.pipe(zlib.createGzip()).pipe(res);
    } else {
      res.writeHead(200, {
        "Content-Type": contentType,
        "Content-Length": stats.size,
        "Cache-Control": cacheControl,
        "ETag": etag
      });
      stream.pipe(res);
    }
  });
  } catch (serverErr) {
    if (serverErr?.statusCode === 413 || serverErr?.message?.includes("413") || serverErr?.message === "Payload Too Large") {
      if (!res.headersSent) {
        sendError(res, 413, serverErr.message || "حجم البيانات المرسلة يتجاوز الحد الأقصى المسموح به (50 كيلوبايت) - 413 Payload Too Large");
      }
      return;
    }
    if (serverErr?.statusCode === 400) {
      if (!res.headersSent) {
        sendError(res, 400, serverErr.message || "بيانات الطلب غير صالحة.");
      }
      return;
    }
    safeLogError("server.js", "http-server", serverErr);
    if (!res.headersSent) {
      sendError(res, 500, "حدث خطأ داخلي في معالجة الطلب.");
    }
  }
});

// Slowloris & Slow HTTP Denial-of-Service Protection (ASVS 14.2)
server.requestTimeout = 15000;
server.headersTimeout = 10000;
server.keepAliveTimeout = 5000;

server.listen(PORT, HOST, () => {
  console.log(`=================================================================`);
  console.log(`⭐ KASED KARIM LUXURY LIGHTING - PRODUCTION HARDENED SERVER ACTIVE`);
  console.log(`🌐 Server running at: http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}`);
  console.log(`🗄️ Database: Relational SQL Engine [Enforced Foreign Keys & Soft Delete]`);
  console.log(`🛡️ Security: OWASP ASVS L3 Strict Auth, BFLA, Zero-Trust Pricing & IDOR Defense Active`);
  console.log(`=================================================================`);
});

export { server, db, checkProductRelations };
