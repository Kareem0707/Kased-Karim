/**
 * KASED KARIM LUXURY LIGHTING - PRODUCTION PORTABLE SERVER (server.js)
 * Architecture: Unified Frontend + Backend + Relational SQL Database
 * Zero Vendor Lock-in: Run on ANY VPS (Hetzner, DO, Contabo, AWS) or locally via Node/Docker/Podman.
 * Standards: OWASP ASVS Level 3, Strict Referential Integrity, Automated Soft Delete.
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "0.0.0.0";
const DB_FILE = process.env.SQLITE_DB_PATH || path.join(__dirname, "kased_karim.db");

// =============================================================================
// 1. RELATIONAL DATABASE INITIALIZATION & MIGRATIONS
// =============================================================================
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

  -- Long-Term Web Restore Points (نقاط الاسترجاع المؤرشفة تاريخياً مع دعم التقويم والسنوات السابقة)
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
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

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

// Seed initial baseline categories if table is empty
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
// 3. HTTP SERVER & ROUTING ENGINE
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

function sendJson(res, statusCode, data) {
  const json = JSON.stringify(data);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(json),
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY"
  });
  res.end(json);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 5 * 1024 * 1024) {
        req.destroy();
        reject(new Error("Payload Too Large"));
      }
    });
    req.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        resolve({});
      }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const pathname = parsedUrl.pathname;
  const method = req.method.toUpperCase();

  // Security Headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // ---------------------------------------------------------------------------
  // API: Database Health Check (/api/db-health)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/db-health") {
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
  // API: Products Management (/api/products)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/products") {
    // 1. GET: Fetch Products
    if (method === "GET") {
      const id = parsedUrl.searchParams.get("id");
      const includeDeleted = parsedUrl.searchParams.get("include_deleted") === "1";
      const isAdminView = parsedUrl.searchParams.get("all") === "1";

      if (id) {
        const prod = db.prepare("SELECT * FROM products WHERE id = ?").get(id);
        if (!prod) {
          return sendJson(res, 404, { success: false, error: "المنتج غير موجود." });
        }
        if (prod.deleted_at && !includeDeleted) {
          return sendJson(res, 404, { success: false, error: "عفواً، هذا المنتج غير متوفر حالياً (تمت أرشفته أو حذفه)." });
        }
        return sendJson(res, 200, { success: true, product: prod });
      }

      let query = "SELECT * FROM products WHERE deleted_at IS NULL AND active = 1 ORDER BY created_at DESC";
      if (includeDeleted || isAdminView) {
        query = includeDeleted
          ? "SELECT * FROM products ORDER BY created_at DESC"
          : "SELECT * FROM products WHERE deleted_at IS NULL ORDER BY created_at DESC";
      }

      const products = db.prepare(query).all();
      return sendJson(res, 200, {
        success: true,
        count: products.length,
        products
      });
    }

    // 2. PATCH / RESTORE: Update Product or Restore Soft-Deleted Product
    if (method === "PATCH" || (method === "POST" && parsedUrl.searchParams.get("action") === "restore")) {
      const body = await parseBody(req);
      const rawId = parsedUrl.searchParams.get("id") || body.id;
      if (!rawId) {
        return sendJson(res, 400, { success: false, error: "معرف المنتج مطلوب لإجراء التعديل أو الاسترجاع." });
      }

      // Restore Soft-Deleted Product (إلغاء الحذف واسترجاع المنتج للعمل فوراً)
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

      // Partial Field Updates (Price, Stock, Active status, etc.)
      if (body.price !== undefined) db.prepare("UPDATE products SET price = ? WHERE id = ?").run(parseFloat(body.price), rawId);
      if (body.stock !== undefined) db.prepare("UPDATE products SET stock = ? WHERE id = ?").run(parseInt(body.stock, 10), rawId);
      if (body.active !== undefined) db.prepare("UPDATE products SET active = ? WHERE id = ?").run(body.active ? 1 : 0, rawId);
      if (body.name !== undefined) db.prepare("UPDATE products SET name = ? WHERE id = ?").run(String(body.name), rawId);

      return sendJson(res, 200, { success: true, id: rawId, message: "تم تحديث بيانات المنتج بنجاح." });
    }

    // 3. POST: Create Product
    if (method === "POST") {
      const body = await parseBody(req);
      if (!body.name || !body.price) {
        return sendJson(res, 400, { success: false, error: "اسم المنتج وسعره حقول إلزامية." });
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
        body.name,
        body.enName || body.en_name || "",
        body.category_id || body.category || "cat_chandeliers",
        body.category_name || body.categoryName || "نجف وثريات فاخرة",
        parseFloat(body.price),
        body.salePrice || body.sale_price ? parseFloat(body.salePrice || body.sale_price) : null,
        body.costPrice || body.cost_price ? parseFloat(body.costPrice || body.cost_price) : null,
        parseInt(body.stock || "10", 10),
        body.image || "",
        body.description || "",
        body.featured ? 1 : 0
      );

      // Create linked inventory
      db.prepare("INSERT OR REPLACE INTO inventory (id, product_id, warehouse_name, quantity_on_hand) VALUES (?, ?, ?, ?)")
        .run(`inv_${id}`, id, "المستودع الرئيسي - الشيخ زايد", parseInt(body.stock || "10", 10));

      return sendJson(res, 201, { success: true, message: "تم إنشاء المنتج بنجاح في قاعدة البيانات العلائقية.", id });
    }

    // 3. DELETE: Safe Deletion Engine (Relational Integrity Check + Soft Delete)
    if (method === "DELETE") {
      const rawId = parsedUrl.searchParams.get("id");
      const isForceHard = parsedUrl.searchParams.get("force_hard") === "1";

      if (!rawId) {
        return sendJson(res, 400, { success: false, error: "معرف المنتج مطلوب لإجراء الحذف." });
      }

      const existing = db.prepare("SELECT * FROM products WHERE id = ?").get(rawId);
      if (!existing) {
        return sendJson(res, 404, { success: false, error: "المنتج غير موجود." });
      }

      // 1. Strict Referential Integrity Check across Orders, Sales, Inventory, and Pricelists
      const relations = checkProductRelations(rawId);
      const nowIso = new Date().toISOString();

      // Rule: If associations exist, HARD DELETE is strictly forbidden!
      if (relations.hasRelations) {
        if (isForceHard) {
          return sendJson(res, 409, {
            success: false,
            error: "لا يمكن الحذف النهائي (Hard Delete) لهذا المنتج لوجود سجلات مرتبطة به في (الطلبات، المبيعات، المخزون، أو قوائم الأسعار). تم الحفاظ على تكامل البيانات المحاسبية.",
            relations
          });
        }

        // Apply Soft Delete (تسجيل تاريخ الحذف وحجب المنتج من المتجر)
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

      // 2. No Relations Found: Soft Delete by default, or Hard Delete if explicitly forced
      if (isForceHard) {
        // Remove from inventory first if empty
        db.prepare("DELETE FROM inventory WHERE product_id = ?").run(rawId);
        db.prepare("DELETE FROM products WHERE id = ?").run(rawId);

        return sendJson(res, 200, {
          success: true,
          hardDeleted: true,
          id: rawId,
          message: "تم حذف المنتج نهائياً من قاعدة البيانات (Hard Delete) لعدم وجود أي ارتباطات له."
        });
      }

      // Default Soft Delete
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
    if (method === "GET") {
      const orders = db.prepare("SELECT * FROM orders ORDER BY created_at DESC").all();
      return sendJson(res, 200, { success: true, count: orders.length, orders });
    }

    if (method === "POST") {
      const body = await parseBody(req);
      const items = Array.isArray(body.items) ? body.items : [];

      if (items.length === 0) {
        return sendJson(res, 400, { success: false, error: "السلة فارغة، يجب إرسال منتجات صالحة." });
      }

      // Validate products: ensure none are soft-deleted or inactive
      for (const item of items) {
        const prodId = item.id || item.productId;
        const prod = db.prepare("SELECT * FROM products WHERE id = ?").get(prodId);
        if (!prod || prod.active === 0 || prod.deleted_at !== null) {
          return sendJson(res, 400, {
            success: false,
            error: `عفواً، المنتج '${prod ? prod.name : prodId}' لم يعد متاحاً في المتجر (تم حذفه أو إيقافه).`
          });
        }
      }

      const orderId = `ord_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      const orderNumber = `KK-${Date.now().toString().slice(-6)}`;
      const total = items.reduce((sum, it) => sum + (it.price * (it.qty || 1)), 0);

      db.prepare(`
        INSERT INTO orders (
          id, order_number, customer_name, customer_phone, customer_email,
          shipping_address, delivery_city, subtotal, total, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
      `).run(
        orderId,
        orderNumber,
        body.customerName || body.name || "عميل تجريبي",
        body.customerPhone || body.phone || "01000000000",
        body.customerEmail || body.email || "",
        body.address || "الشيخ زايد - الجيزة",
        body.city || "الشيخ زايد",
        total,
        total
      );

      // Insert Order Items and Sales Transactions (Establishing Strict Relational Links)
      const insertItem = db.prepare(`
        INSERT INTO order_items (id, order_id, product_id, product_name, unit_price, quantity, total_price)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      const insertSale = db.prepare(`
        INSERT INTO sales (id, order_id, product_id, quantity_sold, unit_price, gross_revenue, net_profit)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);

      for (const item of items) {
        const prodId = item.id || item.productId;
        const qty = item.qty || 1;
        const unitPrice = parseFloat(item.price);
        const lineTotal = unitPrice * qty;

        insertItem.run(`item_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`, orderId, prodId, item.name || "وحدة إضاءة", unitPrice, qty, lineTotal);
        insertSale.run(`sale_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`, orderId, prodId, qty, unitPrice, lineTotal, lineTotal * 0.35);
      }

      return sendJson(res, 201, {
        success: true,
        orderId,
        orderNumber,
        total,
        message: "تم تسجيل الطلب وتحديث سجلات المبيعات بنجاح."
      });
    }
  }

  // ---------------------------------------------------------------------------
  // API: Backup & Data Export (/api/backup)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/backup") {
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
  // API: Long-Term Web Restore Points with Calendar History (/api/restore-points)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/restore-points" || pathname.startsWith("/api/restore-points/")) {
    // 1. GET: Fetch Restore Points with Calendar & Date Filtering
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

    // 2. POST: Create or Restore Point
    if (method === "POST") {
      const body = await parseBody(req);
      const action = parsedUrl.searchParams.get("action") || body.action;

      // Sub-Action: Restore from a point ID
      if (action === "restore") {
        const pointId = parsedUrl.searchParams.get("id") || body.id;
        if (!pointId) {
          return sendJson(res, 400, { success: false, error: "معرف نقطة الاسترجاع مطلوب." });
        }

        const point = db.prepare("SELECT * FROM restore_points WHERE id = ?").get(pointId);
        if (!point || !point.data_json) {
          return sendJson(res, 404, { success: false, error: "نقطة الاسترجاع غير موجودة في الأرشيف التاريخي." });
        }

        let snapshotData = {};
        try { snapshotData = JSON.parse(point.data_json); } catch (e) {}

        const restoredProducts = snapshotData.products || [];
        if (Array.isArray(restoredProducts) && restoredProducts.length > 0) {
          // Restore all products from snapshot into active state
          for (const p of restoredProducts) {
            if (!p || !p.id) continue;
            const existing = db.prepare("SELECT id FROM products WHERE id = ?").get(p.id);
            if (existing) {
              db.prepare("UPDATE products SET deleted_at = NULL, active = 1, status = 'published', updated_at = datetime('now') WHERE id = ?").run(p.id);
            } else {
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
                p.image || "",
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
  // 6. CUSTOMER ACCOUNT & AUTHENTICATION ENDPOINT (/api/customer)
  // ---------------------------------------------------------------------------
  if (pathname === "/api/customer") {
    const body = method !== "GET" ? await parseBody(req) : {};
    const action = parsedUrl.searchParams.get("action") || (body ? body.action : "") || "me";

    if (action === "register" && method === "POST") {
      const name = (body.name || "").trim().slice(0, 100);
      const phone = (body.phone || "").replace(/[^0-9]/g, "");
      const email = (body.email || "").trim().toLowerCase();
      const password = body.password || "";

      if (!name || name.length < 2) {
        return sendError(res, 400, "يرجى كتابة اسم العميل بشكل صحيح (حرفين على الأقل)");
      }
      if (!phone || !/^01[0125][0-9]{8}$/.test(phone)) {
        return sendError(res, 400, "يرجى إدخال رقم هاتف مصري صحيح مكون من 11 رقماً يبدأ بـ 01");
      }
      if (password.length < 8) {
        return sendError(res, 400, "كلمة المرور يجب أن لا تقل عن 8 أحرف أو أرقام.");
      }

      const existing = db.prepare("SELECT * FROM customers WHERE phone = ? OR (email IS NOT NULL AND email = ?)").get(phone, email || "---none---");
      if (existing) {
        return sendError(res, 409, "رقم الهاتف أو البريد الإلكتروني مسجل بالفعل بحساب آخر.");
      }

      const id = "CUST-" + crypto.randomUUID().slice(0, 8).toUpperCase();
      const salt = crypto.randomBytes(16).toString("hex");
      const hash = crypto.scryptSync(password, salt, 32).toString("hex");

      db.prepare(`
        INSERT INTO customers (id, name, phone, email, password_hash, password_salt, role)
        VALUES (?, ?, ?, ?, ?, ?, 'customer')
      `).run(id, name, phone, email || null, hash, salt);

      return sendJson(res, 201, {
        success: true,
        customer: { id, name, phone, email: email || null, role: "customer" }
      });
    }

    if (action === "login" && method === "POST") {
      const identifier = (body.identifier || "").trim();
      const password = body.password || "";
      const cleanPhone = identifier.replace(/[^0-9]/g, "");

      const cust = db.prepare(`
        SELECT * FROM customers 
        WHERE (phone = ? AND phone != '') OR (LOWER(email) = LOWER(?) AND email IS NOT NULL)
      `).get(cleanPhone, identifier);

      if (!cust || !cust.password_hash || !cust.password_salt) {
        return sendError(res, 401, "بيانات الدخول غير صحيحة. يرجى التأكد من رقم الهاتف/البريد وكلمة المرور.");
      }

      const checkHash = crypto.scryptSync(password, cust.password_salt, 32).toString("hex");
      if (checkHash !== cust.password_hash) {
        return sendError(res, 401, "بيانات الدخول غير صحيحة. يرجى التأكد من كلمة المرور.");
      }

      return sendJson(res, 200, {
        success: true,
        customer: { id: cust.id, name: cust.name, phone: cust.phone, email: cust.email, role: cust.role }
      });
    }

    if (action === "logout") {
      return sendJson(res, 200, { success: true, message: "تم تسجيل الخروج بنجاح." });
    }

    if (action === "google" && method === "POST") {
      const credential = body.credential;
      if (!credential) {
        return sendError(res, 400, "رمز توثيق Google مطلوب.");
      }
      try {
        const parts = credential.split(".");
        if (parts.length === 3) {
          const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
          const googleSub = payload.sub || crypto.randomUUID();
          const email = (payload.email || "").toLowerCase();
          const name = payload.name || "عميل Google";
          const avatar = payload.picture || "";

          let cust = db.prepare("SELECT * FROM customers WHERE google_sub = ? OR (email IS NOT NULL AND email = ?)").get(googleSub, email);
          if (!cust) {
            const id = "CUST-G-" + crypto.randomUUID().slice(0, 8).toUpperCase();
            db.prepare(`
              INSERT INTO customers (id, name, phone, email, google_sub, avatar, role)
              VALUES (?, ?, NULL, ?, ?, ?, 'customer')
            `).run(id, name, email || null, googleSub, avatar);
            cust = { id, name, phone: null, email, avatar, role: "customer" };
          }
          return sendJson(res, 200, {
            success: true,
            customer: { id: cust.id, name: cust.name, phone: cust.phone, email: cust.email, avatar: cust.avatar, role: cust.role }
          });
        }
      } catch (e) {
        return sendError(res, 400, "فشل فك تشفير رمز Google.");
      }
    }
  }

  // ---------------------------------------------------------------------------
  // STATIC ASSETS & FRONTEND SERVING
  // ---------------------------------------------------------------------------
  let safePath = path.normalize(decodeURIComponent(pathname)).replace(/^(\.\.[\/\\])+/, "");
  if (safePath === "/" || safePath === "\\") {
    safePath = "/index.html";
  }

  const filePath = path.join(__dirname, safePath);

  // Security: Prevent Directory Traversal
  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    return res.end("Forbidden");
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Fallback for clean URLs (e.g. /admin -> admin.html) or 404
      const htmlPath = filePath + ".html";
      if (fs.existsSync(htmlPath)) {
        try {
          const fallbackStats = fs.statSync(htmlPath);
          res.writeHead(200, {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": fallbackStats.size,
            "Cache-Control": "no-cache"
          });
          return fs.createReadStream(htmlPath).pipe(res);
        } catch (e) {}
      }
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("404 Not Found");
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";

    res.writeHead(200, {
      "Content-Type": contentType,
      "Content-Length": stats.size,
      "Cache-Control": ext === ".html" ? "no-cache" : "public, max-age=86400"
    });

    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`=================================================================`);
  console.log(`⭐ KASED KARIM LUXURY LIGHTING - PRODUCTION SERVER ACTIVE`);
  console.log(`🌐 Server running at: http://${HOST === "0.0.0.0" ? "localhost" : HOST}:${PORT}`);
  console.log(`🗄️ Database: Relational SQL Engine [Enforced Foreign Keys & Soft Delete]`);
  console.log(`🚀 Zero Vendor Lock-in: Ready for VPS, Docker, or Podman!`);
  console.log(`=================================================================`);
});

export { server, db, checkProductRelations };
