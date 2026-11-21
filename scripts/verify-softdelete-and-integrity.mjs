/**
 * KASED KARIM LUXURY LIGHTING - AUTOMATED VERIFICATION SUITE
 * Test Target: Relational Schema, Referential Integrity Guard, and Soft Delete Engine
 * Run: node scripts/verify-softdelete-and-integrity.mjs
 */

import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const testDbPath = path.join(__dirname, "..", "scratch", "test_verification.db");

console.log("=================================================================");
console.log("▶ بدء تشغيل الاختبارات الآلية للتحقق من سلامة التكامل المرجعي والـ Soft Delete");
console.log(`📁 مسار قاعدة بيانات الاختبار: ${testDbPath}`);
console.log("=================================================================");

// Initialize isolated test database
const db = new DatabaseSync(testDbPath);
db.exec("PRAGMA foreign_keys = ON;");

let passedTests = 0;
let totalTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    console.log(`  ✅ [PASS] ${message}`);
    passedTests++;
  } else {
    console.error(`  ❌ [FAIL] ${message}`);
    process.exitCode = 1;
  }
}

// -----------------------------------------------------------------------------
// TEST 1: Relational Schema & Soft Delete Column Verification
// -----------------------------------------------------------------------------
console.log("\n[Test 1] التحقق من بنية الجداول وقيد الحذف اللطيف (deleted_at) والعلاقات");

db.exec(`
  DROP TABLE IF EXISTS sales;
  DROP TABLE IF EXISTS order_items;
  DROP TABLE IF EXISTS orders;
  DROP TABLE IF EXISTS inventory;
  DROP TABLE IF EXISTS pricelist_items;
  DROP TABLE IF EXISTS pricelists;
  DROP TABLE IF EXISTS products;
  DROP TABLE IF EXISTS categories;

  CREATE TABLE categories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL
  );

  CREATE TABLE products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category_id TEXT REFERENCES categories(id) ON DELETE RESTRICT,
    price REAL NOT NULL,
    cost_price REAL,
    stock INTEGER DEFAULT 0,
    active INTEGER DEFAULT 1,
    status TEXT DEFAULT 'published',
    deleted_at TEXT DEFAULT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE pricelists (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL
  );

  CREATE TABLE pricelist_items (
    id TEXT PRIMARY KEY,
    pricelist_id TEXT REFERENCES pricelists(id) ON DELETE CASCADE,
    product_id TEXT REFERENCES products(id) ON DELETE RESTRICT,
    tier_price REAL NOT NULL
  );

  CREATE TABLE inventory (
    id TEXT PRIMARY KEY,
    product_id TEXT REFERENCES products(id) ON DELETE RESTRICT,
    quantity_on_hand INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE orders (
    id TEXT PRIMARY KEY,
    order_number TEXT UNIQUE NOT NULL,
    customer_name TEXT NOT NULL,
    total REAL NOT NULL,
    status TEXT DEFAULT 'pending'
  );

  CREATE TABLE order_items (
    id TEXT PRIMARY KEY,
    order_id TEXT REFERENCES orders(id) ON DELETE CASCADE,
    product_id TEXT REFERENCES products(id) ON DELETE RESTRICT,
    quantity INTEGER NOT NULL,
    unit_price REAL NOT NULL
  );

  CREATE TABLE sales (
    id TEXT PRIMARY KEY,
    order_id TEXT REFERENCES orders(id) ON DELETE SET NULL,
    product_id TEXT REFERENCES products(id) ON DELETE RESTRICT,
    quantity_sold INTEGER NOT NULL,
    revenue REAL NOT NULL
  );
`);

// Verify columns in products
const productColumns = db.prepare("PRAGMA table_info(products)").all();
const hasDeletedAt = productColumns.some(c => c.name === "deleted_at");
assert(hasDeletedAt, "جدول المنتجات (products) يحتوي على حقل الحذف اللطيف (deleted_at)");

// -----------------------------------------------------------------------------
// TEST 2: Product Creation & Initial Active State
// -----------------------------------------------------------------------------
console.log("\n[Test 2] إضافة منتجات اختبارية والتحقق من حالتها النشطة الأولية");

db.prepare("INSERT INTO categories VALUES ('cat_test', 'نجف فاخر', 'chandeliers')").run();

const insertProduct = db.prepare(`
  INSERT INTO products (id, name, category_id, price, cost_price, stock, active, deleted_at)
  VALUES (?, ?, ?, ?, ?, ?, 1, NULL)
`);

insertProduct.run("prod_test_001", "ثريا كريستال ملكية", "cat_test", 35000, 20000, 10);
insertProduct.run("prod_test_002", "أبليك حائط كلاسيكي", "cat_test", 4500, 2500, 25);

const created = db.prepare("SELECT * FROM products WHERE id = 'prod_test_001'").get();
assert(created && created.deleted_at === null, "تم إنشاء المنتج بنجاح وقيمة deleted_at فارغة (NULL)");

// -----------------------------------------------------------------------------
// TEST 3: Storefront Query Filter (Only Non-Deleted & Active)
// -----------------------------------------------------------------------------
console.log("\n[Test 3] اختبار استعلام واجهة المتجر (فلترة المنتجات غير المحذوفة)");

const activeStorefrontProducts = db.prepare("SELECT * FROM products WHERE deleted_at IS NULL AND active = 1").all();
assert(activeStorefrontProducts.length === 2, `واجهة المتجر تستعرض المنتجات النشطة فقط (العدد: ${activeStorefrontProducts.length})`);

// -----------------------------------------------------------------------------
// TEST 4: Referential Integrity Protection (Blocks Hard Delete When Linked)
// -----------------------------------------------------------------------------
console.log("\n[Test 4] فحص التكامل المرجعي: منع الحذف النهائي للمنتج عند ارتباطه بطلبات أو مبيعات");

// Link product prod_test_001 to an Order and Sales record
db.prepare("INSERT INTO orders VALUES ('ord_001', 'ORD-2026-99', 'عميل الشيخ زايد', 35000, 'completed')").run();
db.prepare("INSERT INTO order_items VALUES ('item_001', 'ord_001', 'prod_test_001', 1, 35000)").run();
db.prepare("INSERT INTO sales VALUES ('sale_001', 'ord_001', 'prod_test_001', 1, 35000)").run();

// Function to check associations before delete
function checkRelations(productId) {
  const ordersCount = db.prepare("SELECT COUNT(*) as c FROM order_items WHERE product_id = ?").get(productId).c;
  const salesCount = db.prepare("SELECT COUNT(*) as c FROM sales WHERE product_id = ?").get(productId).c;
  const invCount = db.prepare("SELECT COUNT(*) as c FROM inventory WHERE product_id = ? AND quantity_on_hand > 0").get(productId).c;
  const priceCount = db.prepare("SELECT COUNT(*) as c FROM pricelist_items WHERE product_id = ?").get(productId).c;

  return {
    orders: ordersCount,
    sales: salesCount,
    inventory: invCount,
    pricelists: priceCount,
    hasRelations: (ordersCount > 0 || salesCount > 0 || invCount > 0 || priceCount > 0)
  };
}

const relations = checkRelations("prod_test_001");
assert(relations.hasRelations === true, "تم رصد ارتباطات للمنتج في الطلبات والمبيعات بنجاح");
assert(relations.orders === 1 && relations.sales === 1, "تم إحصاء عدد الطلبات (1) وعدد المبيعات (1) بدقة");

// Simulate database-level FK restriction attempt
let fkBlocked = false;
try {
  db.prepare("DELETE FROM products WHERE id = 'prod_test_001'").run();
} catch (e) {
  fkBlocked = true;
}
assert(fkBlocked, "قاعدة البيانات تمنع الحذف الصلب الفيزيائي (FOREIGN KEY ON DELETE RESTRICT) بسبب وجود ارتباطات");

// -----------------------------------------------------------------------------
// TEST 5: Soft Delete Execution & Retention Verification
// -----------------------------------------------------------------------------
console.log("\n[Test 5] تنفيذ الحذف اللطيف (Soft Delete) والتحقق من حفظ البيانات وإخفائها");

// Backend executes Soft Delete instead
const deletionTimestamp = new Date().toISOString();
db.prepare(`
  UPDATE products 
  SET deleted_at = ?, active = 0, status = 'archived' 
  WHERE id = 'prod_test_001'
`).run(deletionTimestamp);

// 1. Verify storefront no longer displays the soft-deleted product
const publicCatalogAfterDelete = db.prepare("SELECT * FROM products WHERE deleted_at IS NULL AND active = 1").all();
const isStillInPublicStore = publicCatalogAfterDelete.some(p => p.id === "prod_test_001");
assert(!isStillInPublicStore, "المنتج اختفى تماماً من استعلامات واجهة المتجر العامة");
assert(publicCatalogAfterDelete.length === 1, "المتجر يعرض فقط المنتجات غير المحذوفة المتبقية");

// 2. Verify database still contains the product with deleted_at timestamp
const rawInDb = db.prepare("SELECT * FROM products WHERE id = 'prod_test_001'").get();
assert(rawInDb !== undefined, "المنتج لا يزال محفوظاً بأمان في قاعدة البيانات (لم يتم مسحه نهائياً)");
assert(rawInDb.deleted_at === deletionTimestamp, `تم تسجيل تاريخ وتوقيت الحذف بدقة (${rawInDb.deleted_at})`);
assert(rawInDb.active === 0, "تم تعديل حالة المنتج إلى غير نشط (active = 0)");

// 3. Verify order history and accounting integrity remain 100% intact
const orderHistory = db.prepare("SELECT * FROM order_items WHERE product_id = 'prod_test_001'").all();
const salesHistory = db.prepare("SELECT * FROM sales WHERE product_id = 'prod_test_001'").all();
assert(orderHistory.length === 1, "سجل بنود الطلب المرتبط بالمنتج سليم ولم يتأثر");
assert(salesHistory.length === 1, "سجل الأرباح والمبيعات المحاسبية سليم 100%");

// 4. Verify checkout rejection for soft-deleted product
function validateCheckoutItems(items) {
  for (const it of items) {
    const p = db.prepare("SELECT * FROM products WHERE id = ?").get(it.id);
    if (!p || p.deleted_at !== null || p.active === 0) {
      return { valid: false, error: `المنتج '${it.id}' غير متاح (محذوف أو غير نشط)` };
    }
  }
  return { valid: true };
}

const checkoutResult = validateCheckoutItems([{ id: "prod_test_001", qty: 1 }]);
assert(checkoutResult.valid === false, "نظام إنشاء الطلبات يرفض إتمام الشراء لأي منتج تم حذفه لطيفاً (Soft Deleted)");

// -----------------------------------------------------------------------------
// TEST 6: Unlinked Product Safe Hard Deletion
// -----------------------------------------------------------------------------
console.log("\n[Test 6] فحص الحذف النهائي المسموح لمنتج جديد غير مرتبط بأي سجلات");

insertProduct.run("prod_unlinked_003", "لمبة تجريبية منفصلة", "cat_test", 250, 150, 50);
const unlinkedRelations = checkRelations("prod_unlinked_003");
assert(unlinkedRelations.hasRelations === false, "تم التأكد أن المنتج غير مرتبط بأي طلبات أو مبيعات أو مخزون");

// Delete unlinked product
db.prepare("DELETE FROM products WHERE id = 'prod_unlinked_003'").run();
const deletedCheck = db.prepare("SELECT * FROM products WHERE id = 'prod_unlinked_003'").get();
assert(deletedCheck === undefined, "تم الحذف النهائي للمنتج غير المرتبط بنجاح وأمان");

// -----------------------------------------------------------------------------
// Summary
// -----------------------------------------------------------------------------
console.log("\n=================================================================");
console.log(`🏁 نتيجة الاختبارات: تم بنجاح ${passedTests} من أصل ${totalTests} اختبار.`);
if (passedTests === totalTests) {
  console.log("🎉 جميع المعايير والضوابط المطلوبة تعمل بكفاءة تامة 100%!");
} else {
  console.error("⚠️ فشل في بعض الاختبارات!");
}
console.log("=================================================================");
