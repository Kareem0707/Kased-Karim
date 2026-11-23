/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED SHOWROOM
 * Production Catalog, Inventory & Products Management Engine (api/products.js)
 * Hardened strictly according to OWASP ASVS (Level 3) & OWASP API Security Top 10 (3B-2)
 *
 * Core Security & Architectural Controls:
 * 1. Strict BFLA: All mutation routes (POST, PUT, PATCH, DELETE) strictly gated by verifyAdminRequest.
 * 2. Catastrophic Overwrite Defense: Bulk PUT requires confirmation header & 100% All-or-Nothing validation.
 * 3. URL Validation & SSRF Mitigation: Absolute URLs must be HTTPS, strictly blocking private IPs,
 *    cloud metadata (169.254.169.254), decimal/octal/hex IP notations, and dangerous protocols (javascript:, data:).
 * 4. Payload & Array Bounds: Max 2MB body for bulk (<= 500 items), 50KB for single product, capped arrays.
 * 5. Financial & Stock Integrity: Strict numbers (price > 0, stock integer >= 0, salePrice <= price).
 * 6. Path Traversal & Root Wipe Protection: DELETE strictly requires validated non-empty ID; root wipe blocked.
 * 7. Shared Cache Deception Defense: GET ?all=1 sets Cache-Control: no-store; public GET strips wholesale/supplier PII.
 * 8. Stored XSS & Prototype Pollution Defense: Strict HTML neutralization and prototype key bans.
 */

import {
  verifyAdminRequest,
  sanitizePathId,
  getFirebaseUrl,
  firebaseFetch,
  buildSafeRtdbPath,
  assertSafeRtdbPayload,
  setSecurityHeaders,
  validateSafeImageUrl,
  redactSecretUrl,
  withApiHardening,
  safeLogError
} from "./_auth.js";
import { enforceRateLimit } from "../lib/rateLimit.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// System Constraints & Boundary Limits (Axis 3 & 4)
const MAX_BULK_PAYLOAD_SIZE = 2 * 1024 * 1024;      // 2 MB
const MAX_SINGLE_PAYLOAD_SIZE = 50 * 1024;          // 50 KB
const MAX_BULK_PRODUCTS_COUNT = 500;
const MAX_PRODUCT_IMAGES = 15;
const MAX_PRODUCT_VARIANTS = 50;
const MAX_PRODUCT_TAGS = 30;
const MAX_PRODUCT_SPECS = 30;
const MAX_PRICE_VALUE = 10000000;                   // 10,000,000 EGP
const MAX_STOCK_VALUE = 1000000;

// -----------------------------------------------------------------------------
// TEXT SANITIZATION & ANTI-XSS UTILITIES (Axis 5 & 7)
// -----------------------------------------------------------------------------
function cleanString(val, maxLength = 255) {
  if (typeof val !== "string") return "";
  // Axis 4: Bound length FIRST to guarantee O(n) execution with zero backtracking (CWE-1333)
  const bounded = val.slice(0, maxLength);
  return bounded
    .replace(/[\x00-\x1F\x7F]/g, "") // Strip control characters
    .replace(/[<>]/g, "")            // Strip HTML tag brackets (neutralizes script tags)
    .replace(/javascript\s*:/gi, "") // Neutralize pseudo-protocol
    .replace(/on\w+\s*=/gi, "")      // Neutralize inline events
    .trim();
}

// -----------------------------------------------------------------------------
// PRODUCT SCHEMA VALIDATOR & SANITIZER (Axis 4 & 5: Explicit Product DTO)
// -----------------------------------------------------------------------------
function validateAndSanitizeProduct(p, { isUpdate = false } = {}) {
  if (!p || typeof p !== "object" || Array.isArray(p)) {
    return { valid: false, error: "بيانات المنتج يجب أن تكون كائناً غير فارغ." };
  }

  // 1. Prototype Pollution Defense
  const proto = Object.getPrototypeOf(p);
  if (proto !== Object.prototype && proto !== null) {
    return { valid: false, error: "كائن المنتج غير صالح أمنياً (تم رصد تعديل في النموذج الأولي Prototype Pollution)." };
  }

  const keys = Object.getOwnPropertyNames(p);
  for (const k of keys) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") {
      return { valid: false, error: `مفتاح تلوث النماذج المحظور '${k}' مرفوض أمنياً.` };
    }
    if (k.startsWith(".") || k.includes("/") || k.includes("\\") || k.includes("$") || k.includes("#")) {
      return { valid: false, error: `المفتاح '${k}' يحتوي على رموز خاصة غير مصرح بها.` };
    }
  }

  // 2. Name Validation
  const rawName = typeof p.name === "string" ? p.name : "";
  const cleanName = cleanString(rawName, 150);
  if (!cleanName || cleanName.length < 2) {
    return { valid: false, error: "اسم المنتج مطلوب ويجب ألا يقل عن حرفين (بحد أقصى 150 حرفاً)." };
  }

  const cleanEnName = p.enName ? cleanString(String(p.enName), 150) : "";

  // 3. Category Validation
  const rawCategory = typeof p.category === "string" ? p.category : "";
  const cleanCategory = rawCategory.trim().replace(/[^a-zA-Z0-9_\-\u0600-\u06FF]/g, "").slice(0, 60);
  if (!cleanCategory || cleanCategory.length < 2) {
    return { valid: false, error: "تصنيف المنتج مطلوب ويجب أن يكون نصاً صالحاً." };
  }
  const cleanCategoryName = p.categoryName ? cleanString(String(p.categoryName), 60) : cleanCategory;

  // 4. Financial & Pricing Integrity (Axis 4)
  if (typeof p.price !== "number" || !Number.isFinite(p.price) || Number.isNaN(p.price)) {
    return { valid: false, error: "سعر المنتج الأساسي مطلوب ويجب أن يكون رقماً حقيقياً موجباً." };
  }
  if (p.price <= 0 || p.price > MAX_PRICE_VALUE) {
    return { valid: false, error: `سعر المنتج يجب أن يكون أكبر من 0 ولا يتجاوز ${MAX_PRICE_VALUE.toLocaleString()} ج.م.` };
  }
  const safePrice = Math.round(p.price * 100) / 100;

  // Sale / Discount Price
  let safeSalePrice = null;
  if (p.salePrice !== undefined && p.salePrice !== null && p.salePrice !== "") {
    if (typeof p.salePrice !== "number" || !Number.isFinite(p.salePrice) || Number.isNaN(p.salePrice)) {
      return { valid: false, error: "سعر التخفيض يجب أن يكون رقماً حقيقياً." };
    }
    if (p.salePrice <= 0 || p.salePrice > safePrice) {
      return { valid: false, error: "سعر التخفيض يجب أن يكون أكبر من صفر وأقل من أو يساوي السعر الأساسي." };
    }
    safeSalePrice = Math.round(p.salePrice * 100) / 100;
  }

  // Original Price (Strikethrough reference)
  let safeOriginalPrice = null;
  if (p.originalPrice !== undefined && p.originalPrice !== null && p.originalPrice !== "") {
    if (typeof p.originalPrice !== "number" || !Number.isFinite(p.originalPrice) || Number.isNaN(p.originalPrice)) {
      return { valid: false, error: "السعر الأصلي المقارن يجب أن يكون رقماً حقيقياً." };
    }
    if (p.originalPrice < safePrice || p.originalPrice > MAX_PRICE_VALUE) {
      return { valid: false, error: "السعر الأصلي المقارن يجب ألا يقل عن سعر البيع الحالي." };
    }
    safeOriginalPrice = Math.round(p.originalPrice * 100) / 100;
  }

  // Admin Cost Price (Wholesale / Supplier Price - Privileged only)
  let safeCostPrice = null;
  if (p.costPrice !== undefined && p.costPrice !== null && p.costPrice !== "") {
    if (typeof p.costPrice !== "number" || !Number.isFinite(p.costPrice) || Number.isNaN(p.costPrice) || p.costPrice < 0) {
      return { valid: false, error: "سعر التكلفة يجب أن يكون رقماً موجباً أو صفراً." };
    }
    safeCostPrice = Math.round(p.costPrice * 100) / 100;
  }

  // 5. Stock / Inventory Bounds (Axis 4)
  if (typeof p.stock !== "number" || !Number.isInteger(p.stock)) {
    return { valid: false, error: "كمية المخزون مطلوبة ويجب أن تكون رقماً صحيحاً." };
  }
  if (p.stock < 0 || p.stock > MAX_STOCK_VALUE) {
    return { valid: false, error: `كمية المخزون يجب أن تكون بين 0 و ${MAX_STOCK_VALUE.toLocaleString()} قطعة.` };
  }
  const safeStock = p.stock;

  // 6. Media & Image Validation against SSRF / Dangerous Protocols (Axis 2)
  let safeMainImage = "";
  if (p.image) {
    const imgCheck = validateSafeImageUrl(String(p.image));
    if (!imgCheck.valid) {
      return { valid: false, error: `رابط الصورة الرئيسية غير صالح: ${imgCheck.error}` };
    }
    safeMainImage = imgCheck.sanitizedUrl;
  }

  let safeSecondaryImage = "";
  if (p.secondaryImage) {
    const secCheck = validateSafeImageUrl(String(p.secondaryImage));
    if (!secCheck.valid) {
      return { valid: false, error: `رابط الصورة الثانوية غير صالح: ${secCheck.error}` };
    }
    safeSecondaryImage = secCheck.sanitizedUrl;
  }

  // Images Gallery Array Bounds & SSRF Check
  const safeImagesGallery = [];
  if (Array.isArray(p.images)) {
    if (p.images.length > MAX_PRODUCT_IMAGES) {
      return { valid: false, error: `معرض الصور يتجاوز الحد الأقصى المسموح به (${MAX_PRODUCT_IMAGES} صورة).` };
    }
    for (let i = 0; i < p.images.length; i++) {
      const imgItem = p.images[i];
      if (typeof imgItem !== "string" || !imgItem.trim()) continue;
      const galleryCheck = validateSafeImageUrl(imgItem);
      if (!galleryCheck.valid) {
        return { valid: false, error: `رابط الصورة رقم ${i + 1} في المعرض غير صالح: ${galleryCheck.error}` };
      }
      safeImagesGallery.push(galleryCheck.sanitizedUrl);
    }
  }

  // 7. Textual Fields Validation
  const safeDescription = p.description ? cleanString(String(p.description), 5000) : "";
  const safeShortDescription = p.shortDescription ? cleanString(String(p.shortDescription), 400) : "";
  const safeStyle = p.style ? cleanString(String(p.style), 60) : "";
  const safeWarranty = p.warranty ? cleanString(String(p.warranty), 100) : "5 سنوات ضمان معتمد";
  const safeSku = p.sku ? cleanString(String(p.sku), 50).replace(/[^a-zA-Z0-9_\-]/g, "") : "";
  const safeSupplier = p.supplier ? cleanString(String(p.supplier), 100) : "";
  const safeAdminNotes = p.adminNotes ? cleanString(String(p.adminNotes), 1000) : "";

  // 8. Variants Array Bounds & Validation
  const safeVariants = [];
  if (Array.isArray(p.variants)) {
    if (p.variants.length > MAX_PRODUCT_VARIANTS) {
      return { valid: false, error: `عدد متغيرات المنتج يتجاوز الحد الأقصى (${MAX_PRODUCT_VARIANTS} متغيراً).` };
    }
    for (let i = 0; i < p.variants.length; i++) {
      const v = p.variants[i];
      if (!v || typeof v !== "object") continue;

      const vName = cleanString(String(v.name || v.id || `variant-${i + 1}`), 60);
      let vPrice = safePrice;
      if (v.price !== undefined && v.price !== null) {
        if (typeof v.price !== "number" || !Number.isFinite(v.price) || v.price <= 0 || v.price > MAX_PRICE_VALUE) {
          return { valid: false, error: `سعر المتغير '${vName}' غير صالح.` };
        }
        vPrice = Math.round(v.price * 100) / 100;
      }

      let vStock = safeStock;
      if (v.stock !== undefined && v.stock !== null) {
        if (typeof v.stock !== "number" || !Number.isInteger(v.stock) || v.stock < 0 || v.stock > MAX_STOCK_VALUE) {
          return { valid: false, error: `مخزون المتغير '${vName}' غير صالح.` };
        }
        vStock = v.stock;
      }

      let vImage = "";
      if (v.image) {
        const vImgCheck = validateSafeImageUrl(String(v.image));
        if (vImgCheck.valid) vImage = vImgCheck.sanitizedUrl;
      }

      safeVariants.push({
        id: cleanString(String(v.id || `var-${i + 1}`), 50).replace(/[^a-zA-Z0-9_\-]/g, "") || `var-${i + 1}`,
        name: vName,
        price: vPrice,
        stock: vStock,
        image: vImage
      });
    }
  }

  // 9. Technical Specifications Object Bounds
  const safeSpecs = {};
  if (p.specs && typeof p.specs === "object" && !Array.isArray(p.specs)) {
    const specEntries = Object.entries(p.specs).slice(0, MAX_PRODUCT_SPECS);
    for (const [sKey, sVal] of specEntries) {
      const cleanKey = cleanString(String(sKey), 50).replace(/[^a-zA-Z0-9_\-\u0600-\u06FF\s]/g, "");
      if (!cleanKey) continue;
      safeSpecs[cleanKey] = cleanString(String(sVal || ""), 200);
    }
  }

  // 10. Tags Array Bounds
  const safeTags = [];
  if (Array.isArray(p.tags)) {
    p.tags.slice(0, MAX_PRODUCT_TAGS).forEach(t => {
      const ct = cleanString(String(t || ""), 50);
      if (ct) safeTags.push(ct);
    });
  }

  // 11. State Flags
  const isActive = p.active !== undefined ? Boolean(p.active) : true;
  let status = "active";
  if (p.status && ["active", "draft", "archived"].includes(String(p.status).toLowerCase())) {
    status = String(p.status).toLowerCase();
  } else {
    status = isActive ? "active" : "draft";
  }

  // 12. ID & Identity Enforcement
  let safeId = "";
  if (p.id) {
    safeId = sanitizePathId(String(p.id));
  }
  if (!safeId) {
    // Generate secure showroom ID
    safeId = "kk-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 7);
  }

  const now = Date.now();
  const safeProduct = {
    id: safeId,
    name: cleanName,
    enName: cleanEnName,
    category: cleanCategory,
    categoryName: cleanCategoryName,
    price: safePrice,
    stock: safeStock,
    image: safeMainImage,
    active: isActive,
    status,
    featured: Boolean(p.featured),
    isNew: Boolean(p.isNew),
    isExclusive: Boolean(p.isExclusive),
    isBestSeller: Boolean(p.isBestSeller),
    updatedAt: now
  };

  // Optional attributes
  if (safeSalePrice !== null) safeProduct.salePrice = safeSalePrice;
  if (safeOriginalPrice !== null) safeProduct.originalPrice = safeOriginalPrice;
  if (safeSecondaryImage) safeProduct.secondaryImage = safeSecondaryImage;
  if (safeImagesGallery.length > 0) safeProduct.images = safeImagesGallery;
  if (safeDescription) safeProduct.description = safeDescription;
  if (safeShortDescription) safeProduct.shortDescription = safeShortDescription;
  if (safeStyle) safeProduct.style = safeStyle;
  if (safeWarranty) safeProduct.warranty = safeWarranty;
  if (safeSku) safeProduct.sku = safeSku;
  if (safeVariants.length > 0) safeProduct.variants = safeVariants;
  if (Object.keys(safeSpecs).length > 0) safeProduct.specs = safeSpecs;
  if (safeTags.length > 0) safeProduct.tags = safeTags;

  // Privileged Admin-Only Fields
  if (safeCostPrice !== null) safeProduct.costPrice = safeCostPrice;
  if (safeSupplier) safeProduct.supplier = safeSupplier;
  if (safeAdminNotes) safeProduct.adminNotes = safeAdminNotes;

  // Soft Delete State Persistence (Relational Integrity)
  if (p.deleted_at) {
    safeProduct.deleted_at = String(p.deleted_at).slice(0, 60);
  }
  if (p.status) {
    safeProduct.status = cleanString(String(p.status), 30);
  }

  if (!isUpdate) {
    safeProduct.createdAt = p.createdAt && typeof p.createdAt === "number" ? p.createdAt : now;
  }

  return { valid: true, product: safeProduct };
}

// -----------------------------------------------------------------------------
// PUBLIC SANITIZATION DTO (Axis 7: Zero Wholesale/Supplier Cost Leakage)
// -----------------------------------------------------------------------------
function sanitizePublicProduct(p) {
  if (!p || typeof p !== "object") return null;
  return Object.freeze({
    id: p.id,
    name: p.name || "",
    enName: p.enName || "",
    category: p.category || "",
    categoryName: p.categoryName || "",
    price: typeof p.price === "number" ? p.price : 0,
    salePrice: typeof p.salePrice === "number" ? p.salePrice : undefined,
    originalPrice: typeof p.originalPrice === "number" ? p.originalPrice : undefined,
    stock: typeof p.stock === "number" ? p.stock : 0,
    inStock: typeof p.stock === "number" ? p.stock > 0 : true,
    image: p.image || "",
    secondaryImage: p.secondaryImage || "",
    images: Array.isArray(p.images) ? p.images : [],
    description: p.description || "",
    shortDescription: p.shortDescription || "",
    style: p.style || "",
    warranty: p.warranty || "5 سنوات ضمان معتمد",
    featured: Boolean(p.featured),
    isNew: Boolean(p.isNew),
    isExclusive: Boolean(p.isExclusive),
    isBestSeller: Boolean(p.isBestSeller),
    specs: (p.specs && typeof p.specs === "object") ? p.specs : {},
    variants: Array.isArray(p.variants) ? p.variants : [],
    tags: Array.isArray(p.tags) ? p.tags : [],
    sku: p.sku || "",
    rating: typeof p.rating === "number" ? p.rating : 5.0,
    reviewsCount: typeof p.reviewsCount === "number" ? p.reviewsCount : 0,
    updatedAt: p.updatedAt || undefined
  });
}

// -----------------------------------------------------------------------------
// CLOUD STORAGE ADAPTERS (Firebase RTDB + Vercel KV Resilience)
// -----------------------------------------------------------------------------
async function bumpSyncMetadata(actionType = "product_update") {
  try {
    const now = Date.now();
    await firebaseFetch(buildSafeRtdbPath("sync_meta", "products"), {
      method: "PUT",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version: now,
        timestamp: now,
        action: actionType
      })
    });
  } catch (e) {}
}

async function fetchProductsFromCloud(req) {
  const t = Date.now();

  // A. Firebase Realtime Database Primary Store
  try {
    const res = await firebaseFetch(buildSafeRtdbPath("products"), {
      cache: "no-store",
      headers: { "Accept": "application/json", "Cache-Control": "no-cache, no-store" }
    }, { t });

    if (res.ok) {
      const raw = await res.json();
      if (raw) {
        if (Array.isArray(raw)) {
          return { products: raw.filter(Boolean), provider: "firebase-rtdb" };
        }
        if (typeof raw === "object") {
          return { products: Object.values(raw).filter(Boolean), provider: "firebase-rtdb" };
        }
      }
      return { products: [], provider: "firebase-rtdb" };
    }
  } catch (err) {
    console.warn("Firebase fetch error:", redactSecretUrl(err.message));
  }

  // B. Vercel KV Fallback
  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  if (kvUrl && kvToken) {
    try {
      const res = await fetch(`${kvUrl}/get/kased_karim_products`, {
        cache: "no-store",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Cache-Control": "no-cache, no-store"
        }
      });
      if (res.ok) {
        const data = await res.json();
        let products = data && data.result;
        if (typeof products === "string") {
          try { products = JSON.parse(products); } catch (e) {}
        }
        if (Array.isArray(products)) {
          return { products, provider: "vercel-kv" };
        }
      }
    } catch (err) {
      console.warn("KV fetch error:", redactSecretUrl(err.message));
    }
  }

  return { products: [], provider: "none" };
}

// -----------------------------------------------------------------------------
// REFERENTIAL INTEGRITY CHECKER (Axis: Relational Integrity & Safe Deletion)
// Verifies whether product has associations in: Orders, Sales, Inventory, Pricelists
// -----------------------------------------------------------------------------
async function checkProductReferentialIntegrity(safeId) {
  const relations = {
    orders: 0,
    sales: 0,
    inventory: 0,
    pricelists: 0,
    hasRelations: false
  };

  try {
    // 1. Scan Orders Collection
    const ordersRes = await firebaseFetch(buildSafeRtdbPath("orders"), {
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });
    if (ordersRes.ok) {
      const ordersData = await ordersRes.json();
      if (ordersData && typeof ordersData === "object") {
        const orderList = Array.isArray(ordersData) ? ordersData : Object.values(ordersData);
        for (const order of orderList) {
          if (!order || !Array.isArray(order.items)) continue;
          const match = order.items.some(it => it && (it.id === safeId || it.productId === safeId));
          if (match) {
            relations.orders++;
            if (order.status === "completed" || order.status === "delivered" || order.status === "paid") {
              relations.sales++;
            }
          }
        }
      }
    }
  } catch (e) {}

  try {
    // 2. Scan Sales / Accounting Ledger
    const salesRes = await firebaseFetch(buildSafeRtdbPath("sales"), {
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });
    if (salesRes.ok) {
      const salesData = await salesRes.json();
      if (salesData && typeof salesData === "object") {
        const salesList = Array.isArray(salesData) ? salesData : Object.values(salesData);
        const matchCount = salesList.filter(s => s && (s.productId === safeId || s.product_id === safeId)).length;
        relations.sales += matchCount;
      }
    }
  } catch (e) {}

  try {
    // 3. Scan Custom Pricelists
    const priceRes = await firebaseFetch(buildSafeRtdbPath("pricelists"), {
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });
    if (priceRes.ok) {
      const priceData = await priceRes.json();
      if (priceData && typeof priceData === "object") {
        const priceList = Array.isArray(priceData) ? priceData : Object.values(priceData);
        for (const pl of priceList) {
          if (pl && Array.isArray(pl.items) && pl.items.some(it => it && (it.productId === safeId || it.id === safeId))) {
            relations.pricelists++;
          }
        }
      }
    }
  } catch (e) {}

  try {
    // 4. Scan Inventory Stock Ledger
    const invRes = await firebaseFetch(buildSafeRtdbPath("inventory", safeId), {
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });
    if (invRes.ok) {
      const invData = await invRes.json();
      if (invData && (invData.quantity_on_hand > 0 || invData.stock > 0 || invData.quantity_reserved > 0)) {
        relations.inventory = 1;
      }
    }
  } catch (e) {}

  relations.hasRelations = (relations.orders > 0 || relations.sales > 0 || relations.inventory > 0 || relations.pricelists > 0);
  return relations;
}

// =============================================================================
// MAIN REQUEST ROUTER & CONTROLLER
// =============================================================================
async function productsHandler(req, res, { requestId, safeBody } = {}) {
  // 1. Mandatory CORS & Security Headers Gate (Axis 8: ASVS 14.4 & 14.5)
  if (setSecurityHeaders(req, res)) return;

  try {
    // -------------------------------------------------------------------------
    // 1. GET / HEAD: Fetch Products (Separated Public Storefront vs Admin Catalog)
    // -------------------------------------------------------------------------
    if (req.method === "GET" || req.method === "HEAD") {
      // Sliding Window Rate Limiting for Public Catalog (60 requests per minute per IP)
      const allowed = await enforceRateLimit(req, res, "read");
      if (!allowed) return;
      const { all, includeInactive, include_deleted, includeDeleted, id } = req.query || {};
      const isAdminQuery = all === "1" || all === "true" || includeInactive === "1" || includeInactive === "true";
      const shouldIncludeDeleted = include_deleted === "1" || include_deleted === "true" || includeDeleted === "1" || includeDeleted === "true";

      // Detect credentials / session tokens (Web Cache Deception Defense)
      const rawCookie = req.headers?.cookie || req.headers?.Cookie || "";
      const rawAuth = req.headers?.authorization || req.headers?.Authorization || "";
      const rawAdminToken = req.headers?.["x-admin-token"] || req.headers?.["X-Admin-Token"] || "";
      const rawCustomerToken = req.headers?.["x-customer-token"] || req.headers?.["X-Customer-Token"] || "";
      const hasAuth = Boolean(rawCookie || rawAuth || rawAdminToken || rawCustomerToken);

      // Privilege Verification for Admin Reads (Axis 1 & 7)
      let isAdmin = false;
      if (isAdminQuery || shouldIncludeDeleted) {
        const admin = verifyAdminRequest(req);
        if (!admin) {
          res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
          res.setHeader("CDN-Cache-Control", "no-store");
          res.setHeader("Vercel-CDN-Cache-Control", "no-store");
          res.setHeader("Pragma", "no-cache");
          res.setHeader("Expires", "0");
          return res.status(401).json({
            success: false,
            error: "غير مصرح بالوصول. استعراض المنتجات المحذوفة أو بيانات التكلفة يتطلب صلاحيات الإدارة العليا."
          });
        }
        isAdmin = true;
      }

      const { products, provider } = await fetchProductsFromCloud(req);

      // Single Product Lookup by ID
      if (id) {
        const cleanId = sanitizePathId(String(id));
        const found = products.find(p => p && p.id === cleanId);
        if (!found) {
          res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
          res.setHeader("CDN-Cache-Control", "no-store");
          res.setHeader("Vercel-CDN-Cache-Control", "no-store");
          return res.status(404).json({ success: false, error: "لم يتم العثور على المنتج المطلوب." });
        }

        // Soft-deleted product check
        const isSoftDeleted = Boolean(found.deleted_at || found.deleted === true);
        if (isSoftDeleted && !shouldIncludeDeleted) {
          res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
          res.setHeader("CDN-Cache-Control", "no-store");
          res.setHeader("Vercel-CDN-Cache-Control", "no-store");
          return res.status(404).json({ success: false, error: "عفواً، هذا المنتج غير متوفر حالياً (تمت أرشفته أو حذفه)." });
        }

        // Public visitor looking at inactive product
        if (!isAdmin && (found.active === false || found.hidden === true || found.status === "draft" || found.status === "archived" || isSoftDeleted)) {
          res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
          res.setHeader("CDN-Cache-Control", "no-store");
          res.setHeader("Vercel-CDN-Cache-Control", "no-store");
          return res.status(404).json({ success: false, error: "عفواً، هذا المنتج غير متوفر حالياً." });
        }

        const isPublicCacheable = req.method === "GET" && !isAdmin && !isAdminQuery && !shouldIncludeDeleted && !hasAuth;
        const outProduct = isAdmin ? found : sanitizePublicProduct(found);
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
        return res.status(200).json({ success: true, product: outProduct, provider });
      }

      // Catalog List Response for Admin
      if (isAdmin) {
        const filteredProducts = shouldIncludeDeleted
          ? products
          : products.filter(p => p && !p.deleted_at && p.deleted !== true);

        // Enforce pagination bound (max 50 items)
        const rawPage = parseInt(req.query?.page || "1", 10);
        const rawLimit = parseInt(req.query?.limit || "50", 10);
        const page = Number.isInteger(rawPage) && rawPage >= 1 ? rawPage : 1;
        const limit = Number.isInteger(rawLimit) && rawLimit >= 1 ? Math.min(rawLimit, 50) : 50;
        const total = filteredProducts.length;
        const totalPages = Math.ceil(total / limit) || 1;
        const startIndex = (page - 1) * limit;
        const paginatedProducts = filteredProducts.slice(startIndex, startIndex + limit);

        // Enforce anti-caching so CDNs never store admin catalogs (Axis 7: Cache Poisoning Defense)
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
        res.setHeader("CDN-Cache-Control", "no-store");
        res.setHeader("Vercel-CDN-Cache-Control", "no-store");
        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");
        res.setHeader("Vary", "Cookie, Authorization");
        return res.status(200).json({
          success: true,
          adminView: true,
          count: paginatedProducts.length,
          total,
          page,
          limit,
          totalPages,
          provider,
          products: paginatedProducts
        });
      }

      // Public Storefront: Strict Soft Delete Exemption & Active Products Only (Axis 7)
      const publicProducts = products
        .filter(p => p && p.active !== false && p.hidden !== true && p.status !== "draft" && p.status !== "archived" && !p.deleted_at && p.deleted !== true)
        .map(sanitizePublicProduct)
        .filter(Boolean);

      // Enforce pagination bound (max 50 items)
      const rawPage = parseInt(req.query?.page || "1", 10);
      const rawLimit = parseInt(req.query?.limit || "50", 10);
      const page = Number.isInteger(rawPage) && rawPage >= 1 ? rawPage : 1;
      const limit = Number.isInteger(rawLimit) && rawLimit >= 1 ? Math.min(rawLimit, 50) : 50;
      const total = publicProducts.length;
      const totalPages = Math.ceil(total / limit) || 1;
      const startIndex = (page - 1) * limit;
      const paginatedProducts = publicProducts.slice(startIndex, startIndex + limit);

      const isPublicCacheable = req.method === "GET" && !isAdmin && !isAdminQuery && !shouldIncludeDeleted && !hasAuth;
      if (isPublicCacheable) {
        // Edge Caching: 5 minutes cache, 10 minutes stale-while-revalidate
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

      return res.status(200).json({
        success: true,
        count: paginatedProducts.length,
        total,
        page,
        limit,
        totalPages,
        provider,
        products: paginatedProducts
      });
    }

    // -------------------------------------------------------------------------
    // MUTATION PRE-FLIGHT: Strict BFLA Check on POST, PUT, PATCH, DELETE (Axis 1)
    // -------------------------------------------------------------------------
    const admin = verifyAdminRequest(req);
    if (!admin) {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
      return res.status(401).json({
        success: false,
        error: "غير مصرح بالوصول. يلزم توفير صلاحيات الإدارة العليا لتعديل أو حذف أو إضافة عناصر الكتالوج."
      });
    }

    // -------------------------------------------------------------------------
    // 2. POST: Add Single Product (ADMIN ONLY)
    // -------------------------------------------------------------------------
    if (req.method === "POST") {
      let body = req.body;
      if (typeof body === "string") {
        if (body.length > MAX_SINGLE_PAYLOAD_SIZE) {
          return res.status(413).json({ success: false, error: "حجم الطلب يتجاوز الحد المسموح به (50 كيلوبايت)." });
        }
        try { body = JSON.parse(body); } catch (e) {
          return res.status(400).json({ success: false, error: "صيغة البيانات (JSON) غير صالحة." });
        }
      }

      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return res.status(400).json({ success: false, error: "إضافة منتج يتطلب إرسال كائن منتج مفرد (المصفوفات تستخدم PUT للعمليات الجماعية)." });
      }

      const valResult = validateAndSanitizeProduct(body, { isUpdate: false });
      if (!valResult.valid) {
        return res.status(400).json({ success: false, error: valResult.error });
      }

      const safeProduct = valResult.product;
      const safeId = safeProduct.id;

      assertSafeRtdbPayload(safeProduct);

      const putRes = await firebaseFetch(buildSafeRtdbPath("products", safeId), {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(safeProduct)
      });

      if (!putRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر حفظ المنتج على السحابة المركزية." });
      }

      await bumpSyncMetadata("product_create");
      return res.status(201).json({
        success: true,
        message: "تم إنشاء وحفظ المنتج بنجاح في الكتالوج.",
        product: safeProduct
      });
    }

    // -------------------------------------------------------------------------
    // 3. PUT: Bulk Overwrite OR Single Product Replace (ADMIN ONLY - Axis 1 & 3)
    // -------------------------------------------------------------------------
    if (req.method === "PUT") {
      const contentLength = parseInt(req.headers["content-length"] || "0", 10);
      if (contentLength > MAX_BULK_PAYLOAD_SIZE) {
        return res.status(413).json({ success: false, error: "حجم البيانات يتجاوز السقف الأقصى المسموح به (2 ميجابايت)." });
      }

      let payload = req.body;
      if (typeof payload === "string") {
        try { payload = JSON.parse(payload); } catch (e) {
          return res.status(400).json({ success: false, error: "صيغة البيانات (JSON) غير صالحة." });
        }
      }

      if (!payload || typeof payload !== "object") {
        return res.status(400).json({ success: false, error: "بيانات الطلب فارغة أو غير صالحة." });
      }

      // SUB-CASE A: BULK CATALOG OVERWRITE (Axis 1: Catastrophic Overwrite Defense)
      const isBulk = Array.isArray(payload) || (payload.products && Array.isArray(payload.products));
      if (isBulk) {
        const productList = Array.isArray(payload) ? payload : payload.products;
        const confirmHeader = req.headers["x-destructive-confirm"];

        // Step-Up Confirmation Requirement
        if (confirmHeader !== "CONFIRM_BULK_PRODUCTS_OVERWRITE" && confirmHeader !== "CONFIRM_RESTORE_PRODUCTS_PERMANENT") {
          return res.status(400).json({
            success: false,
            error: "إجراء خطير: استبدال كتالوج المنتجات بالكامل يتطلب ترويسة التأكيد الإداري المزدوجة 'x-destructive-confirm: CONFIRM_BULK_PRODUCTS_OVERWRITE'."
          });
        }

        // Empty catalog wipe guard
        if (productList.length === 0) {
          if (confirmHeader !== "CONFIRM_EMPTY_PRODUCTS_CATALOG") {
            return res.status(400).json({
              success: false,
              error: "تفريغ الكتالوج بالكامل يتطلب ترويسة تأكيد خاصة: 'x-destructive-confirm: CONFIRM_EMPTY_PRODUCTS_CATALOG'."
            });
          }
        }

        if (productList.length > MAX_BULK_PRODUCTS_COUNT) {
          return res.status(400).json({
            success: false,
            error: `عدد المنتجات في الدفعة يتجاوز السقف الأقصى المسموح به (${MAX_BULK_PRODUCTS_COUNT} منتج).`
          });
        }

        // All-or-Nothing 100% Validation before writing any single byte (Axis 1)
        const validatedMap = {};
        const seenIds = new Set();

        for (let i = 0; i < productList.length; i++) {
          const rawItem = productList[i];
          const valRes = validateAndSanitizeProduct(rawItem, { isUpdate: true });
          if (!valRes.valid) {
            return res.status(400).json({
              success: false,
              error: `فشل التحقق من المنتج رقم ${i + 1} (${cleanString(String(rawItem?.name || rawItem?.id || 'غير معرّف'), 60)}): ${valRes.error}. تم إلغاء العملية بالكامل دون المساس بالكتالوج.`
            });
          }

          const cleanItem = valRes.product;
          if (seenIds.has(cleanItem.id)) {
            return res.status(400).json({
              success: false,
              error: `تكرار في معرف المنتج '${cleanItem.id}' داخل الدفعة المرسلة.`
            });
          }
          seenIds.add(cleanItem.id);
          validatedMap[cleanItem.id] = cleanItem;
        }

        assertSafeRtdbPayload(validatedMap);

        const rtdbRes = await firebaseFetch(buildSafeRtdbPath("products"), {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(validatedMap)
        });

        if (!rtdbRes.ok) {
          return res.status(502).json({ success: false, error: "تعذر حفظ دفعة المنتجات على السحابة المركزية." });
        }

        await bumpSyncMetadata("batch_catalog_overwrite");
        return res.status(200).json({
          success: true,
          count: Object.keys(validatedMap).length,
          message: `تم تحديث واستبدال الكتالوج بنجاح (${Object.keys(validatedMap).length} منتج موثق ومطابق للمواصفات).`
        });
      }

      // SUB-CASE B: SINGLE PRODUCT REPLACE
      const rawId = req.query?.id || payload.id;
      const safeId = sanitizePathId(String(rawId || ""));
      if (!safeId) {
        return res.status(400).json({ success: false, error: "معرف المنتج مطلوب لاستبدال بيانات المنتج." });
      }

      const valResult = validateAndSanitizeProduct({ ...payload, id: safeId }, { isUpdate: true });
      if (!valResult.valid) {
        return res.status(400).json({ success: false, error: valResult.error });
      }

      const cleanProduct = valResult.product;
      assertSafeRtdbPayload(cleanProduct);

      const putRes = await firebaseFetch(buildSafeRtdbPath("products", safeId), {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(cleanProduct)
      });

      if (!putRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر تحديث المنتج على السحابة." });
      }

      await bumpSyncMetadata("product_update");
      return res.status(200).json({ success: true, product: cleanProduct });
    }

    // -------------------------------------------------------------------------
    // 4. PATCH: Partial Product Updates (ADMIN ONLY - Axis 1 & 6)
    // -------------------------------------------------------------------------
    if (req.method === "PATCH") {
      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {
          return res.status(400).json({ success: false, error: "صيغة البيانات (JSON) غير صالحة." });
        }
      }

      if (!body || typeof body !== "object" || Array.isArray(body)) {
        return res.status(400).json({ success: false, error: "بيانات التعديل الجزئي غير صالحة." });
      }

      const rawId = req.query?.id || body.id;
      const safeId = sanitizePathId(String(rawId || ""));
      if (!safeId) {
        return res.status(400).json({ success: false, error: "معرف المنتج مطلوب للتعديل الجزئي." });
      }

      // Build strictly sanitized patch object
      const patchData = { updatedAt: Date.now() };

      if (body.name !== undefined) {
        const cn = cleanString(String(body.name), 150);
        if (!cn || cn.length < 2) return res.status(400).json({ success: false, error: "اسم المنتج غير صالح." });
        patchData.name = cn;
      }

      if (body.price !== undefined) {
        if (typeof body.price !== "number" || !Number.isFinite(body.price) || body.price <= 0 || body.price > MAX_PRICE_VALUE) {
          return res.status(400).json({ success: false, error: "سعر المنتج يجب أن يكون رقماً موجباً حقيقياً." });
        }
        patchData.price = Math.round(body.price * 100) / 100;
      }

      if (body.stock !== undefined) {
        if (typeof body.stock !== "number" || !Number.isInteger(body.stock) || body.stock < 0 || body.stock > MAX_STOCK_VALUE) {
          return res.status(400).json({ success: false, error: "كمية المخزون يجب أن تكون رقماً صحيحاً غير سالب." });
        }
        patchData.stock = body.stock;
      }

      if (body.active !== undefined) {
        patchData.active = Boolean(body.active);
      }

      if (body.featured !== undefined) {
        patchData.featured = Boolean(body.featured);
      }

      if (body.image !== undefined) {
        if (body.image) {
          const imgCheck = validateSafeImageUrl(String(body.image));
          if (!imgCheck.valid) return res.status(400).json({ success: false, error: imgCheck.error });
          patchData.image = imgCheck.sanitizedUrl;
        } else {
          patchData.image = "";
        }
      }

      if (body.secondaryImage !== undefined) {
        if (body.secondaryImage) {
          const secCheck = validateSafeImageUrl(String(body.secondaryImage));
          if (!secCheck.valid) return res.status(400).json({ success: false, error: secCheck.error });
          patchData.secondaryImage = secCheck.sanitizedUrl;
        } else {
          patchData.secondaryImage = "";
        }
      }

      if (body.description !== undefined) {
        patchData.description = cleanString(String(body.description), 5000);
      }

      if (body.shortDescription !== undefined) {
        patchData.shortDescription = cleanString(String(body.shortDescription), 400);
      }

      if (body.category !== undefined) {
        const cc = String(body.category).trim().replace(/[^a-zA-Z0-9_\-\u0600-\u06FF]/g, "").slice(0, 60);
        if (cc.length >= 2) patchData.category = cc;
      }

      if (body.adminNotes !== undefined) {
        patchData.adminNotes = cleanString(String(body.adminNotes), 1000);
      }

      if (body.costPrice !== undefined) {
        if (typeof body.costPrice === "number" && Number.isFinite(body.costPrice) && body.costPrice >= 0) {
          patchData.costPrice = Math.round(body.costPrice * 100) / 100;
        }
      }

      assertSafeRtdbPayload(patchData, {
        allowedKeys: [
          "name", "price", "stock", "active", "featured", "image", "secondaryImage",
          "description", "shortDescription", "category", "adminNotes", "costPrice", "updatedAt",
          "deleted_at", "status"
        ]
      });

      const patchRes = await firebaseFetch(buildSafeRtdbPath("products", safeId), {
        method: "PATCH",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patchData)
      });

      if (!patchRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر تحديث بيانات المنتج على السحابة." });
      }

      await bumpSyncMetadata("product_patch");
      return res.status(200).json({ success: true, id: safeId, patch: patchData });
    }

    // -------------------------------------------------------------------------
    // 5. DELETE: Safe Deletion Engine (Relational Integrity Check + Soft Delete)
    // -------------------------------------------------------------------------
    if (req.method === "DELETE") {
      const rawId = req.query?.id || (req.body && typeof req.body === "object" ? req.body.id : null);
      const isForceHard = req.query?.force_hard === "1" || req.query?.force_hard === "true" || (req.body && req.body.forceHard === true);

      // Strict Type & Non-Empty Check
      if (typeof rawId !== "string" || !rawId.trim()) {
        return res.status(400).json({
          success: false,
          error: "معرف المنتج مطلوب لحذف عنصر محدد. يمنع منعاً باتاً مسح الكتالوج كاملاً عبر DELETE."
        });
      }

      const safeId = sanitizePathId(rawId);
      if (!safeId || safeId === "products" || safeId === "." || safeId === ".." || safeId.includes("/")) {
        return res.status(400).json({ success: false, error: "معرف المنتج غير صالح أمنياً." });
      }

      // 1. Fetch current product to verify existence
      const targetRes = await firebaseFetch(buildSafeRtdbPath("products", safeId), { cache: "no-store" });
      if (!targetRes.ok) {
        return res.status(404).json({ success: false, error: "المنتج المطلوب حذفه غير موجود في الكتالوج." });
      }
      const existingProduct = await targetRes.json();
      if (!existingProduct) {
        return res.status(404).json({ success: false, error: "المنتج المطلوب حذفه غير موجود." });
      }

      // 2. Strict Referential Integrity Check across Orders, Sales, Inventory, and Pricelists
      const integrity = await checkProductReferentialIntegrity(safeId);
      const nowIso = new Date().toISOString();

      // Rule: If associations exist, HARD DELETE is strictly forbidden (Referential Protection)
      if (integrity.hasRelations) {
        if (isForceHard) {
          return res.status(409).json({
            success: false,
            error: "لا يمكن الحذف النهائي (Hard Delete) لهذا المنتج نظراً لوجود سجلات مرتبطة به في (الطلبات، المبيعات، المخزون، أو قوائم الأسعار). تم الحفاظ على البيانات لتفادي كسر التكامل المرجعي.",
            relations: integrity
          });
        }

        // Apply Soft Delete (حفظ المنتج وتسجيل تاريخ الحذف وحجبه من المتجر)
        const softDeletePayload = {
          deleted_at: nowIso,
          active: false,
          status: "archived",
          updatedAt: Date.now()
        };

        const patchRes = await firebaseFetch(buildSafeRtdbPath("products", safeId), {
          method: "PATCH",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(softDeletePayload)
        });

        if (!patchRes.ok) {
          return res.status(502).json({ success: false, error: "تعذر تحديث حالة الحذف اللطيف للمنتج على السحابة." });
        }

        await bumpSyncMetadata("product_soft_delete");
        return res.status(200).json({
          success: true,
          softDeleted: true,
          id: safeId,
          deleted_at: nowIso,
          message: "تم تنفيذ الحذف اللطيف (Soft Delete) بنجاح. المنتج محفوظ تاريخياً ومحاسبياً وتم استثناؤه من المتجر.",
          relations: integrity
        });
      }

      // 3. No Relations Found: Allow hard delete only if explicitly requested, otherwise Soft Delete
      if (isForceHard) {
        const delRes = await firebaseFetch(buildSafeRtdbPath("products", safeId), {
          method: "DELETE",
          cache: "no-store"
        });

        if (!delRes.ok) {
          return res.status(502).json({ success: false, error: "تعذر حذف المنتج من السحابة المركزية." });
        }

        await bumpSyncMetadata("product_hard_delete");
        return res.status(200).json({
          success: true,
          hardDeleted: true,
          id: safeId,
          message: "تم حذف المنتج نهائياً من الكتالوج (Hard Delete) لعدم وجود أي ارتباطات له."
        });
      }

      // Standard Default Action: Soft Delete
      const softDeletePayload = {
        deleted_at: nowIso,
        active: false,
        status: "archived",
        updatedAt: Date.now()
      };

      const patchRes = await firebaseFetch(buildSafeRtdbPath("products", safeId), {
        method: "PATCH",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(softDeletePayload)
      });

      if (!patchRes.ok) {
        return res.status(502).json({ success: false, error: "تعذر تحديث حالة الحذف اللطيف للمنتج على السحابة." });
      }

      await bumpSyncMetadata("product_soft_delete");
      return res.status(200).json({
        success: true,
        softDeleted: true,
        id: safeId,
        deleted_at: nowIso,
        message: "تم تنفيذ الحذف اللطيف (Soft Delete) بنجاح. تم حفظ المنتج وأرشفته مع إخفائه من المتجر."
      });
    }

    return res.status(405).json({ success: false, error: "طريقة الطلب غير مسموح بها (Method Not Allowed)." });
  } catch (err) {
    safeLogError("/api/products", requestId, err);
    return res.status(500).json({
      success: false,
      ok: false,
      error: "حدث خطأ غير متوقع في معالجة طلبات الكتالوج والمنتجات.",
      requestId
    });
  }
}

export default withApiHardening(productsHandler, {
  allowedMethods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
  maxBodyBytes: 2 * 1024 * 1024,
  maxDepth: 6,
  maxKeys: 10000,
  isArrayAllowed: true,
  context: "/api/products"
});
