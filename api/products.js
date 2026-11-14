// Vercel Serverless Function: /api/products
// Handles High-Performance Multi-Device Products Catalog Persistence & Real-Time Sync
// Protected with Server-Side Authorization for Mutations (POST, PUT, DELETE)

import { verifyAdminRequest } from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Resolve Cloud Database Endpoint
function getFirebaseUrl(req) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) {
    return envUrl.trim().replace(/\/$/, "");
  }
  return "https://kased-karim-default-rtdb.firebaseio.com";
}

// Update Global Sync Metadata
async function bumpSyncMetadata(firebaseUrl, actionType = "product_update") {
  if (!firebaseUrl) return;
  try {
    const now = Date.now();
    await fetch(`${firebaseUrl}/sync_meta.json`, {
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

// 1. Fetch Products from Cloud
async function fetchProductsFromCloud(req) {
  const t = Date.now();
  const firebaseUrl = getFirebaseUrl(req);

  // A. Firebase Realtime Database
  if (firebaseUrl) {
    try {
      const res = await fetch(`${firebaseUrl}/products.json?t=${t}`, {
        cache: "no-store",
        headers: { "Accept": "application/json", "Cache-Control": "no-cache, no-store" }
      });
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
      console.warn("Firebase fetch error:", err.message);
    }
  }

  // B. Vercel KV / Upstash Redis
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
      console.warn("KV fetch error:", err.message);
    }
  }

  return { products: [], provider: "none" };
}

// 2. Batch Save/Overwrite All Products to Cloud
async function saveBatchProductsToCloud(req, productList) {
  const firebaseUrl = getFirebaseUrl(req);
  let saved = false;
  let provider = "none";

  if (firebaseUrl) {
    try {
      const prodMap = {};
      productList.forEach(p => {
        if (p && p.id) {
          prodMap[p.id] = p;
        }
      });

      const res = await fetch(`${firebaseUrl}/products.json`, {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(prodMap)
      });
      if (res.ok) {
        saved = true;
        provider = "firebase-rtdb";
      }
    } catch (err) {
      console.warn("Firebase batch products error:", err.message);
    }
  }

  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  if (kvUrl && kvToken) {
    try {
      await fetch(`${kvUrl}/set/kased_karim_products`, {
        method: "POST",
        cache: "no-store",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(productList)
      });
      saved = true;
      provider = "vercel-kv";
    } catch (err) {}
  }

  if (saved) {
    await bumpSyncMetadata(firebaseUrl, "batch_catalog_overwrite");
  }

  return { success: saved, provider };
}

// 3. Save Single Product to Cloud
async function saveProductToCloud(req, product) {
  const firebaseUrl = getFirebaseUrl(req);

  if (firebaseUrl) {
    try {
      const safeId = encodeURIComponent(product.id);
      const res = await fetch(`${firebaseUrl}/products/${safeId}.json`, {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(product)
      });
      if (res.ok) {
        await bumpSyncMetadata(firebaseUrl, "product_save");
        return { success: true, provider: "firebase-rtdb" };
      }
    } catch (err) {
      console.warn("Firebase save error:", err.message);
    }
  }

  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  if (kvUrl && kvToken) {
    try {
      const { products } = await fetchProductsFromCloud(req);
      const idx = products.findIndex(p => p.id === product.id);
      if (idx > -1) {
        products[idx] = product;
      } else {
        products.unshift(product);
      }
      const res = await fetch(`${kvUrl}/set/kased_karim_products`, {
        method: "POST",
        cache: "no-store",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(products)
      });
      if (res.ok) {
        return { success: true, provider: "vercel-kv" };
      }
    } catch (err) {
      console.warn("KV save error:", err.message);
    }
  }

  return { success: false, provider: "none" };
}

// 4. Delete Product from Cloud
async function deleteProductFromCloud(req, productId) {
  const firebaseUrl = getFirebaseUrl(req);

  if (firebaseUrl) {
    try {
      const safeId = encodeURIComponent(productId);
      await fetch(`${firebaseUrl}/products/${safeId}.json`, {
        method: "DELETE",
        cache: "no-store"
      });
      await bumpSyncMetadata(firebaseUrl, "product_delete");
      return { success: true, provider: "firebase-rtdb" };
    } catch (err) {
      console.warn("Firebase delete error:", err.message);
    }
  }

  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;
  if (kvUrl && kvToken) {
    try {
      const { products } = await fetchProductsFromCloud(req);
      const filtered = products.filter(p => p.id !== productId);
      await fetch(`${kvUrl}/set/kased_karim_products`, {
        method: "POST",
        cache: "no-store",
        headers: {
          "Authorization": `Bearer ${kvToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(filtered)
      });
      return { success: true, provider: "vercel-kv" };
    } catch (err) {
      console.warn("KV delete error:", err.message);
    }
  }

  return { success: false, provider: "none" };
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
  res.setHeader("CDN-Cache-Control", "no-store");
  res.setHeader("Vercel-CDN-Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-Control", "no-store");

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin-token, Cache-Control, Pragma");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    // 1. GET: Fetch products across all devices (Public Storefront Read)
    if (req.method === "GET") {
      const { products, provider } = await fetchProductsFromCloud(req);
      return res.status(200).json({
        success: true,
        count: products.length,
        provider,
        products
      });
    }

    // 2. POST / PUT: Add, update or batch-overwrite products (ADMIN-ONLY ACCESS REQUIREMENT)
    if (req.method === "POST" || req.method === "PUT") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لإضافة أو تعديل المنتجات." });
      }

      let payload = req.body;
      if (typeof payload === "string") {
        try { payload = JSON.parse(payload); } catch (e) {}
      }

      if (!payload) {
        return res.status(400).json({ error: "بيانات الطلب فارغة" });
      }

      // CASE A: BATCH CATALOG REPLACEMENT / RESTORE OVERWRITE
      if (Array.isArray(payload) || (payload.products && Array.isArray(payload.products))) {
        const productList = Array.isArray(payload) ? payload : payload.products;
        const batchResult = await saveBatchProductsToCloud(req, productList);
        return res.status(200).json({
          success: batchResult.success,
          batch: true,
          count: productList.length,
          provider: batchResult.provider
        });
      }

      // CASE B: SINGLE PRODUCT SAVE / UPDATE
      const product = payload;
      if (!product || !product.name) {
        return res.status(400).json({ error: "بيانات المنتج غير مكتملة" });
      }

      if (!product.id) {
        product.id = "kk-" + Date.now().toString().slice(-6);
      }

      const saveResult = await saveProductToCloud(req, product);
      return res.status(201).json({
        success: true,
        persistedToCloud: saveResult.success,
        provider: saveResult.provider,
        product
      });
    }

    // 3. DELETE: Remove product from catalog (ADMIN-ONLY ACCESS REQUIREMENT)
    if (req.method === "DELETE") {
      const admin = verifyAdminRequest(req);
      if (!admin) {
        return res.status(401).json({ success: false, error: "غير مصرح بالوصول. يلزم صلاحيات الإدارة لحذف المنتجات." });
      }

      const { id } = req.query || {};
      if (!id) return res.status(400).json({ error: "Missing product ID" });

      const delResult = await deleteProductFromCloud(req, id);
      return res.status(200).json({
        success: true,
        persistedToCloud: delResult.success,
        deleted: id
      });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error("API Error in /api/products:", err);
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
