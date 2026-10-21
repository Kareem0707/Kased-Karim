// Vercel Serverless Function: /api/products
// Handles High-Performance Multi-Device Products Catalog Persistence
// Supports Firebase Realtime Database (Google Cloud) & Vercel KV / Upstash Redis

export const dynamic = "force-dynamic";
export const revalidate = 0;

// Resolve Cloud Database Endpoint
function getFirebaseUrl(req) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) {
    return envUrl.trim().replace(/\/$/, "");
  }
  const headerUrl = req && (req.headers["x-cloud-db-url"] || req.headers["x-firebase-url"]);
  if (headerUrl && typeof headerUrl === "string" && headerUrl.startsWith("http")) {
    return headerUrl.trim().replace(/\/$/, "");
  }
  return null;
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

// 2. Save Product to Cloud
async function saveProductToCloud(req, product) {
  const firebaseUrl = getFirebaseUrl(req);

  // A. Firebase Realtime Database (Direct Keyed Save)
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
        return { success: true, provider: "firebase-rtdb" };
      }
    } catch (err) {
      console.warn("Firebase save error:", err.message);
    }
  }

  // B. Vercel KV / Upstash Redis
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

// 3. Delete Product from Cloud
async function deleteProductFromCloud(req, productId) {
  const firebaseUrl = getFirebaseUrl(req);

  if (firebaseUrl) {
    try {
      const safeId = encodeURIComponent(productId);
      await fetch(`${firebaseUrl}/products/${safeId}.json`, {
        method: "DELETE",
        cache: "no-store"
      });
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
  // Ultra-Strict Anti-Caching Headers for instant real-time sync across devices
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
  res.setHeader("CDN-Cache-Control", "no-store");
  res.setHeader("Vercel-CDN-Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-Control", "no-store");

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Cache-Control, Pragma, x-cloud-db-url, x-firebase-url");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    // 1. GET: Fetch products across all devices
    if (req.method === "GET") {
      const { products, provider } = await fetchProductsFromCloud(req);
      return res.status(200).json({
        success: true,
        count: products.length,
        provider,
        products
      });
    }

    // 2. POST / PUT: Add or update product
    if (req.method === "POST" || req.method === "PUT") {
      let product = req.body;
      if (typeof product === "string") {
        try { product = JSON.parse(product); } catch (e) {}
      }

      if (!product || !product.name) {
        return res.status(400).json({ error: "بيانات المنتج غير مكتملة" });
      }

      if (!product.id) {
        product.id = "kk-" + Date.now().toString().slice(-5);
      }

      const saveResult = await saveProductToCloud(req, product);
      return res.status(201).json({
        success: true,
        persistedToCloud: saveResult.success,
        provider: saveResult.provider,
        product
      });
    }

    // 3. DELETE: Remove product from catalog
    if (req.method === "DELETE") {
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
