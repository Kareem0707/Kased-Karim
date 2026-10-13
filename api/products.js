// Vercel Serverless Function: /api/products
// Handles Products Catalog Persistence across devices
// Strictly disables all caching across Vercel Edge, Browser, and CDNs

export const dynamic = "force-dynamic";
export const revalidate = 0;

const CLOUD_BINS = [
  "https://extendsclass.com/api/json-storage/bin/faabcdf",
  "https://extendsclass.com/api/json-storage/bin/fdeedbd"
];

async function fetchFromBins() {
  const t = Date.now();
  for (const binUrl of CLOUD_BINS) {
    try {
      const res = await fetch(`${binUrl}?t=${t}`, {
        cache: "no-store",
        headers: {
          "Accept": "application/json",
          "Cache-Control": "no-cache, no-store",
          "Pragma": "no-cache"
        }
      });
      if (res.ok) {
        const data = await res.json();
        if (data && Array.isArray(data.products)) {
          return { data, activeBin: binUrl };
        }
      }
    } catch (e) {}
  }
  return { data: { orders: [], products: [] }, activeBin: CLOUD_BINS[0] };
}

async function saveToBins(binData) {
  const jsonStr = JSON.stringify(binData);
  const promises = CLOUD_BINS.map(binUrl =>
    fetch(binUrl, {
      method: "PUT",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache, no-store"
      },
      body: jsonStr
    }).catch(err => console.warn("Save bin err:", err.message))
  );
  await Promise.allSettled(promises);
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
  res.setHeader("CDN-Cache-Control", "no-store");
  res.setHeader("Vercel-CDN-Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-Control", "no-store");

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Cache-Control, Pragma");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    // 1. GET: Fetch products
    if (req.method === "GET") {
      const { data } = await fetchFromBins();
      const products = Array.isArray(data.products) ? data.products : [];
      return res.status(200).json({ success: true, count: products.length, products });
    }

    // 2. POST: Add or update product
    if (req.method === "POST") {
      let product = req.body;
      if (typeof product === "string") {
        try { product = JSON.parse(product); } catch (e) {}
      }

      if (!product || !product.name) {
        return res.status(400).json({ error: "Invalid product data" });
      }

      if (!product.id) {
        product.id = "kk-cloud-" + Date.now();
      }

      const { data } = await fetchFromBins();
      if (!Array.isArray(data.products)) data.products = [];

      const idx = data.products.findIndex(p => p.id === product.id);
      if (idx > -1) {
        data.products[idx] = { ...data.products[idx], ...product };
      } else {
        data.products.unshift(product);
      }

      await saveToBins(data);
      return res.status(201).json({ success: true, product });
    }

    // 3. DELETE: Delete product
    if (req.method === "DELETE") {
      const { id } = req.query || {};
      if (!id) return res.status(400).json({ error: "Missing product ID" });

      const { data } = await fetchFromBins();
      if (Array.isArray(data.products)) {
        data.products = data.products.filter(p => p.id !== id);
        await saveToBins(data);
      }

      return res.status(200).json({ success: true, deleted: id });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error("API Error in /api/products:", err);
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
