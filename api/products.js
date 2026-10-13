// Vercel Serverless Function: /api/products
// Handles Products Catalog Persistence for Kased Karim Lighting Showroom

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const KV_URL = process.env.KV_REST_API_URL;
  const KV_TOKEN = process.env.KV_REST_API_TOKEN;
  const FIREBASE_URL = process.env.FIREBASE_DB_URL || "https://kased-karim-zayed-default-rtdb.firebaseio.com";

  try {
    // 1. GET: Fetch products
    if (req.method === "GET") {
      let products = [];

      if (KV_URL && KV_TOKEN) {
        const kvRes = await fetch(`${KV_URL}/get/products`, {
          headers: { Authorization: `Bearer ${KV_TOKEN}` }
        });
        const kvData = await kvRes.json();
        products = kvData.result ? (typeof kvData.result === "string" ? JSON.parse(kvData.result) : kvData.result) : [];
      } else if (FIREBASE_URL) {
        try {
          const fbRes = await fetch(`${FIREBASE_URL}/products.json`);
          if (fbRes.ok) {
            const fbData = await fbRes.json();
            if (fbData) {
              products = Object.keys(fbData).map(k => ({ ...fbData[k], _fbKey: k }));
            }
          }
        } catch (e) {
          console.warn("Firebase fetch fallback:", e.message);
        }
      }

      return res.status(200).json({ success: true, count: products.length, products });
    }

    // 2. POST: Add or update product
    if (req.method === "POST") {
      const product = req.body;
      if (!product || !product.name) {
        return res.status(400).json({ error: "Invalid product data" });
      }

      if (!product.id) {
        product.id = "kk-cloud-" + Date.now();
      }

      if (KV_URL && KV_TOKEN) {
        const kvGet = await fetch(`${KV_URL}/get/products`, {
          headers: { Authorization: `Bearer ${KV_TOKEN}` }
        });
        const kvData = await kvGet.json();
        let products = kvData.result ? (typeof kvData.result === "string" ? JSON.parse(kvData.result) : kvData.result) : [];
        products.unshift(product);

        await fetch(`${KV_URL}/set/products`, {
          method: "POST",
          headers: { Authorization: `Bearer ${KV_TOKEN}`, "Content-Type": "application/json" },
          body: JSON.stringify(products)
        });
      } else if (FIREBASE_URL) {
        await fetch(`${FIREBASE_URL}/products.json`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(product)
        });
      }

      return res.status(201).json({ success: true, product });
    }

    // 3. DELETE: Remove product
    if (req.method === "DELETE") {
      const { id } = req.query || {};
      if (!id) return res.status(400).json({ error: "Missing product ID" });

      if (KV_URL && KV_TOKEN) {
        const kvGet = await fetch(`${KV_URL}/get/products`, {
          headers: { Authorization: `Bearer ${KV_TOKEN}` }
        });
        const kvData = await kvGet.json();
        let products = kvData.result ? (typeof kvData.result === "string" ? JSON.parse(kvData.result) : kvData.result) : [];
        products = products.filter(p => p.id !== id);
        await fetch(`${KV_URL}/set/products`, {
          method: "POST",
          headers: { Authorization: `Bearer ${KV_TOKEN}`, "Content-Type": "application/json" },
          body: JSON.stringify(products)
        });
      }

      return res.status(200).json({ success: true, deleted: id });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error("API Error in /api/products:", err);
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
