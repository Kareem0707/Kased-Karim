// Vercel Serverless Function: /api/products
// Handles Products Catalog Persistence across devices

const CLOUD_BIN = process.env.CLOUD_BIN_URL || "https://extendsclass.com/api/json-storage/bin/faabcdf";

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    // 1. GET: Fetch products
    if (req.method === "GET") {
      let products = [];
      try {
        const binRes = await fetch(CLOUD_BIN, { headers: { "Accept": "application/json" } });
        if (binRes.ok) {
          const binData = await binRes.json();
          products = Array.isArray(binData.products) ? binData.products : [];
        }
      } catch (err) {
        console.error("Cloud fetch products error:", err.message);
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

      try {
        let binData = { orders: [], products: [] };
        const binRes = await fetch(CLOUD_BIN);
        if (binRes.ok) {
          binData = await binRes.json();
          if (!Array.isArray(binData.products)) binData.products = [];
        }

        const idx = binData.products.findIndex(p => p.id === product.id);
        if (idx > -1) {
          binData.products[idx] = { ...binData.products[idx], ...product };
        } else {
          binData.products.unshift(product);
        }

        await fetch(CLOUD_BIN, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(binData)
        });
      } catch (err) {
        console.error("Cloud save product error:", err.message);
      }

      return res.status(201).json({ success: true, product });
    }

    // 3. DELETE: Delete product
    if (req.method === "DELETE") {
      const { id } = req.query || {};
      if (!id) return res.status(400).json({ error: "Missing product ID" });

      try {
        const binRes = await fetch(CLOUD_BIN);
        if (binRes.ok) {
          const binData = await binRes.json();
          if (Array.isArray(binData.products)) {
            binData.products = binData.products.filter(p => p.id !== id);
            await fetch(CLOUD_BIN, {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(binData)
            });
          }
        }
      } catch (err) {
        console.error("Cloud delete product error:", err.message);
      }

      return res.status(200).json({ success: true, deleted: id });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error("API Error in /api/products:", err);
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
