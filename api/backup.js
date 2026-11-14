// Vercel Serverless Function: /api/backup
// Handles Cloud Snapshots & Remote Backup Synchronization
// Strictly Protected with Admin-Only Authorization

import { verifyAdminRequest } from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

function getFirebaseUrl(req) {
  const envUrl = process.env.FIREBASE_DB_URL || process.env.NEXT_PUBLIC_FIREBASE_DB_URL;
  if (envUrl && envUrl.trim()) return envUrl.trim().replace(/\/$/, "");
  return "https://kased-karim-default-rtdb.firebaseio.com";
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0");
  res.setHeader("CDN-Cache-Control", "no-store");
  res.setHeader("Vercel-CDN-Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-Control", "no-store");

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin-token, Cache-Control, Pragma");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // STRICT ADMIN AUTHORIZATION CHECK FOR BOTH READ AND WRITE
  const admin = verifyAdminRequest(req);
  if (!admin) {
    return res.status(401).json({
      success: false,
      error: "غير مصرح بالوصول. النسخ الاحتياطية واسترجاع البيانات تتطلب صلاحيات الإدارة العليا."
    });
  }

  const firebaseUrl = getFirebaseUrl(req);
  const kvUrl = process.env.KV_REST_API_URL;
  const kvToken = process.env.KV_REST_API_TOKEN;

  try {
    // -------------------------------------------------------------------------
    // 1. GET: Fetch Latest Cloud Backup Point or Sync Metadata
    // -------------------------------------------------------------------------
    if (req.method === "GET") {
      const t = Date.now();
      const action = req.query?.action;

      if (action === "sync_version") {
        try {
          const metaRes = await fetch(`${firebaseUrl}/sync_meta.json?t=${t}`, { cache: "no-store" });
          if (metaRes.ok) {
            const meta = await metaRes.json();
            return res.status(200).json({ success: true, meta: meta || { version: t } });
          }
        } catch (e) {}
        return res.status(200).json({ success: true, meta: { version: t } });
      }

      // Default: fetch latest cloud snapshot
      const snapRes = await fetch(`${firebaseUrl}/backups/latest.json?t=${t}`, { cache: "no-store" });
      if (snapRes.ok) {
        const data = await snapRes.json();
        return res.status(200).json({ success: true, backup: data });
      }
      return res.status(404).json({ success: false, message: "No cloud backup found" });
    }

    // -------------------------------------------------------------------------
    // 2. POST: Handle Restore Snapshot OR Save Backup Point
    // -------------------------------------------------------------------------
    if (req.method === "POST") {
      let body = req.body;
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch (e) {}
      }
      if (!body) return res.status(400).json({ error: "Invalid backup data" });

      const syncTimestamp = Date.now();

      // =======================================================================
      // CASE A: RESTORE ACTION (Comprehensive Multi-Device Cloud Overwrite)
      // =======================================================================
      if (body.action === "restore" || body.restore === true) {
        const backupData = body.data || body;
        const products = Array.isArray(backupData.products) ? backupData.products : [];
        const orders = Array.isArray(backupData.orders) ? backupData.orders : [];
        const categories = Array.isArray(backupData.categories) ? backupData.categories : [];
        const settings = (backupData.settings && typeof backupData.settings === "object") ? backupData.settings : null;

        const tasks = [];

        // 1. Overwrite Products in Firebase RTDB
        if (products.length > 0) {
          const prodMap = {};
          products.forEach(p => {
            if (p && p.id) prodMap[p.id] = p;
          });
          tasks.push(
            fetch(`${firebaseUrl}/products.json`, {
              method: "PUT",
              cache: "no-store",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(prodMap)
            })
          );
        }

        // 2. Overwrite Orders in Firebase RTDB
        const ordMap = {};
        orders.forEach(o => {
          if (o && o.id) {
            ordMap[encodeURIComponent(o.id)] = o;
          }
        });
        tasks.push(
          fetch(`${firebaseUrl}/orders.json`, {
            method: "PUT",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(ordMap)
          })
        );

        // 3. Overwrite Categories in Firebase RTDB
        if (categories.length > 0) {
          tasks.push(
            fetch(`${firebaseUrl}/categories.json`, {
              method: "PUT",
              cache: "no-store",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(categories)
            })
          );
        }

        // 4. Overwrite Settings in Firebase RTDB
        if (settings) {
          const safeSettings = { ...settings, updatedAt: syncTimestamp };
          tasks.push(
            fetch(`${firebaseUrl}/settings.json`, {
              method: "PUT",
              cache: "no-store",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(safeSettings)
            })
          );
        }

        // 5. Update Sync Metadata (signals all other devices to refresh immediately)
        tasks.push(
          fetch(`${firebaseUrl}/sync_meta.json`, {
            method: "PUT",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              version: syncTimestamp,
              action: "restore",
              timestamp: syncTimestamp,
              restoredCounts: {
                products: products.length,
                orders: orders.length,
                categories: categories.length
              }
            })
          })
        );

        // 6. Overwrite Vercel KV if available
        if (kvUrl && kvToken) {
          if (products.length > 0) {
            tasks.push(
              fetch(`${kvUrl}/set/kased_karim_products`, {
                method: "POST",
                cache: "no-store",
                headers: { "Authorization": `Bearer ${kvToken}`, "Content-Type": "application/json" },
                body: JSON.stringify(products)
              }).catch(() => null)
            );
          }
          tasks.push(
            fetch(`${kvUrl}/set/kased_karim_orders`, {
              method: "POST",
              cache: "no-store",
              headers: { "Authorization": `Bearer ${kvToken}`, "Content-Type": "application/json" },
              body: JSON.stringify(orders)
            }).catch(() => null)
          );
        }

        await Promise.all(tasks);

        return res.status(200).json({
          success: true,
          action: "restore",
          message: "تم استرجاع النسخة ومزامنة كافة المنتجات والطلبات والأقسام والإعدادات على السحابة بنجاح تام",
          counts: {
            products: products.length,
            orders: orders.length,
            categories: categories.length
          },
          syncVersion: syncTimestamp
        });
      }

      // =======================================================================
      // CASE B: SAVE BACKUP SNAPSHOT
      // =======================================================================
      await fetch(`${firebaseUrl}/backups/latest.json`, {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      // Optionally save to history if an ID is present
      if (body.id) {
        const safeId = encodeURIComponent(body.id);
        fetch(`${firebaseUrl}/backups/history/${safeId}.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body)
        }).catch(() => null);
      }

      return res.status(200).json({ success: true, message: "Cloud backup saved successfully" });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
