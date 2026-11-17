// Vercel Serverless Function: /api/backup
// Handles Cloud Snapshots & Remote Backup Synchronization
// Strictly Protected with Admin-Only Authorization (F-06, F-09)

import {
  verifyAdminRequest,
  sanitizePathId,
  getFirebaseUrl,
  setSecurityHeaders
} from "./_auth.js";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default async function handler(req, res) {
  setSecurityHeaders(req, res);

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  // STRICT ADMIN AUTHORIZATION CHECK FOR BOTH READ AND WRITE (F-06, F-09)
  const admin = verifyAdminRequest(req);
  if (!admin) {
    return res.status(401).json({
      success: false,
      error: "غير مصرح بالوصول. النسخ الاحتياطية واسترجاع البيانات تتطلب صلاحيات الإدارة العليا."
    });
  }

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
          const metaUrl = getFirebaseUrl("sync_meta.json", { t });
          const metaRes = await fetch(metaUrl, { cache: "no-store" });
          if (metaRes.ok) {
            const meta = await metaRes.json();
            return res.status(200).json({ success: true, meta: meta || { version: t } });
          }
        } catch (e) {}
        return res.status(200).json({ success: true, meta: { version: t } });
      }

      // Default: fetch latest cloud snapshot (ADMIN ONLY)
      const snapUrl = getFirebaseUrl("backups/latest.json", { t });
      const snapRes = await fetch(snapUrl, { cache: "no-store" });
      if (snapRes.ok) {
        const data = await snapRes.json();
        return res.status(200).json({ success: true, backup: data });
      }
      return res.status(404).json({ success: false, message: "No cloud backup found" });
    }

    // -------------------------------------------------------------------------
    // 2. POST: Handle Restore Snapshot OR Save Backup Point (ADMIN ONLY)
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
            const safeId = sanitizePathId(p?.id);
            if (safeId) prodMap[safeId] = p;
          });
          const prodUrl = getFirebaseUrl("products.json");
          tasks.push(
            fetch(prodUrl, {
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
          const safeId = sanitizePathId(o?.id);
          if (safeId) ordMap[safeId] = o;
        });
        const ordUrl = getFirebaseUrl("orders.json");
        tasks.push(
          fetch(ordUrl, {
            method: "PUT",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(ordMap)
          })
        );

        // 3. Overwrite Categories in Firebase RTDB
        if (categories.length > 0) {
          const catUrl = getFirebaseUrl("categories.json");
          tasks.push(
            fetch(catUrl, {
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
          const setUrl = getFirebaseUrl("settings.json");
          tasks.push(
            fetch(setUrl, {
              method: "PUT",
              cache: "no-store",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(safeSettings)
            })
          );
        }

        // 5. Update Sync Metadata
        const syncUrl = getFirebaseUrl("sync_meta.json");
        tasks.push(
          fetch(syncUrl, {
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
      const latestUrl = getFirebaseUrl("backups/latest.json");
      await fetch(latestUrl, {
        method: "PUT",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      if (body.id) {
        const safeId = sanitizePathId(body.id);
        if (safeId) {
          const historyUrl = getFirebaseUrl(`backups/history/${safeId}.json`);
          fetch(historyUrl, {
            method: "PUT",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
          }).catch(() => null);
        }
      }

      return res.status(200).json({ success: true, message: "Cloud backup saved successfully" });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    return res.status(500).json({ error: "Server error", message: err.message });
  }
}
