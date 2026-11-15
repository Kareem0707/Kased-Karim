/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Hybrid Real-Time Cloud Database Engine (js/db.js)
 * متصل بنظام سحابي لحظي ومزدوج لضمان وصول واستقبال الطلبات فورياً عبر جميع الأجهزة والهواتف
 * يدعم Firebase Realtime Database (Google Cloud) و Vercel Serverless KV
 */

const DB_KEYS = {
  PRODUCTS: "kased_karim_db_products_v3",
  ORDERS: "kased_karim_db_orders_v2",
  CATEGORIES: "kased_karim_db_categories_v2",
  SETTINGS: "kased_karim_db_settings_v3",
  BACKUPS: "kased_karim_db_backups_v1",
  CLOUD_CONFIG: "kased_karim_cloud_config_v1",
  CUSTOM_CLOUD_URL: "kk_custom_cloud_url",
  DELIVERY_AREAS: "kased_karim_db_delivery_areas_v1",
  REVIEWS: "kased_karim_db_reviews_v1",
  CUSTOMER_TOKEN: "kk_customer_token",
  CUSTOMER_USER: "kk_customer_user",
  AUDIT_LOGS: "kased_karim_db_audit_logs_v1"
};

// Production Orders Cache (Zero Hardcoded Customer Data)
// All orders are dynamically stored and fetched via encrypted serverless endpoints

class KasedKarimDB {
  constructor() {
    this.cloudEnabled = true;
    this.lastSyncTimestamp = 0;
    this.isSyncing = false;
    this.cloudProvider = "Vercel / Cloud Sync";
    this.knownOrderIds = new Set();
    this.notifiedOrderIds = new Set();
    this.pageSessionStartTime = Date.now();
    this.isInitialSyncCompleted = false;
    this.audioCtx = null;

    try {
      const storedNotified = localStorage.getItem("kk_notified_orders");
      if (storedNotified) {
        JSON.parse(storedNotified).forEach(id => this.notifiedOrderIds.add(id));
      }
    } catch (e) {}
    
    this.initDatabase();
    this.setupAudioUnlock();
    this.initCloudSync();
  }

  // 1. Initialize Database & Local Cache
  initDatabase() {
    // A. Retrieve tombstone set of deleted product IDs so they are NEVER resurrected on refresh
    let deletedProductIds = new Set();
    try {
      const rawDeleted = localStorage.getItem("kk_deleted_product_ids_v1");
      if (rawDeleted) {
        const parsed = JSON.parse(rawDeleted);
        if (Array.isArray(parsed)) parsed.forEach(id => deletedProductIds.add(id));
      }
    } catch (e) {}

    // B. Check existing cached products in localStorage
    let cachedProducts = null;
    try {
      const raw = localStorage.getItem(DB_KEYS.PRODUCTS);
      if (raw) cachedProducts = JSON.parse(raw);
    } catch (e) {
      cachedProducts = null;
    }

    // Only if local database has never been initialized on this device, seed with INITIAL_PRODUCTS
    if (!Array.isArray(cachedProducts) || cachedProducts.length === 0) {
      // First visit seed (excluding any previously deleted IDs)
      const seeded = (typeof INITIAL_PRODUCTS !== "undefined" ? INITIAL_PRODUCTS : [])
        .filter(p => !deletedProductIds.has(p.id))
        .map((p, idx) => ({
          ...p,
          salesCount: [34, 28, 22, 19, 15, 45, 12, 17, 14, 25, 9, 11][idx] || 10,
          warranty: p.specs?.warranty || "5 سنوات ضمان معتمد"
        }));
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(seeded));
    } else {
      // Clean any accidental resurrected items that exist in deletedProductIds
      const sanitized = cachedProducts.filter(p => p && p.id && !deletedProductIds.has(p.id));
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(sanitized));
    }

    // Initialize Orders - sanitize and remove old dummy placeholder and test orders
    let localOrders = [];
    try {
      const raw = localStorage.getItem(DB_KEYS.ORDERS);
      localOrders = raw ? JSON.parse(raw) : [];
    } catch (e) {
      localOrders = [];
    }

    localOrders = (localOrders || []).filter(o => 
      o && o.id &&
      o.id !== "ORD-3985" &&
      o.id !== "ORD-5412" &&
      o.id !== "ORD-8941" && 
      o.id !== "ORD-8820" &&
      !o.id.startsWith("DEMO-") &&
      (!o.customer || (
        !o.customer.name.includes("ككك") && 
        !o.customer.name.includes("منك") &&
        o.customer.name !== "test"
      ))
    );

    localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(localOrders));

    localOrders.forEach(o => {
      this.knownOrderIds.add(o.id);
      this.notifiedOrderIds.add(o.id);
    });

    // 3. Initialize Categories
    let cachedCategories = null;
    try {
      const raw = localStorage.getItem(DB_KEYS.CATEGORIES);
      if (raw) cachedCategories = JSON.parse(raw);
    } catch (e) {}

    if (Array.isArray(cachedCategories) && cachedCategories.length > 0) {
      if (!cachedCategories.some(c => c.id === "all")) {
        cachedCategories.unshift({ id: "all", name: "الكل المعروض", parentId: null });
      }
      cachedCategories.forEach(c => {
        if (typeof c.parentId === "undefined") c.parentId = null;
      });
      localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(cachedCategories));
      window.CATEGORIES = cachedCategories;
      if (typeof CATEGORIES !== "undefined") CATEGORIES = cachedCategories;
    } else {
      const defaultCats = typeof INITIAL_CATEGORIES !== "undefined" ? [...INITIAL_CATEGORIES] : [
        { id: "all", name: "الكل المعروض", parentId: null },
        { id: "table-lamps", name: "أباجورات", parentId: null },
        { id: "pendants", name: "دلايات", parentId: null },
        { id: "wall-sconces", name: "أباليك", parentId: null },
        { id: "spotlights", name: "سبوت لايت", parentId: null },
        { id: "floor-lamps", name: "لمباديرات", parentId: null },
        { id: "track-lights", name: "تراك لايت", parentId: null },
        { id: "bollards-lanterns", name: "فوانيس سور، بولارد", parentId: null },
        { id: "spike-lights", name: "حربة", parentId: null },
        { id: "led-panels", name: "بانلات", parentId: null },
        { id: "floodlights", name: "كشافات", parentId: null },
        { id: "led-profiles", name: "أعواد البروفايل", parentId: null },
        { id: "stair-lights", name: "درج سلم", parentId: null }
      ];
      localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(defaultCats));
      window.CATEGORIES = defaultCats;
      if (typeof CATEGORIES !== "undefined") CATEGORIES = defaultCats;
    }

    // 4. Initialize Settings
    let cachedSettings = null;
    try {
      const raw = localStorage.getItem(DB_KEYS.SETTINGS);
      if (raw) cachedSettings = JSON.parse(raw);
    } catch (e) {}

    const defaultSettings = typeof INITIAL_SHOWROOM_INFO !== "undefined" ? { ...INITIAL_SHOWROOM_INFO } : {
      brandName: "Kased Karim",
      brandArabic: "قاصد كريم للإضاءة الفاخرة",
      tagline: "أيقونة الإضاءة الديكورية والمعمارية في الشيخ زايد",
      location: "الشيخ زايد - الحي الأول، سنتر الطاهرة، الجيزة، مصر",
      mapUrl: "https://maps.app.goo.gl/EzzitFCzNSpQc7w77?g_st=ic",
      mapEmbedUrl: "https://maps.google.com/maps?q=%D9%82%D8%A7%D8%B5%D8%AF%20%D9%83%D8%B1%D9%8A%D9%85%202%20%D9%84%D9%84%D8%A7%D8%AF%D9%88%D8%A7%D8%AA%20%D8%A7%D9%84%D9%83%D9%87%D8%B1%D8%A8%D8%A7%D8%A6%D9%8A%D8%A9%2C%20%D8%B1%D9%82%D9%85%2039%D8%8C%20%D8%A3%D9%88%D9%84%20%D8%A7%D9%84%D8%B4%D9%8A%D8%AE%20%D8%B2%D8%A7%D9%8A%D8%AF%D8%8C%20%D9%85%D8%AD%D8%A7%D9%81%D8%B8%D8%A9%20%D8%A7%D9%84%D8%AC%D9%8A%D8%B2%D8%A9&t=&z=14&ie=UTF8&iwloc=&output=embed",
      phone: "01006367690",
      whatsapp: "201006367690",
      email: "vip@kasedkarim.com",
      workingHours: "يومياً من 11:00 صباحاً حتى 11:00 مساءً",
      consultationFee: "مجاناً للمشاريع والفيلات السكنية عند التعاقد",
      social: {
        facebook: "https://facebook.com",
        instagram: "https://instagram.com",
        tiktok: "https://tiktok.com",
        designerUrl: "https://karimodesign.vercel.app/"
      }
    };

    if (cachedSettings && typeof cachedSettings === "object") {
      const mergedSettings = { ...defaultSettings, ...cachedSettings, social: { ...defaultSettings.social, ...(cachedSettings.social || {}) } };
      localStorage.setItem(DB_KEYS.SETTINGS, JSON.stringify(mergedSettings));
      window.SHOWROOM_INFO = mergedSettings;
      if (typeof SHOWROOM_INFO !== "undefined") SHOWROOM_INFO = mergedSettings;
    } else {
      localStorage.setItem(DB_KEYS.SETTINGS, JSON.stringify(defaultSettings));
      window.SHOWROOM_INFO = defaultSettings;
      if (typeof SHOWROOM_INFO !== "undefined") SHOWROOM_INFO = defaultSettings;
    }

    // 5. Automatic Daily Restore Point on first visit of day
    this.checkAndCreateDailyRestorePoint();
  }

  // --------------------------------------------------------------------------
  // AUDIO ENGINE & UNLOCKING (Web Audio API)
  // --------------------------------------------------------------------------
  setupAudioUnlock() {
    const unlock = () => {
      try {
        if (!this.audioCtx) {
          const AudioContextClass = window.AudioContext || window.webkitAudioContext;
          if (AudioContextClass) this.audioCtx = new AudioContextClass();
        }
        if (this.audioCtx && this.audioCtx.state === "suspended") {
          this.audioCtx.resume();
        }
      } catch (e) {}
    };

    window.addEventListener("click", unlock, { passive: true });
    window.addEventListener("touchstart", unlock, { passive: true });
    window.addEventListener("keydown", unlock, { passive: true });
  }

  playLuxuryChime() {
    try {
      if (!this.audioCtx) {
        const AudioContextClass = window.AudioContext || window.webkitAudioContext;
        if (AudioContextClass) this.audioCtx = new AudioContextClass();
      }
      if (!this.audioCtx) return;
      if (this.audioCtx.state === "suspended") {
        this.audioCtx.resume();
      }

      const ctx = this.audioCtx;
      const now = ctx.currentTime;

      // 4-Tone Luxury Showroom Crystal Bell: E5 (659Hz) -> G#5 (830Hz) -> B5 (987Hz) -> E6 (1318Hz)
      const notes = [
        { freq: 659.25, time: 0, dur: 0.5, gain: 0.28 },
        { freq: 830.61, time: 0.12, dur: 0.5, gain: 0.32 },
        { freq: 987.77, time: 0.24, dur: 0.6, gain: 0.35 },
        { freq: 1318.51, time: 0.36, dur: 1.2, gain: 0.40 }
      ];

      notes.forEach(n => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = "sine";
        osc.frequency.setValueAtTime(n.freq, now + n.time);

        gain.gain.setValueAtTime(0, now + n.time);
        gain.gain.linearRampToValueAtTime(n.gain, now + n.time + 0.04);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + n.time + n.dur);

        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now + n.time);
        osc.stop(now + n.time + n.dur);
      });
    } catch (e) {
      console.warn("Audio alert restricted until user interaction:", e.message);
    }
  }

  // --------------------------------------------------------------------------
  // CLOUD DATABASE SETTINGS & HEADERS
  // --------------------------------------------------------------------------
  getCustomCloudUrl() {
    try {
      const saved = localStorage.getItem(DB_KEYS.CUSTOM_CLOUD_URL);
      if (saved && saved.trim()) return saved.trim().replace(/\/$/, "");
      return "https://kased-karim-default-rtdb.firebaseio.com";
    } catch (e) {
      return "https://kased-karim-default-rtdb.firebaseio.com";
    }
  }

  setCustomCloudUrl(url) {
    if (url && typeof url === "string") {
      localStorage.setItem(DB_KEYS.CUSTOM_CLOUD_URL, url.trim());
    } else {
      localStorage.removeItem(DB_KEYS.CUSTOM_CLOUD_URL);
    }
  }

  getCloudHeaders() {
    const headers = {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "Cache-Control": "no-cache, no-store",
      "Pragma": "no-cache"
    };

    // Attach Admin Authentication Token if available
    const adminToken = (typeof sessionStorage !== "undefined" && sessionStorage.getItem("kk_admin_token")) ||
                       (typeof localStorage !== "undefined" && localStorage.getItem("kk_admin_token"));
    if (adminToken) {
      headers["Authorization"] = `Bearer ${adminToken}`;
      headers["x-admin-token"] = adminToken;
    }

    const customUrl = this.getCustomCloudUrl();
    if (customUrl) {
      headers["x-cloud-db-url"] = customUrl;
      headers["x-firebase-url"] = customUrl;
    }
    return headers;
  }

  // --------------------------------------------------------------------------
  // CLOUD DATABASE SYNC ENGINE (Adaptive, Privacy-Preserving Polling)
  // --------------------------------------------------------------------------
  initCloudSync() {
    // 1. Initial sync of public catalog, categories, and settings
    this.syncProductsFromCloud(false);
    this.syncCategoriesFromCloud();
    this.syncSettingsFromCloud();

    const isAdminPage = typeof window !== "undefined" && (
      window.location.pathname.includes("admin.html") || 
      !!document.getElementById("adminPageRoot")
    );

    // Only sync orders if user is explicitly on admin dashboard and has admin credentials
    const hasAdminToken = typeof sessionStorage !== "undefined" && (
      !!sessionStorage.getItem("kk_admin_token") || !!localStorage.getItem("kk_admin_token")
    );

    if (isAdminPage && hasAdminToken) {
      this.syncFromCloud(false);
    }

    // 2. High-Frequency Real-Time Polling & Adaptive Visibility Refresh
    let orderInterval = null;
    let catalogInterval = null;

    const startBackgroundSync = () => {
      if (orderInterval) clearInterval(orderInterval);
      if (catalogInterval) clearInterval(catalogInterval);

      // Admin orders polling: every 15 seconds (when on admin dashboard and visible)
      if (isAdminPage) {
        orderInterval = setInterval(() => {
          if (typeof document !== "undefined" && !document.hidden) {
            const token = sessionStorage.getItem("kk_admin_token") || localStorage.getItem("kk_admin_token");
            if (token) {
              this.syncFromCloud(true);
            }
          }
        }, 15000);
      }

      // Catalog & Settings polling: every 20 seconds across all devices
      catalogInterval = setInterval(() => {
        if (typeof document !== "undefined" && !document.hidden) {
          this.syncProductsFromCloud(true);
          this.syncCategoriesFromCloud();
          this.syncSettingsFromCloud();
        }
      }, 20000);
    };

    const stopBackgroundSync = () => {
      if (orderInterval) clearInterval(orderInterval);
      if (catalogInterval) clearInterval(catalogInterval);
      orderInterval = null;
      catalogInterval = null;
    };

    startBackgroundSync();

    // 3. Instant Multi-Device Sync on Foreground Focus / Reconnection
    if (typeof window !== "undefined") {
      window.addEventListener("focus", () => {
        this.forceSyncNow();
      });

      window.addEventListener("online", () => {
        this.forceSyncNow();
      });

      if (typeof document !== "undefined") {
        document.addEventListener("visibilitychange", () => {
          if (document.hidden) {
            stopBackgroundSync();
          } else {
            startBackgroundSync();
            this.forceSyncNow();
          }
        });
      }
    }
  }

  // Sync Products from Cloud to Local (Cloud is Ground Truth)
  async syncProductsFromCloud(isBackground = false) {
    try {
      let cloudProducts = null;
      const t = Date.now();
      const customUrl = this.getCustomCloudUrl();

      // 1. Direct Firebase Realtime Database Fetch (if configured)
      if (customUrl) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 4500);
          const directRes = await fetch(`${customUrl}/products.json?t=${t}`, {
            signal: controller.signal,
            cache: "no-store",
            headers: { "Accept": "application/json" }
          });
          clearTimeout(timeoutId);
          if (directRes.ok) {
            const raw = await directRes.json();
            if (raw) {
              if (Array.isArray(raw)) {
                cloudProducts = raw.filter(Boolean);
              } else if (typeof raw === "object") {
                cloudProducts = Object.values(raw).filter(Boolean);
              }
              this.cloudProvider = "Firebase Realtime DB (Direct)";
            }
          }
        } catch (e) {}
      }

      // 2. Vercel Serverless Endpoint /api/products
      if (!cloudProducts || cloudProducts.length === 0) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 4500);
          const res = await fetch(`/api/products?t=${t}`, {
            signal: controller.signal,
            cache: "no-store",
            headers: this.getCloudHeaders()
          });
          clearTimeout(timeoutId);

          if (res.ok) {
            const data = await res.json();
            if (data && data.success && Array.isArray(data.products) && data.products.length > 0) {
              cloudProducts = data.products;
              this.cloudProvider = data.provider === "firebase-rtdb" ? "Firebase RTDB (via Vercel)" : (data.provider === "vercel-kv" ? "Vercel KV" : "Vercel Serverless");
            }
          }
        } catch (errApi) {}
      }

      // Cloud Ground Truth Synchronization
      let deletedIds = new Set();
      try {
        const rawDel = localStorage.getItem("kk_deleted_product_ids_v1");
        if (rawDel) JSON.parse(rawDel).forEach(id => deletedIds.add(id));
      } catch(e) {}

      if (cloudProducts && Array.isArray(cloudProducts)) {
        // Strictly filter out any products marked as deleted
        cloudProducts = cloudProducts.filter(p => p && p.id && !deletedIds.has(p.id));
        const currentProducts = this.getProducts();
        const currentStr = JSON.stringify(currentProducts);
        const cloudStr = JSON.stringify(cloudProducts);

        if (currentStr !== cloudStr) {
          localStorage.setItem(DB_KEYS.PRODUCTS, cloudStr);
          window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: { merged: false, products: cloudProducts } }));
        }
      }
    } catch (e) {
      console.warn("Product sync note:", e.message);
    }
  }

  // Sync Orders from Cloud to Local
  async syncFromCloud(isBackgroundPoll = false) {
    if (this.isSyncing) return;
    this.isSyncing = true;

    try {
      let orders = null;
      const t = Date.now();
      const customUrl = this.getCustomCloudUrl();

      // 1. Direct Firebase Realtime Database Fetch (if configured)
      if (customUrl) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 4000);
          const directRes = await fetch(`${customUrl}/orders.json?t=${t}`, {
            signal: controller.signal,
            cache: "no-store",
            headers: { "Accept": "application/json" }
          });
          clearTimeout(timeoutId);
          if (directRes.ok) {
            const raw = await directRes.json();
            if (raw) {
              if (Array.isArray(raw)) {
                orders = raw.filter(Boolean);
              } else if (typeof raw === "object") {
                orders = Object.values(raw).filter(Boolean);
              }
            }
          }
        } catch (e) {}
      }

      // 2. Vercel Serverless Endpoint /api/orders
      if (!orders || orders.length === 0) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 4000);
          const res = await fetch(`/api/orders?t=${t}`, {
            signal: controller.signal,
            cache: "no-store",
            headers: this.getCloudHeaders()
          });
          clearTimeout(timeoutId);

          if (res.ok) {
            const data = await res.json();
            if (data && data.success && Array.isArray(data.orders) && data.orders.length > 0) {
              orders = data.orders;
            }
          }
        } catch (errApi) {}
      }

      if (orders && Array.isArray(orders)) {
        this.lastSyncTimestamp = Date.now();

        // 1. Sanitize: filter out fake test orders
        const cleanCloudOrders = orders.filter(o => {
          if (!o || !o.id) return false;
          if (o.id === "ORD-8941" || o.id === "ORD-8820") return false;
          if (o.customer && (
            (o.customer.name && (o.customer.name.includes("ككك") || o.customer.name.includes("منك") || o.customer.name === "test"))
          )) {
            this.deleteOrderFromCloud(o.id);
            return false;
          }
          return true;
        });

        // Normalize items and customer for all cloud orders
        cleanCloudOrders.forEach(o => {
          if (o && o.items && !Array.isArray(o.items) && typeof o.items === "object") {
            o.items = Object.values(o.items);
          }
          if (o && typeof o.customer === "string") {
            try { o.customer = JSON.parse(o.customer); } catch(e) { o.customer = { name: o.customer }; }
          }
        });

        // STRICT CHRONOLOGICAL SORT: Newest orders first
        cleanCloudOrders.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

        const trulyNewOrders = [];

        cleanCloudOrders.forEach(cloudOrder => {
          const isKnown = this.knownOrderIds.has(cloudOrder.id);

          // Only consider an order for instant alert if:
          // 1. Initial sync has already completed (so historical orders on page load never alert!)
          // 2. The order was not known and not previously notified
          // 3. The order was placed either during this session or within the last 5 minutes!
          if (!isKnown && this.isInitialSyncCompleted) {
            const isRecent = (cloudOrder.timestamp >= this.pageSessionStartTime) || (cloudOrder.timestamp >= Date.now() - 5 * 60 * 1000);
            if (isRecent && !this.notifiedOrderIds.has(cloudOrder.id)) {
              trulyNewOrders.push(cloudOrder);
            }
          }
        });

        // Cloud is Ground Truth: set known IDs to current cloud orders
        this.knownOrderIds.clear();
        cleanCloudOrders.forEach(o => this.knownOrderIds.add(o.id));

        // Mark initial sync complete
        this.isInitialSyncCompleted = true;

        const localOrders = this.getOrders();
        const localOrdStr = JSON.stringify(localOrders);
        const cloudOrdStr = JSON.stringify(cleanCloudOrders);

        if (localOrdStr !== cloudOrdStr) {
          localStorage.setItem(DB_KEYS.ORDERS, cloudOrdStr);
          this.recalculateAllProductSales();
        }

        if (trulyNewOrders.length > 0) {
          // Strictly pick the newest order with highest timestamp
          trulyNewOrders.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
          const latestNewOrder = trulyNewOrders[0];

          this.notifiedOrderIds.add(latestNewOrder.id);
          try {
            localStorage.setItem("kk_notified_orders", JSON.stringify(Array.from(this.notifiedOrderIds)));
          } catch (e) {}

          const isAdmin = typeof document !== 'undefined' && (document.body.classList.contains("is-admin-user") || !!document.getElementById("adminPageRoot"));
          if (isAdmin) {
            this.playLuxuryChime();
          }
          window.dispatchEvent(new CustomEvent("kk_new_order_placed", { detail: latestNewOrder }));
        } else if (localOrdStr !== cloudOrdStr) {
          window.dispatchEvent(new CustomEvent("kk_orders_updated"));
        }
      }
    } catch (e) {
      console.warn("Cloud sync note:", e.message);
    } finally {
      this.isSyncing = false;
    }
  }

  async forceSyncNow() {
    await Promise.allSettled([
      this.syncProductsFromCloud(false),
      this.syncCategoriesFromCloud(),
      this.syncSettingsFromCloud(),
      this.syncFromCloud(false)
    ]);
  }

  // --------------------------------------------------------------------------
  // PRODUCTS CLOUD PUSH & DELETE
  // --------------------------------------------------------------------------
  async sendProductToCloud(product) {
    const customUrl = this.getCustomCloudUrl();
    const safeProduct = {
      id: product.id,
      name: product.name,
      enName: product.enName || "",
      category: product.category || "pendants",
      categoryName: product.categoryName || "دلايات",
      style: product.style || "",
      price: parseFloat(product.price) || 0,
      originalPrice: product.originalPrice ? parseFloat(product.originalPrice) : null,
      warranty: product.warranty || "",
      image: product.image || "",
      secondaryImage: product.secondaryImage || "",
      description: product.description || "",
      isNew: !!product.isNew,
      isExclusive: !!product.isExclusive,
      isBestSeller: !!product.isBestSeller,
      specs: product.specs || {}
    };

    let saved = false;

    // 1. Direct Firebase Realtime Database
    if (customUrl) {
      try {
        const safeId = encodeURIComponent(safeProduct.id);
        const res = await fetch(`${customUrl}/products/${safeId}.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(safeProduct)
        });
        if (res.ok) saved = true;
      } catch (e) {}
    }

    // 2. Vercel Serverless Function /api/products
    try {
      const apiRes = await fetch("/api/products", {
        method: "POST",
        cache: "no-store",
        headers: this.getCloudHeaders(),
        body: JSON.stringify(safeProduct)
      });
      if (apiRes.ok) saved = true;
    } catch (e) {}

    return saved;
  }

  async deleteProductFromCloud(productId) {
    const customUrl = this.getCustomCloudUrl();
    if (customUrl) {
      try {
        const safeId = encodeURIComponent(productId);
        fetch(`${customUrl}/products/${safeId}.json`, { method: "DELETE", cache: "no-store" }).catch(() => null);
      } catch (e) {}
    }
    fetch(`/api/products?id=${productId}`, {
      method: "DELETE",
      cache: "no-store",
      headers: this.getCloudHeaders()
    }).catch(() => null);
  }

  // Push entire local catalog to cloud database with one atomic call
  async syncAllLocalProductsToCloud() {
    const products = this.getProducts();
    const customUrl = this.getCustomCloudUrl();

    // 1. Direct Firebase RTDB Batch (if customUrl configured)
    if (customUrl) {
      try {
        const mapObj = {};
        products.forEach(p => {
          if (p && p.id) mapObj[p.id] = p;
        });
        const res = await fetch(`${customUrl}/products.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(mapObj)
        });
        if (res.ok) return products.length;
      } catch (e) {}
    }

    // 2. Atomic Batch Overwrite to /api/products
    try {
      const res = await fetch("/api/products", {
        method: "PUT",
        cache: "no-store",
        headers: this.getCloudHeaders(),
        body: JSON.stringify({ products })
      });
      if (res.ok) {
        return products.length;
      }
    } catch (e) {}

    // 3. Fallback: individual product push
    let count = 0;
    for (const p of products) {
      try {
        await this.sendProductToCloud(p);
        count++;
      } catch (e) {}
    }
    return count;
  }

  // --------------------------------------------------------------------------
  // ORDERS CLOUD PUSH & UPDATE
  // --------------------------------------------------------------------------
  async sendOrderToCloud(order) {
    const customUrl = this.getCustomCloudUrl();

    // 1. Direct Firebase RTDB
    if (customUrl) {
      try {
        const safeId = encodeURIComponent(order.id);
        fetch(`${customUrl}/orders/${safeId}.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(order)
        }).catch(() => null);
      } catch (e) {}
    }

    // 2. Vercel Serverless Function
    fetch("/api/orders", {
      method: "POST",
      cache: "no-store",
      headers: this.getCloudHeaders(),
      body: JSON.stringify(order)
    }).catch(() => null);
  }

  // Fetch single order directly from cloud with zero lag
  async fetchLiveOrder(orderId) {
    if (!orderId) return null;
    const cleanId = orderId.toString().replace(/[#]/g, "").trim();
    const customUrl = this.getCustomCloudUrl();
    const t = Date.now();
    let cloudOrder = null;

    // 1. Direct Firebase RTDB single-order fetch
    if (customUrl) {
      try {
        const safeId = encodeURIComponent(cleanId);
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3500);
        const res = await fetch(`${customUrl}/orders/${safeId}.json?t=${t}`, {
          signal: controller.signal,
          cache: "no-store",
          headers: { "Accept": "application/json" }
        });
        clearTimeout(timeoutId);
        if (res.ok) {
          const data = await res.json();
          if (data && typeof data === "object" && data.id) {
            cloudOrder = data;
          }
        }
      } catch (e) {}
    }

    // 2. Fallback to /api/orders
    if (!cloudOrder) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3500);
        const res = await fetch(`/api/orders?t=${t}`, {
          signal: controller.signal,
          cache: "no-store",
          headers: this.getCloudHeaders()
        });
        clearTimeout(timeoutId);
        if (res.ok) {
          const json = await res.json();
          if (json && json.orders && Array.isArray(json.orders)) {
            cloudOrder = json.orders.find(o => 
              o.id.toUpperCase() === cleanId.toUpperCase() || 
              o.id.replace("ORD-", "") === cleanId.replace("ORD-", "")
            );
          }
        }
      } catch (e) {}
    }

    if (cloudOrder) {
      const orders = this.getOrders();
      const idx = orders.findIndex(o => o.id === cloudOrder.id);
      if (idx > -1) {
        orders[idx] = {
          ...orders[idx],
          ...cloudOrder,
          status: cloudOrder.status || orders[idx].status
        };
      } else {
        orders.unshift(cloudOrder);
      }
      localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(orders));
      window.dispatchEvent(new CustomEvent("kk_orders_updated"));
      return cloudOrder;
    }

    return null;
  }

  async updateOrderStatusInCloud(orderId, status) {
    const customUrl = this.getCustomCloudUrl();
    const safeId = encodeURIComponent(orderId);
    const updatedAt = Date.now();

    if (customUrl) {
      try {
        // Fast PATCH on the order object in Firebase RTDB
        fetch(`${customUrl}/orders/${safeId}.json`, {
          method: "PATCH",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status, updatedAt })
        }).catch(() => null);

        // Also ensure status.json child is updated
        fetch(`${customUrl}/orders/${safeId}/status.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(status)
        }).catch(() => null);
      } catch (e) {}
    }

    fetch("/api/orders", {
      method: "PATCH",
      cache: "no-store",
      headers: this.getCloudHeaders(),
      body: JSON.stringify({ id: orderId, status, updatedAt })
    }).catch(() => null);
  }

  async deleteOrderFromCloud(orderId) {
    const customUrl = this.getCustomCloudUrl();
    if (customUrl) {
      try {
        const safeId = encodeURIComponent(orderId);
        fetch(`${customUrl}/orders/${safeId}.json`, { method: "DELETE", cache: "no-store" }).catch(() => null);
      } catch (e) {}
    }
    fetch(`/api/orders?id=${orderId}`, {
      method: "DELETE",
      cache: "no-store",
      headers: this.getCloudHeaders()
    }).catch(() => null);
  }

  // --------------------------------------------------------------------------
  // PRODUCTS CRUD
  // --------------------------------------------------------------------------
  getProducts() {
    try {
      const data = localStorage.getItem(DB_KEYS.PRODUCTS);
      let list = data ? JSON.parse(data) : [...INITIAL_PRODUCTS];
      try {
        const rawDeleted = localStorage.getItem("kk_deleted_product_ids_v1");
        if (rawDeleted) {
          const deletedIds = new Set(JSON.parse(rawDeleted));
          if (deletedIds.size > 0) {
            list = list.filter(p => p && p.id && !deletedIds.has(p.id));
          }
        }
      } catch(e) {}

      // Ensure stock attributes (PRD Section 6)
      list.forEach(p => {
        if (p.stock === undefined) p.stock = 12;
        p.inStock = p.stock > 0 && p.inStock !== false;
      });

      return list;
    } catch (e) {
      console.error("DB Error getProducts:", e);
      return [...INITIAL_PRODUCTS];
    }
  }

  getProductById(id) {
    const products = this.getProducts();
    return products.find(p => p.id === id) || null;
  }

  addProduct(productData) {
    const products = this.getProducts();
    const newProduct = {
      id: "kk-" + Date.now().toString().slice(-5),
      name: productData.name,
      enName: productData.enName || "",
      category: productData.category || "pendants",
      categoryName: productData.categoryName || "دلايات فاخرة",
      style: productData.style || "",
      price: parseFloat(productData.price) || 0,
      originalPrice: productData.originalPrice ? parseFloat(productData.originalPrice) : null,
      warranty: productData.warranty || "",
      image: productData.image,
      secondaryImage: productData.secondaryImage || "",
      description: productData.description || "",
      isExclusive: !!productData.isExclusive,
      isBestSeller: !!productData.isBestSeller,
      isNew: true,
      rating: 5.0,
      reviewsCount: 1,
      salesCount: 0,
      specs: {
        dimensions: productData.specs?.dimensions || "",
        material: productData.specs?.material || "",
        colorTemp: productData.specs?.colorTemp || "",
        wattage: productData.specs?.wattage || "",
        cri: productData.specs?.cri || "",
        voltage: productData.specs?.voltage || "",
        warranty: productData.warranty || ""
      }
    };

    products.unshift(newProduct);
    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
    
    // Multi-device cloud push
    this.sendProductToCloud(newProduct);

    window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: newProduct }));
    return newProduct;
  }

  async deleteProduct(productId) {
    // 1. Record ID in permanent tombstone set so it can NEVER be resurrected by refresh or stale cache
    try {
      const rawDeleted = localStorage.getItem("kk_deleted_product_ids_v1");
      const deletedIds = rawDeleted ? JSON.parse(rawDeleted) : [];
      if (!deletedIds.includes(productId)) {
        deletedIds.push(productId);
        localStorage.setItem("kk_deleted_product_ids_v1", JSON.stringify(deletedIds));
      }
    } catch(e) {}

    // 2. Filter local products
    let products = this.getProducts();
    const target = products.find(p => p.id === productId);
    if (target) {
      this.saveWebRestorePoint(`قبل حذف المنتج: ${target.name}`);
    }
    products = products.filter(p => p.id !== productId);
    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));

    // 3. Multi-device cloud delete and batch overwrite
    await this.deleteProductFromCloud(productId);
    await this.syncAllLocalProductsToCloud();

    this.recalculateAllProductSales();
    window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: { deletedId: productId } }));
    return true;
  }

  async updateProduct(productId, updatedData) {
    let products = this.getProducts();
    const idx = products.findIndex(p => p.id === productId);
    if (idx === -1) return { success: false, error: "المنتج غير موجود" };

    const oldProduct = products[idx];
    this.saveWebRestorePoint(`قبل تعديل المنتج: ${oldProduct.name}`);

    const updatedProduct = {
      ...oldProduct,
      ...updatedData,
      id: productId, // Never change product ID
      price: parseFloat(updatedData.price) || 0,
      originalPrice: updatedData.originalPrice ? parseFloat(updatedData.originalPrice) : null,
      updatedAt: Date.now()
    };

    products[idx] = updatedProduct;
    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));

    // Push updated product and full batch to cloud
    await this.sendProductToCloud(updatedProduct);
    await this.syncAllLocalProductsToCloud();

    this.recalculateAllProductSales();
    window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: updatedProduct }));
    return { success: true, product: updatedProduct };
  }

  // --------------------------------------------------------------------------
  // ORDERS MANAGEMENT & CHECKOUT
  // --------------------------------------------------------------------------
  getOrders() {
    try {
      const data = localStorage.getItem(DB_KEYS.ORDERS);
      let parsed = data ? JSON.parse(data) : [];
      if (!Array.isArray(parsed)) {
        if (typeof parsed === "object" && parsed !== null) {
          parsed = Object.values(parsed).filter(Boolean);
        } else {
          parsed = [];
        }
      }
      const filtered = parsed.filter(o => 
        o && o.id &&
        o.id !== "ORD-8941" && 
        o.id !== "ORD-8820" && 
        o.customer?.name !== "كككك" && 
        o.customer?.name !== "منك"
      );

      // Normalize items & customer structure for all orders
      filtered.forEach(o => {
        if (o && o.items && !Array.isArray(o.items) && typeof o.items === "object") {
          o.items = Object.values(o.items);
        }
        if (o && typeof o.customer === "string") {
          try { o.customer = JSON.parse(o.customer); } catch(e) { o.customer = { name: o.customer }; }
        }
      });

      // STRICT CHRONOLOGICAL SORT: Newest orders ALWAYS at index 0 (top of list)
      filtered.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      return filtered;
    } catch (e) {
      console.error("DB Error getOrders:", e);
      return [];
    }
  }

  async createOrder(customerData, cartItems) {
    if (!cartItems || cartItems.length === 0) {
      throw new Error("سلة الطلبات فارغة");
    }

    const payload = {
      customer: {
        name: (customerData.name || "").trim(),
        phone: (customerData.phone || "").trim(),
        city: customerData.city || "الشيخ زايد",
        address: (customerData.address || "").trim(),
        notes: (customerData.notes || "").trim()
      },
      items: cartItems.map(item => ({
        id: item.id,
        name: item.name,
        enName: item.enName || "",
        price: item.price,
        qty: parseInt(item.qty, 10) || 1,
        image: item.image,
        categoryName: item.categoryName || ""
      }))
    };

    // Submit order to secure server endpoint and await persistence confirmation
    const res = await fetch("/api/orders", {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || "تعذر إرسال الطلب إلى الخادم السحابي");
    }

    const confirmedOrder = data.order || {};

    // Merge payload defensively so all customer info & product items are 100% guaranteed
    const fullOrder = {
      ...payload,
      ...confirmedOrder,
      customer: {
        ...payload.customer,
        ...(confirmedOrder.customer || {})
      },
      items: (confirmedOrder.items && confirmedOrder.items.length > 0)
        ? confirmedOrder.items
        : payload.items
    };

    // Cache locally on this device (at top of list)
    try {
      const orders = this.getOrders();
      const filtered = orders.filter(o => o.id !== fullOrder.id);
      filtered.unshift(fullOrder);
      this.knownOrderIds.add(fullOrder.id);
      localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(filtered));
    } catch (e) {}

    this.incrementSales(cartItems);
    this.reserveStock(cartItems);
    this.logActivity("order_created", `طلب جديد #${fullOrder.id} بقيمة ${fullOrder.total} ج.م`);

    const isAdmin = typeof document !== 'undefined' && (
      document.body.classList.contains("is-admin-user") || !!document.getElementById("adminPageRoot")
    );
    if (isAdmin) {
      this.playLuxuryChime();
    }

    window.dispatchEvent(new CustomEvent("kk_new_order_placed", { detail: fullOrder }));
    return fullOrder;
  }

  updateOrderStatus(orderId, newStatus) {
    const orders = this.getOrders();
    const order = orders.find(o => o.id === orderId);
    if (order) {
      const oldStatus = order.status;
      order.status = newStatus;
      if (newStatus !== "pending" && newStatus !== "received") {
        order.isRead = true;
      }
      localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(orders));
      
      // Stock management (PRD Section 6): Release stock if cancelled or failed
      if ((newStatus === "cancelled" || newStatus === "failed") && (oldStatus !== "cancelled" && oldStatus !== "failed")) {
        this.releaseStock(order.items);
      } else if ((oldStatus === "cancelled" || oldStatus === "failed") && (newStatus !== "cancelled" && newStatus !== "failed")) {
        this.reserveStock(order.items);
      }

      this.updateOrderStatusInCloud(orderId, newStatus);
      this.recalculateAllProductSales();
      this.logActivity("order_status_updated", `تغيير حالة الطلب #${orderId} إلى: ${newStatus}`);
      window.dispatchEvent(new CustomEvent("kk_orders_updated"));
      return true;
    }
    return false;
  }

  updateOrderPaymentStatus(orderId, paymentStatus) {
    const orders = this.getOrders();
    const order = orders.find(o => o.id === orderId);
    if (order) {
      order.paymentStatus = paymentStatus;
      order.paymentStatusText = paymentStatus === "collected" ? "تم التحصيل نقدياً بنجاح" : "الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد";
      order.paymentStatusTextEn = paymentStatus === "collected" ? "Cash Collected Successfully" : "Cash on delivery — not yet collected";
      if (paymentStatus === "collected") {
        order.paidAt = Date.now();
      }
      localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(orders));

      // PATCH server
      fetch("/api/orders", {
        method: "PATCH",
        cache: "no-store",
        headers: this.getCloudHeaders(),
        body: JSON.stringify({ id: orderId, paymentStatus })
      }).catch(() => {});

      this.logActivity("payment_status_updated", `تحديث حالة الدفع للطلب #${orderId} إلى: ${paymentStatus === "collected" ? "تم التحصيل" : "لم يتم التحصيل"}`);
      window.dispatchEvent(new CustomEvent("kk_orders_updated"));
      return true;
    }
    return false;
  }

  markAllOrdersAsRead() {
    const orders = this.getOrders();
    orders.forEach(o => o.isRead = true);
    localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(orders));
    window.dispatchEvent(new CustomEvent("kk_orders_updated"));
  }

  deleteOrder(orderId) {
    let orders = this.getOrders();
    const target = orders.find(o => o.id === orderId);
    if (target) {
      this.saveWebRestorePoint(`قبل حذف طلب: #${orderId} (${target.customer?.name || ''})`);
    }
    orders = orders.filter(o => o.id !== orderId);
    this.knownOrderIds.delete(orderId);
    localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(orders));

    this.deleteOrderFromCloud(orderId);
    this.recalculateAllProductSales();
    window.dispatchEvent(new CustomEvent("kk_orders_updated"));
    return true;
  }

  getUnreadOrdersCount() {
    const orders = this.getOrders();
    return orders.filter(o => o.status === "pending" || !o.isRead).length;
  }

  incrementSales(cartItems) {
    const products = this.getProducts();
    cartItems.forEach(item => {
      const p = products.find(prod => prod.id === item.id);
      if (p) {
        const qty = parseInt(item.qty) || 1;
        p.salesCount = (p.salesCount || 0) + qty;
        this.sendProductToCloud(p); // Multi-device cloud sync
      }
    });
    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
    this.recalculateAllProductSales();
    window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: products }));
  }

  recalculateAllProductSales() {
    const orders = this.getOrders();
    const products = this.getProducts();
    const activeOrders = orders.filter(o => o.status !== "cancelled");

    const salesMap = new Map();
    activeOrders.forEach(o => {
      if (Array.isArray(o.items)) {
        o.items.forEach(it => {
          if (it.id) {
            salesMap.set(it.id, (salesMap.get(it.id) || 0) + (parseInt(it.qty) || 1));
          }
        });
      }
    });

    let hasChanges = false;
    products.forEach(p => {
      const orderSales = salesMap.get(p.id) || 0;
      if (typeof p.baseSalesCount !== "number") {
        p.baseSalesCount = p.salesCount || (p.isCustom ? 0 : 10);
      }
      const calculated = p.baseSalesCount + orderSales;
      if (p.salesCount !== calculated) {
        p.salesCount = calculated;
        hasChanges = true;
      }
    });

    if (hasChanges) {
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
      window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: products }));
    }
  }

  getAnalytics() {
    const orders = this.getOrders();
    const products = this.getProducts();

    // 1. Total revenue excludes cancelled orders!
    const activeOrders = orders.filter(o => o.status !== "cancelled");
    const totalRevenue = activeOrders.reduce((sum, o) => sum + (o.total || 0), 0);
    const totalOrdersCount = orders.length;
    const pendingOrdersCount = orders.filter(o => o.status === "pending").length;
    const activeProductsCount = products.length;

    // 2. Real-time sales per product
    const salesMap = new Map();
    activeOrders.forEach(o => {
      if (Array.isArray(o.items)) {
        o.items.forEach(it => {
          if (it.id) {
            salesMap.set(it.id, (salesMap.get(it.id) || 0) + (parseInt(it.qty) || 1));
          }
        });
      }
    });

    const enrichedProducts = products.map(p => {
      const orderSales = salesMap.get(p.id) || 0;
      const base = typeof p.baseSalesCount === "number" ? p.baseSalesCount : (p.salesCount || (p.isCustom ? 0 : 10));
      const totalSales = Math.max(p.salesCount || 0, base + orderSales);
      return {
        ...p,
        salesCount: totalSales,
        totalRevenue: totalSales * (p.price || 0)
      };
    });

    // 3. Best Sellers:
    // Boost products marked with isBestSeller to top, then sort by salesCount descending
    const bestSellers = [...enrichedProducts]
      .sort((a, b) => {
        if (a.isBestSeller && !b.isBestSeller && (b.salesCount || 0) < 50) return -1;
        if (!a.isBestSeller && b.isBestSeller && (a.salesCount || 0) < 50) return 1;
        return (b.salesCount || 0) - (a.salesCount || 0);
      })
      .slice(0, 10);

    return {
      totalRevenue,
      totalOrdersCount,
      pendingOrdersCount,
      activeProductsCount,
      bestSellers
    };
  }

  // --------------------------------------------------------------------------
  // CATEGORIES MANAGEMENT (إدارة وتخصيص الأقسام والأقسام الفرعية ديناميكياً)
  // --------------------------------------------------------------------------
  getCategories() {
    let cats = [];
    try {
      const raw = localStorage.getItem(DB_KEYS.CATEGORIES);
      const parsed = raw ? JSON.parse(raw) : [];
      if (Array.isArray(parsed) && parsed.length > 0) cats = parsed;
    } catch (e) {}

    if (!cats || cats.length === 0) {
      cats = typeof INITIAL_CATEGORIES !== "undefined" ? [...INITIAL_CATEGORIES] : [];
    }

    const defaultMap = new Map();
    if (typeof INITIAL_CATEGORIES !== "undefined") {
      INITIAL_CATEGORIES.forEach(c => defaultMap.set(c.id, c));
    }

    return cats.map(c => {
      const def = defaultMap.get(c.id);
      return {
        ...c,
        enName: c.enName || (def ? def.enName : c.name)
      };
    });
  }

  async addCategory(categoryData) {
    if (!categoryData || !categoryData.name || !categoryData.name.trim()) {
      return { success: false, error: "اسم القسم إجباري" };
    }
    const name = categoryData.name.trim();
    const categories = this.getCategories();
    const parentId = (categoryData.parentId && categoryData.parentId.trim()) ? categoryData.parentId.trim() : null;

    // Check if name already exists under the same parent
    if (categories.some(c => c.name.toLowerCase() === name.toLowerCase() && (c.parentId || null) === parentId)) {
      return { success: false, error: "هذا القسم موجود بالفعل في الكتالوج" };
    }

    let id = (categoryData.id || "").trim().toLowerCase().replace(/[^a-z0-9_-]/g, "-");
    if (!id || categories.some(c => c.id === id)) {
      id = "cat-" + Date.now().toString().slice(-5);
    }

    const newCat = {
      id: id,
      name: name,
      parentId: parentId,
      isCustom: true,
      createdAt: Date.now()
    };

    categories.push(newCat);
    localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(categories));
    window.CATEGORIES = categories;
    if (typeof CATEGORIES !== "undefined") CATEGORIES = categories;

    await this.sendCategoriesToCloud(categories);
    window.dispatchEvent(new CustomEvent("kk_categories_updated", { detail: { action: "add", category: newCat } }));
    return { success: true, category: newCat };
  }

  async updateCategory(id, updatedData) {
    if (!id || id === "all") return { success: false, error: "لا يمكن تعديل هذا القسم الأساسي" };
    const categories = this.getCategories();
    const cat = categories.find(c => c.id === id);
    if (!cat) return { success: false, error: "القسم غير موجود" };

    if (updatedData.name && updatedData.name.trim()) cat.name = updatedData.name.trim();
    if (typeof updatedData.parentId !== "undefined") {
      cat.parentId = (updatedData.parentId && updatedData.parentId.trim()) ? updatedData.parentId.trim() : null;
    }

    localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(categories));
    window.CATEGORIES = categories;
    if (typeof CATEGORIES !== "undefined") CATEGORIES = categories;

    await this.sendCategoriesToCloud(categories);
    window.dispatchEvent(new CustomEvent("kk_categories_updated", { detail: { action: "update", category: cat } }));
    return { success: true, category: cat };
  }

  async deleteCategory(id) {
    if (!id || id === "all") return { success: false, error: "لا يمكن حذف قسم الكل المعروض" };
    let categories = this.getCategories();
    const deletedCat = categories.find(c => c.id === id);
    if (!deletedCat) return { success: false, error: "القسم غير موجود" };

    // Auto-save a restore point before deleting category
    this.saveWebRestorePoint(`قبل حذف قسم: ${deletedCat.name}`);

    // If deleting a parent category, also delete or un-parent its subcategories
    categories = categories.filter(c => c.id !== id && c.parentId !== id);
    localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(categories));
    window.CATEGORIES = categories;
    if (typeof CATEGORIES !== "undefined") CATEGORIES = categories;

    await this.sendCategoriesToCloud(categories);
    window.dispatchEvent(new CustomEvent("kk_categories_updated", { detail: { action: "delete", id } }));
    return { success: true };
  }

  async syncCategoriesFromCloud() {
    try {
      const customUrl = this.getCustomCloudUrl();
      const t = Date.now();
      let cloudCats = null;

      if (customUrl) {
        try {
          const res = await fetch(`${customUrl}/categories.json?t=${t}`, {
            cache: "no-store",
            headers: { "Accept": "application/json" }
          });
          if (res.ok) {
            const raw = await res.json();
            if (raw && Array.isArray(raw)) cloudCats = raw;
            else if (raw && typeof raw === "object") cloudCats = Object.values(raw);
          }
        } catch (e) {}
      }

      if (!cloudCats) {
        try {
          const res = await fetch(`/api/settings?type=categories&t=${t}`, {
            cache: "no-store",
            headers: this.getCloudHeaders()
          });
          if (res.ok) {
            const data = await res.json();
            if (data && data.success && Array.isArray(data.categories)) {
              cloudCats = data.categories;
            }
          }
        } catch (e) {}
      }

      if (cloudCats && Array.isArray(cloudCats) && cloudCats.length > 0) {
        const localCats = this.getCategories();
        if (JSON.stringify(cloudCats) !== JSON.stringify(localCats)) {
          localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(cloudCats));
          window.CATEGORIES = cloudCats;
          if (typeof CATEGORIES !== "undefined") CATEGORIES = cloudCats;
          window.dispatchEvent(new CustomEvent("kk_categories_updated", { detail: { merged: false, categories: cloudCats } }));
        }
      }
    } catch (e) {}
  }

  async sendCategoriesToCloud(categories) {
    const customUrl = this.getCustomCloudUrl();
    if (customUrl) {
      try {
        await fetch(`${customUrl}/categories.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(categories)
        });
      } catch (e) {}
    }

    try {
      await fetch("/api/settings", {
        method: "POST",
        cache: "no-store",
        headers: this.getCloudHeaders(),
        body: JSON.stringify({ type: "categories", categories: categories })
      });
    } catch (e) {}
  }

  // --------------------------------------------------------------------------
  // SHOWROOM SETTINGS & CONTACT INFO (أرقام التواصل واللينكات)
  // --------------------------------------------------------------------------
  getSettings() {
    try {
      const raw = localStorage.getItem(DB_KEYS.SETTINGS);
      const parsed = raw ? JSON.parse(raw) : null;
      const base = parsed && typeof parsed === "object" ? parsed : (typeof INITIAL_SHOWROOM_INFO !== "undefined" ? { ...INITIAL_SHOWROOM_INFO } : (typeof SHOWROOM_INFO !== "undefined" ? { ...SHOWROOM_INFO } : {}));
      base.social = { ...(base.social || {}), designerUrl: "https://karimodesign.vercel.app/" };
      return base;
    } catch (e) {
      const fallback = typeof INITIAL_SHOWROOM_INFO !== "undefined" ? { ...INITIAL_SHOWROOM_INFO } : {};
      fallback.social = { ...(fallback.social || {}), designerUrl: "https://karimodesign.vercel.app/" };
      return fallback;
    }
  }

  updateSettings(newSettings) {
    if (!newSettings || typeof newSettings !== "object") return { success: false };
    const current = this.getSettings();
    const merged = {
      ...current,
      ...newSettings,
      social: {
        ...(current.social || {}),
        ...(newSettings.social || {}),
        designerUrl: "https://karimodesign.vercel.app/" // Permanent locked designer attribution
      },
      updatedAt: Date.now()
    };

    localStorage.setItem(DB_KEYS.SETTINGS, JSON.stringify(merged));
    window.SHOWROOM_INFO = merged;
    if (typeof SHOWROOM_INFO !== "undefined") SHOWROOM_INFO = merged;

    this.sendSettingsToCloud(merged);
    window.dispatchEvent(new CustomEvent("kk_settings_updated", { detail: merged }));
    return { success: true, settings: merged };
  }

  async syncSettingsFromCloud() {
    try {
      const customUrl = this.getCustomCloudUrl();
      const t = Date.now();
      let cloudSettings = null;

      if (customUrl) {
        try {
          const res = await fetch(`${customUrl}/settings.json?t=${t}`, {
            cache: "no-store",
            headers: { "Accept": "application/json" }
          });
          if (res.ok) {
            cloudSettings = await res.json();
          }
        } catch (e) {}
      }

      if (!cloudSettings) {
        try {
          const res = await fetch(`/api/settings?type=settings&t=${t}`, {
            cache: "no-store",
            headers: this.getCloudHeaders()
          });
          if (res.ok) {
            const data = await res.json();
            if (data && data.success && data.settings) {
              cloudSettings = data.settings;
            }
          }
        } catch (e) {}
      }

      if (cloudSettings && typeof cloudSettings === "object") {
        const localSettings = this.getSettings();
        if (JSON.stringify(cloudSettings) !== JSON.stringify(localSettings)) {
          const merged = { ...localSettings, ...cloudSettings, social: { ...localSettings.social, ...(cloudSettings.social || {}) } };
          localStorage.setItem(DB_KEYS.SETTINGS, JSON.stringify(merged));
          window.SHOWROOM_INFO = merged;
          if (typeof SHOWROOM_INFO !== "undefined") SHOWROOM_INFO = merged;
          window.dispatchEvent(new CustomEvent("kk_settings_updated", { detail: merged }));
        }
      }
    } catch (e) {}
  }

  async sendSettingsToCloud(settings) {
    const customUrl = this.getCustomCloudUrl();
    if (customUrl) {
      try {
        fetch(`${customUrl}/settings.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(settings)
        }).catch(() => null);
      } catch (e) {}
    }

    try {
      await fetch("/api/settings", {
        method: "POST",
        cache: "no-store",
        headers: this.getCloudHeaders(),
        body: JSON.stringify({ type: "settings", settings: settings })
      });
    } catch (e) {}
  }

  // --------------------------------------------------------------------------
  // DAILY BACKUP & RESTORE SYSTEM (نظام النسخ الاحتياطي والاسترجاع المزدوج)
  // --------------------------------------------------------------------------
  generateBackupData(label = "Daily Backup") {
    const products = this.getProducts();
    const orders = this.getOrders();
    const categories = this.getCategories();
    const settings = this.getSettings();
    const analytics = this.getAnalytics();
    const now = new Date();
    const dateFormatted = now.toISOString().slice(0, 10);
    const timeFormatted = now.toLocaleTimeString("ar-EG", { hour: "2-digit", minute: "2-digit" });

    return {
      system: "Kased Karim Lighting OS",
      version: "2.1",
      backupType: "full_snapshot",
      label: label,
      timestamp: Date.now(),
      dateFormatted: dateFormatted,
      timeFormatted: timeFormatted,
      analytics: {
        totalRevenue: analytics.totalRevenue,
        totalOrdersCount: analytics.totalOrdersCount,
        pendingOrdersCount: analytics.pendingOrdersCount,
        activeProductsCount: analytics.activeProductsCount,
        bestSellersSummary: (analytics.bestSellers || []).map(b => ({
          id: b.id,
          name: b.name,
          categoryName: b.categoryName,
          price: b.price,
          salesCount: b.salesCount || 0,
          totalRevenue: (b.price || 0) * (b.salesCount || 0)
        }))
      },
      counts: {
        products: products.length,
        orders: orders.length,
        categories: categories.length
      },
      products: products,
      orders: orders,
      categories: categories,
      settings: settings
    };
  }

  async downloadBackupFile(label = "نسخة احتياطية يومية") {
    const backupData = this.generateBackupData(label);
    const jsonStr = JSON.stringify(backupData, null, 2);
    const now = new Date();
    const dateStr = now.toISOString().slice(0, 10);
    const fileName = `kased-karim-backup-${dateStr}.json`;

    let savedLocally = false;

    // 1. Native Windows/OS "Save As" Location Picker
    if (typeof window.showSaveFilePicker === "function") {
      try {
        const fileHandle = await window.showSaveFilePicker({
          suggestedName: fileName,
          types: [{
            description: "ملف نسخة احتياطية لكافة بيانات المعرض (JSON)",
            accept: { "application/json": [".json"] }
          }]
        });
        const writableStream = await fileHandle.createWritable();
        await writableStream.write(jsonStr);
        await writableStream.close();
        savedLocally = true;
      } catch (err) {
        if (err.name === "AbortError") {
          return { success: false, canceled: true };
        }
        console.warn("File Picker API fallback:", err);
      }
    }

    // 2. Standard Browser Download Fallback (Mobile / Non-supported desktop browsers)
    if (!savedLocally) {
      const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    }

    // Record today as having downloaded backup
    localStorage.setItem("kk_last_downloaded_backup_date", dateStr);
    localStorage.setItem("kk_last_downloaded_backup_time", Date.now().toString());

    // Also auto-save a web restore point
    this.saveWebRestorePoint(`تحميل ملف جهاز: ${dateStr}`, backupData);

    return { success: true, fileName, backupData };
  }

  getWebRestorePoints() {
    try {
      const raw = localStorage.getItem(DB_KEYS.BACKUPS);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }

  saveWebRestorePoint(label = "نقطة استرجاع", explicitData = null) {
    const backupData = explicitData || this.generateBackupData(label);
    let points = this.getWebRestorePoints();

    const newPoint = {
      id: "RST-" + Date.now().toString().slice(-7),
      timestamp: Date.now(),
      dateFormatted: backupData.dateFormatted,
      timeFormatted: backupData.timeFormatted,
      label: label,
      counts: backupData.counts,
      totalRevenue: backupData.analytics?.totalRevenue || 0,
      data: backupData
    };

    // Prepend and limit to 15 points
    points = [newPoint, ...points.filter(p => p.id !== newPoint.id)].slice(0, 15);
    localStorage.setItem(DB_KEYS.BACKUPS, JSON.stringify(points));

    // Push latest restore point to cloud
    const customUrl = this.getCustomCloudUrl();
    if (customUrl) {
      try {
        fetch(`${customUrl}/backups/latest.json`, {
          method: "PUT",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(newPoint)
        }).catch(() => null);
      } catch (e) {}
    }

    // Always push snapshot to /api/backup so all admin devices can access it!
    fetch("/api/backup", {
      method: "POST",
      cache: "no-store",
      headers: this.getCloudHeaders(),
      body: JSON.stringify(newPoint)
    }).catch(() => null);

    window.dispatchEvent(new CustomEvent("kk_restore_points_updated"));
    return newPoint;
  }

  checkAndCreateDailyRestorePoint() {
    try {
      const today = new Date().toISOString().slice(0, 10);
      const lastDaily = localStorage.getItem("kk_last_daily_restore_point_date");
      if (lastDaily !== today) {
        this.saveWebRestorePoint(`نسخة يومية تلقائية (${today})`);
        localStorage.setItem("kk_last_daily_restore_point_date", today);
      }
    } catch (e) {}
  }

  async restoreFromData(backupData, syncToCloud = true) {
    if (!backupData || typeof backupData !== "object") {
      return { success: false, error: "بيانات النسخة الاحتياطية غير صالحة" };
    }

    // Auto-save a restore point of current state before applying restore!
    this.saveWebRestorePoint("نقطة أمان تلقائية (قبل الاسترجاع)");

    // 1. Restore Products
    if (Array.isArray(backupData.products)) {
      // Un-tombstone any restored product IDs so they won't be filtered out
      const restoredIds = new Set(backupData.products.map(p => p.id));
      try {
        const rawDel = localStorage.getItem("kk_deleted_product_ids_v1");
        if (rawDel) {
          const remainingDel = JSON.parse(rawDel).filter(id => !restoredIds.has(id));
          localStorage.setItem("kk_deleted_product_ids_v1", JSON.stringify(remainingDel));
        }
      } catch(e) {}

      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(backupData.products));
      window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: { merged: false, products: backupData.products } }));
    }

    // 2. Restore Orders
    if (Array.isArray(backupData.orders)) {
      localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(backupData.orders));
      this.knownOrderIds.clear();
      backupData.orders.forEach(o => this.knownOrderIds.add(o.id));
      this.recalculateAllProductSales();
      window.dispatchEvent(new CustomEvent("kk_orders_updated"));
    }

    // 3. Restore Categories
    if (Array.isArray(backupData.categories) && backupData.categories.length > 0) {
      localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(backupData.categories));
      window.CATEGORIES = backupData.categories;
      if (typeof CATEGORIES !== "undefined") CATEGORIES = backupData.categories;
      window.dispatchEvent(new CustomEvent("kk_categories_updated", { detail: { merged: false, categories: backupData.categories } }));
    }

    // 4. Restore Settings
    if (backupData.settings && typeof backupData.settings === "object") {
      const safeSettings = { ...backupData.settings, updatedAt: Date.now() };
      localStorage.setItem(DB_KEYS.SETTINGS, JSON.stringify(safeSettings));
      window.SHOWROOM_INFO = safeSettings;
      if (typeof SHOWROOM_INFO !== "undefined") SHOWROOM_INFO = safeSettings;
      window.dispatchEvent(new CustomEvent("kk_settings_updated", { detail: safeSettings }));
    }

    // 5. Cloud Synchronization (Multi-Device Ground Truth Overwrite)
    let cloudSynced = false;
    if (syncToCloud) {
      const cloudHeaders = this.getCloudHeaders();

      // Primary: Atomic multi-device cloud restore via /api/backup
      try {
        const backupRes = await fetch("/api/backup", {
          method: "POST",
          cache: "no-store",
          headers: cloudHeaders,
          body: JSON.stringify({
            action: "restore",
            data: {
              products: backupData.products || [],
              orders: backupData.orders || [],
              categories: backupData.categories || [],
              settings: backupData.settings ? { ...backupData.settings, updatedAt: Date.now() } : {}
            }
          })
        });
        if (backupRes.ok) {
          cloudSynced = true;
        }
      } catch (errBackup) {
        console.warn("Restore backup endpoint error:", errBackup);
      }

      // Secondary: Direct Batch endpoints confirmation
      try {
        const batchTasks = [];
        if (Array.isArray(backupData.products) && backupData.products.length > 0) {
          batchTasks.push(this.syncAllLocalProductsToCloud());
        }
        if (Array.isArray(backupData.orders)) {
          batchTasks.push(
            fetch("/api/orders", {
              method: "PUT",
              cache: "no-store",
              headers: cloudHeaders,
              body: JSON.stringify({ orders: backupData.orders })
            })
          );
        }
        if (Array.isArray(backupData.categories) && backupData.categories.length > 0) {
          batchTasks.push(this.sendCategoriesToCloud(backupData.categories));
        }
        if (backupData.settings && typeof backupData.settings === "object") {
          batchTasks.push(this.sendSettingsToCloud({ ...backupData.settings, updatedAt: Date.now() }));
        }
        await Promise.allSettled(batchTasks);
      } catch (e) {}
    }

    return {
      success: true,
      cloudSynced,
      restoredCounts: {
        products: backupData.products?.length || 0,
        orders: backupData.orders?.length || 0,
        categories: backupData.categories?.length || 0
      }
    };
  }

  async restoreFromWebPoint(pointId) {
    const points = this.getWebRestorePoints();
    const point = points.find(p => p.id === pointId);
    if (!point || !point.data) {
      return { success: false, error: "نقطة الاسترجاع غير موجودة" };
    }
    return await this.restoreFromData(point.data, true);
  }

  deleteWebRestorePoint(pointId) {
    let points = this.getWebRestorePoints();
    points = points.filter(p => p.id !== pointId);
    localStorage.setItem(DB_KEYS.BACKUPS, JSON.stringify(points));
    window.dispatchEvent(new CustomEvent("kk_restore_points_updated"));
    return true;
  }

  async restoreFactoryDefaults() {
    this.saveWebRestorePoint("قبل استعادة ضبط المصنع");

    const defaultProducts = [...INITIAL_PRODUCTS];
    const defaultOrders = [];
    const defaultCategories = typeof INITIAL_CATEGORIES !== "undefined" ? [...INITIAL_CATEGORIES] : [...CATEGORIES];
    const defaultSettings = typeof INITIAL_SHOWROOM_INFO !== "undefined" ? { ...INITIAL_SHOWROOM_INFO } : { ...SHOWROOM_INFO };

    return await this.restoreFromData({
      products: defaultProducts,
      orders: defaultOrders,
      categories: defaultCategories,
      settings: defaultSettings
    }, true);
  }

  // --------------------------------------------------------------------------
  // CUSTOMER ACCOUNT MANAGEMENT (PRD Sections 2, 3, 4 & 10)
  // --------------------------------------------------------------------------
  getCustomer() {
    try {
      const data = localStorage.getItem(DB_KEYS.CUSTOMER_USER) || localStorage.getItem("kk_customer_account");
      return data ? JSON.parse(data) : null;
    } catch (e) {
      return null;
    }
  }

  saveCustomer(customer) {
    if (!customer) return;
    try {
      localStorage.setItem(DB_KEYS.CUSTOMER_USER, JSON.stringify(customer));
      localStorage.setItem("kk_customer_account", JSON.stringify(customer));
      if (customer.name) localStorage.setItem("kk_customer_name", customer.name);
      if (customer.phone) localStorage.setItem("kk_customer_phone", customer.phone);
      window.dispatchEvent(new CustomEvent("kk_customer_auth_changed", { detail: customer }));
    } catch (e) {}
  }

  getCustomerToken() {
    try {
      return localStorage.getItem(DB_KEYS.CUSTOMER_TOKEN) || null;
    } catch (e) {
      return null;
    }
  }

  async customerRegister(name, phone, email, password) {
    const res = await fetch("/api/customer?action=register", {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, phone, email, password })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || "تعذر إنشاء الحساب");
    }
    if (data.token && data.customer) {
      localStorage.setItem(DB_KEYS.CUSTOMER_TOKEN, data.token);
      localStorage.setItem(DB_KEYS.CUSTOMER_USER, JSON.stringify(data.customer));
      localStorage.setItem("kk_customer_account", JSON.stringify(data.customer));
      window.dispatchEvent(new CustomEvent("kk_customer_auth_changed", { detail: data.customer }));
    }
    return data.customer;
  }

  async customerLogin(identifier, password) {
    const res = await fetch("/api/customer?action=login", {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identifier, password })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || "بيانات الدخول غير صحيحة");
    }
    if (data.token && data.customer) {
      localStorage.setItem(DB_KEYS.CUSTOMER_TOKEN, data.token);
      localStorage.setItem(DB_KEYS.CUSTOMER_USER, JSON.stringify(data.customer));
      localStorage.setItem("kk_customer_account", JSON.stringify(data.customer));
      window.dispatchEvent(new CustomEvent("kk_customer_auth_changed", { detail: data.customer }));
    }
    return data.customer;
  }

  customerLogout() {
    localStorage.removeItem(DB_KEYS.CUSTOMER_TOKEN);
    localStorage.removeItem(DB_KEYS.CUSTOMER_USER);
    localStorage.removeItem("kk_customer_account");
    window.dispatchEvent(new CustomEvent("kk_customer_auth_changed", { detail: null }));
  }

  async getCustomerOrders() {
    const token = this.getCustomerToken();
    if (!token) return [];
    try {
      const res = await fetch("/api/customer?action=orders", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        return data.orders || [];
      }
    } catch (e) {}
    return [];
  }

  // --------------------------------------------------------------------------
  // PRODUCT REVIEWS & MODERATION (PRD Section 11)
  // --------------------------------------------------------------------------
  async getProductReviews(productId) {
    try {
      const res = await fetch(`/api/reviews?productId=${encodeURIComponent(productId)}`, { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        if (data.success && Array.isArray(data.reviews)) {
          return data.reviews;
        }
      }
    } catch (e) {}
    const fallback = (typeof REVIEWS !== "undefined" ? REVIEWS : []).filter(r => r.productId === productId && r.status === "approved");
    return fallback;
  }

  async submitReview(productId, productName, author, rating, comment) {
    const res = await fetch("/api/reviews", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ productId, productName, author, rating, comment })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || "تعذر إرسال التقييم");
    }
    this.logActivity("review_submitted", `تقييم جديد للمنتج: ${productName} بواسطة ${author}`);
    return data.review;
  }

  async getAllReviewsForAdmin() {
    const headers = this.getCloudHeaders();
    try {
      const res = await fetch("/api/reviews?all=1", { headers, cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        return data.reviews || [];
      }
    } catch (e) {}
    return typeof REVIEWS !== "undefined" ? REVIEWS : [];
  }

  async moderateReview(reviewId, status) {
    const headers = this.getCloudHeaders();
    const res = await fetch("/api/reviews", {
      method: "PATCH",
      headers,
      body: JSON.stringify({ id: reviewId, status })
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || "تعذر تعديل التقييم");
    }
    this.logActivity("review_moderated", `تعديل حالة التقييم #${reviewId} إلى ${status}`);
    window.dispatchEvent(new CustomEvent("kk_reviews_updated"));
    return true;
  }

  async deleteReview(reviewId) {
    const headers = this.getCloudHeaders();
    const res = await fetch(`/api/reviews?id=${encodeURIComponent(reviewId)}`, {
      method: "DELETE",
      headers
    });
    const data = await res.json();
    if (!res.ok || !data.success) {
      throw new Error(data.error || "تعذر حذف التقييم");
    }
    this.logActivity("review_deleted", `حذف التقييم #${reviewId}`);
    window.dispatchEvent(new CustomEvent("kk_reviews_updated"));
    return true;
  }

  // --------------------------------------------------------------------------
  // DELIVERY AREAS & STOCK RESERVATION (PRD Sections 5 & 6)
  // --------------------------------------------------------------------------
  getDeliveryAreas() {
    let areas = [];
    try {
      const saved = localStorage.getItem(DB_KEYS.DELIVERY_AREAS);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) areas = parsed;
      }
    } catch (e) {}

    if (!areas || areas.length === 0) {
      areas = typeof DELIVERY_AREAS !== "undefined" ? [...DELIVERY_AREAS] : [];
    }

    // Ensure all areas have names array for multi-region support
    return areas.map(a => {
      let names = Array.isArray(a.names) && a.names.length > 0 
        ? a.names 
        : (a.name ? a.name.split(/[،,]/).map(s => s.trim()).filter(Boolean) : [a.nameAr || a.id]);
      let name = a.name || names.join("، ") || a.nameAr || a.id;
      return {
        ...a,
        name: name,
        names: names,
        fee: Number(a.fee) || 0,
        active: a.active !== false
      };
    });
  }

  updateDeliveryAreas(areas) {
    localStorage.setItem(DB_KEYS.DELIVERY_AREAS, JSON.stringify(areas));
    this.logActivity("delivery_areas_updated", "تحديث مناطق وأسعار التوصيل");
    window.dispatchEvent(new CustomEvent("kk_delivery_areas_updated"));
  }

  reserveStock(items) {
    if (!Array.isArray(items) || items.length === 0) return;
    const products = this.getProducts();
    let changed = false;
    items.forEach(item => {
      const prod = products.find(p => p.id === item.id);
      if (prod) {
        const currentStock = parseInt(prod.stock !== undefined ? prod.stock : 10, 10);
        const qty = parseInt(item.qty || 1, 10);
        prod.stock = Math.max(0, currentStock - qty);
        prod.inStock = prod.stock > 0;
        changed = true;
      }
    });
    if (changed) {
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
      window.dispatchEvent(new CustomEvent("kk_products_updated"));
    }
  }

  releaseStock(items) {
    if (!Array.isArray(items) || items.length === 0) return;
    const products = this.getProducts();
    let changed = false;
    items.forEach(item => {
      const prod = products.find(p => p.id === item.id);
      if (prod) {
        const currentStock = parseInt(prod.stock !== undefined ? prod.stock : 0, 10);
        const qty = parseInt(item.qty || 1, 10);
        prod.stock = currentStock + qty;
        prod.inStock = prod.stock > 0;
        changed = true;
      }
    });
    if (changed) {
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
      window.dispatchEvent(new CustomEvent("kk_products_updated"));
    }
  }

  updateProductStock(productId, newStock) {
    const products = this.getProducts();
    const prod = products.find(p => p.id === productId);
    if (prod) {
      prod.stock = Math.max(0, parseInt(newStock, 10) || 0);
      prod.inStock = prod.stock > 0;
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
      this.sendProductToCloud(prod);
      this.logActivity("stock_updated", `تعديل مخزون ${prod.name} إلى ${prod.stock} وحدة`);
      window.dispatchEvent(new CustomEvent("kk_products_updated"));
      return true;
    }
    return false;
  }

  // --------------------------------------------------------------------------
  // ADMINISTRATIVE AUDIT & ACTIVITY LOG (PRD Section 3)
  // --------------------------------------------------------------------------
  logActivity(action, details) {
    try {
      const logs = this.getAuditLogs();
      const newEntry = {
        id: "LOG-" + Date.now().toString(36) + "-" + Math.random().toString(36).substring(2, 6),
        action,
        details,
        timestamp: Date.now(),
        dateFormatted: new Date().toLocaleDateString("ar-EG", {
          year: "numeric",
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit"
        })
      };
      logs.unshift(newEntry);
      localStorage.setItem(DB_KEYS.AUDIT_LOGS, JSON.stringify(logs.slice(0, 100)));
      window.dispatchEvent(new CustomEvent("kk_audit_logs_updated"));
    } catch (e) {}
  }

  getAuditLogs() {
    try {
      const data = localStorage.getItem(DB_KEYS.AUDIT_LOGS);
      return data ? JSON.parse(data) : [];
    } catch (e) {
      return [];
    }
  }
}

// Global Singleton Database Instance
window.KK_DB = new KasedKarimDB();
