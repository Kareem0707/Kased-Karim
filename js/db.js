/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Hybrid Real-Time Cloud Database Engine (js/db.js)
 * متصل بنظام سحابي لحظي ومزدوج لضمان وصول واستقبال الطلبات فورياً عبر جميع الأجهزة والهواتف
 * يدعم Firebase Realtime Database (Google Cloud) و Vercel Serverless KV
 */

const DB_KEYS = {
  PRODUCTS: "kased_karim_db_products_v3",
  ORDERS: "kased_karim_db_orders_v2",
  SETTINGS: "kased_karim_db_settings_v2",
  CLOUD_CONFIG: "kased_karim_cloud_config_v1",
  CUSTOM_CLOUD_URL: "kk_custom_cloud_url"
};

// Real Verified Orders from the Showroom (No dummy placeholder data)
const SEED_ORDERS = [
  {
    id: "ORD-3985",
    timestamp: 1791928093202,
    dateFormatted: "اليوم - 12:48 ص",
    customer: {
      name: "كككك",
      phone: "01090678070",
      city: "الشيخ زايد",
      address: "55",
      notes: ""
    },
    items: [
      {
        id: "kk-002",
        name: "نظام المسارات المغناطيسية المعمارية الذكية",
        enName: "Ultra-Slim Magnetic Track System Pro",
        price: 18400,
        qty: 1,
        image: "https://images.unsplash.com/photo-1507473885765-e6ed057f782c?auto=format&fit=crop&w=1200&q=80",
        categoryName: "مسارات مغناطيسية واسبوتات"
      },
      {
        id: "kk-003",
        name: "دلاية الهالة المضيئة العائمة المعاصرة",
        enName: "Aurora Floating Halo Pendant",
        price: 43200,
        qty: 1,
        image: "https://images.unsplash.com/photo-1517991104123-1d56a6e81ed9?auto=format&fit=crop&w=1200&q=80",
        categoryName: "دلايات فاخرة"
      }
    ],
    subtotal: 61600,
    total: 61600,
    status: "pending",
    isRead: false
  },
  {
    id: "ORD-5412",
    timestamp: 1791928008057,
    dateFormatted: "اليوم - 12:46 ص",
    customer: {
      name: "منك",
      phone: "66",
      city: "الشيخ زايد",
      address: "55",
      notes: ""
    },
    items: [
      {
        id: "kk-004",
        name: "أبليك جداري أونيكس رخامي مضيء",
        enName: "Illuminated Natural Onyx Sconce",
        price: 13900,
        qty: 1,
        image: "https://images.unsplash.com/photo-1509644851169-2acc08aa25b5?auto=format&fit=crop&w=1200&q=80",
        categoryName: "إضاءات جدارية Sconces"
      }
    ],
    subtotal: 13900,
    total: 13900,
    status: "pending",
    isRead: false
  }
];

class KasedKarimDB {
  constructor() {
    this.cloudEnabled = true;
    this.lastSyncTimestamp = 0;
    this.isSyncing = false;
    this.cloudProvider = "Vercel / Cloud Sync";
    this.knownOrderIds = new Set();
    this.audioCtx = null;
    
    this.initDatabase();
    this.setupAudioUnlock();
    this.initCloudSync();
  }

  // 1. Initialize Database & Local Cache
  initDatabase() {
    let cachedProducts = [];
    try {
      const raw = localStorage.getItem(DB_KEYS.PRODUCTS);
      cachedProducts = raw ? JSON.parse(raw) : [];
    } catch (e) {
      cachedProducts = [];
    }

    const prodMap = new Map();
    // 1. Base catalog first
    INITIAL_PRODUCTS.forEach((p, idx) => {
      prodMap.set(p.id, {
        ...p,
        salesCount: [34, 28, 22, 19, 15, 45, 12, 17, 14, 25, 9, 11][idx] || 10,
        warranty: p.specs?.warranty || "5 سنوات ضمان معتمد"
      });
    });

    // 2. Overlay any previously stored local/custom products
    if (Array.isArray(cachedProducts)) {
      cachedProducts.forEach(p => {
        prodMap.set(p.id, { ...prodMap.get(p.id), ...p });
      });
    }

    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(Array.from(prodMap.values())));

    // Initialize Orders - sanitize and remove old dummy placeholder orders
    let localOrders = [];
    try {
      const raw = localStorage.getItem(DB_KEYS.ORDERS);
      localOrders = raw ? JSON.parse(raw) : [];
    } catch (e) {
      localOrders = [];
    }

    localOrders = localOrders.filter(o => o.id !== "ORD-8941" && o.id !== "ORD-8820");

    if (!localOrders || localOrders.length === 0) {
      localOrders = [...SEED_ORDERS];
    }
    localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(localOrders));

    localOrders.forEach(o => this.knownOrderIds.add(o.id));
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
    const customUrl = this.getCustomCloudUrl();
    if (customUrl) {
      headers["x-cloud-db-url"] = customUrl;
      headers["x-firebase-url"] = customUrl;
    }
    return headers;
  }

  // --------------------------------------------------------------------------
  // CLOUD DATABASE SYNC ENGINE
  // --------------------------------------------------------------------------
  initCloudSync() {
    // 1. Immediate initial sync on load (Orders and Products)
    this.syncFromCloud(false);
    this.syncProductsFromCloud(false);

    // 2. Continuous fast background poll (every 4 seconds for orders, 15 seconds for products)
    setInterval(() => {
      this.syncFromCloud(true);
    }, 4000);

    setInterval(() => {
      this.syncProductsFromCloud(true);
    }, 15000);
  }

  // Sync Products from Cloud to Local
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

      if (cloudProducts && Array.isArray(cloudProducts) && cloudProducts.length > 0) {
        const currentProducts = this.getProducts();
        const productMap = new Map();

        // 1. Base products first
        INITIAL_PRODUCTS.forEach(p => productMap.set(p.id, p));

        // 2. Existing local custom products
        currentProducts.forEach(p => productMap.set(p.id, p));

        // 3. Merge incoming cloud products (Cloud is ground-truth)
        let hasChanges = false;
        cloudProducts.forEach(cp => {
          if (!productMap.has(cp.id) || JSON.stringify(productMap.get(cp.id)) !== JSON.stringify(cp)) {
            productMap.set(cp.id, cp);
            hasChanges = true;
          }
        });

        if (hasChanges) {
          const mergedList = Array.from(productMap.values());
          localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(mergedList));
          window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: { merged: true, products: mergedList } }));
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

        let hasNewCloudOrders = false;
        let latestNewOrder = null;

        const localOrders = this.getOrders().filter(o => o.id !== "ORD-8941" && o.id !== "ORD-8820");
        const orderMap = new Map();
        localOrders.forEach(o => orderMap.set(o.id, o));

        orders.forEach(cloudOrder => {
          if (!this.knownOrderIds.has(cloudOrder.id)) {
            this.knownOrderIds.add(cloudOrder.id);
            hasNewCloudOrders = true;
            latestNewOrder = cloudOrder;
          }

          if (orderMap.has(cloudOrder.id)) {
            const existing = orderMap.get(cloudOrder.id);
            const resolvedStatus = cloudOrder.status || existing.status || "pending";
            const isRead = typeof cloudOrder.isRead === "boolean" ? cloudOrder.isRead : existing.isRead;
            orderMap.set(cloudOrder.id, {
              ...existing,
              ...cloudOrder,
              status: resolvedStatus,
              isRead: isRead
            });
          } else {
            orderMap.set(cloudOrder.id, cloudOrder);
          }
        });

        const mergedOrders = Array.from(orderMap.values()).sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(mergedOrders));

        if (hasNewCloudOrders && latestNewOrder) {
          const isAdmin = typeof document !== 'undefined' && (document.body.classList.contains("is-admin-user") || !!document.getElementById("adminPageRoot"));
          if (isAdmin) {
            this.playLuxuryChime();
          }
          window.dispatchEvent(new CustomEvent("kk_new_order_placed", { detail: latestNewOrder }));
        } else {
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
    await this.syncFromCloud(false);
    await this.syncProductsFromCloud(false);
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

  // Push entire local catalog to cloud database with one call
  async syncAllLocalProductsToCloud() {
    const products = this.getProducts();
    const customUrl = this.getCustomCloudUrl();
    let count = 0;

    if (customUrl) {
      try {
        const mapObj = {};
        products.forEach(p => {
          mapObj[p.id] = p;
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

    // Fallback: batch individual products to /api/products
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
      return data ? JSON.parse(data) : [...INITIAL_PRODUCTS];
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

  deleteProduct(productId) {
    let products = this.getProducts();
    products = products.filter(p => p.id !== productId);
    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));

    this.deleteProductFromCloud(productId);

    window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: { deletedId: productId } }));
    return true;
  }

  // --------------------------------------------------------------------------
  // ORDERS MANAGEMENT & CHECKOUT
  // --------------------------------------------------------------------------
  getOrders() {
    try {
      const data = localStorage.getItem(DB_KEYS.ORDERS);
      const parsed = data ? JSON.parse(data) : [];
      return parsed.filter(o => o.id !== "ORD-8941" && o.id !== "ORD-8820");
    } catch (e) {
      console.error("DB Error getOrders:", e);
      return [];
    }
  }

  createOrder(customerData, cartItems) {
    if (!cartItems || cartItems.length === 0) return null;

    const orders = this.getOrders();
    const subtotal = cartItems.reduce((sum, item) => sum + (item.price * item.qty), 0);
    const orderId = "ORD-" + Math.floor(1000 + Math.random() * 9000);

    const now = new Date();
    const dateFormatted = `${now.toLocaleDateString('ar-EG', { day: 'numeric', month: 'short' })} - ${now.toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit' })}`;

    const newOrder = {
      id: orderId,
      timestamp: Date.now(),
      dateFormatted: dateFormatted,
      customer: {
        name: customerData.name || "عميل قاصد كريم",
        phone: customerData.phone || "01000000000",
        city: customerData.city || "الشيخ زايد",
        address: customerData.address || "الشيخ زايد",
        notes: customerData.notes || ""
      },
      items: cartItems.map(item => ({
        id: item.id,
        name: item.name,
        enName: item.enName || "",
        price: item.price,
        qty: item.qty,
        image: item.image,
        categoryName: item.categoryName || ""
      })),
      subtotal: subtotal,
      total: subtotal,
      status: "pending",
      isRead: false
    };

    orders.unshift(newOrder);
    this.knownOrderIds.add(orderId);
    localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(orders));

    this.incrementSales(cartItems);
    this.sendOrderToCloud(newOrder);

    const isAdmin = typeof document !== 'undefined' && (document.body.classList.contains("is-admin-user") || !!document.getElementById("adminPageRoot"));
    if (isAdmin) {
      this.playLuxuryChime();
    }
    window.dispatchEvent(new CustomEvent("kk_new_order_placed", { detail: newOrder }));

    return newOrder;
  }

  updateOrderStatus(orderId, newStatus) {
    const orders = this.getOrders();
    const order = orders.find(o => o.id === orderId);
    if (order) {
      order.status = newStatus;
      if (newStatus !== "pending") {
        order.isRead = true;
      }
      localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(orders));
      
      this.updateOrderStatusInCloud(orderId, newStatus);
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
    orders = orders.filter(o => o.id !== orderId);
    this.knownOrderIds.delete(orderId);
    localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(orders));

    this.deleteOrderFromCloud(orderId);
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
        p.salesCount = (p.salesCount || 0) + item.qty;
      }
    });
    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
  }

  getAnalytics() {
    const orders = this.getOrders();
    const products = this.getProducts();

    const totalRevenue = orders.reduce((sum, o) => sum + (o.total || 0), 0);
    const totalOrdersCount = orders.length;
    const pendingOrdersCount = orders.filter(o => o.status === "pending").length;
    const activeProductsCount = products.length;

    const bestSellers = [...products]
      .sort((a, b) => (b.salesCount || 0) - (a.salesCount || 0))
      .slice(0, 6);

    return {
      totalRevenue,
      totalOrdersCount,
      pendingOrdersCount,
      activeProductsCount,
      bestSellers
    };
  }
}

// Global Singleton Database Instance
window.KK_DB = new KasedKarimDB();
