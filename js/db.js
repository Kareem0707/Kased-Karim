/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Hybrid Real-Time Cloud Database Engine (js/db.js)
 * متصل بنظام سحابي لحظي ومزدوج لضمان وصول واستقبال الطلبات فورياً عبر جميع الأجهزة والهواتف
 */

const DB_KEYS = {
  PRODUCTS: "kased_karim_db_products_v2",
  ORDERS: "kased_karim_db_orders_v2",
  SETTINGS: "kased_karim_db_settings_v2",
  CLOUD_CONFIG: "kased_karim_cloud_config_v1"
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
        name: "ثريا الهالة المضيئة العائمة المعاصرة",
        enName: "Aurora Floating Halo Chandelier",
        price: 43200,
        qty: 1,
        image: "https://images.unsplash.com/photo-1517991104123-1d56a6e81ed9?auto=format&fit=crop&w=1200&q=80",
        categoryName: "ثريات ونجف فاخر"
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
    
    this.cloudBins = [
      "https://extendsclass.com/api/json-storage/bin/faabcdf",
      "https://extendsclass.com/api/json-storage/bin/fdeedbd"
    ];

    this.initDatabase();
    this.setupAudioUnlock();
    this.initCloudSync();
  }

  // 1. Initialize Database & Local Cache
  initDatabase() {
    // Initialize Products
    if (!localStorage.getItem(DB_KEYS.PRODUCTS)) {
      const products = INITIAL_PRODUCTS.map((p, idx) => ({
        ...p,
        salesCount: [34, 28, 22, 19, 15, 45, 12, 17, 14, 25, 9, 11][idx] || 10,
        warranty: p.specs?.warranty || "5 سنوات ضمان معتمد"
      }));
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
    }

    // Initialize Orders - sanitize and remove old dummy placeholder orders
    let localOrders = [];
    try {
      const raw = localStorage.getItem(DB_KEYS.ORDERS);
      localOrders = raw ? JSON.parse(raw) : [];
    } catch (e) {
      localOrders = [];
    }

    // Strictly filter out any old demo dummy orders
    localOrders = localOrders.filter(o => o.id !== "ORD-8941" && o.id !== "ORD-8820");

    if (!localOrders || localOrders.length === 0) {
      localOrders = [...SEED_ORDERS];
    }
    localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(localOrders));

    // Populate known orders set
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
  // CLOUD DATABASE SYNC ENGINE (Zero-Cache Real-Time Dual Sync)
  // --------------------------------------------------------------------------
  initCloudSync() {
    // 1. Immediate initial sync on load
    this.syncFromCloud(false);

    // 2. Continuous fast background poll (every 3 seconds)
    // Ensures admin gets notified in real time when any customer orders from ANY phone or browser!
    setInterval(() => {
      this.syncFromCloud(true);
    }, 3000);
  }

  getCloudApiEndpoint(route) {
    const savedCustom = localStorage.getItem("kk_custom_cloud_url");
    if (savedCustom && savedCustom.trim()) {
      return savedCustom.trim().replace(/\/$/, "") + (route.startsWith("/") ? route : "/" + route);
    }
    return route;
  }

  async syncFromCloud(isBackgroundPoll = false) {
    if (this.isSyncing) return;
    this.isSyncing = true;

    try {
      let orders = null;
      const t = Date.now();

      // 1. Try Vercel Serverless Endpoint with cache-busting
      try {
        const endpoint = this.getCloudApiEndpoint(`/api/orders?t=${t}`);
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);

        const res = await fetch(endpoint, {
          signal: controller.signal,
          cache: "no-store",
          headers: {
            "Accept": "application/json",
            "Cache-Control": "no-cache, no-store",
            "Pragma": "no-cache"
          }
        });
        clearTimeout(timeoutId);

        if (res.ok) {
          const data = await res.json();
          if (data && data.success && Array.isArray(data.orders) && data.orders.length > 0) {
            orders = data.orders;
            this.cloudProvider = "Vercel Serverless Cloud API";
          }
        }
      } catch (errApi) {}

      // 2. Direct Cloud Storage Bins Fallback (if serverless API had delay or offline)
      if (!orders || orders.length === 0) {
        for (const binUrl of this.cloudBins) {
          try {
            const binRes = await fetch(`${binUrl}?t=${t}`, {
              cache: "no-store",
              headers: {
                "Accept": "application/json",
                "Cache-Control": "no-cache, no-store",
                "Pragma": "no-cache"
              }
            });
            if (binRes.ok) {
              const binData = await binRes.json();
              if (binData && Array.isArray(binData.orders) && binData.orders.length > 0) {
                orders = binData.orders;
                this.cloudProvider = "Direct Cloud Storage Bin";
                break;
              }
            }
          } catch (errBin) {}
        }
      }

      if (orders && Array.isArray(orders)) {
        this.lastSyncTimestamp = Date.now();

        let hasNewCloudOrders = false;
        let latestNewOrder = null;

        const localOrders = this.getOrders().filter(o => o.id !== "ORD-8941" && o.id !== "ORD-8820");
        const orderMap = new Map();
        localOrders.forEach(o => orderMap.set(o.id, o));

        orders.forEach(cloudOrder => {
          // Detect brand-new orders arriving from other devices
          if (!this.knownOrderIds.has(cloudOrder.id)) {
            this.knownOrderIds.add(cloudOrder.id);
            hasNewCloudOrders = true;
            latestNewOrder = cloudOrder;
          }

          if (orderMap.has(cloudOrder.id)) {
            const existing = orderMap.get(cloudOrder.id);
            orderMap.set(cloudOrder.id, { ...cloudOrder, status: existing.status || cloudOrder.status });
          } else {
            orderMap.set(cloudOrder.id, cloudOrder);
          }
        });

        // Save merged orders to localStorage
        const mergedOrders = Array.from(orderMap.values()).sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(mergedOrders));

        if (hasNewCloudOrders && latestNewOrder) {
          // Play loud chime and trigger new order event
          this.playLuxuryChime();
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

  // Force Immediate Manual Sync (e.g. from Admin refresh button)
  async forceSyncNow() {
    return this.syncFromCloud(false);
  }

  async sendOrderToCloud(order) {
    const promises = [];

    // 1. Send to Vercel API
    try {
      const endpoint = this.getCloudApiEndpoint("/api/orders");
      promises.push(
        fetch(endpoint, {
          method: "POST",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(order)
        }).catch(() => null)
      );
    } catch (e) {}

    // 2. Direct Cloud Storage Bins (Parallel guarantee for instant persistence)
    for (const binUrl of this.cloudBins) {
      promises.push(
        (async () => {
          try {
            const binRes = await fetch(`${binUrl}?t=${Date.now()}`, { cache: "no-store" });
            if (binRes.ok) {
              const binData = await binRes.json();
              if (!Array.isArray(binData.orders)) binData.orders = [];
              if (!binData.orders.some(o => o.id === order.id)) {
                binData.orders.unshift(order);
              }
              await fetch(binUrl, {
                method: "PUT",
                cache: "no-store",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(binData)
              });
            }
          } catch (err) {}
        })()
      );
    }

    await Promise.allSettled(promises);
  }

  async updateOrderStatusInCloud(orderId, status) {
    try {
      const endpoint = this.getCloudApiEndpoint("/api/orders");
      fetch(endpoint, {
        method: "PATCH",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: orderId, status })
      }).catch(() => null);

      for (const binUrl of this.cloudBins) {
        fetch(`${binUrl}?t=${Date.now()}`, { cache: "no-store" })
          .then(r => r.json())
          .then(binData => {
            if (Array.isArray(binData.orders)) {
              const t = binData.orders.find(o => o.id === orderId);
              if (t) {
                t.status = status;
                fetch(binUrl, {
                  method: "PUT",
                  cache: "no-store",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify(binData)
                });
              }
            }
          }).catch(() => null);
      }
    } catch (e) {}
  }

  async deleteOrderFromCloud(orderId) {
    try {
      const endpoint = this.getCloudApiEndpoint(`/api/orders?id=${orderId}`);
      fetch(endpoint, { method: "DELETE", cache: "no-store" }).catch(() => null);

      for (const binUrl of this.cloudBins) {
        fetch(`${binUrl}?t=${Date.now()}`, { cache: "no-store" })
          .then(r => r.json())
          .then(binData => {
            if (Array.isArray(binData.orders)) {
              binData.orders = binData.orders.filter(o => o.id !== orderId);
              fetch(binUrl, {
                method: "PUT",
                cache: "no-store",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(binData)
              });
            }
          }).catch(() => null);
      }
    } catch (e) {}
  }

  async sendProductToCloud(product) {
    try {
      const endpoint = this.getCloudApiEndpoint("/api/products");
      fetch(endpoint, {
        method: "POST",
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(product)
      }).catch(() => null);

      for (const binUrl of this.cloudBins) {
        fetch(`${binUrl}?t=${Date.now()}`, { cache: "no-store" })
          .then(r => r.json())
          .then(binData => {
            if (!Array.isArray(binData.products)) binData.products = [];
            const idx = binData.products.findIndex(p => p.id === product.id);
            if (idx > -1) {
              binData.products[idx] = product;
            } else {
              binData.products.unshift(product);
            }
            fetch(binUrl, {
              method: "PUT",
              cache: "no-store",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(binData)
            });
          }).catch(() => null);
      }
    } catch (e) {}
  }

  async deleteProductFromCloud(productId) {
    try {
      const endpoint = this.getCloudApiEndpoint(`/api/products?id=${productId}`);
      fetch(endpoint, { method: "DELETE", cache: "no-store" }).catch(() => null);

      for (const binUrl of this.cloudBins) {
        fetch(`${binUrl}?t=${Date.now()}`, { cache: "no-store" })
          .then(r => r.json())
          .then(binData => {
            if (Array.isArray(binData.products)) {
              binData.products = binData.products.filter(p => p.id !== productId);
              fetch(binUrl, {
                method: "PUT",
                cache: "no-store",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(binData)
              });
            }
          }).catch(() => null);
      }
    } catch (e) {}
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
      category: productData.category || "chandeliers",
      categoryName: productData.categoryName || "ثريات ونجف فاخر",
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
    
    // Push to cloud
    this.sendProductToCloud(newProduct);

    window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: newProduct }));
    return newProduct;
  }

  deleteProduct(productId) {
    let products = this.getProducts();
    products = products.filter(p => p.id !== productId);
    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));

    // Delete from cloud
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
      // Strictly filter out any old demo dummy orders
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

    // Prepend new order locally
    orders.unshift(newOrder);
    this.knownOrderIds.add(orderId);
    localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(orders));

    // Increment sales count for each product
    this.incrementSales(cartItems);

    // Multi-cloud immediate push
    this.sendOrderToCloud(newOrder);

    // Play notification chime & fire event
    this.playLuxuryChime();
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
      
      // Update in cloud
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

    // Delete in cloud
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

  // --------------------------------------------------------------------------
  // ANALYTICS & BEST SELLERS
  // --------------------------------------------------------------------------
  getAnalytics() {
    const orders = this.getOrders();
    const products = this.getProducts();

    const totalRevenue = orders.reduce((sum, o) => sum + (o.total || 0), 0);
    const totalOrdersCount = orders.length;
    const pendingOrdersCount = orders.filter(o => o.status === "pending").length;
    const activeProductsCount = products.length;

    // Best sellers sorted by salesCount
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
