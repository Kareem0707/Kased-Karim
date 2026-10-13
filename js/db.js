/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Hybrid Cloud & Local Database Engine (js/db.js)
 * متصل بقاعدة بيانات سحابية متوافقة مع Vercel Serverless و Firebase و LocalStorage
 */

const DB_KEYS = {
  PRODUCTS: "kased_karim_db_products_v2",
  ORDERS: "kased_karim_db_orders_v2",
  SETTINGS: "kased_karim_db_settings_v2",
  CLOUD_CONFIG: "kased_karim_cloud_config_v1"
};

// Initial Seed Orders for Realistic Showroom Demonstration
const SEED_ORDERS = [
  {
    id: "ORD-8941",
    timestamp: Date.now() - (1000 * 60 * 45), // 45 minutes ago
    dateFormatted: "اليوم - 10:15 مساءً",
    customer: {
      name: "م. كريم البنا",
      phone: "01023456789",
      city: "الشيخ زايد",
      address: "كمبوند بالم هيلز - فيلا 18A",
      notes: "المعاينة بالمعرض واستلام المقايسة الرسمية"
    },
    items: [
      {
        id: "kk-001",
        name: "ثريا كريستال كاسكيد الإمبراطورية",
        enName: "Cascade Grand Imperial Chandelier",
        price: 68500,
        qty: 1,
        image: "https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=1200&q=80",
        categoryName: "ثريات ونجف فاخر"
      },
      {
        id: "kk-006",
        name: "إسبوت لايت Dark Light مضاد للتوهج 15W",
        enName: "Architectural Deep Dark-Light Spot 15W",
        price: 3650,
        qty: 8,
        image: "https://images.unsplash.com/photo-1618221195710-dd6b41faaea6?auto=format&fit=crop&w=1200&q=80",
        categoryName: "مسارات مغناطيسية واسبوتات"
      }
    ],
    subtotal: 97700,
    total: 97700,
    status: "pending",
    isRead: false
  },
  {
    id: "ORD-8820",
    timestamp: Date.now() - (1000 * 60 * 60 * 24),
    dateFormatted: "أمس - 04:30 مساءً",
    customer: {
      name: "د. هبة المنصوري",
      phone: "01098765432",
      city: "الشيخ زايد",
      address: "كمبوند بيفرلي هيلز - فيلا 42C",
      notes: "طلب مسارات مغناطيسية غاطسة لغرفة المعيشة"
    },
    items: [
      {
        id: "kk-002",
        name: "نظام المسارات المغناطيسية المعمارية الذكية",
        enName: "Ultra-Slim Magnetic Track System Pro",
        price: 18400,
        qty: 2,
        image: "https://images.unsplash.com/photo-1507473885765-e6ed057f782c?auto=format&fit=crop&w=1200&q=80",
        categoryName: "مسارات مغناطيسية واسبوتات"
      }
    ],
    subtotal: 36800,
    total: 36800,
    status: "confirmed",
    isRead: true
  }
];

class KasedKarimDB {
  constructor() {
    this.cloudEnabled = true;
    this.lastSyncTimestamp = 0;
    this.isSyncing = false;
    this.cloudProvider = "Vercel / Cloud Sync";
    this.knownOrderIds = new Set();
    
    this.initDatabase();
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

    // Initialize Orders
    if (!localStorage.getItem(DB_KEYS.ORDERS)) {
      localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(SEED_ORDERS));
    }

    // Populate known orders set
    const currentOrders = this.getOrders();
    currentOrders.forEach(o => this.knownOrderIds.add(o.id));
  }

  // --------------------------------------------------------------------------
  // CLOUD DATABASE SYNC ENGINE (Vercel Serverless & Cloud REST Integration)
  // --------------------------------------------------------------------------
  initCloudSync() {
    // Attempt initial sync from Cloud
    setTimeout(() => {
      this.syncFromCloud();
    }, 1500);

    // Periodic silent background poll (every 10 seconds)
    // Ensures admin gets notified in real-time if a customer orders from phone!
    setInterval(() => {
      this.syncFromCloud(true);
    }, 10000);
  }

  getCloudApiEndpoint(route) {
    // Custom configured endpoint in localStorage takes priority
    const savedCustom = localStorage.getItem("kk_custom_cloud_url");
    if (savedCustom && savedCustom.trim()) {
      return savedCustom.trim().replace(/\/$/, "") + (route.startsWith("/") ? route : "/" + route);
    }
    // Default Vercel relative path
    return route;
  }

  async syncFromCloud(isBackgroundPoll = false) {
    if (this.isSyncing) return;
    this.isSyncing = true;

    try {
      const endpoint = this.getCloudApiEndpoint("/api/orders");
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const res = await fetch(endpoint, {
        signal: controller.signal,
        headers: { "Accept": "application/json" }
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const data = await res.json();
        if (data && data.success && Array.isArray(data.orders)) {
          this.cloudProvider = "Vercel Cloud Serverless API";
          this.lastSyncTimestamp = Date.now();

          // Check for newly arrived orders
          let hasNewCloudOrders = false;
          let latestNewOrder = null;

          const localOrders = this.getOrders();
          const orderMap = new Map();
          localOrders.forEach(o => orderMap.set(o.id, o));

          data.orders.forEach(cloudOrder => {
            if (!this.knownOrderIds.has(cloudOrder.id)) {
              this.knownOrderIds.add(cloudOrder.id);
              hasNewCloudOrders = true;
              latestNewOrder = cloudOrder;
            }
            // Update or add
            orderMap.set(cloudOrder.id, cloudOrder);
          });

          // Save merged orders
          const mergedOrders = Array.from(orderMap.values()).sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
          localStorage.setItem(DB_KEYS.ORDERS, JSON.stringify(mergedOrders));

          if (hasNewCloudOrders && latestNewOrder && isBackgroundPoll) {
            // New order received from cloud while browsing! Trigger alert:
            this.playLuxuryChime();
            window.dispatchEvent(new CustomEvent("kk_new_order_placed", { detail: latestNewOrder }));
          } else {
            window.dispatchEvent(new CustomEvent("kk_orders_updated"));
          }
        }
      }
    } catch (e) {
      // Local development or offline - silently continues with local database
      // console.log("Cloud sync note:", e.message);
    } finally {
      this.isSyncing = false;
    }
  }

  async sendOrderToCloud(order) {
    try {
      const endpoint = this.getCloudApiEndpoint("/api/orders");
      await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(order)
      });
    } catch (e) {
      console.warn("Cloud push buffered locally:", e.message);
    }
  }

  async updateOrderStatusInCloud(orderId, status) {
    try {
      const endpoint = this.getCloudApiEndpoint("/api/orders");
      await fetch(endpoint, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: orderId, status })
      });
    } catch (e) {
      console.warn("Cloud status update buffered locally:", e.message);
    }
  }

  async deleteOrderFromCloud(orderId) {
    try {
      const endpoint = this.getCloudApiEndpoint(`/api/orders?id=${orderId}`);
      await fetch(endpoint, { method: "DELETE" });
    } catch (e) {
      console.warn("Cloud delete buffered locally:", e.message);
    }
  }

  async sendProductToCloud(product) {
    try {
      const endpoint = this.getCloudApiEndpoint("/api/products");
      await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(product)
      });
    } catch (e) {
      console.warn("Cloud product push buffered locally:", e.message);
    }
  }

  async deleteProductFromCloud(productId) {
    try {
      const endpoint = this.getCloudApiEndpoint(`/api/products?id=${productId}`);
      await fetch(endpoint, { method: "DELETE" });
    } catch (e) {
      console.warn("Cloud product delete buffered locally:", e.message);
    }
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
      enName: productData.enName || "Luxury Lighting Luminaire",
      category: productData.category || "chandeliers",
      categoryName: productData.categoryName || "ثريات ونجف فاخر",
      style: productData.style || "معاصر",
      price: parseFloat(productData.price) || 0,
      originalPrice: productData.originalPrice ? parseFloat(productData.originalPrice) : null,
      warranty: productData.warranty || "5 سنوات ضمان شامل",
      image: productData.image || "https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=1200&q=80",
      secondaryImage: productData.secondaryImage || productData.image,
      description: productData.description || "وحدة إضاءة معمارية فاخرة من معرض قاصد كريم بالشيخ زايد.",
      isExclusive: !!productData.isExclusive,
      isBestSeller: !!productData.isBestSeller,
      isNew: true,
      rating: 5.0,
      reviewsCount: 1,
      salesCount: 0,
      specs: {
        dimensions: productData.specs?.dimensions || "حسب الطلب",
        material: productData.specs?.material || "نحاس وألمنيوم فندقي",
        colorTemp: productData.specs?.colorTemp || "3000K دافئ",
        wattage: productData.specs?.wattage || "LED موفر عالي الكفاءة",
        cri: productData.specs?.cri || "CRI > 97",
        voltage: "220V",
        warranty: productData.warranty || "5 سنوات ضمان شامل"
      }
    };

    products.unshift(newProduct);
    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
    
    // Asynchronously sync to cloud
    this.sendProductToCloud(newProduct);

    window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: newProduct }));
    return newProduct;
  }

  deleteProduct(productId) {
    let products = this.getProducts();
    products = products.filter(p => p.id !== productId);
    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));

    // Asynchronously delete from cloud
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
      return data ? JSON.parse(data) : [];
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
        enName: item.enName,
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

    // Asynchronously push to cloud for Vercel persistence
    this.sendOrderToCloud(newOrder);

    // Play notification sound & trigger event
    this.playLuxuryChime();
    window.dispatchEvent(new CustomEvent("kk_new_order_placed", { detail: newOrder }));

    return newOrder;
  }

  updateOrderStatus(orderId, newStatus) {
    const orders = this.getOrders();
    const order = orders.find(o => o.id === orderId);
    if (order) {
      order.status = newStatus;
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
    return orders.filter(o => !o.isRead || o.status === "pending").length;
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

  // Synthetic Luxury Audio Chime using Web Audio API
  playLuxuryChime() {
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (!AudioContext) return;
      const ctx = new AudioContext();

      const now = ctx.currentTime;
      // Note 1: E5 (659.25 Hz)
      const osc1 = ctx.createOscillator();
      const gain1 = ctx.createGain();
      osc1.type = "sine";
      osc1.frequency.setValueAtTime(659.25, now);
      gain1.gain.setValueAtTime(0, now);
      gain1.gain.linearRampToValueAtTime(0.25, now + 0.05);
      gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.8);
      osc1.connect(gain1);
      gain1.connect(ctx.destination);
      osc1.start(now);
      osc1.stop(now + 0.8);

      // Note 2: B5 (987.77 Hz)
      const osc2 = ctx.createOscillator();
      const gain2 = ctx.createGain();
      osc2.type = "sine";
      osc2.frequency.setValueAtTime(987.77, now + 0.15);
      gain2.gain.setValueAtTime(0, now + 0.15);
      gain2.gain.linearRampToValueAtTime(0.3, now + 0.2);
      gain2.gain.exponentialRampToValueAtTime(0.001, now + 1.2);
      osc2.connect(gain2);
      gain2.connect(ctx.destination);
      osc2.start(now + 0.15);
      osc2.stop(now + 1.2);
    } catch (e) {
      console.log("Audio alert muted or autoplay restricted", e);
    }
  }
}

// Global Database Singleton
window.KK_DB = new KasedKarimDB();
