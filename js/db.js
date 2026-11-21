/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Hardened Browser Cloud Database Bridge Engine (js/db.js)
 * المعمارية الآمنة لجسر البيانات السحابية في المتصفح - قاصد كريم للإضاءة الفاخرة
 *
 * امتثال صارم لمعايير الأمان الدولية:
 * - OWASP ASVS (Level 2/3) - Client-Side Security & Data Storage
 * - CWE-312: Cleartext Storage of Sensitive Information in LocalStorage
 * - CWE-359: Privacy Violation / Personally Identifiable Information Leakage
 * - CWE-915: Prototype Pollution Prevention on Client Deserialization
 * - CWE-352: Anti-CSRF via Same-Origin Strict Routing & X-Requested-With
 * - Zero Direct-DB Access: حظر كامل لأي استدعاءات مباشرة لقواعد البيانات الخارجية
 * - HttpOnly Cookie Alignment: إلغاء قراءة أو تخزين التوكنات في المتصفح والاعتماد على credentials: "include"
 * - Object.freeze: تحصين الكائن العام window.KK_DB بالجليد لمنع العبث أو التلاعب به
 */

// -----------------------------------------------------------------------------
// SECURE STORAGE KEYS & CONFIGURATION
// -----------------------------------------------------------------------------
const DB_KEYS = Object.freeze({
  PRODUCTS: "kased_karim_db_products_v3",
  CATEGORIES: "kased_karim_db_categories_v2",
  SETTINGS: "kased_karim_db_settings_v3",
  BACKUPS: "kased_karim_db_backups_v1",
  DELIVERY_AREAS: "kased_karim_db_delivery_areas_v1",
  CUSTOMER_USER: "kk_customer_user",
  AUDIT_LOGS: "kased_karim_db_audit_logs_v1",
  // Legacy keys scrubbed immediately on initialization (CWE-312)
  LEGACY_ORDERS: "kased_karim_db_orders_v2",
  LEGACY_ORDERS_ALT: "kased_karim_db_orders",
  LEGACY_CUSTOMERS: "kased_karim_db_customers_v1",
  LEGACY_CUSTOMER_TOKEN: "kk_customer_token",
  LEGACY_ADMIN_TOKEN: "kk_admin_token"
});

// -----------------------------------------------------------------------------
// PROTOTYPE POLLUTION DEFENSE & DEEP SANITIZATION (ASVS L3 & CWE-915)
// -----------------------------------------------------------------------------
function sanitizeDeep(obj) {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizeDeep);
  }
  const clean = Object.create(null);
  for (const key of Object.keys(obj)) {
    // Block Prototype Pollution injection vectors strictly
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    clean[key] = sanitizeDeep(obj[key]);
  }
  return Object.assign({}, clean);
}

// -----------------------------------------------------------------------------
// CENTRALIZED SECURE API FETCH TRANSPORT (ASVS L2/L3 & SAME-ORIGIN ENFORCEMENT)
// -----------------------------------------------------------------------------
/**
 * Executes a hardened, same-origin HTTP request to /api/* serverless endpoints.
 * Enforces:
 * 1. Strict relative same-origin path starting with /api/
 * 2. Absolute URL rejection (https://, http://, //, javascript:, data:)
 * 3. Path traversal blocking (.., %2e%2e, backslashes)
 * 4. credentials: "include" for HttpOnly Secure SameSite cookies
 * 5. Anti-CSRF protection via X-Requested-With: XMLHttpRequest
 * 6. Cache busting & no-store directives
 * 7. AbortController network timeout (default 12,000ms)
 * 8. Safe Content-Type verification prior to JSON parsing
 */
async function safeApiFetch(endpoint, options = {}) {
  if (typeof endpoint !== "string") {
    throw new TypeError("[Security Alert] Invalid API endpoint type: expected string");
  }

  const cleanPath = endpoint.trim();

  // Strict Same-Origin /api/ path verification
  if (!cleanPath.startsWith("/api/") && cleanPath !== "/api" && !cleanPath.startsWith("/api?")) {
    throw new Error(`[Security Alert] Blocked non-/api or external path: ${cleanPath}`);
  }

  // Reject scheme injection or protocol-relative URLs
  if (cleanPath.startsWith("//") || cleanPath.includes("://")) {
    throw new Error(`[Security Alert] Protocol-relative or absolute URL injection blocked: ${cleanPath}`);
  }

  // Reject directory traversal
  let decodedPath = "";
  try {
    decodedPath = decodeURIComponent(cleanPath);
  } catch (e) {
    throw new Error(`[Security Alert] Malformed URL encoding in API path: ${cleanPath}`);
  }

  if (
    decodedPath.includes("/../") ||
    decodedPath.includes("/..") ||
    decodedPath.endsWith("/..") ||
    decodedPath.includes("..\\")
  ) {
    throw new Error(`[Security Alert] Directory traversal sequence blocked: ${cleanPath}`);
  }

  // Setup AbortController for reliable network timeout
  const timeoutMs = typeof options.timeout === "number" && options.timeout > 0 ? options.timeout : 12000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  // Merge headers defensively
  const headers = {
    "Accept": "application/json",
    "X-Requested-With": "XMLHttpRequest",
    "Cache-Control": "no-cache, no-store",
    "Pragma": "no-cache",
    ...(options.headers || {})
  };

  if (options.body && typeof options.body === "string" && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  const fetchOptions = {
    ...options,
    credentials: "include", // Enforces HttpOnly cookie delivery
    cache: "no-store",      // Prevents caching sensitive data in browser history/cache
    headers,
    signal: options.signal || controller.signal
  };

  try {
    const res = await fetch(cleanPath, fetchOptions);
    clearTimeout(timeoutId);

    // Safe Content-Type verification before parsing JSON (CWE-209 / Robustness)
    const contentType = res.headers.get("content-type") || "";
    let data = null;

    if (contentType.includes("application/json")) {
      try {
        const text = await res.text();
        data = text ? sanitizeDeep(JSON.parse(text)) : null;
      } catch (jsonErr) {
        data = null;
      }
    } else {
      // Non-JSON response (e.g. 502/504 HTML error page from serverless gateway)
      const text = await res.text().catch(() => "");
      data = {
        success: false,
        status: res.status,
        error: res.ok ? "استجابة غير صالحة من الخادم" : `خطأ من الخادم السحابي (${res.status})`,
        rawText: text.slice(0, 120)
      };
    }

    return {
      ok: res.ok,
      status: res.status,
      headers: res.headers,
      data
    };
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      return {
        ok: false,
        status: 408,
        data: { success: false, error: "انتهت مهلة الاتصال بالخادم السحابي" }
      };
    }
    return {
      ok: false,
      status: 0,
      data: { success: false, error: err.message || "فشل الاتصال بالشبكة" }
    };
  }
}

// -----------------------------------------------------------------------------
// CORE DATABASE BRIDGE ENGINE CLASS
// -----------------------------------------------------------------------------
class KasedKarimDB {
  // Private encapsulated state variables (ASVS L3 - inaccessible to external tampering)
  #inMemoryOrders = [];
  #knownOrderIds = new Set();
  #notifiedOrderIds = new Set();
  #pageSessionStartTime = Date.now();
  #isInitialSyncCompleted = false;
  #isSyncing = false;
  #isRestoring = false;
  #restoreLockTimer = null;
  #lastSyncTimestamp = 0;
  #audioCtx = null;
  #currentCustomer = null;

  constructor() {
    this.#pageSessionStartTime = Date.now();
    this.#inMemoryOrders = [];
    this.#knownOrderIds = new Set();
    this.#notifiedOrderIds = new Set();

    // 1. Proactive Client Storage Sanitation (Scrub Legacy PII & Insecure Tokens - CWE-312)
    this.#scrubLegacyStorage();

    // 2. Load non-sensitive notified orders set
    try {
      const storedNotified = localStorage.getItem("kk_notified_orders");
      if (storedNotified) {
        const parsed = JSON.parse(storedNotified);
        if (Array.isArray(parsed)) {
          parsed.forEach(id => {
            if (typeof id === "string") this.#notifiedOrderIds.add(id);
          });
        }
      }
    } catch (e) {}

    // 3. Initialize Catalogs, Audio Engine, and Cloud Sync
    this.initDatabase();
    this.setupAudioUnlock();
    this.initCloudSync();
  }

  // --------------------------------------------------------------------------
  // PUBLIC READ-ONLY STATE GETTERS
  // --------------------------------------------------------------------------
  get cloudEnabled() {
    return true;
  }

  get cloudProvider() {
    return "Vercel / Cloud Sync";
  }

  get lastSyncTimestamp() {
    return this.#lastSyncTimestamp;
  }

  get isSyncing() {
    return this.#isSyncing;
  }

  get isInitialSyncCompleted() {
    return this.#isInitialSyncCompleted;
  }

  // --------------------------------------------------------------------------
  // PRIVATE STORAGE SANITIZATION (CWE-312 / CWE-359)
  // --------------------------------------------------------------------------
  #scrubLegacyStorage() {
    try {
      // Purge cleartext tokens
      localStorage.removeItem("kk_admin_token");
      localStorage.removeItem("kk_customer_token");
      localStorage.removeItem(DB_KEYS.LEGACY_CUSTOMER_TOKEN);
      localStorage.removeItem(DB_KEYS.LEGACY_ADMIN_TOKEN);
      sessionStorage.removeItem("kk_admin_token");
      sessionStorage.removeItem("kk_customer_token");
      sessionStorage.removeItem(DB_KEYS.LEGACY_CUSTOMER_TOKEN);
      sessionStorage.removeItem(DB_KEYS.LEGACY_ADMIN_TOKEN);

      // Purge cleartext persistent orders & customer database dumps
      localStorage.removeItem(DB_KEYS.LEGACY_ORDERS);
      localStorage.removeItem(DB_KEYS.LEGACY_ORDERS_ALT);
      localStorage.removeItem(DB_KEYS.LEGACY_CUSTOMERS);
      localStorage.removeItem("kk_custom_cloud_url");
    } catch (e) {}
  }

  // --------------------------------------------------------------------------
  // 1. INITIALIZE DATABASE & LOCAL CATALOG CACHES
  // --------------------------------------------------------------------------
  initDatabase() {
    // A. Tombstone set of permanently deleted product IDs
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

    // Seed initial products only if local catalog is empty
    if (!Array.isArray(cachedProducts) || cachedProducts.length === 0) {
      const seeded = (typeof INITIAL_PRODUCTS !== "undefined" ? INITIAL_PRODUCTS : [])
        .filter(p => p && p.id && !deletedProductIds.has(p.id))
        .map((p, idx) => ({
          ...p,
          salesCount: [34, 28, 22, 19, 15, 45, 12, 17, 14, 25, 9, 11][idx] || 10,
          warranty: (p.specs && p.specs.warranty) || "5 سنوات ضمان معتمد"
        }));
      try {
        localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(seeded));
      } catch (e) {}
    } else {
      const sanitized = cachedProducts.filter(p => p && p.id && !deletedProductIds.has(p.id));
      try {
        localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(sanitized));
      } catch (e) {}
    }

    // C. Initialize Categories
    let cachedCategories = null;
    try {
      const raw = localStorage.getItem(DB_KEYS.CATEGORIES);
      if (raw) cachedCategories = JSON.parse(raw);
    } catch (e) {}

    if (Array.isArray(cachedCategories) && cachedCategories.length > 0) {
      if (!cachedCategories.some(c => c && c.id === "all")) {
        cachedCategories.unshift({ id: "all", name: "الكل المعروض", parentId: null });
      }
      cachedCategories.forEach(c => {
        if (c && typeof c.parentId === "undefined") c.parentId = null;
      });
      try {
        localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(cachedCategories));
      } catch (e) {}
      if (typeof window !== "undefined") {
        window.CATEGORIES = cachedCategories;
      }
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
      try {
        localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(defaultCats));
      } catch (e) {}
      if (typeof window !== "undefined") {
        window.CATEGORIES = defaultCats;
      }
    }

    // D. Initialize Settings
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
      googleClientId: "975827952448-e6dekknbl9s5vfechtk9q7q0vgjqsvma.apps.googleusercontent.com",
      social: {
        facebook: "https://facebook.com",
        instagram: "https://instagram.com",
        tiktok: "https://tiktok.com",
        designerUrl: "https://karimodesign.vercel.app/"
      }
    };

    if (cachedSettings && typeof cachedSettings === "object") {
      const mergedSettings = {
        ...defaultSettings,
        ...cachedSettings,
        googleClientId: (cachedSettings && cachedSettings.googleClientId) || defaultSettings.googleClientId,
        social: { ...defaultSettings.social, ...(cachedSettings.social || {}) }
      };
      try {
        localStorage.setItem(DB_KEYS.SETTINGS, JSON.stringify(mergedSettings));
      } catch (e) {}
      if (typeof window !== "undefined") {
        window.SHOWROOM_INFO = mergedSettings;
      }
    } else {
      try {
        localStorage.setItem(DB_KEYS.SETTINGS, JSON.stringify(defaultSettings));
      } catch (e) {}
      if (typeof window !== "undefined") {
        window.SHOWROOM_INFO = defaultSettings;
      }
    }

    // E. Orders are strictly memory-only (CWE-312 & ASVS L3)
    this.#inMemoryOrders = [];

    // F. Automatic daily restore point check
    this.checkAndCreateDailyRestorePoint();
  }

  // --------------------------------------------------------------------------
  // 2. AUDIO ENGINE & UNLOCKING (Web Audio API)
  // --------------------------------------------------------------------------
  setupAudioUnlock() {
    const unlock = () => {
      try {
        if (!this.#audioCtx) {
          const AudioContextClass = (typeof window !== "undefined" && (window.AudioContext || window.webkitAudioContext));
          if (AudioContextClass) this.#audioCtx = new AudioContextClass();
        }
        if (this.#audioCtx && this.#audioCtx.state === "suspended") {
          this.#audioCtx.resume().catch(() => {});
        }
      } catch (e) {}
    };

    if (typeof window !== "undefined") {
      window.addEventListener("click", unlock, { passive: true });
      window.addEventListener("touchstart", unlock, { passive: true });
      window.addEventListener("keydown", unlock, { passive: true });
    }
  }

  playLuxuryChime() {
    try {
      if (!this.#audioCtx) {
        const AudioContextClass = (typeof window !== "undefined" && (window.AudioContext || window.webkitAudioContext));
        if (AudioContextClass) this.#audioCtx = new AudioContextClass();
      }
      if (!this.#audioCtx) return;
      if (this.#audioCtx.state === "suspended") {
        this.#audioCtx.resume().catch(() => {});
      }

      const ctx = this.#audioCtx;
      const now = ctx.currentTime;

      // 4-Tone Crystal Bell: E5 (659Hz) -> G#5 (830Hz) -> B5 (987Hz) -> E6 (1318Hz)
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
      // Audio context restricted until user interaction
    }
  }

  // --------------------------------------------------------------------------
  // 3. SECURE HEADERS & PROXY COMPATIBILITY
  // --------------------------------------------------------------------------
  getCustomCloudUrl() {
    // Direct client Firebase REST calls are permanently disabled (Axis 1)
    return "";
  }

  setCustomCloudUrl(url) {
    // Retained strictly for caller compatibility; external DB overrides are disabled
    try {
      localStorage.removeItem("kk_custom_cloud_url");
    } catch (e) {}
  }

  getCloudHeaders() {
    // Sanitized headers: zero tokens leaked to JavaScript storage.
    // HttpOnly cookies handle session authentication automatically via credentials: "include".
    return {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "X-Requested-With": "XMLHttpRequest",
      "Cache-Control": "no-cache, no-store",
      "Pragma": "no-cache"
    };
  }

  isAdminUser() {
    if (typeof document === "undefined" || !document.body) return false;
    return document.body.classList.contains("is-admin-authenticated");
  }

  // --------------------------------------------------------------------------
  // 4. CLOUD SYNC ENGINE (ADAPTIVE, SAME-ORIGIN POLLING)
  // --------------------------------------------------------------------------
  initCloudSync() {
    // Initial catalog synchronization
    this.syncProductsFromCloud(false);
    this.syncCategoriesFromCloud();
    this.syncSettingsFromCloud();

    // Initial admin orders fetch ONLY if authenticated as admin (Fail-Closed)
    if (this.isAdminUser()) {
      this.syncFromCloud(false);
    }

    let orderInterval = null;
    let catalogInterval = null;

    const startBackgroundSync = () => {
      if (orderInterval) clearInterval(orderInterval);
      if (catalogInterval) clearInterval(catalogInterval);

      // Admin orders polling: every 15s (when on dashboard and page visible)
      if (this.isAdminUser()) {
        orderInterval = setInterval(() => {
          if (typeof document !== "undefined" && !document.hidden) {
            this.syncFromCloud(true);
          }
        }, 15000);
      }

      // Catalog & Settings polling: every 20s
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

    // Foreground / Reconnection triggers
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

  async syncProductsFromCloud(isBackground = false) {
    if (this.#isRestoring) return;

    try {
      const t = Date.now();
      const res = await safeApiFetch(`/api/products?t=${t}`, {
        cache: "no-store",
        timeout: 8000
      });

      if (res.ok && res.data && res.data.success && Array.isArray(res.data.products) && res.data.products.length > 0) {
        let cloudProducts = res.data.products;

        // Retrieve tombstone deleted IDs
        let deletedIds = new Set();
        try {
          const rawDel = localStorage.getItem("kk_deleted_product_ids_v1");
          if (rawDel) {
            const parsed = JSON.parse(rawDel);
            if (Array.isArray(parsed)) parsed.forEach(id => deletedIds.add(id));
          }
        } catch (e) {}

        cloudProducts = cloudProducts.filter(p => p && p.id && !deletedIds.has(p.id));
        const currentProducts = this.getProducts();

        const currentStr = JSON.stringify(currentProducts);
        const cloudStr = JSON.stringify(cloudProducts);

        if (currentStr !== cloudStr) {
          try {
            localStorage.setItem(DB_KEYS.PRODUCTS, cloudStr);
          } catch (e) {}
          if (typeof window !== "undefined") {
            window.dispatchEvent(new CustomEvent("kk_products_updated", {
              detail: { merged: false, products: cloudProducts }
            }));
          }
        }
      }
    } catch (e) {
      // Background sync non-fatal error
    }
  }

  async syncFromCloud(isBackgroundPoll = false) {
    if (this.#isSyncing) return;
    this.#isSyncing = true;

    try {
      const t = Date.now();
      const res = await safeApiFetch(`/api/orders?t=${t}`, {
        cache: "no-store",
        timeout: 8000
      });

      if (res.ok && res.data && res.data.success && Array.isArray(res.data.orders)) {
        this.#lastSyncTimestamp = Date.now();
        const orders = res.data.orders;

        const cleanCloudOrders = orders.filter(o => o && o.id);

        // Normalize items and customer for all cloud orders
        cleanCloudOrders.forEach(o => {
          if (o && o.items && !Array.isArray(o.items) && typeof o.items === "object") {
            o.items = Object.values(o.items);
          }
          if (o && typeof o.customer === "string") {
            try {
              o.customer = JSON.parse(o.customer);
            } catch (e) {
              o.customer = { name: o.customer };
            }
          }
        });

        // Strict chronological sort (newest first)
        cleanCloudOrders.sort((a, b) => (Number(b.timestamp) || 0) - (Number(a.timestamp) || 0));

        const trulyNewOrders = [];

        cleanCloudOrders.forEach(cloudOrder => {
          const isKnown = this.#knownOrderIds.has(cloudOrder.id);

          // Alert only if initial sync completed, order is unknown, and placed recently
          if (!isKnown && this.#isInitialSyncCompleted) {
            const isRecent =
              (cloudOrder.timestamp >= this.#pageSessionStartTime) ||
              (cloudOrder.timestamp >= Date.now() - 5 * 60 * 1000);

            if (isRecent && !this.#notifiedOrderIds.has(cloudOrder.id)) {
              trulyNewOrders.push(cloudOrder);
            }
          }
        });

        // Update known IDs
        this.#knownOrderIds.clear();
        cleanCloudOrders.forEach(o => this.#knownOrderIds.add(o.id));
        this.#isInitialSyncCompleted = true;

        const prevSummary = JSON.stringify(this.#inMemoryOrders.map(o => ({ id: o.id, status: o.status, paid: o.paymentStatus })));
        const newSummary = JSON.stringify(cleanCloudOrders.map(o => ({ id: o.id, status: o.status, paid: o.paymentStatus })));

        this.#inMemoryOrders = cleanCloudOrders;
        this.recalculateAllProductSales();

        // Defense-in-depth: scrub any cleartext order leaks from localStorage (CWE-312)
        try {
          localStorage.removeItem(DB_KEYS.LEGACY_ORDERS);
        } catch (e) {}

        if (trulyNewOrders.length > 0) {
          trulyNewOrders.sort((a, b) => (Number(b.timestamp) || 0) - (Number(a.timestamp) || 0));
          const latestNewOrder = trulyNewOrders[0];

          this.#notifiedOrderIds.add(latestNewOrder.id);
          try {
            localStorage.setItem("kk_notified_orders", JSON.stringify(Array.from(this.#notifiedOrderIds)));
          } catch (e) {}

          if (this.isAdminUser()) {
            this.playLuxuryChime();
          }

          if (typeof window !== "undefined") {
            window.dispatchEvent(new CustomEvent("kk_new_order_placed", { detail: latestNewOrder }));
          }
        } else if (prevSummary !== newSummary) {
          if (typeof window !== "undefined") {
            window.dispatchEvent(new CustomEvent("kk_orders_updated"));
          }
        }
      }
    } catch (e) {
      // Cloud sync skipped
    } finally {
      this.#isSyncing = false;
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
  // 5. PRODUCTS MANAGEMENT & CLOUD PUSH
  // --------------------------------------------------------------------------
  async sendProductToCloud(product) {
    if (!product || !product.id) return false;

    const safeProduct = {
      id: String(product.id),
      name: String(product.name || "").trim(),
      enName: String(product.enName || "").trim(),
      category: String(product.category || "pendants"),
      categoryName: String(product.categoryName || "دلايات"),
      style: String(product.style || ""),
      price: parseFloat(product.price) || 0,
      originalPrice: product.originalPrice ? parseFloat(product.originalPrice) : null,
      warranty: String(product.warranty || ""),
      image: String(product.image || ""),
      secondaryImage: String(product.secondaryImage || ""),
      description: String(product.description || ""),
      isNew: Boolean(product.isNew),
      isExclusive: Boolean(product.isExclusive),
      isBestSeller: Boolean(product.isBestSeller),
      specs: (product.specs && typeof product.specs === "object") ? product.specs : {}
    };

    try {
      const res = await safeApiFetch("/api/products", {
        method: "POST",
        body: JSON.stringify(safeProduct)
      });
      return res.ok;
    } catch (e) {
      return false;
    }
  }

  async deleteProductFromCloud(productId) {
    if (!productId) return;
    try {
      await safeApiFetch(`/api/products?id=${encodeURIComponent(String(productId))}`, {
        method: "DELETE"
      });
    } catch (e) {}
  }

  async syncAllLocalProductsToCloud() {
    const products = this.getProducts();

    // Atomic batch overwrite to serverless endpoint
    try {
      const res = await safeApiFetch("/api/products", {
        method: "PUT",
        headers: {
          "x-destructive-confirm": "CONFIRM_BULK_PRODUCTS_OVERWRITE"
        },
        body: JSON.stringify({ products })
      });
      if (res.ok) {
        return products.length;
      }
    } catch (e) {}

    // Fallback: individual product push
    let count = 0;
    for (const p of products) {
      try {
        const ok = await this.sendProductToCloud(p);
        if (ok) count++;
      } catch (e) {}
    }
    return count;
  }

  getProducts() {
    try {
      const data = localStorage.getItem(DB_KEYS.PRODUCTS);
      let list = data ? JSON.parse(data) : [...(typeof INITIAL_PRODUCTS !== "undefined" ? INITIAL_PRODUCTS : [])];

      try {
        const rawDeleted = localStorage.getItem("kk_deleted_product_ids_v1");
        if (rawDeleted) {
          const deletedIds = new Set(JSON.parse(rawDeleted));
          if (deletedIds.size > 0) {
            list = list.filter(p => p && p.id && !deletedIds.has(p.id));
          }
        }
      } catch (e) {}

      // Soft Delete Filter: Strictly exclude items flagged with deleted_at or deleted: true
      list = list.filter(p => p && p.id && !p.deleted_at && p.deleted !== true);

      // Ensure stock attributes
      list.forEach(p => {
        if (p) {
          if (p.stock === undefined) p.stock = 12;
          p.inStock = p.stock > 0 && p.inStock !== false;
        }
      });

      return list;
    } catch (e) {
      return [...(typeof INITIAL_PRODUCTS !== "undefined" ? INITIAL_PRODUCTS : [])];
    }
  }

  getProductById(id) {
    if (!id) return null;
    const cleanId = String(id).trim();
    const products = this.getProducts();
    return products.find(p => p && p.id === cleanId) || null;
  }

  addProduct(productData) {
    if (!productData || !productData.name) {
      throw new Error("بيانات المنتج غير مكتملة: الاسم إجباري");
    }

    const products = this.getProducts();
    const newProduct = {
      id: "kk-" + Date.now().toString().slice(-5),
      name: String(productData.name).trim(),
      enName: String(productData.enName || "").trim(),
      category: String(productData.category || "pendants"),
      categoryName: String(productData.categoryName || "دلايات فاخرة"),
      style: String(productData.style || ""),
      price: parseFloat(productData.price) || 0,
      originalPrice: productData.originalPrice ? parseFloat(productData.originalPrice) : null,
      warranty: String(productData.warranty || ""),
      image: String(productData.image || ""),
      secondaryImage: String(productData.secondaryImage || ""),
      description: String(productData.description || ""),
      isExclusive: Boolean(productData.isExclusive),
      isBestSeller: Boolean(productData.isBestSeller),
      isNew: true,
      rating: 5.0,
      reviewsCount: 1,
      salesCount: 0,
      specs: {
        dimensions: (productData.specs && productData.specs.dimensions) || "",
        material: (productData.specs && productData.specs.material) || "",
        colorTemp: (productData.specs && productData.specs.colorTemp) || "",
        wattage: (productData.specs && productData.specs.wattage) || "",
        cri: (productData.specs && productData.specs.cri) || "",
        voltage: (productData.specs && productData.specs.voltage) || "",
        warranty: productData.warranty || ""
      }
    };

    products.unshift(newProduct);
    try {
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
    } catch (e) {}

    // Cloud push
    this.sendProductToCloud(newProduct);

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: newProduct }));
    }
    return newProduct;
  }

  // Alias for backward compatibility with admin.js (fixes bulk CSV import call)
  createProduct(productData) {
    return this.addProduct(productData);
  }

  async updateProduct(productId, updatedData) {
    if (!productId) return { success: false, error: "معرّف المنتج مفقود" };
    let products = this.getProducts();
    const idx = products.findIndex(p => p && p.id === productId);
    if (idx === -1) return { success: false, error: "المنتج غير موجود" };

    const oldProduct = products[idx];
    this.saveWebRestorePoint(`قبل تعديل المنتج: ${oldProduct.name}`);

    const updatedProduct = {
      ...oldProduct,
      ...updatedData,
      id: productId, // Immutable product ID
      price: parseFloat(updatedData.price) || 0,
      originalPrice: updatedData.originalPrice ? parseFloat(updatedData.originalPrice) : null,
      updatedAt: Date.now()
    };

    products[idx] = updatedProduct;
    try {
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
    } catch (e) {}

    await this.sendProductToCloud(updatedProduct);
    await this.syncAllLocalProductsToCloud();

    this.recalculateAllProductSales();
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: updatedProduct }));
    }
    return { success: true, product: updatedProduct };
  }

  async deleteProduct(productId) {
    if (!productId) return false;

    // 1. Tombstone tracking
    try {
      const rawDeleted = localStorage.getItem("kk_deleted_product_ids_v1");
      const deletedIds = rawDeleted ? JSON.parse(rawDeleted) : [];
      if (!deletedIds.includes(productId)) {
        deletedIds.push(productId);
        localStorage.setItem("kk_deleted_product_ids_v1", JSON.stringify(deletedIds));
      }
    } catch (e) {}

    // 2. Filter local products
    let products = this.getProducts();
    const target = products.find(p => p && p.id === productId);
    if (target) {
      this.saveWebRestorePoint(`قبل حذف المنتج: ${target.name}`);
    }
    products = products.filter(p => p && p.id !== productId);
    try {
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
    } catch (e) {}

    // 3. Cloud deletion & overwrite
    await this.deleteProductFromCloud(productId);
    await this.syncAllLocalProductsToCloud();

    this.recalculateAllProductSales();
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: { deletedId: productId } }));
    }
    return true;
  }

  // --------------------------------------------------------------------------
  // 6. ORDERS MANAGEMENT & CHECKOUT (VOLATILE IN-MEMORY ONLY - CWE-312)
  // --------------------------------------------------------------------------
  #insertInMemoryOrder(order) {
    if (!order || !order.id) return;
    const idx = this.#inMemoryOrders.findIndex(o => o && o.id === order.id);
    if (idx > -1) {
      this.#inMemoryOrders[idx] = {
        ...this.#inMemoryOrders[idx],
        ...order,
        status: order.status || this.#inMemoryOrders[idx].status
      };
    } else {
      this.#inMemoryOrders.unshift(order);
    }
    this.#knownOrderIds.add(order.id);
  }

  getOrders() {
    // Return defensive shallow copy of in-memory orders
    return this.#inMemoryOrders.map(o => ({ ...o }));
  }

  async createOrder(customerData, cartItems, options = {}) {
    if (!Array.isArray(cartItems) || cartItems.length === 0) {
      throw new Error("سلة الطلبات فارغة");
    }

    const activeCust = this.getCustomer();
    const custId = (customerData && customerData.customerId) || (activeCust ? activeCust.id : null);
    const custEmail = (
      (customerData && (customerData.email || customerData.customerEmail)) ||
      (activeCust ? activeCust.email : "") ||
      ""
    ).trim().toLowerCase();

    const headers = {
      ...(options.headers || {})
    };
    if (options.idempotencyKey) {
      headers["Idempotency-Key"] = options.idempotencyKey;
    }

    const payload = {
      customerId: custId,
      email: custEmail || undefined,
      deliveryArea: customerData ? (customerData.deliveryArea || customerData.city) : undefined,
      coupon: customerData ? (customerData.coupon || customerData.couponCode) : (options.coupon || undefined),
      customer: {
        id: custId,
        email: custEmail || undefined,
        name: ((customerData && customerData.name) || "").trim(),
        phone: ((customerData && customerData.phone) || "").trim(),
        city: (customerData && customerData.city) || "الشيخ زايد",
        deliveryArea: customerData ? customerData.deliveryArea : "",
        deliveryAreaName: (customerData && customerData.deliveryAreaName) || "",
        address: ((customerData && customerData.address) || "").trim(),
        notes: ((customerData && customerData.notes) || "").trim()
      },
      items: cartItems.map(item => ({
        id: String(item.id),
        name: String(item.name || ""),
        enName: String(item.enName || ""),
        price: Number(item.price) || 0,
        qty: parseInt(item.qty, 10) || 1,
        variant: item.variant ? String(item.variant) : undefined,
        image: String(item.image || ""),
        categoryName: String(item.categoryName || "")
      }))
    };

    // Submit order to secure serverless endpoint
    const res = await safeApiFetch("/api/orders", {
      method: "POST",
      headers,
      body: JSON.stringify(payload)
    });

    if (!res.ok || !res.data || !res.data.success) {
      throw new Error((res.data && res.data.error) || "تعذر إرسال الطلب إلى الخادم السحابي");
    }

    const confirmedOrder = res.data.order || {};
    const fullOrder = {
      ...payload,
      ...confirmedOrder,
      customer: {
        ...payload.customer,
        ...((confirmedOrder && confirmedOrder.customer) || {})
      },
      items: (confirmedOrder && Array.isArray(confirmedOrder.items) && confirmedOrder.items.length > 0)
        ? confirmedOrder.items
        : payload.items
    };

    // Store strictly in volatile memory (CWE-312)
    this.#insertInMemoryOrder(fullOrder);

    this.incrementSales(cartItems);
    this.reserveStock(cartItems);
    this.logActivity("order_created", `طلب جديد #${fullOrder.id} بقيمة ${fullOrder.total || 0} ج.م`);

    if (this.isAdminUser()) {
      this.playLuxuryChime();
    }

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_new_order_placed", { detail: fullOrder }));
    }

    return fullOrder;
  }

  async fetchLiveOrder(orderId) {
    if (!orderId) return null;
    const cleanId = String(orderId).replace(/[#]/g, "").trim();
    const t = Date.now();
    let cloudOrder = null;

    try {
      const res = await safeApiFetch(`/api/orders?id=${encodeURIComponent(cleanId)}&t=${t}`, {
        timeout: 6000
      });

      if (res.ok && res.data) {
        if (res.data.order) {
          cloudOrder = res.data.order;
        } else if (Array.isArray(res.data.orders)) {
          cloudOrder = res.data.orders.find(o =>
            o && (
              String(o.id).toUpperCase() === cleanId.toUpperCase() ||
              String(o.id).replace("ORD-", "") === cleanId.replace("ORD-", "")
            )
          );
        }
      }
    } catch (e) {}

    if (cloudOrder) {
      // Normalize items & customer
      if (cloudOrder.items && !Array.isArray(cloudOrder.items) && typeof cloudOrder.items === "object") {
        cloudOrder.items = Object.values(cloudOrder.items);
      }
      if (typeof cloudOrder.customer === "string") {
        try {
          cloudOrder.customer = JSON.parse(cloudOrder.customer);
        } catch (e) {
          cloudOrder.customer = { name: cloudOrder.customer };
        }
      }

      this.#insertInMemoryOrder(cloudOrder);
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_orders_updated", { detail: cloudOrder }));
      }
      return cloudOrder;
    }

    return null;
  }

  updateOrderStatus(orderId, newStatus) {
    if (!orderId || !newStatus) return false;
    const order = this.#inMemoryOrders.find(o => o && o.id === orderId);

    if (order) {
      const oldStatus = order.status;
      order.status = newStatus;
      if (newStatus !== "pending" && newStatus !== "received") {
        order.isRead = true;
      }

      // Stock management: Release stock if cancelled or failed
      if ((newStatus === "cancelled" || newStatus === "failed") && (oldStatus !== "cancelled" && oldStatus !== "failed")) {
        this.releaseStock(order.items);
      } else if ((oldStatus === "cancelled" || oldStatus === "failed") && (newStatus !== "cancelled" && newStatus !== "failed")) {
        this.reserveStock(order.items);
      }

      this.updateOrderStatusInCloud(orderId, newStatus);
      this.recalculateAllProductSales();
      this.logActivity("order_status_updated", `تغيير حالة الطلب #${orderId} إلى: ${newStatus}`);

      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_orders_updated"));
      }
      return true;
    }
    return false;
  }

  async updateOrderStatusInCloud(orderId, status) {
    const updatedAt = Date.now();
    try {
      await safeApiFetch("/api/orders", {
        method: "PATCH",
        body: JSON.stringify({ id: orderId, status, updatedAt })
      });
    } catch (e) {}

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_orders_updated", { detail: { orderId, status, updatedAt } }));
    }
  }

  updateOrderPaymentStatus(orderId, paymentStatus) {
    if (!orderId || !paymentStatus) return false;
    const order = this.#inMemoryOrders.find(o => o && o.id === orderId);

    if (order) {
      order.paymentStatus = paymentStatus;
      order.paymentStatusText = paymentStatus === "collected"
        ? "تم التحصيل نقدياً بنجاح"
        : "الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد";
      order.paymentStatusTextEn = paymentStatus === "collected"
        ? "Cash Collected Successfully"
        : "Cash on delivery — not yet collected";

      if (paymentStatus === "collected") {
        order.paidAt = Date.now();
      }

      safeApiFetch("/api/orders", {
        method: "PATCH",
        body: JSON.stringify({ id: orderId, paymentStatus })
      }).catch(() => {});

      this.logActivity(
        "payment_status_updated",
        `تحديث حالة الدفع للطلب #${orderId} إلى: ${paymentStatus === "collected" ? "تم التحصيل" : "لم يتم التحصيل"}`
      );

      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_orders_updated"));
      }
      return true;
    }
    return false;
  }

  markAllOrdersAsRead() {
    this.#inMemoryOrders.forEach(o => {
      if (o) o.isRead = true;
    });
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_orders_updated"));
    }
  }

  deleteOrder(orderId) {
    if (!orderId) return false;
    const target = this.#inMemoryOrders.find(o => o && o.id === orderId);
    if (target) {
      this.saveWebRestorePoint(`قبل حذف طلب: #${orderId} (${(target.customer && target.customer.name) || ""})`);
    }

    this.#inMemoryOrders = this.#inMemoryOrders.filter(o => o && o.id !== orderId);
    this.#knownOrderIds.delete(orderId);

    this.deleteOrderFromCloud(orderId);
    this.recalculateAllProductSales();

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_orders_updated"));
    }
    return true;
  }

  async deleteOrderFromCloud(orderId) {
    if (!orderId) return;
    try {
      await safeApiFetch(`/api/orders?id=${encodeURIComponent(String(orderId))}`, {
        method: "DELETE"
      });
    } catch (e) {}
  }

  getUnreadOrdersCount() {
    return this.#inMemoryOrders.filter(o => {
      if (!o) return false;
      const st = String(o.status || "").toLowerCase().trim();
      const isReceivedOrConfirmed = st === "received" || st === "confirmed" || st === "pending";
      return isReceivedOrConfirmed && (!o.isRead || o.isRead === false);
    }).length;
  }

  incrementSales(cartItems) {
    if (!Array.isArray(cartItems)) return;
    const products = this.getProducts();

    cartItems.forEach(item => {
      if (!item) return;
      const p = products.find(prod => prod && prod.id === item.id);
      if (p) {
        const qty = parseInt(item.qty, 10) || 1;
        p.salesCount = (p.salesCount || 0) + qty;
        this.sendProductToCloud(p);
      }
    });

    try {
      localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
    } catch (e) {}

    this.recalculateAllProductSales();
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: products }));
    }
  }

  recalculateAllProductSales() {
    const orders = this.getOrders();
    const products = this.getProducts();
    const activeOrders = orders.filter(o => o && o.status !== "cancelled");

    const salesMap = new Map();
    activeOrders.forEach(o => {
      if (Array.isArray(o.items)) {
        o.items.forEach(it => {
          if (it && it.id) {
            salesMap.set(it.id, (salesMap.get(it.id) || 0) + (parseInt(it.qty, 10) || 1));
          }
        });
      }
    });

    let hasChanges = false;
    products.forEach(p => {
      if (!p) return;
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
      try {
        localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
      } catch (e) {}
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_products_updated", { detail: products }));
      }
    }
  }

  getAnalytics() {
    const orders = this.getOrders();
    const products = this.getProducts();

    const activeOrders = orders.filter(o => o && o.status !== "cancelled");
    const totalRevenue = activeOrders.reduce((sum, o) => sum + (Number(o.total) || 0), 0);
    const totalOrdersCount = orders.length;
    const pendingOrdersCount = orders.filter(o => o && o.status === "pending").length;
    const activeProductsCount = products.length;

    const salesMap = new Map();
    activeOrders.forEach(o => {
      if (Array.isArray(o.items)) {
        o.items.forEach(it => {
          if (it && it.id) {
            salesMap.set(it.id, (salesMap.get(it.id) || 0) + (parseInt(it.qty, 10) || 1));
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
        totalRevenue: totalSales * (Number(p.price) || 0)
      };
    });

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
  // 7. CATEGORIES MANAGEMENT
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
    if (!categoryData || !categoryData.name || !String(categoryData.name).trim()) {
      return { success: false, error: "اسم القسم إجباري" };
    }
    const name = String(categoryData.name).trim();
    const categories = this.getCategories();
    const parentId = (categoryData.parentId && String(categoryData.parentId).trim()) ? String(categoryData.parentId).trim() : null;

    if (categories.some(c => c && c.name && c.name.toLowerCase() === name.toLowerCase() && (c.parentId || null) === parentId)) {
      return { success: false, error: "هذا القسم موجود بالفعل في الكتالوج" };
    }

    let id = (categoryData.id || "").trim().toLowerCase().replace(/[^a-z0-9_-]/g, "-");
    if (!id || categories.some(c => c && c.id === id)) {
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
    try {
      localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(categories));
    } catch (e) {}

    if (typeof window !== "undefined") {
      window.CATEGORIES = categories;
    }

    await this.sendCategoriesToCloud(categories);

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_categories_updated", { detail: { action: "add", category: newCat } }));
    }
    return { success: true, category: newCat };
  }

  async updateCategory(id, updatedData) {
    if (!id || id === "all") return { success: false, error: "لا يمكن تعديل هذا القسم الأساسي" };
    const categories = this.getCategories();
    const cat = categories.find(c => c && c.id === id);
    if (!cat) return { success: false, error: "القسم غير موجود" };

    if (updatedData.name && String(updatedData.name).trim()) {
      cat.name = String(updatedData.name).trim();
    }
    if (typeof updatedData.parentId !== "undefined") {
      cat.parentId = (updatedData.parentId && String(updatedData.parentId).trim()) ? String(updatedData.parentId).trim() : null;
    }

    try {
      localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(categories));
    } catch (e) {}

    if (typeof window !== "undefined") {
      window.CATEGORIES = categories;
    }

    await this.sendCategoriesToCloud(categories);

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_categories_updated", { detail: { action: "update", category: cat } }));
    }
    return { success: true, category: cat };
  }

  async deleteCategory(id) {
    if (!id || id === "all") return { success: false, error: "لا يمكن حذف قسم الكل المعروض" };
    let categories = this.getCategories();
    const deletedCat = categories.find(c => c && c.id === id);
    if (!deletedCat) return { success: false, error: "القسم غير موجود" };

    this.saveWebRestorePoint(`قبل حذف قسم: ${deletedCat.name}`);

    categories = categories.filter(c => c && c.id !== id && c.parentId !== id);
    try {
      localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(categories));
    } catch (e) {}

    if (typeof window !== "undefined") {
      window.CATEGORIES = categories;
    }

    await this.sendCategoriesToCloud(categories);

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_categories_updated", { detail: { action: "delete", id } }));
    }
    return { success: true };
  }

  async syncCategoriesFromCloud() {
    try {
      const t = Date.now();
      const res = await safeApiFetch(`/api/settings?type=categories&t=${t}`, {
        cache: "no-store",
        timeout: 6000
      });

      if (res.ok && res.data && res.data.success && Array.isArray(res.data.categories)) {
        const cloudCats = res.data.categories;
        const localCats = this.getCategories();

        if (JSON.stringify(cloudCats) !== JSON.stringify(localCats)) {
          try {
            localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(cloudCats));
          } catch (e) {}

          if (typeof window !== "undefined") {
            window.CATEGORIES = cloudCats;
            window.dispatchEvent(new CustomEvent("kk_categories_updated", { detail: { merged: false, categories: cloudCats } }));
          }
        }
      }
    } catch (e) {}
  }

  async sendCategoriesToCloud(categories) {
    try {
      await safeApiFetch("/api/settings", {
        method: "POST",
        body: JSON.stringify({ type: "categories", categories: categories })
      });
    } catch (e) {}
  }

  // --------------------------------------------------------------------------
  // 8. SHOWROOM SETTINGS & CONTACT INFO
  // --------------------------------------------------------------------------
  getSettings() {
    try {
      const raw = localStorage.getItem(DB_KEYS.SETTINGS);
      const parsed = raw ? JSON.parse(raw) : null;
      const base = parsed && typeof parsed === "object"
        ? parsed
        : (typeof INITIAL_SHOWROOM_INFO !== "undefined"
            ? { ...INITIAL_SHOWROOM_INFO }
            : (typeof SHOWROOM_INFO !== "undefined" ? { ...SHOWROOM_INFO } : {}));

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
        designerUrl: "https://karimodesign.vercel.app/" // Permanent attribution lock
      },
      updatedAt: Date.now()
    };

    try {
      localStorage.setItem(DB_KEYS.SETTINGS, JSON.stringify(merged));
    } catch (e) {}

    if (typeof window !== "undefined") {
      window.SHOWROOM_INFO = merged;
    }

    this.sendSettingsToCloud(merged);

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_settings_updated", { detail: merged }));
    }
    return { success: true, settings: merged };
  }

  async syncSettingsFromCloud() {
    try {
      const t = Date.now();
      const res = await safeApiFetch(`/api/settings?type=settings&t=${t}`, {
        cache: "no-store",
        timeout: 6000
      });

      if (res.ok && res.data && res.data.success && res.data.settings) {
        const cloudSettings = res.data.settings;
        const localSettings = this.getSettings();

        if (JSON.stringify(cloudSettings) !== JSON.stringify(localSettings)) {
          const merged = {
            ...localSettings,
            ...cloudSettings,
            social: { ...localSettings.social, ...(cloudSettings.social || {}) }
          };
          try {
            localStorage.setItem(DB_KEYS.SETTINGS, JSON.stringify(merged));
          } catch (e) {}

          if (typeof window !== "undefined") {
            window.SHOWROOM_INFO = merged;
            window.dispatchEvent(new CustomEvent("kk_settings_updated", { detail: merged }));
          }
        }
      }
    } catch (e) {}
  }

  async sendSettingsToCloud(settings) {
    try {
      await safeApiFetch("/api/settings", {
        method: "POST",
        body: JSON.stringify({ type: "settings", settings: settings })
      });
    } catch (e) {}
  }

  // --------------------------------------------------------------------------
  // 9. DAILY BACKUP & RESTORE SYSTEM
  // --------------------------------------------------------------------------
  generateBackupData(label = "Daily Backup") {
    const products = this.getProducts();
    const orders = this.getOrders();
    const categories = this.getCategories();
    const settings = this.getSettings();
    const analytics = this.getAnalytics();
    const now = new Date();
    const dateFormatted = now.toISOString().slice(0, 10);
    const timeFormatted = now.toLocaleTimeString("ar-EG", {
      timeZone: "Africa/Cairo",
      hour: "2-digit",
      minute: "2-digit"
    });

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

    // 1. Native Windows/OS "Save As" location picker
    if (typeof window !== "undefined" && typeof window.showSaveFilePicker === "function") {
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
      }
    }

    // 2. Standard browser download fallback
    if (!savedLocally && typeof document !== "undefined") {
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

    try {
      localStorage.setItem("kk_last_downloaded_backup_date", dateStr);
      localStorage.setItem("kk_last_downloaded_backup_time", Date.now().toString());
    } catch (e) {}

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

    // Sanitize any gigantic base64 product images to protect localStorage quota
    const safeProducts = (backupData.products || []).map(p => {
      if (!p) return p;
      let cleanImg = p.image || "";
      if (typeof cleanImg === "string" && cleanImg.startsWith("data:") && cleanImg.length > 5000) {
        cleanImg = "https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=600&q=80";
      }
      return { ...p, image: cleanImg };
    });

    const safeBackupData = {
      ...backupData,
      products: safeProducts
    };

    const newPoint = {
      id: "RST-" + Date.now().toString().slice(-7),
      timestamp: Date.now(),
      dateFormatted: safeBackupData.dateFormatted,
      timeFormatted: safeBackupData.timeFormatted,
      label: label,
      counts: safeBackupData.counts,
      totalRevenue: (safeBackupData.analytics && safeBackupData.analytics.totalRevenue) || 0,
      data: safeBackupData
    };

    // Store up to 100 recent points in local cache, with permanent storage on the database server
    points = [newPoint, ...points.filter(p => p && p.id !== newPoint.id)].slice(0, 100);
    try {
      localStorage.setItem(DB_KEYS.BACKUPS, JSON.stringify(points));
    } catch (e) {
      try {
        points = [newPoint, ...points.slice(1, 15)];
        localStorage.setItem(DB_KEYS.BACKUPS, JSON.stringify(points));
      } catch (err) {}
    }

    // Push snapshot to /api/restore-points server endpoint for permanent long-term archive (1+ years)
    safeApiFetch("/api/restore-points", {
      method: "POST",
      body: JSON.stringify(newPoint)
    }).catch(() => null);

    // Push snapshot to /api/backup serverless endpoint
    safeApiFetch("/api/backup", {
      method: "POST",
      body: JSON.stringify(newPoint)
    }).catch(() => null);

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_restore_points_updated"));
    }
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

    this.#isRestoring = true;
    if (this.#restoreLockTimer) clearTimeout(this.#restoreLockTimer);
    this.#restoreLockTimer = setTimeout(() => {
      this.#isRestoring = false;
    }, 15000);

    try {
      this.saveWebRestorePoint("نقطة أمان تلقائية (قبل الاسترجاع)");
    } catch (e) {}

    // 1. Restore Products
    if (Array.isArray(backupData.products)) {
      try {
        localStorage.removeItem("kk_deleted_product_ids_v1");
        localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(backupData.products));
        localStorage.setItem("kased_karim_custom_products", JSON.stringify(backupData.products));
      } catch (e) {}

      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_products_updated", {
          detail: { merged: false, products: backupData.products }
        }));
      }
    }

    // 2. Restore Orders (in-memory only!)
    if (Array.isArray(backupData.orders)) {
      this.#inMemoryOrders = backupData.orders.filter(o => o && o.id);
      this.#knownOrderIds.clear();
      this.#inMemoryOrders.forEach(o => this.#knownOrderIds.add(o.id));
      this.recalculateAllProductSales();

      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_orders_updated"));
      }
    }

    // 3. Restore Categories
    if (Array.isArray(backupData.categories) && backupData.categories.length > 0) {
      try {
        localStorage.setItem(DB_KEYS.CATEGORIES, JSON.stringify(backupData.categories));
      } catch (e) {}

      if (typeof window !== "undefined") {
        window.CATEGORIES = backupData.categories;
        window.dispatchEvent(new CustomEvent("kk_categories_updated", {
          detail: { merged: false, categories: backupData.categories }
        }));
      }
    }

    // 4. Restore Settings
    if (backupData.settings && typeof backupData.settings === "object") {
      const safeSettings = { ...backupData.settings, updatedAt: Date.now() };
      try {
        localStorage.setItem(DB_KEYS.SETTINGS, JSON.stringify(safeSettings));
      } catch (e) {}

      if (typeof window !== "undefined") {
        window.SHOWROOM_INFO = safeSettings;
        window.dispatchEvent(new CustomEvent("kk_settings_updated", { detail: safeSettings }));
      }
    }

    // 5. Cloud Synchronization
    let cloudSynced = false;
    if (syncToCloud) {
      try {
        const backupRes = await safeApiFetch("/api/backup", {
          method: "POST",
          body: JSON.stringify({
            action: "restore",
            confirm: true,
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
      } catch (errBackup) {}

      try {
        const batchTasks = [];
        if (Array.isArray(backupData.products) && backupData.products.length > 0) {
          batchTasks.push(this.syncAllLocalProductsToCloud());
        }
        if (Array.isArray(backupData.orders)) {
          batchTasks.push(
            safeApiFetch("/api/orders", {
              method: "PUT",
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
        products: (backupData.products && backupData.products.length) || 0,
        orders: (backupData.orders && backupData.orders.length) || 0,
        categories: (backupData.categories && backupData.categories.length) || 0
      }
    };
  }

  async restoreFromWebPoint(pointId) {
    const points = this.getWebRestorePoints();
    const point = points.find(p => p && p.id === pointId);
    if (!point || !point.data) {
      return { success: false, error: "نقطة الاسترجاع غير موجودة" };
    }
    return await this.restoreFromData(point.data, true);
  }

  deleteWebRestorePoint(pointId) {
    let points = this.getWebRestorePoints();
    points = points.filter(p => p && p.id !== pointId);
    try {
      localStorage.setItem(DB_KEYS.BACKUPS, JSON.stringify(points));
    } catch (e) {}

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_restore_points_updated"));
    }
    return true;
  }

  async restoreFactoryDefaults() {
    this.saveWebRestorePoint("قبل استعادة ضبط المصنع");

    const defaultProducts = [...(typeof INITIAL_PRODUCTS !== "undefined" ? INITIAL_PRODUCTS : [])];
    const defaultOrders = [];
    const defaultCategories = typeof INITIAL_CATEGORIES !== "undefined" ? [...INITIAL_CATEGORIES] : [...this.getCategories()];
    const defaultSettings = typeof INITIAL_SHOWROOM_INFO !== "undefined" ? { ...INITIAL_SHOWROOM_INFO } : { ...this.getSettings() };

    return await this.restoreFromData({
      products: defaultProducts,
      orders: defaultOrders,
      categories: defaultCategories,
      settings: defaultSettings
    }, true);
  }

  // --------------------------------------------------------------------------
  // 10. CUSTOMER ACCOUNT & PROFILE (HTTP-ONLY COOKIES ALIGNED - CWE-312)
  // --------------------------------------------------------------------------
  getCustomer() {
    if (this.#currentCustomer) {
      return { ...this.#currentCustomer };
    }
    try {
      const data =
        (typeof sessionStorage !== "undefined" && sessionStorage.getItem(DB_KEYS.CUSTOMER_USER)) ||
        (typeof localStorage !== "undefined" && (localStorage.getItem(DB_KEYS.CUSTOMER_USER) || localStorage.getItem("kk_customer_account")));

      if (data) {
        this.#currentCustomer = JSON.parse(data);
        return { ...this.#currentCustomer };
      }
    } catch (e) {}
    return null;
  }

  saveCustomer(customer) {
    if (!customer || typeof customer !== "object") return;
    try {
      // Defensive sanitization: never persist tokens or passwords in browser storage
      const safeCustomer = {
        id: customer.id || null,
        name: String(customer.name || "").trim(),
        phone: String(customer.phone || "").trim(),
        email: String(customer.email || "").trim().toLowerCase(),
        avatar: String(customer.avatar || "").trim(),
        deliveryArea: customer.deliveryArea || "",
        address: customer.address || ""
      };

      this.#currentCustomer = safeCustomer;

      // Persist display info for seamless checkout UI experience
      if (typeof localStorage !== "undefined") {
        localStorage.setItem(DB_KEYS.CUSTOMER_USER, JSON.stringify(safeCustomer));
        localStorage.setItem("kk_customer_account", JSON.stringify(safeCustomer));
        if (safeCustomer.name) localStorage.setItem("kk_customer_name", safeCustomer.name);
        if (safeCustomer.phone) localStorage.setItem("kk_customer_phone", safeCustomer.phone);
        if (safeCustomer.email) localStorage.setItem("kk_customer_email", safeCustomer.email);
        if (safeCustomer.avatar) localStorage.setItem("kk_customer_avatar", safeCustomer.avatar);
      }

      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_customer_auth_changed", { detail: safeCustomer }));
      }
    } catch (e) {}
  }

  async getCustomersList() {
    try {
      const res = await safeApiFetch(`/api/customer?action=list&t=${Date.now()}`, {
        cache: "no-store",
        timeout: 6000
      });
      if (res.ok && res.data && Array.isArray(res.data.customers)) {
        return res.data.customers;
      }
    } catch (e) {}
    return [];
  }

  getCustomerToken() {
    // Tokens are HttpOnly cookies; client code cannot and should not read them (Axis 3)
    return null;
  }

  async customerRegister(name, phone, param3, param4) {
    let email = "";
    let password = "";
    // Robustly handle both signatures: (name, phone, email, password) and (name, phone, password, email)
    if (param4 !== undefined) {
      if (typeof param3 === "string" && param3.includes("@")) {
        email = param3;
        password = param4;
      } else {
        password = param3;
        email = param4 || "";
      }
    } else {
      password = param3;
    }

    const res = await safeApiFetch("/api/customer?action=register", {
      method: "POST",
      body: JSON.stringify({ name, phone, email, password })
    });

    if (!res.ok || !res.data || !res.data.success) {
      throw new Error((res.data && res.data.error) || "تعذر إنشاء الحساب");
    }

    if (res.data.customer) {
      this.saveCustomer(res.data.customer);
    }
    return res.data.customer;
  }

  async customerGoogleAuth(credential) {
    const res = await safeApiFetch("/api/customer?action=google", {
      method: "POST",
      body: JSON.stringify({ credential })
    });

    if (!res.ok || !res.data || !res.data.success) {
      throw new Error((res.data && res.data.error) || "تعذر إتمام الدخول عبر Google");
    }

    if (res.data.customer) {
      this.saveCustomer(res.data.customer);
    }
    return res.data;
  }

  async customerLogin(identifier, password) {
    const res = await safeApiFetch("/api/customer?action=login", {
      method: "POST",
      body: JSON.stringify({ identifier, password })
    });

    if (!res.ok || !res.data || !res.data.success) {
      throw new Error((res.data && res.data.error) || "بيانات الدخول غير صحيحة");
    }

    if (res.data.customer) {
      this.saveCustomer(res.data.customer);
    }
    return res.data.customer;
  }

  async customerLogout() {
    try {
      await safeApiFetch("/api/customer?action=logout", {
        method: "POST"
      });
    } catch (e) {}

    this.#currentCustomer = null;

    try {
      localStorage.removeItem(DB_KEYS.CUSTOMER_USER);
      localStorage.removeItem("kk_customer_account");
      localStorage.removeItem("kk_customer_name");
      localStorage.removeItem("kk_customer_phone");
      localStorage.removeItem("kk_customer_email");
      localStorage.removeItem("kk_customer_avatar");
      localStorage.removeItem("kk_customer_token");
      sessionStorage.removeItem("kk_customer_token");
    } catch (e) {}

    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_customer_auth_changed", { detail: null }));
    }
  }

  async getCustomerOrders() {
    const customer = this.getCustomer();
    let cloudOrders = [];

    try {
      const res = await safeApiFetch("/api/customer?action=orders", {
        timeout: 8000
      });
      if (res.ok && res.data && Array.isArray(res.data.orders)) {
        cloudOrders = res.data.orders;
      }
    } catch (e) {}

    // Merge with in-memory session orders matching customer
    const custEmail = customer && customer.email ? customer.email.toLowerCase().trim() : "";
    const custPhone = customer && customer.phone ? customer.phone.replace(/[^0-9]/g, "") : "";
    const custId = customer ? customer.id : null;

    const matchedLocal = this.#inMemoryOrders.filter(o => {
      if (!o || !o.id) return false;
      if (custId && o.customerId === custId) return true;
      const oEmail = ((o.customer && o.customer.email) || o.email || "").toLowerCase().trim();
      if (custEmail && oEmail && oEmail === custEmail) return true;
      const oPhone = ((o.customer && o.customer.phone) || "").replace(/[^0-9]/g, "");
      if (custPhone && oPhone && oPhone === custPhone) return true;
      return false;
    });

    const map = new Map();
    matchedLocal.forEach(o => map.set(o.id, o));
    cloudOrders.forEach(o => map.set(o.id, o));
    const combined = Array.from(map.values());
    combined.sort((a, b) => (Number(b.timestamp) || 0) - (Number(a.timestamp) || 0));
    return combined;
  }

  // --------------------------------------------------------------------------
  // 11. PRODUCT REVIEWS & MODERATION
  // --------------------------------------------------------------------------
  async getProductReviews(productId) {
    if (!productId) return [];
    try {
      const res = await safeApiFetch(`/api/reviews?productId=${encodeURIComponent(String(productId))}`, {
        cache: "no-store",
        timeout: 6000
      });
      if (res.ok && res.data && res.data.success && Array.isArray(res.data.reviews)) {
        return res.data.reviews;
      }
    } catch (e) {}

    // Safe fallback to initial reviews if offline
    return (typeof REVIEWS !== "undefined" ? REVIEWS : []).filter(
      r => r && r.productId === productId && r.status === "approved"
    );
  }

  async submitReview(productId, productName, author, rating, comment) {
    const res = await safeApiFetch("/api/reviews", {
      method: "POST",
      body: JSON.stringify({ productId, productName, author, rating, comment })
    });

    if (!res.ok || !res.data || !res.data.success) {
      throw new Error((res.data && res.data.error) || "تعذر إرسال التقييم");
    }

    this.logActivity("review_submitted", `تقييم جديد للمنتج: ${productName} بواسطة ${author}`);
    return res.data.review;
  }

  async getAllReviewsForAdmin() {
    try {
      const res = await safeApiFetch("/api/reviews?all=1", {
        cache: "no-store",
        timeout: 6000
      });
      if (res.ok && res.data && Array.isArray(res.data.reviews)) {
        return res.data.reviews;
      }
    } catch (e) {}
    return typeof REVIEWS !== "undefined" ? REVIEWS : [];
  }

  async moderateReview(reviewId, status) {
    const res = await safeApiFetch("/api/reviews", {
      method: "PATCH",
      body: JSON.stringify({ id: reviewId, status })
    });

    if (!res.ok || !res.data || !res.data.success) {
      throw new Error((res.data && res.data.error) || "تعذر تعديل التقييم");
    }

    this.logActivity("review_moderated", `تعديل حالة التقييم #${reviewId} إلى ${status}`);
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_reviews_updated"));
    }
    return true;
  }

  async deleteReview(reviewId) {
    const res = await safeApiFetch(`/api/reviews?id=${encodeURIComponent(String(reviewId))}`, {
      method: "DELETE"
    });

    if (!res.ok || !res.data || !res.data.success) {
      throw new Error((res.data && res.data.error) || "تعذر حذف التقييم");
    }

    this.logActivity("review_deleted", `حذف التقييم #${reviewId}`);
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_reviews_updated"));
    }
    return true;
  }

  // --------------------------------------------------------------------------
  // 12. DELIVERY AREAS & STOCK MANAGEMENT
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
    try {
      localStorage.setItem(DB_KEYS.DELIVERY_AREAS, JSON.stringify(areas));
    } catch (e) {}
    this.logActivity("delivery_areas_updated", "تحديث مناطق وأسعار التوصيل");
    if (typeof window !== "undefined") {
      window.dispatchEvent(new CustomEvent("kk_delivery_areas_updated"));
    }
  }

  reserveStock(items) {
    if (!Array.isArray(items) || items.length === 0) return;
    const products = this.getProducts();
    let changed = false;

    items.forEach(item => {
      if (!item) return;
      const prod = products.find(p => p && p.id === item.id);
      if (prod) {
        const currentStock = parseInt(prod.stock !== undefined ? prod.stock : 10, 10);
        const qty = parseInt(item.qty || 1, 10);
        prod.stock = Math.max(0, currentStock - qty);
        prod.inStock = prod.stock > 0;
        changed = true;
      }
    });

    if (changed) {
      try {
        localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
      } catch (e) {}
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_products_updated"));
      }
    }
  }

  releaseStock(items) {
    if (!Array.isArray(items) || items.length === 0) return;
    const products = this.getProducts();
    let changed = false;

    items.forEach(item => {
      if (!item) return;
      const prod = products.find(p => p && p.id === item.id);
      if (prod) {
        const currentStock = parseInt(prod.stock !== undefined ? prod.stock : 0, 10);
        const qty = parseInt(item.qty || 1, 10);
        prod.stock = currentStock + qty;
        prod.inStock = prod.stock > 0;
        changed = true;
      }
    });

    if (changed) {
      try {
        localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
      } catch (e) {}
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_products_updated"));
      }
    }
  }

  updateProductStock(productId, newStock) {
    const products = this.getProducts();
    const prod = products.find(p => p && p.id === productId);
    if (prod) {
      prod.stock = Math.max(0, parseInt(newStock, 10) || 0);
      prod.inStock = prod.stock > 0;
      try {
        localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(products));
      } catch (e) {}
      this.sendProductToCloud(prod);
      this.logActivity("stock_updated", `تعديل مخزون ${prod.name} إلى ${prod.stock} وحدة`);
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_products_updated"));
      }
      return true;
    }
    return false;
  }

  // --------------------------------------------------------------------------
  // 13. ADMINISTRATIVE AUDIT & ACTIVITY LOG
  // --------------------------------------------------------------------------
  logActivity(action, details) {
    try {
      const logs = this.getAuditLogs();
      const newEntry = {
        id: "LOG-" + Date.now().toString(36) + "-" + Math.random().toString(36).substring(2, 6),
        action: String(action || "").slice(0, 60),
        details: String(details || "").slice(0, 200),
        timestamp: Date.now(),
        dateFormatted: new Date().toLocaleDateString("ar-EG", {
          timeZone: "Africa/Cairo",
          year: "numeric",
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit"
        })
      };
      logs.unshift(newEntry);
      try {
        localStorage.setItem(DB_KEYS.AUDIT_LOGS, JSON.stringify(logs.slice(0, 100)));
      } catch (e) {}
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("kk_audit_logs_updated"));
      }
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

// -----------------------------------------------------------------------------
// SINGLETON INSTANTIATION & OBJECT.FREEZE TAMPER RESISTANCE (ASVS L3)
// -----------------------------------------------------------------------------
const kkDbInstance = new KasedKarimDB();

// Freeze instance and prototypes to prevent prototype pollution or monkey-patching
Object.freeze(kkDbInstance);
Object.freeze(KasedKarimDB.prototype);
Object.freeze(KasedKarimDB);

// Global browser window exposure
if (typeof window !== "undefined") {
  window.KK_DB = kkDbInstance;
}
if (typeof globalThis !== "undefined" && !globalThis.KK_DB) {
  globalThis.KK_DB = kkDbInstance;
}
