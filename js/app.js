/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Main E-Commerce & Interactive Application Logic
 * Hardened strictly according to OWASP ASVS (Level 3 — V5) & OWASP DOM-Based XSS Prevention Cheat Sheet
 * 100% Strict Content-Security-Policy (CSP) Compliant — Zero Inline Handlers & Zero Dynamic innerHTML
 */

// -----------------------------------------------------------------------------
// 1. SAFE HTML & TEXT ESCAPING UTILITY (OWASP ASVS V5.1.4, V5.3.3)
// -----------------------------------------------------------------------------
window.escapeHtml = window.escapeHtml || function(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/`/g, "&#96;");
};

// CSS Escape polyfill for safe DOM querySelector matching
function safeCssEscape(str) {
  if (typeof CSS !== "undefined" && typeof CSS.escape === "function") {
    return CSS.escape(String(str || ""));
  }
  return String(str || "").replace(/["'\\]/g, "\\$&");
}

// -----------------------------------------------------------------------------
// 2. SAFE URL & MEDIA SANITIZER (CWE-79 / Protocol Whitelisting)
// -----------------------------------------------------------------------------
const DEFAULT_FALLBACK_IMAGE = "https://images.unsplash.com/photo-1513506003901-1e6a229e2d15?auto=format&fit=crop&w=1200&q=80";

function sanitizeUrl(rawUrl, { allowTel = false, allowMailto = false, fallback = "#" } = {}) {
  if (typeof rawUrl !== "string") return fallback;
  if (rawUrl.length === 0 || rawUrl.length > 2048) return fallback;

  // Strip control characters (\x00-\x1F, \x7F) and leading/trailing whitespace
  const clean = rawUrl.replace(/[\x00-\x1F\x7F]/g, "").trim();
  if (!clean) return fallback;

  // Reject dangerous pseudo-protocols and protocol-relative links
  const lower = clean.toLowerCase();
  if (
    lower.startsWith("javascript:") ||
    lower.startsWith("data:") ||
    lower.startsWith("vbscript:") ||
    lower.startsWith("file:") ||
    lower.startsWith("blob:") ||
    lower.startsWith("//")
  ) {
    return fallback;
  }

  // Handle tel:
  if (allowTel && lower.startsWith("tel:")) {
    const phonePart = clean.slice(4).replace(/[^0-9+]/g, "");
    return phonePart.length >= 3 && phonePart.length <= 20 ? `tel:${phonePart}` : fallback;
  }

  // Handle mailto:
  if (allowMailto && lower.startsWith("mailto:")) {
    const emailPart = clean.slice(7).trim();
    return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(emailPart) ? `mailto:${emailPart}` : fallback;
  }

  // Validate via URL parser
  try {
    const baseOrigin = typeof window !== "undefined" && window.location ? window.location.origin : "https://www.kasedkarim.com";
    const parsed = new URL(clean, baseOrigin);

    // Strictly enforce https: (or http: on localhost)
    if (parsed.protocol === "https:" || (parsed.protocol === "http:" && (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1"))) {
      if (clean.startsWith("/") && clean.includes("..")) {
        return fallback;
      }
      return clean.startsWith("/") ? clean : parsed.href;
    }
  } catch {
    return fallback;
  }

  return fallback;
}

function sanitizeImageUrl(rawUrl, fallback = DEFAULT_FALLBACK_IMAGE) {
  const safe = sanitizeUrl(rawUrl, { fallback });
  return safe === "#" ? fallback : safe;
}

function setSafeImageWithFallback(imgEl, rawSrc, fallbackSrc = DEFAULT_FALLBACK_IMAGE) {
  if (!imgEl) return;
  const safeSrc = sanitizeImageUrl(rawSrc, fallbackSrc);
  imgEl.src = safeSrc;
  imgEl.loading = "lazy";
  let hasHandledError = false;
  imgEl.addEventListener("error", () => {
    if (!hasHandledError) {
      hasHandledError = true;
      imgEl.src = fallbackSrc;
    }
  }, { once: true });
}

// -----------------------------------------------------------------------------
// 3. SAFE DOM ELEMENT CONSTRUCTOR (Zero innerHTML / Direct DOM Construction)
// -----------------------------------------------------------------------------
function safeClearContainer(container) {
  if (!container) return;
  if (typeof container.replaceChildren === "function") {
    container.replaceChildren();
  } else {
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }
  }
}

function createSafeEl(tag, attrs = {}, children = []) {
  const el = document.createElement(tag);

  for (const [key, val] of Object.entries(attrs)) {
    if (val === undefined || val === null) continue;

    if (key === "className" || key === "class") {
      el.className = String(val);
    } else if (key === "textContent") {
      el.textContent = String(val);
    } else if (key === "dataset" && typeof val === "object") {
      for (const [dKey, dVal] of Object.entries(val)) {
        if (dVal !== undefined && dVal !== null) {
          el.dataset[dKey] = String(dVal);
        }
      }
    } else if (key === "style" && typeof val === "object") {
      Object.assign(el.style, val);
    } else if (key === "style" && typeof val === "string") {
      if (!/expression|javascript/i.test(val)) {
        el.style.cssText = val;
      }
    } else if (key.startsWith("on")) {
      // Strictly reject inline event handlers under CSP
      console.warn(`[CSP Violation Blocked] Inline handler '${key}' rejected in createSafeEl.`);
    } else {
      el.setAttribute(key, String(val));
    }
  }

  const childList = Array.isArray(children) ? children : [children];
  for (const child of childList) {
    if (child === undefined || child === null) continue;
    if (typeof child === "string" || typeof child === "number") {
      el.appendChild(document.createTextNode(String(child)));
    } else if (child instanceof Node) {
      el.appendChild(child);
    }
  }

  return el;
}

// Application State
const STATE = {
  products: [],
  activeCategory: "all",
  searchQuery: "",
  sortBy: "featured",
  cart: [],
  selectedProduct: null,
  visibleCount: 6
};
window.STATE = STATE;

function isCurrentEn() {
  if (!window.KK_I18N) return false;
  if (typeof window.KK_I18N.getCurrentLanguage === "function") {
    return window.KK_I18N.getCurrentLanguage() === "en";
  }
  return window.KK_I18N.currentLang === "en";
}

// Storage Keys
const STORAGE_KEYS = {
  PRODUCTS: "kased_karim_custom_products",
  CART: "kased_karim_quotation_cart"
};

// Initialize Application
function initApp() {
  checkAndDisplayAdminHeaderIcon();
  if (typeof updateCustomerButtonUI === "function") updateCustomerButtonUI();
  initLightingCeremony();
  loadProducts();
  loadCart();
  renderCategoryTabs();
  renderSubBarCategories();
  renderMobileAccordionCategories();
  renderFooterCategories();
  applyDynamicSettings();
  renderProducts();
  setupEventListeners();
  initEventDelegation();
  setupCategoryTabsScroll();
  updateCartUI();
  handleHeaderScroll();
  checkEmailVerificationParam();
}

async function checkEmailVerificationParam() {
  try {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("verify_email");
    const email = params.get("email");
    if (token) {
      showToast("⏳ جارٍ التحقق من بريدك الإلكتروني وتفعيله سحابياً...", "info", 4000);
      const res = await window.KK_DB.customerVerifyEmail(token, email);
      showToast("🎉 تم تفعيل بريدك الإلكتروني بنجاح ومصادقة حسابك رسمياً!", "success", 8000);
      if (typeof updateCustomerButtonUI === "function") updateCustomerButtonUI();
      params.delete("verify_email");
      params.delete("email");
      const newQuery = params.toString();
      const newUrl = window.location.pathname + (newQuery ? `?${newQuery}` : "") + window.location.hash;
      window.history.replaceState({}, document.title, newUrl);
    }
  } catch (err) {
    showToast(`❌ ${err.message || "فشل تفعيل البريد الإلكتروني"}`, "error", 8000);
  }
}
window.checkEmailVerificationParam = checkEmailVerificationParam;

// 1. Load Products from Database Engine with Prototype Pollution Defense
function loadProducts() {
  if (window.KK_DB) {
    STATE.products = window.KK_DB.getProducts();
    return;
  }
  const saved = localStorage.getItem(STORAGE_KEYS.PRODUCTS);
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed)) {
        STATE.products = parsed.filter(p => p && typeof p === "object" && !Object.prototype.hasOwnProperty.call(p, "__proto__"));
      } else {
        STATE.products = typeof INITIAL_PRODUCTS !== "undefined" ? [...INITIAL_PRODUCTS] : [];
      }
    } catch (e) {
      STATE.products = typeof INITIAL_PRODUCTS !== "undefined" ? [...INITIAL_PRODUCTS] : [];
    }
  } else {
    STATE.products = typeof INITIAL_PRODUCTS !== "undefined" ? [...INITIAL_PRODUCTS] : [];
  }
}

// Save products to database
function saveCustomProducts() {
  if (window.KK_DB) {
    const dbKey = typeof DB_KEYS !== "undefined" && DB_KEYS.PRODUCTS ? DB_KEYS.PRODUCTS : STORAGE_KEYS.PRODUCTS;
    localStorage.setItem(dbKey, JSON.stringify(STATE.products));
  }
}

// 2. Load Cart from localStorage with Prototype Pollution Defense
function loadCart() {
  const saved = localStorage.getItem(STORAGE_KEYS.CART);
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed)) {
        STATE.cart = parsed.filter(item => (
          item && 
          typeof item === "object" && 
          !Object.prototype.hasOwnProperty.call(item, "__proto__") && 
          typeof item.id === "string" &&
          typeof item.qty === "number" && 
          item.qty > 0
        ));
      } else {
        STATE.cart = [];
      }
    } catch (e) {
      STATE.cart = [];
    }
  } else {
    STATE.cart = [];
  }
  window.STATE = STATE;
}

function saveCart() {
  window.STATE = STATE;
  localStorage.setItem(STORAGE_KEYS.CART, JSON.stringify(STATE.cart));
  updateCartUI();
  window.dispatchEvent(new CustomEvent("kk_cart_updated", { detail: STATE.cart }));
}

// 3. Render Category Tabs with Dynamic Item Counts & Anchored Subcategories (Safe DOM)
function renderActiveSubcategoriesStrip(parentCat, cats) {
  const strip = document.getElementById("activeSubcategoryBar");
  if (!strip) return;

  if (!parentCat || parentCat.id === "all") {
    strip.style.display = "none";
    safeClearContainer(strip);
    return;
  }

  const subCats = cats.filter(c => c.parentId === parentCat.id);
  if (!subCats || subCats.length === 0) {
    strip.style.display = "none";
    safeClearContainer(strip);
    return;
  }

  const subCatIds = subCats.map(c => c.id);
  const totalParentCount = STATE.products.filter(p => p.category === parentCat.id || subCatIds.includes(p.category)).length;
  const isParentSelected = STATE.activeCategory === parentCat.id;

  const isEn = isCurrentEn();
  const parentName = (isEn && parentCat.enName) ? parentCat.enName : parentCat.name;

  const frag = document.createDocumentFragment();

  // Strip Label
  const labelSpan = createSafeEl("span", { class: "subcat-strip-label" }, [
    createSafeEl("i", { class: "fas fa-layer-group" }),
    createSafeEl("span", { textContent: isEn ? `Subcategories for ${parentName}:` : `الأقسام الفرعية لـ ${parentName}:` })
  ]);
  frag.appendChild(labelSpan);

  // All in Parent Category Chip
  const parentChip = createSafeEl("button", {
    type: "button",
    class: `subcat-chip ${isParentSelected ? "active" : ""}`,
    dataset: { action: "select-subcategory", catId: parentCat.id },
    title: isEn ? `View all ${parentName}` : `عرض كافة منتجات ${parentName}`
  }, [
    createSafeEl("span", { textContent: isEn ? `All in ${parentName}` : `الكل في ${parentName}` }),
    createSafeEl("span", { class: "subcat-count", textContent: String(totalParentCount) })
  ]);
  frag.appendChild(parentChip);

  // Subcategory Chips
  subCats.forEach(sub => {
    const count = STATE.products.filter(p => p.category === sub.id).length;
    const isActive = STATE.activeCategory === sub.id;
    const subName = (isEn && sub.enName) ? sub.enName : sub.name;

    const subChip = createSafeEl("button", {
      type: "button",
      class: `subcat-chip ${isActive ? "active" : ""}`,
      dataset: { action: "select-subcategory", catId: sub.id },
      title: isEn ? `Subcategory: ${subName}` : `قسم فرعي: ${subName}`
    }, [
      createSafeEl("span", { textContent: String(subName) }),
      createSafeEl("span", { class: "subcat-count", textContent: String(count) })
    ]);
    frag.appendChild(subChip);
  });

  safeClearContainer(strip);
  strip.appendChild(frag);
  strip.style.display = "flex";
}

window.selectSubcategory = function(catId) {
  STATE.activeCategory = catId;
  STATE.visibleCount = 6;
  renderCategoryTabs();
  renderProducts();
  if (typeof updateSubBarActiveCategory === "function") updateSubBarActiveCategory();
};

function renderCategoryTabs() {
  const tabsContainer = document.getElementById("categoryTabs");
  if (!tabsContainer) return;

  const isEn = isCurrentEn();
  const cats = window.KK_DB ? window.KK_DB.getCategories() : (typeof CATEGORIES !== "undefined" ? CATEGORIES : []);
  const mainCats = cats.filter(c => !c.parentId);

  // Determine current active main category or parent of active subcategory
  const activeSub = cats.find(c => c.id === STATE.activeCategory && c.parentId);
  const activeParent = activeSub ? mainCats.find(c => c.id === activeSub.parentId) : null;
  const activeMain = mainCats.find(c => c.id === STATE.activeCategory);
  const currentFamily = activeMain || activeParent || null;

  const frag = document.createDocumentFragment();

  mainCats.forEach(cat => {
    let count = 0;
    const childCats = cats.filter(c => c.parentId === cat.id);
    const hasSubs = childCats.length > 0;

    if (cat.id === "all") {
      count = STATE.products.length;
    } else {
      const childIds = childCats.map(c => c.id);
      count = STATE.products.filter(p => p.category === cat.id || childIds.includes(p.category)).length;
    }

    const isDirectActive = STATE.activeCategory === cat.id;
    const isParentActive = hasSubs && activeParent && activeParent.id === cat.id;
    const activeClass = isDirectActive ? "active" : (isParentActive ? "active-parent" : "");
    const hasSubClass = hasSubs ? "has-subcategories" : "";
    const catDisplayName = (isEn && cat.enName) ? cat.enName : (cat.id === "all" && isEn ? "All Products" : cat.name);

    const btnChildren = [
      createSafeEl("span", { textContent: String(catDisplayName) })
    ];

    if (hasSubs) {
      btnChildren.push(createSafeEl("i", { class: "fas fa-angle-down subcat-caret", "aria-hidden": "true" }));
    }
    btnChildren.push(createSafeEl("span", { class: "tab-count", textContent: String(count) }));

    const tabBtn = createSafeEl("button", {
      type: "button",
      class: `category-tab-btn ${activeClass} ${hasSubClass}`.trim(),
      dataset: { action: "select-category-tab", category: cat.id },
      title: hasSubs ? "يحتوي على أقسام فرعية - انقر لعرض التفريعات" : ""
    }, btnChildren);

    // Hover preview of subcategories for categories that have them
    if (hasSubs) {
      tabBtn.addEventListener("mouseenter", () => {
        renderActiveSubcategoriesStrip(cat, cats);
      });
    }

    frag.appendChild(tabBtn);
  });

  safeClearContainer(tabsContainer);
  tabsContainer.appendChild(frag);

  // Restore strip when mouse leaves tabs container
  tabsContainer.onmouseleave = () => {
    renderActiveSubcategoriesStrip(currentFamily, cats);
  };

  // Render anchored subcategories strip
  renderActiveSubcategoriesStrip(currentFamily, cats);

  if (typeof updateCategoryScrollButtons === "function") {
    updateCategoryScrollButtons();
  }
}

// 3.1 Render Sub-Bar Categories (Safe DOM Construction)
function renderSubBarCategories() {
  const container = document.getElementById("subBarItems");
  if (!container) return;

  const isEn = isCurrentEn();
  const cats = window.KK_DB ? window.KK_DB.getCategories() : (typeof CATEGORIES !== "undefined" ? CATEGORIES : []);
  const frag = document.createDocumentFragment();

  cats.forEach(cat => {
    const isSub = !!cat.parentId;
    const rawName = (isEn && cat.enName) ? cat.enName : (cat.id === "all" && isEn ? "All Products" : cat.name);
    const displayName = isSub ? `↳ ${rawName}` : rawName;

    const btn = createSafeEl("button", {
      type: "button",
      class: `sub-bar-cat-btn ${STATE.activeCategory === cat.id ? "active" : ""}`,
      dataset: { action: "select-subbar-cat", catId: cat.id }
    }, [
      createSafeEl("span", { textContent: String(displayName) })
    ]);

    frag.appendChild(btn);
  });

  safeClearContainer(container);
  container.appendChild(frag);
}

// 3.2 Render Mobile Accordion Categories (Safe DOM Construction)
function renderMobileAccordionCategories() {
  const container = document.getElementById("mobileAccordionContent");
  if (!container) return;

  const isEn = isCurrentEn();
  const cats = window.KK_DB ? window.KK_DB.getCategories() : (typeof CATEGORIES !== "undefined" ? CATEGORIES : []);
  const frag = document.createDocumentFragment();

  cats.forEach(cat => {
    const isSub = !!cat.parentId;
    const rawName = (isEn && cat.enName) ? cat.enName : (cat.id === "all" && isEn ? "All Products" : cat.name);
    const displayName = isSub ? `— ${rawName}` : rawName;

    const btn = createSafeEl("button", {
      type: "button",
      class: `mobile-sub-cat-item ${STATE.activeCategory === cat.id ? "active" : ""} ${isSub ? "is-mobile-subcat" : ""}`,
      dataset: { action: "select-mobile-cat", catId: cat.id },
      style: isSub ? "padding-right: 1.75rem; font-size: 0.88rem; opacity: 0.9;" : ""
    }, [
      createSafeEl("span", { textContent: String(displayName) })
    ]);

    frag.appendChild(btn);
  });

  safeClearContainer(container);
  container.appendChild(frag);
}

// 3.3 Render Footer Collections Categories (Safe DOM Construction)
function renderFooterCategories() {
  const container = document.querySelector(".footer-links-grid");
  if (!container) return;

  const isEn = isCurrentEn();
  const cats = (window.KK_DB ? window.KK_DB.getCategories() : (typeof CATEGORIES !== "undefined" ? CATEGORIES : [])).filter(c => c.id !== "all");
  const frag = document.createDocumentFragment();

  cats.forEach(cat => {
    const rawName = (isEn && cat.enName) ? cat.enName : cat.name;
    const li = createSafeEl("li", {}, [
      createSafeEl("a", {
        href: "#catalog",
        class: "footer-link",
        dataset: { action: "select-subbar-cat", catId: cat.id },
        textContent: String(rawName)
      })
    ]);
    frag.appendChild(li);
  });

  safeClearContainer(container);
  container.appendChild(frag);
}

// 3.4 Apply Dynamic Showroom Settings & Contact Links (Strict URL Sanitization)
function applyDynamicSettings() {
  const settings = window.KK_DB ? window.KK_DB.getSettings() : (typeof SHOWROOM_INFO !== "undefined" ? SHOWROOM_INFO : {});
  if (!settings) return;

  const isEn = isCurrentEn();
  const phone = settings.phone || "01006367690";
  const whatsapp = settings.whatsapp || "201006367690";
  const cleanPhone = String(phone).replace(/[^0-9+]/g, "");
  const cleanWa = String(whatsapp).replace(/[^0-9]/g, "");

  const location = isEn ? "Sheikh Zayed - 1st District, University Center, Giza, Egypt" : (settings.location || "الشيخ زايد - الحي الأول، سنتر الطاهرة، الجيزة");
  const hours = isEn ? "Daily: 10:00 AM – 10:00 PM" : (settings.workingHours || "يومياً من 11:00 صباحاً حتى 11:00 مساءً");
  const mapUrl = sanitizeUrl(settings.mapUrl || "https://maps.app.goo.gl/EzzitFCzNSpQc7w77?g_st=ic");
  const defaultMapEmbed = "https://maps.google.com/maps?q=%D9%82%D8%A7%D8%B5%D8%AF%20%D9%83%D8%B1%D9%8A%D9%85%202%20%D9%84%D9%84%D8%A7%D8%AF%D9%88%D8%A7%D8%AA%20%D8%A7%D9%84%D9%83%D9%87%D8%B1%D8%A8%D8%A7%D8%A6%D9%8A%D8%A9%2C%20%D8%B1%D9%82%D9%85%2039%D8%8C%20%D8%A3%D9%88%D9%84%20%D8%A7%D9%84%D8%B4%D9%8A%D8%AE%20%D8%B2%D8%A7%D9%8A%D8%AF%D8%8C%20%D9%85%D8%AD%D8%A7%D9%81%D8%B8%D8%A9%20%D8%A7%D9%84%D8%AC%D9%8A%D8%B2%D8%A9&t=&z=14&ie=UTF8&iwloc=&output=embed";
  const rawMapEmbed = sanitizeUrl(settings.mapEmbedUrl || defaultMapEmbed);
  let mapEmbed = defaultMapEmbed;
  try {
    const parsedEmbed = new URL(rawMapEmbed);
    if (parsedEmbed.protocol === "https:" && (parsedEmbed.hostname === "maps.google.com" || parsedEmbed.hostname === "www.google.com")) {
      mapEmbed = parsedEmbed.href;
    }
  } catch (e) {}
  const social = settings.social || {};

  // Top bar phone & location
  const topPhone = document.getElementById("topBarPhone");
  if (topPhone) topPhone.textContent = isEn ? `Sheikh Zayed Flagship • ${cleanPhone}` : `معرض الشيخ زايد • ${cleanPhone}`;

  const topPill = document.querySelector(".top-bar-pill");
  if (topPill) topPill.textContent = isEn ? "Sheikh Zayed - University Center" : "الشيخ زايد - سنتر الطاهرة";

  // Header WhatsApp
  const headerWa = document.getElementById("headerWhatsappBtn");
  if (headerWa) {
    headerWa.href = `https://wa.me/${cleanWa}`;
    headerWa.setAttribute("rel", "noopener noreferrer");
  }

  // Floating WhatsApp
  const floatingWa = document.getElementById("floatingWhatsappBtn");
  if (floatingWa) {
    const waText = encodeURIComponent(isEn ? "Hello Kased Karim Luxury Lighting, I would like to inquire about your collections." : "مرحباً معرض قاصد كريم للإضاءة بالشيخ زايد، أود الاستفسار عن وحدات الإضاءة.");
    floatingWa.href = `https://wa.me/${cleanWa}?text=${waText}`;
    floatingWa.setAttribute("rel", "noopener noreferrer");
  }

  // Mobile Drawer WhatsApp
  const mobileDrawerWa = document.getElementById("mobileDrawerWhatsappBtn");
  if (mobileDrawerWa) {
    mobileDrawerWa.href = `https://wa.me/${cleanWa}`;
    mobileDrawerWa.setAttribute("rel", "noopener noreferrer");
  }

  // Showroom Section
  const showroomLoc = document.getElementById("showroomLocationText");
  if (showroomLoc) showroomLoc.textContent = location;
  const showroomHrs = document.getElementById("showroomHoursText");
  if (showroomHrs) showroomHrs.textContent = hours;
  const showroomWa = document.getElementById("showroomWhatsappBtn");
  if (showroomWa) {
    showroomWa.href = `https://wa.me/${cleanWa}`;
    showroomWa.setAttribute("rel", "noopener noreferrer");
  }
  const showroomMap = document.getElementById("showroomMapBtn");
  if (showroomMap) {
    showroomMap.href = mapUrl;
    showroomMap.setAttribute("rel", "noopener noreferrer");
  }

  // Footer Location & Maps
  const footerLoc = document.getElementById("footerLocationText");
  if (footerLoc) footerLoc.textContent = location;
  const footerMapIframe = document.getElementById("footerMapEmbed");
  if (footerMapIframe) footerMapIframe.src = mapEmbed;
  const footerMapLnk = document.getElementById("footerMapLink");
  if (footerMapLnk) {
    footerMapLnk.href = mapUrl;
    footerMapLnk.setAttribute("rel", "noopener noreferrer");
  }
  const footerHrs = document.getElementById("footerHoursText");
  if (footerHrs) footerHrs.textContent = hours;

  // Footer Phone & WhatsApp
  const footerPhoneLnk = document.getElementById("footerPhoneLink");
  const footerPhoneSpn = document.getElementById("footerPhoneSpan");
  if (footerPhoneLnk) {
    footerPhoneLnk.href = sanitizeUrl(`tel:${cleanPhone}`, { allowTel: true });
  }
  if (footerPhoneSpn) footerPhoneSpn.textContent = cleanPhone;

  const footerWaLnk = document.getElementById("footerWhatsappLink");
  const footerWaSpn = document.getElementById("footerWhatsappSpan");
  if (footerWaLnk) {
    footerWaLnk.href = `https://wa.me/${cleanWa}`;
    footerWaLnk.setAttribute("rel", "noopener noreferrer");
  }
  if (footerWaSpn) footerWaSpn.textContent = isEn ? `Direct WhatsApp Inquiries (${cleanPhone})` : `واتساب المعرض المباشر (${cleanPhone})`;

  // Footer Socials
  const footerInsta = document.getElementById("footerInstagramBtn");
  if (footerInsta && social.instagram) {
    footerInsta.href = sanitizeUrl(social.instagram);
    footerInsta.setAttribute("rel", "noopener noreferrer");
    footerInsta.style.display = "inline-flex";
  }
  const footerFb = document.getElementById("footerFacebookBtn");
  if (footerFb && social.facebook) {
    footerFb.href = sanitizeUrl(social.facebook);
    footerFb.setAttribute("rel", "noopener noreferrer");
    footerFb.style.display = "inline-flex";
  }
  const footerTt = document.getElementById("footerTiktokBtn");
  if (footerTt) {
    if (social.tiktok && social.tiktok.trim()) {
      footerTt.href = sanitizeUrl(social.tiktok);
      footerTt.setAttribute("rel", "noopener noreferrer");
      footerTt.style.display = "inline-flex";
    } else {
      footerTt.style.display = "none";
    }
  }
  const footerMapSocial = document.getElementById("footerMapSocialBtn");
  if (footerMapSocial) {
    footerMapSocial.href = mapUrl;
    footerMapSocial.setAttribute("rel", "noopener noreferrer");
  }
  const footerWaSocial = document.getElementById("footerWhatsappSocialBtn");
  if (footerWaSocial) {
    footerWaSocial.href = `https://wa.me/${cleanWa}`;
    footerWaSocial.setAttribute("rel", "noopener noreferrer");
  }

  // Footer Designer link
  const designerLink = document.getElementById("footerDesignerLink");
  if (designerLink && social.designerUrl) {
    designerLink.href = sanitizeUrl(social.designerUrl);
    designerLink.setAttribute("rel", "noopener noreferrer");
  }

  // Initialize Google Identity Services if client ID is configured
  if (settings.googleClientId) {
    window.GOOGLE_CLIENT_ID = settings.googleClientId;
  }
  if (typeof initGoogleIdentityServices === "function") {
    setTimeout(initGoogleIdentityServices, 600);
  }
}

// -----------------------------------------------------------------------------
// 4. PRODUCT CARD BUILDER (Safe DOM Construction)
// -----------------------------------------------------------------------------
function createProductCard(item, { isEn, currencyStr, CAT_EN_MAP, CAT_AR_EN_MAP, STYLE_EN_MAP }) {
  const stock = item.stock !== undefined ? item.stock : 10;
  const isAvailable = stock > 0;
  const displayName = (isEn && item.enName) ? item.enName : item.name;
  const displayCategory = isEn 
    ? (item.enCategory || CAT_EN_MAP[item.category] || CAT_AR_EN_MAP[item.categoryName] || "Lighting")
    : (item.categoryName || "إضاءة");

  const displayStyle = (isEn && item.style) ? (STYLE_EN_MAP[item.style] || item.style) : item.style;
  const subtitleText = !isEn ? (item.enName || "") : "";

  // 1. Article element
  const card = createSafeEl("article", {
    class: `product-card ${!isAvailable ? "is-out-of-stock" : ""}`.trim(),
    dataset: { id: item.id }
  });

  // 2. Media container (fully clickable to open QuickView on desktop & touch)
  const mediaDiv = createSafeEl("div", {
    class: "product-media",
    dataset: { action: "quickview", id: item.id },
    style: "cursor: pointer;"
  });

  const imgEl = createSafeEl("img", {
    class: "product-img",
    alt: String(displayName),
    loading: "lazy",
    decoding: "async",
    dataset: { action: "quickview", id: item.id }
  });
  setSafeImageWithFallback(imgEl, item.image, DEFAULT_FALLBACK_IMAGE);
  mediaDiv.appendChild(imgEl);

  // Badges
  const badgesDiv = createSafeEl("div", { class: "card-badges" });
  if (item.isExclusive) {
    badgesDiv.appendChild(createSafeEl("span", { class: "badge-exclusive" }, [
      createSafeEl("i", { class: "fas fa-crown" }),
      ` ${isEn ? "Exclusive" : "حصري في زايد"}`
    ]));
  }
  if (item.isNew) {
    badgesDiv.appendChild(createSafeEl("span", {
      class: "badge-new",
      textContent: isEn ? "New 2026" : "جديد 2026"
    }));
  }
  if (!isAvailable) {
    badgesDiv.appendChild(createSafeEl("span", {
      class: "badge-new",
      style: "background: #EF4444;"
    }, [
      createSafeEl("i", { class: "fas fa-times-circle" }),
      ` ${isEn ? "Out of Stock" : "غير متوفر"}`
    ]));
  }
  mediaDiv.appendChild(badgesDiv);

  // Quickview hover button
  const hoverActionsDiv = createSafeEl("div", { class: "card-hover-actions" }, [
    createSafeEl("button", {
      type: "button",
      class: "btn-card-quickview",
      dataset: { action: "quickview", id: item.id }
    }, [
      createSafeEl("i", { class: "fas fa-expand" }),
      createSafeEl("span", { textContent: isEn ? "Specifications" : "المواصفات الفنية" })
    ])
  ]);
  mediaDiv.appendChild(hoverActionsDiv);
  card.appendChild(mediaDiv);

  // 3. Body container
  const bodyDiv = createSafeEl("div", { class: "product-body" });

  // Category and rating row
  const catRow = createSafeEl("div", { class: "product-category-row" }, [
    createSafeEl("span", { class: "product-cat-tag", textContent: String(displayCategory) }),
    createSafeEl("div", { class: "product-rating" }, [
      createSafeEl("i", { class: "fas fa-star" }),
      createSafeEl("span", { textContent: String(item.rating || "5.0") })
    ])
  ]);
  bodyDiv.appendChild(catRow);

  // Product Name
  const nameH3 = createSafeEl("h3", {
    class: "product-name",
    dataset: { action: "quickview", id: item.id },
    style: "cursor: pointer;",
    textContent: String(displayName)
  });
  bodyDiv.appendChild(nameH3);

  // Subtitle
  if (subtitleText) {
    bodyDiv.appendChild(createSafeEl("p", {
      class: "product-en-name",
      textContent: String(subtitleText)
    }));
  }

  // Specs pills
  const specsDiv = createSafeEl("div", { class: "product-specs-pills" });
  if (item.specs?.cri) {
    specsDiv.appendChild(createSafeEl("span", { class: "spec-pill", textContent: String(item.specs.cri) }));
  }
  if (item.specs?.colorTemp) {
    const kelvinShort = String(item.specs.colorTemp).split(" ")[0];
    specsDiv.appendChild(createSafeEl("span", { class: "spec-pill", textContent: kelvinShort }));
  }
  if (displayStyle) {
    specsDiv.appendChild(createSafeEl("span", { class: "spec-pill", textContent: String(displayStyle) }));
  }
  bodyDiv.appendChild(specsDiv);

  // Footer & Add to Cart button
  const priceCurrent = createSafeEl("div", { class: "product-price-current" }, [
    formatPrice(item.price) + " ",
    createSafeEl("span", { class: "product-currency", textContent: String(currencyStr) })
  ]);

  const priceColChildren = [priceCurrent];
  if (item.originalPrice && Number(item.originalPrice) > Number(item.price)) {
    const savePct = Math.round(((Number(item.originalPrice) - Number(item.price)) / Number(item.originalPrice)) * 100);
    priceColChildren.push(createSafeEl("div", { class: "product-old-price-wrap" }, [
      createSafeEl("span", {
        class: "product-price-old",
        textContent: `${formatPrice(item.originalPrice)} ${currencyStr}`
      }),
      ...(savePct >= 5 ? [createSafeEl("span", {
        class: "product-save-pill",
        textContent: isEn ? `Save ${savePct}%` : `وفر ${savePct}%`
      })] : [])
    ]));
  }
  const priceCol = createSafeEl("div", { class: "product-price-col" }, priceColChildren);

  const cartBtnAttrs = {
    type: "button",
    class: "btn-card-quote btn-card-quote-labeled",
    title: isAvailable ? (isEn ? "Add to Cart" : "أضف للسلة") : (isEn ? "Out of Stock" : "غير متوفر"),
    "aria-label": isAvailable ? (isEn ? `Add ${displayName} to cart` : `أضف ${displayName} إلى السلة`) : (isEn ? "Out of Stock" : "غير متوفر"),
    dataset: { action: "add-to-cart", id: item.id }
  };
  if (!isAvailable) {
    cartBtnAttrs.disabled = "disabled";
    cartBtnAttrs.style = "opacity: 0.5; cursor: not-allowed;";
  }
  const addBtn = createSafeEl("button", cartBtnAttrs, [
    createSafeEl("i", { class: "fas fa-plus", "aria-hidden": "true" }),
    createSafeEl("span", { textContent: isAvailable ? (isEn ? "Add" : "أضف للسلة") : (isEn ? "Sold Out" : "نفد") })
  ]);

  const footerDiv = createSafeEl("div", { class: "product-footer" }, [priceCol, addBtn]);
  bodyDiv.appendChild(footerDiv);
  card.appendChild(bodyDiv);

  return card;
}

// 4. Render Products Grid (Safe DOM Construction)
function renderProducts() {
  const grid = document.getElementById("productsGrid");
  const countBadge = document.getElementById("catalogResultsCount");
  if (!grid) return;

  // Filter products
  const allCats = window.KK_DB ? window.KK_DB.getCategories() : (typeof CATEGORIES !== "undefined" ? CATEGORIES : []);
  const activeCat = STATE.activeCategory;
  const childCatIds = (activeCat && activeCat !== "all")
    ? allCats.filter(c => c.parentId === activeCat).map(c => c.id)
    : [];

  let filtered = STATE.products.filter(item => {
    const matchesCat = activeCat === "all" || 
      item.category === activeCat || 
      childCatIds.includes(item.category);
    const q = STATE.searchQuery.trim().toLowerCase();
    const matchesSearch = !q || 
      (item.name && item.name.toLowerCase().includes(q)) || 
      (item.enName && item.enName.toLowerCase().includes(q)) ||
      (item.style && item.style.toLowerCase().includes(q)) ||
      (item.description && item.description.toLowerCase().includes(q));
    
    return matchesCat && matchesSearch;
  });

  // Sort products
  if (STATE.sortBy === "price-desc") {
    filtered.sort((a, b) => b.price - a.price);
  } else if (STATE.sortBy === "price-asc") {
    filtered.sort((a, b) => a.price - b.price);
  } else if (STATE.sortBy === "newest") {
    filtered.sort((a, b) => (b.isNew ? 1 : 0) - (a.isNew ? 1 : 0));
  }

  const totalCount = filtered.length;
  const initialLimit = STATE.visibleCount || 6;
  const visibleItems = filtered.slice(0, initialLimit);

  const isEn = isCurrentEn();
  const currencyStr = window.KK_I18N ? window.KK_I18N.t("currency") : "ج.م";

  const CAT_EN_MAP = {
    "table-lamps": "Table Lamps",
    "pendants": "Luxury Chandeliers",
    "wall-sconces": "Wall Sconces",
    "spotlights": "Spotlights",
    "floor-lamps": "Floor Lamps",
    "track-lights": "Magnetic Tracks",
    "bollards-lanterns": "Bollards & Lanterns",
    "spike-lights": "Garden Spikes",
    "led-panels": "LED Panels",
    "floodlights": "Floodlights",
    "led-profiles": "LED Profiles",
    "stair-lights": "Stair Lights",
    "indoor": "Indoor Lighting",
    "outdoor": "Outdoor Lighting",
    "architectural": "Architectural",
    "decorative": "Decorative",
    "all": "All Collections"
  };

  const CAT_AR_EN_MAP = {
    "أباجورات": "Table Lamps",
    "دلايات": "Chandeliers",
    "دلايات فاخرة": "Luxury Chandeliers",
    "أباليك": "Wall Sconces",
    "إضاءة جدارية": "Wall Sconces",
    "أبليك": "Wall Sconce",
    "سبوت لايت": "Spotlights",
    "سبوت لايت معماري": "Architectural Spots",
    "لمباديرات": "Floor Lamps",
    "تراك لايت": "Magnetic Tracks",
    "فوانيس سور، بولارد": "Bollards & Lanterns",
    "فوانيس سور وبولارد": "Bollards & Lanterns",
    "حربة": "Garden Spikes",
    "بانلات": "LED Panels",
    "كشافات": "Floodlights",
    "أعواد البروفايل": "LED Profiles",
    "درج سلم": "Stair Lights",
    "إضاءات": "Lighting",
    "إضاءة": "Lighting"
  };

  const STYLE_EN_MAP = {
    "إيطالي معاصر": "Contemporary Italian",
    "إيطالي فاخر": "Italian Luxury",
    "مودرن فاخر": "Luxury Modern",
    "مودرن معاصر": "Modern Contemporary",
    "كلاسيك راقي": "Refined Classic",
    "معماري داخلي": "Architectural Interior",
    "معماري خارجي فائق التحمل": "Heavy-Duty Exterior",
    "أوروجواي فاخر": "Luxury Natural Stone",
    "مودرن نيو كلاسيك": "Neoclassical Modern",
    "مينيمال معاصر": "Contemporary Minimal",
    "مقاوم للعوامل الجوية": "Weatherproof IP65",
    "إنارة غائرة": "Recessed Lighting"
  };

  if (countBadge) {
    if (totalCount <= initialLimit) {
      countBadge.textContent = isEn ? `${totalCount} Luxury Lighting Units` : `${totalCount} وحدة إضاءة فاخرة`;
    } else {
      countBadge.textContent = isEn ? `Showing ${visibleItems.length} of ${totalCount} units` : `عرض ${visibleItems.length} من أصل ${totalCount} وحدة إضاءة`;
    }
  }

  const loadMoreContainer = document.getElementById("loadMoreContainer");
  const loadMoreRemaining = document.getElementById("loadMoreRemaining");
  const loadMoreBtnText = document.querySelector(".btn-load-more-text");

  if (loadMoreBtnText) {
    loadMoreBtnText.textContent = isEn ? "Load More Products" : "عرض المزيد من المنتجات";
  }

  if (loadMoreContainer) {
    if (totalCount > visibleItems.length) {
      loadMoreContainer.style.display = "flex";
      if (loadMoreRemaining) {
        const remaining = totalCount - visibleItems.length;
        loadMoreRemaining.textContent = isEn ? `(${remaining} remaining)` : `(${remaining} إضافية)`;
      }
    } else {
      loadMoreContainer.style.display = "none";
    }
  }

  // Handle Empty State
  if (filtered.length === 0) {
    if (loadMoreContainer) loadMoreContainer.style.display = "none";
    const emptyState = createSafeEl("div", { class: "catalog-empty" }, [
      createSafeEl("div", { class: "catalog-empty-icon" }, [createSafeEl("i", { class: "fas fa-lightbulb" })]),
      createSafeEl("h3", { textContent: isEn ? "No matching lighting units found" : "لم يتم العثور على وحدات إضاءة مطابقة" }),
      createSafeEl("p", {
        class: "text-muted",
        style: "margin-top: 0.5rem;",
        textContent: isEn ? "Try adjusting your search terms or select another category." : "جرب البحث بكلمات أخرى أو اختر تصنيفاً آخر من القائمة أعلاه."
      }),
      createSafeEl("button", {
        type: "button",
        class: "btn-primary",
        style: "margin-top: 1.5rem;",
        dataset: { action: "reset-filters" },
        textContent: isEn ? "View All Collections" : "عرض كافة المجموعات"
      })
    ]);
    safeClearContainer(grid);
    grid.appendChild(emptyState);
    return;
  }

  // Render Product Cards
  const frag = document.createDocumentFragment();
  visibleItems.forEach(item => {
    const card = createProductCard(item, { isEn, currencyStr, CAT_EN_MAP, CAT_AR_EN_MAP, STYLE_EN_MAP });
    frag.appendChild(card);
  });

  safeClearContainer(grid);
  grid.appendChild(frag);
}

function loadMoreProducts() {
  STATE.visibleCount = (STATE.visibleCount || 6) + 6;
  renderProducts();
}

function resetFilters() {
  STATE.activeCategory = "all";
  STATE.searchQuery = "";
  STATE.sortBy = "featured";
  STATE.visibleCount = 6;

  const searchInput = document.getElementById("searchInput");
  if (searchInput) searchInput.value = "";
  const sortSelect = document.getElementById("sortSelect");
  if (sortSelect) sortSelect.value = "featured";

  renderCategoryTabs();
  renderProducts();
  if (typeof updateSubBarActiveCategory === "function") updateSubBarActiveCategory();
}

// Format Currency
function formatPrice(num) {
  if (!num) return "0";
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// 5. Quick View Modal (Safe DOM Construction)
function openQuickView(productId) {
  const item = STATE.products.find(p => p.id === productId);
  if (!item) return;

  STATE.selectedProduct = item;

  const modal = document.getElementById("quickViewModal");
  const modalImg = document.getElementById("modalMainImg");
  const thumbsContainer = document.getElementById("modalThumbs");
  const catEl = document.getElementById("modalCat");
  const titleEl = document.getElementById("modalTitle");
  const enTitleEl = document.getElementById("modalEnTitle");
  const priceEl = document.getElementById("modalPrice");
  const oldPriceEl = document.getElementById("modalOldPrice");
  const descEl = document.getElementById("modalDesc");
  const specsTable = document.getElementById("modalSpecsTable");
  const qtyEl = document.getElementById("modalQtyVal");
  const stockEl = document.getElementById("modalStockStatus") || document.getElementById("modalStockStatusBadge");

  const isEn = isCurrentEn();
  const currencyStr = window.KK_I18N ? window.KK_I18N.t("currency") : "ج.م";
  const stock = item.stock !== undefined ? item.stock : 10;

  // Stock Status Badge
  if (stockEl) {
    safeClearContainer(stockEl);
    stockEl.style.display = "inline-flex";
    stockEl.style.alignItems = "center";
    stockEl.style.gap = "0.35rem";
    if (stock > 0) {
      stockEl.appendChild(createSafeEl("i", { class: "fas fa-check-circle", "aria-hidden": "true" }));
      stockEl.appendChild(createSafeEl("span", {
        textContent: " " + (isEn ? `In Stock (${stock} units)` : `متوفر بالمعرض (${stock} قطعة)`)
      }));
      stockEl.style.color = "#047857";
      stockEl.style.background = "rgba(4, 120, 87, 0.12)";
    } else {
      stockEl.appendChild(createSafeEl("i", { class: "fas fa-times-circle", "aria-hidden": "true" }));
      stockEl.appendChild(createSafeEl("span", {
        textContent: " " + (isEn ? "Out of Stock" : "غير متوفر حالياً")
      }));
      stockEl.style.color = "#B91C1C";
      stockEl.style.background = "rgba(185, 28, 28, 0.12)";
    }
  }

  if (qtyEl) qtyEl.textContent = "1";

  if (modalImg) {
    setSafeImageWithFallback(modalImg, item.image, DEFAULT_FALLBACK_IMAGE);
  }
  if (catEl) catEl.textContent = (isEn && item.enCategory) ? item.enCategory : (item.categoryName || "");
  if (titleEl) titleEl.textContent = (isEn && item.enName) ? item.enName : (item.name || "");
  if (enTitleEl) enTitleEl.textContent = isEn ? (item.name || "") : (item.enName || "");
  if (priceEl) priceEl.textContent = formatPrice(item.price);
  if (oldPriceEl) {
    oldPriceEl.textContent = item.originalPrice ? `${formatPrice(item.originalPrice)} ${currencyStr}` : "";
  }
  if (descEl) descEl.textContent = (isEn && item.enDescription) ? item.enDescription : (item.description || "");

  // Modal Thumbnails
  if (thumbsContainer) {
    const images = [item.image];
    if (item.secondaryImage) images.push(item.secondaryImage);
    const frag = document.createDocumentFragment();

    images.forEach((img, idx) => {
      const safeImg = sanitizeImageUrl(img, DEFAULT_FALLBACK_IMAGE);
      const thumbDiv = createSafeEl("div", {
        class: `modal-thumb ${idx === 0 ? "active" : ""}`,
        dataset: { action: "switch-thumb", imgSrc: safeImg }
      });

      const thumbImg = createSafeEl("img", { alt: "Thumbnail" });
      setSafeImageWithFallback(thumbImg, safeImg, DEFAULT_FALLBACK_IMAGE);
      thumbDiv.appendChild(thumbImg);
      frag.appendChild(thumbDiv);
    });

    safeClearContainer(thumbsContainer);
    thumbsContainer.appendChild(frag);
  }

  // Technical Specs Table (Safe Table Row Construction)
  if (specsTable) {
    const s = item.specs || {};
    const specsConfig = [
      { key: "dimensions", label: isEn ? "Dimensions" : "الأبعاد والمقاسات" },
      { key: "material", label: isEn ? "Materials & Finish" : "الخامات والتشطيب" },
      { key: "colorTemp", label: isEn ? "Color Temperature" : "درجة حرارة الضوء" },
      { key: "wattage", label: isEn ? "Power Consumption" : "الاستهلاك والقدرة" },
      { key: "cri", label: isEn ? "CRI" : "معامل وضوح الألوان" },
      { key: "voltage", label: isEn ? "Operating Voltage" : "جهد التشغيل" },
      { key: "warranty", label: isEn ? "Showroom Warranty" : "الضمان المعتمد" }
    ];

    const frag = document.createDocumentFragment();
    specsConfig.forEach(({ key, label }) => {
      if (s[key]) {
        const tr = createSafeEl("tr", {}, [
          createSafeEl("td", { textContent: label }),
          createSafeEl("td", { textContent: String(s[key]) })
        ]);
        frag.appendChild(tr);
      }
    });

    safeClearContainer(specsTable);
    specsTable.appendChild(frag);
  }

  // Load Customer Reviews for this product
  if (typeof loadProductReviews === "function") {
    loadProductReviews(item.id);
  }
  if (typeof toggleReviewForm === "function") {
    toggleReviewForm(false);
  }

  if (modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
  }
}

function switchModalThumb(imgSrc, element) {
  const modalImg = document.getElementById("modalMainImg");
  if (modalImg) {
    setSafeImageWithFallback(modalImg, imgSrc, DEFAULT_FALLBACK_IMAGE);
  }
  document.querySelectorAll(".modal-thumb").forEach(t => t.classList.remove("active"));
  if (element && element.classList) {
    element.classList.add("active");
  }
}
window.switchModalThumb = switchModalThumb;

function syncOverlayOpenBodyClass() {
  const anyOpen = Boolean(document.querySelector(".modal-backdrop.active, .cart-drawer-backdrop.active, .mobile-nav-drawer.active"));
  document.body.classList.toggle("overlay-open", anyOpen);
  document.body.style.overflow = anyOpen ? "hidden" : "";
}
window.syncOverlayOpenBodyClass = syncOverlayOpenBodyClass;

function closeQuickView() {
  const modal = document.getElementById("quickViewModal");
  if (modal) {
    modal.classList.remove("active");
    syncOverlayOpenBodyClass();
  }
}

// 6. Cart Management (Safe Plain Text & Isolated Storage)
function addToCart(productId, qty = 1, openDrawer = false) {
  const item = STATE.products.find(p => p.id === productId);
  if (!item) return;

  const existing = STATE.cart.find(c => c.id === productId);
  if (existing) {
    existing.qty += Math.max(1, parseInt(qty, 10) || 1);
  } else {
    STATE.cart.push({
      id: String(item.id),
      name: String(item.name || ""),
      price: Number(item.price) || 0,
      image: sanitizeImageUrl(item.image),
      categoryName: String(item.categoryName || "إضاءة"),
      qty: Math.max(1, parseInt(qty, 10) || 1)
    });
  }

  saveCart();
  if (openDrawer) {
    toggleCartDrawer(true);
  }
  showToast(`تمت إضافة "${item.name}" إلى السلة بنجاح`);
}

function updateCartItemQty(productId, delta) {
  const target = STATE.cart.find(item => item.id === productId);
  if (!target) return;
  const nextQty = (parseInt(target.qty, 10) || 1) + delta;
  if (nextQty <= 0) {
    removeFromCart(productId);
    return;
  }
  target.qty = Math.min(99, nextQty);
  saveCart();
}
window.updateCartItemQty = updateCartItemQty;

function removeFromCart(productId) {
  STATE.cart = STATE.cart.filter(item => item.id !== productId);
  saveCart();
}

function updateCartUI() {
  const countPills = document.querySelectorAll(".cart-count-badge");
  const totalCount = STATE.cart.reduce((sum, item) => sum + item.qty, 0);
  
  countPills.forEach(pill => {
    pill.textContent = totalCount;
  });

  const cartList = document.getElementById("cartItemsList");
  const totalValEl = document.getElementById("cartTotalVal");
  const subtotalValEl = document.getElementById("cartSubtotalVal");
  const emptyState = document.getElementById("cartEmptyState");
  const footerEl = document.getElementById("cartFooter");

  const totalAmount = STATE.cart.reduce((sum, item) => sum + (item.price * item.qty), 0);

  if (totalValEl) totalValEl.textContent = `${formatPrice(totalAmount)} ج.م`;
  if (subtotalValEl) subtotalValEl.textContent = `${formatPrice(totalAmount)} ج.م`;

  if (!cartList) return;

  if (STATE.cart.length === 0) {
    if (emptyState) emptyState.style.display = "block";
    if (footerEl) footerEl.style.display = "none";
    safeClearContainer(cartList);
  } else {
    if (emptyState) emptyState.style.display = "none";
    if (footerEl) footerEl.style.display = "block";

    const frag = document.createDocumentFragment();

    STATE.cart.forEach(item => {
      const row = createSafeEl("div", { class: "cart-item-row" });

      const img = createSafeEl("img", {
        class: "cart-item-img",
        alt: String(item.name)
      });
      setSafeImageWithFallback(img, item.image, DEFAULT_FALLBACK_IMAGE);
      row.appendChild(img);

      const infoDiv = createSafeEl("div", { class: "cart-item-info" });
      infoDiv.appendChild(createSafeEl("div", { class: "cart-item-name", textContent: String(item.name) }));
      infoDiv.appendChild(createSafeEl("div", {
        class: "cart-item-spec",
        textContent: `${item.categoryName || "إضاءة"} • سعر القطعة: ${formatPrice(item.price)} ج.م`
      }));

      const qtyStepper = createSafeEl("div", { class: "cart-qty-stepper", role: "group", "aria-label": "تعديل الكمية" }, [
        createSafeEl("button", {
          type: "button",
          class: "cart-qty-btn",
          dataset: { action: "cart-qty-dec", itemId: item.id },
          "aria-label": "إنقاص الكمية",
          title: "إنقاص الكمية",
          textContent: "−"
        }),
        createSafeEl("span", { class: "cart-qty-val", textContent: String(item.qty) }),
        createSafeEl("button", {
          type: "button",
          class: "cart-qty-btn",
          dataset: { action: "cart-qty-inc", itemId: item.id },
          "aria-label": "زيادة الكمية",
          title: "زيادة الكمية",
          textContent: "+"
        })
      ]);

      const priceRow = createSafeEl("div", { class: "cart-item-price-row" }, [
        createSafeEl("div", { class: "cart-item-price", textContent: `${formatPrice(item.price * item.qty)} ج.م` }),
        createSafeEl("div", { class: "cart-item-controls" }, [
          qtyStepper,
          createSafeEl("button", {
            type: "button",
            class: "cart-item-remove-btn",
            dataset: { action: "remove-from-cart", itemId: item.id },
            "aria-label": "حذف المنتج من السلة",
            title: "حذف"
          }, [
            createSafeEl("i", { class: "fas fa-trash-alt", "aria-hidden": "true" })
          ])
        ])
      ]);

      infoDiv.appendChild(priceRow);
      row.appendChild(infoDiv);
      frag.appendChild(row);
    });

    safeClearContainer(cartList);
    cartList.appendChild(frag);
  }
}

function toggleCartDrawer(open) {
  const drawer = document.getElementById("cartDrawerBackdrop");
  if (!drawer) return;
  if (open) {
    drawer.classList.add("active");
  } else {
    drawer.classList.remove("active");
  }
  syncOverlayOpenBodyClass();
}

// 7. Send Quotation & Order via WhatsApp with Official Order Code
async function sendWhatsAppQuotation() {
  if (!STATE.cart || STATE.cart.length === 0) {
    loadCart();
  }
  if (!STATE.cart || STATE.cart.length === 0) {
    showToast("يرجى اختيار وحدات إضاءة أولاً لتأكيد طلبك");
    return;
  }

  showToast("⏳ جاري حجز كود الطلب وتجهيز رسالة الواتساب...");

  try {
    const savedName = localStorage.getItem("kk_customer_name") || "عميل واتساب المباشر";
    const savedPhone = localStorage.getItem("kk_customer_phone") || "";

    const customerData = {
      name: savedName,
      phone: savedPhone,
      city: "الشيخ زايد",
      address: "الشيخ زايد - طلب عبر واتساب",
      notes: "تم الطلب عبر زر واتساب السريع من سلة المشتريات"
    };

    let newOrder = null;
    if (window.KK_DB && typeof window.KK_DB.createOrder === "function") {
      newOrder = await window.KK_DB.createOrder(customerData, STATE.cart);
    }

    if (newOrder && newOrder.id) {
      if (typeof window.saveCustomerRecentOrder === "function") {
        window.saveCustomerRecentOrder(newOrder.id, savedPhone);
      }

      STATE.cart = [];
      saveCart();
      toggleCartDrawer(false);

      if (typeof window.sendOrderViaWhatsApp === "function") {
        window.sendOrderViaWhatsApp(newOrder);
      } else {
        const phone = (window.SHOWROOM_INFO && window.SHOWROOM_INFO.whatsapp) || "201006367690";
        const msg = `*طلب جديد من معرض قاصد كريم للإضاءة الفاخرة* 💎\nكود الطلب المعتمد: #${newOrder.id}\nإجمالي الطلب: ${formatPrice(newOrder.total)} ج.م`;
        window.open(`https://wa.me/${phone}?text=${encodeURIComponent(msg)}`, "_blank", "noopener,noreferrer");
      }

      if (typeof window.openOrderSuccessModal === "function") {
        window.openOrderSuccessModal(newOrder);
      }

      showToast(`✅ تم حجز الطلب برقم #${newOrder.id} وتجهيز محادثة الواتساب`);
    } else {
      const localId = "ORD-" + Math.floor(1000 + Math.random() * 9000);
      let msg = `*طلب وحدات إضاءة فاخرة - معرض Kased Karim (الشيخ زايد)*\n`;
      msg += `🏷️ *كود الطلب المبدئي:* #${localId}\n`;
      msg += `----------------------------------------\n`;
      STATE.cart.forEach((item, index) => {
        msg += `${index + 1}. *${item.name}* (كمية: ${item.qty}) - ${formatPrice(item.price * item.qty)} ج.م\n`;
      });
      const phone = (window.SHOWROOM_INFO && window.SHOWROOM_INFO.whatsapp) || "201006367690";
      window.open(`https://wa.me/${phone}?text=${encodeURIComponent(msg)}`, "_blank", "noopener,noreferrer");
    }
  } catch (err) {
    showToast("تعذر إنشاء الطلب، يرجى المحاولة لاحقاً");
  }
}

// 8. Add Product Modal Handlers
function openAddProductModal() {
  const modal = document.getElementById("addProductModal");
  if (modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
  }
}

function closeAddProductModal() {
  const modal = document.getElementById("addProductModal");
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
}

function handleAddProductSubmit(e) {
  e.preventDefault();
  const form = e.target;
  const cats = window.KK_DB ? window.KK_DB.getCategories() : (typeof CATEGORIES !== "undefined" ? CATEGORIES : []);

  const newUnit = {
    id: "kk-" + Date.now().toString().slice(-4),
    name: form.unitName.value.trim(),
    enName: form.unitEnName.value.trim(),
    category: form.unitCategory.value,
    categoryName: cats.find(c => c.id === form.unitCategory.value)?.name || "إضاءة فاخرة",
    style: form.unitStyle.value.trim() || "معاصر",
    price: parseFloat(form.unitPrice.value) || 0,
    originalPrice: form.unitOldPrice.value ? parseFloat(form.unitOldPrice.value) : null,
    isExclusive: form.isExclusive.checked,
    isNew: true,
    rating: 5.0,
    reviewsCount: 1,
    image: sanitizeImageUrl(form.unitImage.value.trim()),
    description: form.unitDesc.value.trim() || "وحدة إضاءة فاخرة حصرية من معرض قاصد كريم الشيخ زايد.",
    specs: {
      dimensions: form.unitDimensions.value.trim() || "حسب الطلب",
      material: form.unitMaterial.value.trim() || "نحاس وألمنيوم فاخر",
      colorTemp: form.unitKelvin.value.trim() || "3000K دافئ",
      wattage: form.unitWattage.value.trim() || "LED موفر عالي الكفاءة",
      cri: "CRI > 97",
      voltage: "220V",
      warranty: "5 سنوات ضمان شامل"
    }
  };

  STATE.products.unshift(newUnit);
  saveCustomProducts();
  renderCategoryTabs();
  renderProducts();

  const jsonBox = document.getElementById("productJsonSnippet");
  if (jsonBox) {
    jsonBox.textContent = JSON.stringify(newUnit, null, 2);
  }

  showToast(`تمت إضافة "${newUnit.name}" بنجاح إلى المعرض!`);
  form.reset();
}

// 9. Toast Notification Helper (Safe textContent DOM Construction - CWE-79 Protected)
function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const isError = type === "error" || (typeof message === "string" && (message.includes("خطأ") || message.includes("تعذر") || message.includes("❌")));
  const icon = createSafeEl("i", {
    class: isError ? "fas fa-circle-exclamation toast-icon" : "fas fa-check-circle toast-icon",
    style: isError ? "color: #EF4444;" : ""
  });

  const span = createSafeEl("span", {
    textContent: String(message || "")
  });

  const toast = createSafeEl("div", { class: "toast" }, [icon, span]);
  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.add("show");
  });

  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 400);
  }, 3500);
}

// 10. Header Scroll Shadow
function handleHeaderScroll() {
  const header = document.querySelector(".site-header");
  if (!header) return;
  if (window.scrollY > 20) {
    header.classList.add("scrolled");
  } else {
    header.classList.remove("scrolled");
  }
}

// 11. Event Listeners Setup
function setupEventListeners() {
  const searchInput = document.getElementById("searchInput");
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      STATE.searchQuery = e.target.value;
      STATE.visibleCount = 6;
      renderProducts();
    });
  }

  // Custom Luxury Sort Dropdown
  const luxurySortDropdown = document.getElementById("luxurySortDropdown");
  const luxurySortTrigger = document.getElementById("luxurySortTrigger");
  const sortTriggerLabel = document.getElementById("sortTriggerLabel");
  const luxurySortOptions = document.querySelectorAll(".luxury-sort-option");
  const sortSelect = document.getElementById("sortSelect");

  if (luxurySortDropdown && luxurySortTrigger) {
    luxurySortTrigger.addEventListener("click", (e) => {
      e.stopPropagation();
      luxurySortDropdown.classList.toggle("open");
      const isOpen = luxurySortDropdown.classList.contains("open");
      luxurySortTrigger.setAttribute("aria-expanded", isOpen ? "true" : "false");
    });

    luxurySortOptions.forEach((option) => {
      option.addEventListener("click", (e) => {
        e.stopPropagation();
        const value = option.getAttribute("data-value");
        const labelText = option.querySelector("span")?.textContent || "";

        luxurySortOptions.forEach((opt) => opt.classList.remove("active"));
        option.classList.add("active");

        if (sortTriggerLabel) sortTriggerLabel.textContent = labelText;
        luxurySortDropdown.classList.remove("open");
        luxurySortTrigger.setAttribute("aria-expanded", "false");

        if (sortSelect) {
          sortSelect.value = value;
          sortSelect.dispatchEvent(new Event("change"));
        }
      });
    });

    document.addEventListener("click", (e) => {
      if (!luxurySortDropdown.contains(e.target)) {
        luxurySortDropdown.classList.remove("open");
        luxurySortTrigger.setAttribute("aria-expanded", "false");
      }
    });
  }

  // Sort Select Native Change Handler
  if (sortSelect) {
    sortSelect.addEventListener("change", (e) => {
      STATE.sortBy = e.target.value;
      renderProducts();
    });
  }

  // Quick View Quantity Stepper
  const minusBtn = document.getElementById("modalQtyMinus");
  const plusBtn = document.getElementById("modalQtyPlus");
  const qtyVal = document.getElementById("modalQtyVal");

  if (minusBtn && plusBtn && qtyVal) {
    minusBtn.addEventListener("click", () => {
      let current = parseInt(qtyVal.textContent) || 1;
      if (current > 1) qtyVal.textContent = current - 1;
    });
    plusBtn.addEventListener("click", () => {
      let current = parseInt(qtyVal.textContent) || 1;
      qtyVal.textContent = current + 1;
    });
  }

  // Modal Add to Quote button
  const modalAddBtn = document.getElementById("modalAddQuoteBtn");
  if (modalAddBtn) {
    modalAddBtn.addEventListener("click", () => {
      if (!STATE.selectedProduct) return;
      const qty = parseInt(document.getElementById("modalQtyVal")?.textContent) || 1;
      addToCart(STATE.selectedProduct.id, qty);
      closeQuickView();
    });
  }

  // Direct product inquiry via WhatsApp button in modal
  const modalWhatsappBtn = document.getElementById("modalWhatsappBtn");
  if (modalWhatsappBtn) {
    modalWhatsappBtn.addEventListener("click", () => {
      if (!STATE.selectedProduct) return;
      const p = STATE.selectedProduct;
      const settings = window.KK_DB ? window.KK_DB.getSettings() : (typeof SHOWROOM_INFO !== "undefined" ? SHOWROOM_INFO : {});
      const waNumber = settings.whatsapp || "201006367690";
      const msg = `مرحباً، أستفسر عن وحدة الإضاءة: ${p.name} (${p.enName}) - كود: ${p.id} بسعر ${formatPrice(p.price)} ج.م من معرض Kased Karim بالشيخ زايد. هل هي متاحة للعرض في المعرض؟`;
      const url = `https://wa.me/${waNumber}?text=${encodeURIComponent(msg)}`;
      window.open(url, "_blank", "noopener,noreferrer");
    });
  }

  // Add Product Form Submit
  const addProductForm = document.getElementById("addProductForm");
  if (addProductForm) {
    addProductForm.addEventListener("submit", handleAddProductSubmit);
  }

  // Secure Form Submit Bindings (Strict CSP Compliance - Zero onsubmit in HTML)
  const addRevForm = document.getElementById("addReviewForm");
  if (addRevForm) addRevForm.addEventListener("submit", handleReviewSubmit);

  const signInForm = document.getElementById("customerSignInForm");
  if (signInForm) signInForm.addEventListener("submit", handleCustomerSignIn);

  const regForm = document.getElementById("customerRegisterForm");
  if (regForm) regForm.addEventListener("submit", handleCustomerRegister);

  const googleForm = document.getElementById("googleClientIdForm");
  if (googleForm) googleForm.addEventListener("submit", handleSaveGoogleClientId);

  // Mobile Menu Toggle
  const mobileToggle = document.getElementById("mobileMenuToggle");
  const mobileDrawer = document.getElementById("mobileNavDrawer");
  if (mobileToggle && mobileDrawer) {
    mobileToggle.addEventListener("click", () => {
      mobileDrawer.classList.toggle("active");
      syncOverlayOpenBodyClass();
    });
  }

  // Real-time Cloud Sync Listeners
  window.addEventListener("kk_products_updated", () => {
    loadProducts();
    renderCategoryTabs();
    renderProducts();
  });

  window.addEventListener("kk_categories_updated", () => {
    renderCategoryTabs();
    renderSubBarCategories();
    renderMobileAccordionCategories();
    renderFooterCategories();
    renderProducts();
  });

  window.addEventListener("kk_settings_updated", () => {
    applyDynamicSettings();
  });

  window.addEventListener("kk_orders_updated", () => {
    checkAndDisplayAdminHeaderIcon();
  });

  window.addEventListener("kk_new_order_placed", () => {
    checkAndDisplayAdminHeaderIcon();
  });

  window.addEventListener("kk_language_changed", () => {
    renderCategoryTabs();
    renderSubBarCategories();
    renderMobileAccordionCategories();
    renderFooterCategories();
    renderProducts();
    applyDynamicSettings();
    if (typeof updateCustomerButtonUI === "function") updateCustomerButtonUI();
    if (window.KK_I18N) window.KK_I18N.applyLanguageToDOM();
  });

  window.addEventListener("kk_customer_auth_changed", () => {
    if (typeof updateCustomerButtonUI === "function") updateCustomerButtonUI();
  });

  // Safe Deep-link Support (profile & order tracking only — no checkout cart injection)
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const modalParam = urlParams.get("modal") || "";
    if (modalParam === "profile") {
      setTimeout(() => {
        if (typeof openCustomerProfileModal === "function") openCustomerProfileModal();
      }, 400);
    } else if (modalParam === "track") {
      setTimeout(() => {
        if (typeof openTrackOrderModal === "function") openTrackOrderModal();
      }, 400);
    }
  } catch (e) {}
}

// 12. Persistent Executive Admin Header Button Controller
async function checkAndDisplayAdminHeaderIcon() {
  const adminBtn = document.getElementById("adminHeaderBtn");
  const adminBadge = document.getElementById("adminHeaderBadge");
  const mobileAdminItem = document.getElementById("mobileAdminNavItem");
  if (!adminBtn && !mobileAdminItem) return;

  let isAuth = false;
  try {
    const res = await fetch("/api/auth", { credentials: "same-origin" });
    if (res.ok) {
      const data = await res.json();
      isAuth = !!(data && data.authenticated);
    }
  } catch (e) {}

  if (isAuth) {
    document.documentElement.classList.add("is-admin-device");
    if (document.body) document.body.classList.add("is-admin-device", "is-admin-user");
    if (adminBtn) adminBtn.style.setProperty("display", "inline-flex", "important");
    if (mobileAdminItem) mobileAdminItem.style.setProperty("display", "block", "important");

    const unreadCount = window.KK_DB && typeof window.KK_DB.getUnreadOrdersCount === "function"
      ? window.KK_DB.getUnreadOrdersCount()
      : 0;

    if (adminBadge) {
      adminBadge.textContent = unreadCount;
      adminBadge.style.display = unreadCount > 0 ? "flex" : "none";
    }

    if (unreadCount > 0) {
      adminBtn?.classList.add("has-new-orders");
    } else {
      adminBtn?.classList.remove("has-new-orders");
    }
  } else {
    document.documentElement.classList.remove("is-admin-device");
    if (document.body) document.body.classList.remove("is-admin-device", "is-admin-user");
    if (adminBtn) {
      adminBtn.style.setProperty("display", "none", "important");
      adminBtn.classList.remove("has-new-orders");
    }
    if (mobileAdminItem) {
      mobileAdminItem.style.setProperty("display", "none", "important");
    }
  }
}

if (document.readyState === "interactive" || document.readyState === "complete") {
  checkAndDisplayAdminHeaderIcon();
}

// 13. Category Tabs Horizontal Scroll & Arrow Controllers
let updateCategoryScrollButtons = null;

function setupCategoryTabsScroll() {
  const container = document.getElementById("categoryTabs");
  const prevBtn = document.getElementById("categoryScrollPrev");
  const nextBtn = document.getElementById("categoryScrollNext");
  if (!container) return;

  updateCategoryScrollButtons = function() {
    const maxScroll = container.scrollWidth - container.clientWidth;
    if (maxScroll <= 5) {
      if (prevBtn) prevBtn.classList.add("disabled");
      if (nextBtn) nextBtn.classList.add("disabled");
      return;
    }

    const sl = container.scrollLeft;
    if (sl < 0) {
      const atRight = Math.abs(sl) < 10;
      const atLeft = Math.abs(Math.abs(sl) - maxScroll) < 15;
      if (prevBtn) prevBtn.classList.toggle("disabled", atRight);
      if (nextBtn) nextBtn.classList.toggle("disabled", atLeft);
    } else {
      if (prevBtn) prevBtn.classList.toggle("disabled", sl <= 10);
      if (nextBtn) nextBtn.classList.toggle("disabled", sl >= maxScroll - 15);
    }
  };

  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      const step = 340;
      container.scrollBy({ left: -step, behavior: "smooth" });
    });
  }

  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      const step = 340;
      container.scrollBy({ left: step, behavior: "smooth" });
    });
  }

  container.addEventListener("scroll", () => {
    if (typeof updateCategoryScrollButtons === "function") {
      updateCategoryScrollButtons();
    }
  }, { passive: true });

  window.addEventListener("resize", () => {
    if (typeof updateCategoryScrollButtons === "function") {
      updateCategoryScrollButtons();
    }
  }, { passive: true });

  setTimeout(updateCategoryScrollButtons, 300);
}

// 14. Collections Sub-Bar Controller
function toggleCollectionsSubBar(open) {
  const subBar = document.getElementById("siteSubBar");
  const toggleBtn = document.getElementById("navCollectionsBtn");
  if (!subBar) return;

  const shouldOpen = typeof open === "boolean" ? open : !subBar.classList.contains("active");
  if (shouldOpen) {
    subBar.classList.add("active");
    if (toggleBtn) {
      toggleBtn.classList.add("active");
      toggleBtn.setAttribute("aria-expanded", "true");
    }
    updateSubBarActiveCategory();
  } else {
    subBar.classList.remove("active");
    if (toggleBtn) {
      toggleBtn.classList.remove("active");
      toggleBtn.setAttribute("aria-expanded", "false");
    }
  }
}

function selectCategoryFromSubBar(catId) {
  STATE.activeCategory = catId;
  STATE.visibleCount = 6;
  renderCategoryTabs();
  renderProducts();
  updateSubBarActiveCategory();

  const safeCat = safeCssEscape(catId);
  const activeTabBtn = document.querySelector(`.category-tab-btn[data-category="${safeCat}"]`);
  if (activeTabBtn) {
    activeTabBtn.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
  }

  const catalog = document.getElementById("catalog");
  if (catalog) {
    catalog.scrollIntoView({ behavior: "smooth" });
  }
}

function updateSubBarActiveCategory() {
  document.querySelectorAll(".sub-bar-cat-btn").forEach(btn => {
    btn.classList.remove("active");
  });
  const safeActive = safeCssEscape(STATE.activeCategory);
  const matchingBtn = document.querySelector(`.sub-bar-cat-btn[data-cat-id="${safeActive}"]`);
  if (matchingBtn) matchingBtn.classList.add("active");
}

function toggleMobileCollectionsAccordion(e) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  const content = document.getElementById("mobileAccordionContent");
  const arrow = document.getElementById("mobileAccordionArrow");
  if (content) content.classList.toggle("open");
  if (arrow) arrow.classList.toggle("open");
}

function selectCategoryFromMobile(catId) {
  STATE.activeCategory = catId;
  STATE.visibleCount = 6;
  renderCategoryTabs();
  renderProducts();

  const safeCat = safeCssEscape(catId);
  const activeTabBtn = document.querySelector(`.category-tab-btn[data-category="${safeCat}"]`);
  if (activeTabBtn) {
    activeTabBtn.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
  }

  const drawer = document.getElementById("mobileNavDrawer");
  if (drawer) drawer.classList.remove("active");

  const catalog = document.getElementById("catalog");
  if (catalog) {
    catalog.scrollIntoView({ behavior: "smooth" });
  }
}

// 15. Lighting Ceremony Controller
function initLightingCeremony() {
  const overlay = document.getElementById("lightingCeremonyOverlay");
  if (overlay) {
    overlay.style.display = "none";
    overlay.classList.add("ignited");
  }
  document.body.classList.remove("ceremony-in-progress");
  document.body.classList.add("ceremony-illuminated");
}

// 16. Customer Authentication & Profile Portal
window.pendingAuthCallback = null;

function handleCustomerAccountClick() {
  const customer = window.KK_DB && typeof window.KK_DB.getCustomer === "function" 
    ? window.KK_DB.getCustomer() 
    : null;
  if (customer) {
    openCustomerProfileModal();
  } else {
    openCustomerAuthModal();
  }
}
window.handleCustomerAccountClick = handleCustomerAccountClick;

function openCustomerAuthModal(onSuccessCallback) {
  if (typeof toggleCartDrawer === "function") toggleCartDrawer(false);
  window.pendingAuthCallback = onSuccessCallback || null;
  const modal = document.getElementById("customerAuthModal");
  if (modal) {
    modal.classList.add("active");
    syncOverlayOpenBodyClass();
    switchCustomerAuthTab("signin");
  }
}
window.openCustomerAuthModal = openCustomerAuthModal;

function closeCustomerAuthModal() {
  const modal = document.getElementById("customerAuthModal");
  if (modal) {
    modal.classList.remove("active");
    syncOverlayOpenBodyClass();
  }
}
window.closeCustomerAuthModal = closeCustomerAuthModal;

// -----------------------------------------------------------------------------
// Cloudflare Turnstile Integration Helpers (Fail-Closed in Production)
// -----------------------------------------------------------------------------
const IS_LOCAL_HOST = typeof window !== "undefined" && (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1");
window.TURNSTILE_SITE_KEY = window.TURNSTILE_SITE_KEY || (IS_LOCAL_HOST ? "1x00000000000000000000AA" : "");

function renderTurnstileWidget(containerId, options = {}, attempt = 0) {
  const container = document.getElementById(containerId);
  if (!container) return null;
  if (!window.turnstile) {
    if (attempt < 15) {
      setTimeout(() => renderTurnstileWidget(containerId, options, attempt + 1), 300);
    }
    return null;
  }

  const siteKey = (window.STATE && window.STATE.settings && window.STATE.settings.turnstileSiteKey) || window.TURNSTILE_SITE_KEY;
  if (!siteKey) return null;

  try {
    container.replaceChildren();
    return window.turnstile.render(`#${containerId}`, {
      sitekey: siteKey,
      theme: "auto",
      language: "ar",
      ...(options || {})
    });
  } catch (err) {
    console.warn("[Turnstile] Render warning:", err.message);
    return null;
  }
}
window.renderTurnstileWidget = renderTurnstileWidget;

function renderRegisterTurnstile() {
  setTimeout(() => {
    window.turnstileRegisterWidgetId = renderTurnstileWidget("turnstileRegisterContainer");
  }, 100);
}
window.renderRegisterTurnstile = renderRegisterTurnstile;

function switchCustomerAuthTab(tab) {
  const signinForm = document.getElementById("customerSignInForm");
  const regForm = document.getElementById("customerRegisterForm");
  const signinBtn = document.getElementById("tabBtnSignIn");
  const regBtn = document.getElementById("tabBtnRegister");

  if (tab === "signin") {
    if (signinForm) signinForm.style.display = "block";
    if (regForm) regForm.style.display = "none";
    if (signinBtn) {
      signinBtn.style.color = "var(--accent)";
      signinBtn.style.borderBottom = "2px solid var(--accent)";
      signinBtn.style.fontWeight = "800";
    }
    if (regBtn) {
      regBtn.style.color = "var(--text-muted)";
      regBtn.style.borderBottom = "2px solid transparent";
      regBtn.style.fontWeight = "700";
    }
  } else {
    if (signinForm) signinForm.style.display = "none";
    if (regForm) regForm.style.display = "block";
    if (regBtn) {
      regBtn.style.color = "var(--accent)";
      regBtn.style.borderBottom = "2px solid var(--accent)";
      regBtn.style.fontWeight = "800";
    }
    if (signinBtn) {
      signinBtn.style.color = "var(--text-muted)";
      signinBtn.style.borderBottom = "2px solid transparent";
      signinBtn.style.fontWeight = "700";
    }
    renderRegisterTurnstile();
  }
}
window.switchCustomerAuthTab = switchCustomerAuthTab;

// 17. Google Identity Services (GIS)
window.GOOGLE_CLIENT_ID = window.GOOGLE_CLIENT_ID || "975827952448-e6dekknbl9s5vfechtk9q7q0vgjqsvma.apps.googleusercontent.com";

function getActiveGoogleClientId() {
  if (window.GOOGLE_CLIENT_ID && window.GOOGLE_CLIENT_ID.trim()) {
    return window.GOOGLE_CLIENT_ID.trim();
  }
  const dbSettings = window.KK_DB ? window.KK_DB.getSettings() : null;
  if (dbSettings && dbSettings.googleClientId && dbSettings.googleClientId.trim()) {
    return dbSettings.googleClientId.trim();
  }
  try {
    const local = localStorage.getItem("kk_google_client_id");
    if (local && local.trim()) return local.trim();
  } catch (e) {}
  return "";
}

window.initGoogleIdentityServices = function () {
  const clientId = getActiveGoogleClientId();
  if (!clientId || typeof google === "undefined" || !google.accounts || !google.accounts.id) {
    return;
  }

  try {
    google.accounts.id.initialize({
      client_id: clientId,
      callback: async function (response) {
        if (!response || !response.credential) return;
        await completeGoogleCustomerSignIn(response.credential);
      },
      auto_select: false,
      cancel_on_tap_outside: true
    });

    const slot = document.getElementById("googleOfficialBtnSlot");
    if (slot) {
      safeClearContainer(slot);
      slot.style.display = "flex";
      google.accounts.id.renderButton(slot, {
        theme: "outline",
        size: "large",
        type: "standard",
        shape: "rectangular",
        text: "continue_with",
        logo_alignment: "left",
        width: 320
      });
    }
  } catch (err) {
    console.warn("Google ID init note:", err);
  }
};

window.completeGoogleCustomerSignIn = async function (credential) {
  if (!credential || typeof credential !== "string") {
    showToast(isCurrentEn() ? "Invalid Google authentication token" : "رمز توثيق Google غير صالح أو غير موقع رقمياً", "error");
    return;
  }

  const slot = document.getElementById("googleOfficialBtnSlot");
  if (slot) {
    safeClearContainer(slot);
    slot.appendChild(createSafeEl("div", {
      style: "color: var(--accent); font-size: 0.88rem; font-weight: 700; padding: 0.5rem; display: flex; align-items: center; justify-content: center; gap: 0.5rem;"
    }, [
      createSafeEl("i", { class: "fas fa-spinner fa-spin" }),
      createSafeEl("span", { textContent: "جارٍ توثيق الحساب مع Google..." })
    ]));
  }

  try {
    const authRes = await window.KK_DB.customerGoogleAuth(credential);
    if (!authRes || !authRes.customer) {
      throw new Error(authRes?.error || "تعذر إتمام المصادقة عبر Google");
    }

    showToast(`مرحباً بك يا ${authRes.customer.name}! تم تسجيل دخولك بنجاح.`);
    closeCustomerAuthModal();
    updateCustomerButtonUI();

    if (typeof window.pendingAuthCallback === "function") {
      const cb = window.pendingAuthCallback;
      window.pendingAuthCallback = null;
      cb();
    } else {
      const cart = (window.STATE && window.STATE.cart) || [];
      if (cart.length > 0 && typeof window.openCheckoutModal === "function") {
        setTimeout(window.openCheckoutModal, 350);
      }
    }
  } catch (err) {
    showToast(`❌ ${err.message || "فشل تسجيل الدخول بواسطة Google"}`, "error");
  } finally {
    if (typeof window.initGoogleIdentityServices === "function") {
      window.initGoogleIdentityServices();
    }
  }
};

window.openGoogleConfigModal = function () {
  const modal = document.getElementById("googleConfigModal");
  const input = document.getElementById("googleClientIdInput");
  if (input) {
    input.value = getActiveGoogleClientId();
  }
  if (modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
  }
};

window.closeGoogleConfigModal = function () {
  const modal = document.getElementById("googleConfigModal");
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
};

window.handleSaveGoogleClientId = function (e) {
  if (e) e.preventDefault();
  const input = document.getElementById("googleClientIdInput");
  const val = input ? input.value.trim() : "";
  if (!val) {
    showToast("يرجى إدخال Client ID صالح من Google Cloud Console", "error");
    return;
  }

  try {
    localStorage.setItem("kk_google_client_id", val);
    window.GOOGLE_CLIENT_ID = val;
    showToast("تم حفظ معرف Google Client ID بنجاح!");
    closeGoogleConfigModal();
    if (typeof window.initGoogleIdentityServices === "function") {
      window.initGoogleIdentityServices();
    }
  } catch (err) {
    showToast("تعذر حفظ المعرف محلياً", "error");
  }
};

window.handleGoogleSignIn = function () {
  const clientId = getActiveGoogleClientId();
  if (!clientId) {
    openGoogleConfigModal();
    return;
  }

  if (typeof google !== "undefined" && google.accounts && google.accounts.id) {
    google.accounts.id.prompt((notification) => {
      if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
        const slot = document.getElementById("googleOfficialBtnSlot");
        if (slot) {
          slot.scrollIntoView({ behavior: "smooth", block: "center" });
        }
      }
    });
  } else {
    showToast("جارٍ تهيئة خدمات Google... يرجى الانتظار ثانية واحدة", "info");
    if (typeof window.initGoogleIdentityServices === "function") {
      window.initGoogleIdentityServices();
    }
  }
};

// 18. Customer Email/Phone Sign-in & Registration
async function handleCustomerSignIn(e) {
  if (e) e.preventDefault();
  const identEl = document.getElementById("custLoginIdentifier");
  const passEl = document.getElementById("custLoginPassword");
  const submitBtn = document.getElementById("btnCustomerSignInSubmit");

  const identifier = identEl ? identEl.value.trim() : "";
  const password = passEl ? passEl.value : "";

  if (!identifier || !password) {
    showToast("يرجى إدخال رقم الهاتف أو البريد وكلمة المرور");
    return;
  }

  const origDisabled = submitBtn ? submitBtn.disabled : false;
  if (submitBtn) {
    submitBtn.disabled = true;
    safeClearContainer(submitBtn);
    submitBtn.appendChild(createSafeEl("i", { class: "fas fa-spinner fa-spin" }));
    submitBtn.appendChild(createSafeEl("span", { textContent: " جارٍ تسجيل الدخول..." }));
  }

  try {
    const res = await window.KK_DB.customerLogin(identifier, password);
    const custName = (res && res.data && res.data.customer && res.data.customer.name) || (res && res.customer && res.customer.name) || "";
    showToast(custName ? `مرحباً بك مجدداً يا ${custName}!` : "تم تسجيل الدخول بنجاح!");
    closeCustomerAuthModal();
    updateCustomerButtonUI();

    if (window.pendingAuthCallback) {
      const cb = window.pendingAuthCallback;
      window.pendingAuthCallback = null;
      cb();
    }
  } catch (err) {
    showToast(`❌ ${err.message || "تعذر تسجيل الدخول"}`);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = origDisabled;
      safeClearContainer(submitBtn);
      submitBtn.appendChild(createSafeEl("i", { class: "fas fa-arrow-left" }));
      submitBtn.appendChild(createSafeEl("span", { textContent: " متابعة الدخول" }));
    }
  }
}
window.handleCustomerSignIn = handleCustomerSignIn;

async function handleCustomerRegister(e) {
  if (e) e.preventDefault();
  const nameEl = document.getElementById("custRegName");
  const phoneEl = document.getElementById("custRegPhone");
  const emailEl = document.getElementById("custRegEmail");
  const passEl = document.getElementById("custRegPassword");
  const submitBtn = document.getElementById("btnCustomerRegSubmit");

  const name = nameEl ? nameEl.value.trim() : "";
  const phone = phoneEl ? phoneEl.value.trim() : "";
  const email = emailEl ? emailEl.value.trim() : "";
  const password = passEl ? passEl.value : "";

  if (!name || !phone || !password) {
    showToast("يرجى ملء جميع الحقول المطلوبة", "error");
    return;
  }

  const cleanPhone = phone.replace(/[^0-9]/g, "");
  if (!/^01[0125][0-9]{8}$/.test(cleanPhone)) {
    showToast("يرجى إدخال رقم هاتف مصري صحيح (11 رقماً يبدأ بـ 01)", "error");
    return;
  }

  if (password.length < 8) {
    showToast("كلمة المرور يجب أن لا تقل عن 8 خانات لحماية حسابك", "error");
    return;
  }

  // Extract Turnstile Verification Token
  let turnstileToken = "";
  if (window.turnstile && window.turnstileRegisterWidgetId !== undefined) {
    try { turnstileToken = window.turnstile.getResponse(window.turnstileRegisterWidgetId); } catch(e) {}
  }
  if (!turnstileToken) {
    const hiddenInput = document.querySelector("#turnstileRegisterContainer input[name='cf-turnstile-response']");
    if (hiddenInput) turnstileToken = hiddenInput.value;
  }

  const origDisabled = submitBtn ? submitBtn.disabled : false;
  if (submitBtn) {
    submitBtn.disabled = true;
    safeClearContainer(submitBtn);
    submitBtn.appendChild(createSafeEl("i", { class: "fas fa-spinner fa-spin" }));
    submitBtn.appendChild(createSafeEl("span", { textContent: " جارٍ إنشاء الحساب..." }));
  }

  try {
    const res = await window.KK_DB.customerRegister(name, cleanPhone, email, password, { turnstileToken });
    if (email) {
      showToast(`أهلاً بك يا ${res.name || "عميلنا العزيز"}! تم إنشاء الحساب وإرسال رابط التفعيل إلى بريدك الإلكتروني (صالح 24 ساعة).`, "success", 8000);
    } else {
      showToast(`أهلاً بك يا ${res.name || "عميلنا العزيز"}! تم إنشاء حسابك بنجاح.`);
    }
    closeCustomerAuthModal();
    updateCustomerButtonUI();

    if (window.pendingAuthCallback) {
      const cb = window.pendingAuthCallback;
      window.pendingAuthCallback = null;
      cb();
    }
  } catch (err) {
    if (window.turnstile && window.turnstileRegisterWidgetId !== undefined) {
      try { window.turnstile.reset(window.turnstileRegisterWidgetId); } catch(e) {}
    }
    showToast(`❌ ${err.message || "تعذر إنشاء الحساب"}`);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = origDisabled;
      safeClearContainer(submitBtn);
      submitBtn.appendChild(createSafeEl("i", { class: "fas fa-user-check" }));
      submitBtn.appendChild(createSafeEl("span", { textContent: " تأكيد وإنشاء الحساب" }));
    }
  }
}
window.handleCustomerRegister = handleCustomerRegister;

function handleCustomerSignOut() {
  if (window.KK_DB && typeof window.KK_DB.customerLogout === "function") {
    window.KK_DB.customerLogout();
  }
  closeCustomerProfileModal();
  updateCustomerButtonUI();
  showToast("تم تسجيل الخروج بنجاح.");
}
window.handleCustomerSignOut = handleCustomerSignOut;

// 19. Customer Profile Modal & Orders History (Safe DOM Construction)
async function openCustomerProfileModal() {
  const customer = window.KK_DB && typeof window.KK_DB.getCustomer === "function" 
    ? window.KK_DB.getCustomer() 
    : null;
  if (!customer) {
    openCustomerAuthModal();
    return;
  }

  const modal = document.getElementById("customerProfileModal");
  const detailsEl = document.getElementById("customerProfileDetails");
  const listEl = document.getElementById("customerOrdersHistoryList");

  if (detailsEl) {
    safeClearContainer(detailsEl);

    // Profile Avatar
    let avatarEl;
    if (customer.avatar && /^https?:\/\//i.test(customer.avatar)) {
      avatarEl = createSafeEl("img", {
        alt: String(customer.name || "Customer"),
        style: "width: 52px; height: 52px; border-radius: 50%; object-fit: cover; border: 2px solid var(--accent); box-shadow: 0 4px 12px rgba(0,0,0,0.12); flex-shrink: 0;"
      });
      setSafeImageWithFallback(avatarEl, customer.avatar, DEFAULT_FALLBACK_IMAGE);
    } else {
      const monogram = String(customer.name || "U").trim().charAt(0).toUpperCase();
      avatarEl = createSafeEl("div", {
        style: "width: 52px; height: 52px; border-radius: 50%; background: linear-gradient(135deg, var(--accent), #9A7B2C); color: #0F172A; font-weight: 800; font-size: 1.3rem; display: flex; align-items: center; justify-content: center; flex-shrink: 0;",
        textContent: monogram
      });
    }

    // Name and provider row
    const nameRow = createSafeEl("div", {
      style: "font-weight: 800; color: var(--text-main); font-size: 1.15rem; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;"
    }, [
      createSafeEl("span", { textContent: String(customer.name || "") })
    ]);

    if (customer.authProvider === "google") {
      nameRow.appendChild(createSafeEl("span", {
        style: "font-size: 0.72rem; padding: 2px 8px; border-radius: 12px; background: rgba(66,133,244,0.1); color: #1a73e8; font-weight: 700; display: inline-flex; align-items: center; gap: 4px;"
      }, [
        createSafeEl("i", { class: "fab fa-google" }),
        " Google"
      ]));
    }

    // Contact details row
    const contactRow = createSafeEl("div", {
      style: "color: var(--text-muted); font-size: 0.85rem; margin-top: 3px; display: flex; gap: 0.65rem; flex-wrap: wrap;"
    });

    if (customer.email) {
      contactRow.appendChild(createSafeEl("span", { dir: "ltr", textContent: String(customer.email) }));
    }
    if (customer.phone) {
      contactRow.appendChild(createSafeEl("span", { textContent: `• ${customer.phone}` }));
    }

    const textCol = createSafeEl("div", {}, [nameRow, contactRow]);
    const wrapper = createSafeEl("div", {
      style: "display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;"
    }, [avatarEl, textCol]);

    detailsEl.appendChild(wrapper);
  }

  if (modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
  }

  if (listEl) {
    safeClearContainer(listEl);
    listEl.appendChild(createSafeEl("div", {
      style: "text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.88rem;"
    }, [
      createSafeEl("i", { class: "fas fa-spinner fa-spin", style: "margin-left: 0.5rem;" }),
      " جاري تحميل سجل طلباتك..."
    ]));

    try {
      const orders = await window.KK_DB.getCustomerOrders();
      safeClearContainer(listEl);

      if (!orders || orders.length === 0) {
        listEl.appendChild(createSafeEl("div", {
          style: "text-align: center; padding: 2.5rem 1rem; color: var(--text-muted); font-size: 0.88rem;"
        }, [
          createSafeEl("i", { class: "fas fa-receipt", style: "font-size: 2.2rem; color: #CBD5E1; display: block; margin-bottom: 0.75rem;" }),
          "لم تسجل أي طلبات حتى الآن. استكشف المعرض وأضف وحدات الإضاءة إلى سلتك!"
        ]));
      } else {
        const statusMap = {
          received: { text: "تم الاستلام", color: "#3B82F6", bg: "rgba(59,130,246,0.12)" },
          confirmed: { text: "تم التأكيد", color: "#059669", bg: "rgba(5,150,105,0.12)" },
          preparing: { text: "جاري التجهيز", color: "#D97706", bg: "rgba(217,119,6,0.12)" },
          packed: { text: "تم التغليف", color: "#7C3AED", bg: "rgba(124,58,237,0.12)" },
          shipped: { text: "خرج للتوصيل", color: "#2563EB", bg: "rgba(37,99,235,0.12)" },
          delivered: { text: "تم التسليم", color: "#10B981", bg: "rgba(16,185,129,0.12)" },
          cancelled: { text: "ملغي", color: "#EF4444", bg: "rgba(239,68,68,0.12)" },
          failed: { text: "تعذر التسليم", color: "#DC2626", bg: "rgba(220,38,38,0.12)" }
        };

        const frag = document.createDocumentFragment();

        orders.forEach(ord => {
          const st = statusMap[ord.status] || { text: String(ord.status || "طلب"), color: "#6B7280", bg: "#F3F4F6" };
          const items = Array.isArray(ord.items) ? ord.items : Object.values(ord.items || {});

          const dateStr = ord.timestamp
            ? new Date(ord.timestamp).toLocaleDateString("ar-EG", { timeZone: "Africa/Cairo", year: "numeric", month: "short", day: "numeric" })
            : (ord.dateFormatted || "");
          const timeStr = ord.timestamp
            ? new Date(ord.timestamp).toLocaleTimeString("ar-EG", { timeZone: "Africa/Cairo", hour: "2-digit", minute: "2-digit" })
            : (ord.timeFormatted || "");
          const dateTimeDisplay = dateStr ? `${dateStr}${timeStr ? " • " + timeStr : ""}` : "";

          // Card element
          const card = createSafeEl("div", {
            class: "customer-order-card",
            dataset: { action: "view-order-details", orderId: ord.id },
            style: "background: #FFFFFF; border: 1px solid var(--border-light); border-radius: var(--radius-sm); padding: 0.9rem 1rem; margin-bottom: 0.85rem; box-shadow: 0 1px 4px rgba(0,0,0,0.03); cursor: pointer; transition: all 0.2s ease;"
          });

          // Order ID & status row
          const topRow = createSafeEl("div", {
            style: "display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.35rem; flex-wrap: wrap; gap: 0.5rem;"
          }, [
            createSafeEl("span", {
              style: "font-weight: 800; font-family: monospace; font-size: 0.95rem; color: var(--text-main); letter-spacing: 0.5px;",
              textContent: `#${ord.id}`
            }),
            createSafeEl("span", {
              style: `font-size: 0.74rem; font-weight: 800; padding: 3px 10px; border-radius: 4px; color: ${st.color}; background: ${st.bg}; border: 1px solid ${st.color}22;`,
              textContent: st.text
            })
          ]);
          card.appendChild(topRow);

          // Date time
          if (dateTimeDisplay) {
            card.appendChild(createSafeEl("div", {
              style: "font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.45rem;"
            }, [
              createSafeEl("i", { class: "far fa-calendar-alt", style: "margin-left: 4px;" }),
              dateTimeDisplay
            ]));
          }

          // Items summary
          const itemsSummary = items.map(it => `${it.name || "وحدة"} × ${it.qty || 1}`).join(" • ");
          card.appendChild(createSafeEl("div", {
            style: "font-size: 0.82rem; color: var(--text-main); margin-bottom: 0.5rem; line-height: 1.5; background: #FAF7F2; padding: 6px 10px; border-radius: 4px; border: 1px solid #EFEAE1;",
            textContent: itemsSummary
          }));

          // Payment and Total
          const isCollected = ord.paymentStatus === "collected";
          const codSpan = isCollected
            ? createSafeEl("span", { style: "font-size: 0.74rem; color: #10B981; font-weight: 700;" }, [
                createSafeEl("i", { class: "fas fa-check-circle" }), " تم سداد النقدية"
              ])
            : createSafeEl("span", { style: "font-size: 0.74rem; color: #D97706; font-weight: 700;" }, [
                createSafeEl("i", { class: "fas fa-hand-holding-dollar" }), " الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد"
              ]);

          const totalRow = createSafeEl("div", {
            style: "display: flex; justify-content: space-between; align-items: center; border-top: 1px dashed var(--border-light); padding-top: 0.5rem; margin-bottom: 0.65rem; flex-wrap: wrap; gap: 0.4rem;"
          }, [
            createSafeEl("div", {}, [codSpan]),
            createSafeEl("div", {
              style: "font-weight: 900; color: var(--accent); font-size: 1rem;",
              textContent: `${formatPrice(ord.total || 0)} ج.م`
            })
          ]);
          card.appendChild(totalRow);

          // View details button
          const viewBtn = createSafeEl("button", {
            type: "button",
            class: "btn-secondary",
            style: "width: 100%; justify-content: center; font-size: 0.82rem; padding: 0.55rem 0.75rem; font-weight: 700; gap: 0.5rem; border-color: var(--accent); color: var(--accent); background: #FAF7F2;",
            dataset: { action: "view-order-details", orderId: ord.id }
          }, [
            createSafeEl("i", { class: "fas fa-eye" }),
            createSafeEl("span", { textContent: "عرض تفاصيل وتتبع الطلب بالكامل" }),
            createSafeEl("i", { class: "fas fa-arrow-left", style: "font-size: 0.75rem; margin-right: auto;" })
          ]);
          card.appendChild(viewBtn);

          frag.appendChild(card);
        });

        listEl.appendChild(frag);
      }
    } catch (e) {
      safeClearContainer(listEl);
      listEl.appendChild(createSafeEl("div", {
        style: "text-align: center; padding: 2rem; color: #EF4444; font-size: 0.85rem;",
        textContent: "تعذر تحميل سجل الطلبات"
      }));
    }
  }
}
window.openCustomerProfileModal = openCustomerProfileModal;

function closeCustomerProfileModal() {
  const modal = document.getElementById("customerProfileModal");
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
}
window.closeCustomerProfileModal = closeCustomerProfileModal;

function viewCustomerOrderDetails(orderId) {
  closeCustomerProfileModal();
  if (typeof window.openTrackOrderModal === "function") {
    window.openTrackOrderModal(orderId);
  }
}
window.viewCustomerOrderDetails = viewCustomerOrderDetails;

// 20. Update Customer Header Button UI (Safe DOM Construction)
function updateCustomerButtonUI() {
  const customer = window.KK_DB && typeof window.KK_DB.getCustomer === "function" 
    ? window.KK_DB.getCustomer() 
    : null;
  const isEn = isCurrentEn();
  const btn = document.getElementById("customerAccountBtn");
  if (!btn) return;

  safeClearContainer(btn);

  if (customer) {
    const name = customer.name || "عميل";
    const avatar = customer.avatar || "";
    const monogram = name.trim().charAt(0).toUpperCase() || "U";

    btn.style.padding = "0";
    btn.style.overflow = "hidden";
    btn.style.display = "inline-flex";
    btn.style.alignItems = "center";
    btn.style.justifyContent = "center";
    btn.style.width = "38px";
    btn.style.height = "38px";
    btn.style.borderRadius = "50%";

    if (avatar && /^https?:\/\//i.test(avatar)) {
      const img = createSafeEl("img", {
        class: "customer-avatar-header",
        alt: String(name),
        style: "width: 100%; height: 100%; border-radius: 50%; object-fit: cover; display: block; border: 2px solid var(--accent); box-shadow: 0 0 8px rgba(212,175,55,0.35);"
      });
      setSafeImageWithFallback(img, avatar, "");
      img.addEventListener("error", () => {
        safeClearContainer(btn);
        btn.appendChild(createSafeEl("span", {
          style: "width:100%;height:100%;border-radius:50%;background:linear-gradient(135deg,var(--accent),#9A7B2C);color:#0F172A;font-weight:800;font-size:0.85rem;display:flex;align-items:center;justify-content:center;",
          textContent: monogram
        }));
      }, { once: true });
      btn.appendChild(img);
    } else {
      btn.appendChild(createSafeEl("span", {
        style: "width: 100%; height: 100%; border-radius: 50%; background: linear-gradient(135deg, var(--accent), #9A7B2C); color: #0F172A; font-weight: 800; font-size: 0.85rem; display: flex; align-items: center; justify-content: center; border: 2px solid #FDFBF7;",
        textContent: monogram
      }));
    }
    btn.setAttribute("title", isEn ? `Signed in as: ${name}` : `تم تسجيل الدخول: ${name} (${customer.email || customer.phone || ""})`);
  } else {
    btn.style.padding = "";
    btn.style.overflow = "";
    btn.style.width = "";
    btn.style.height = "";
    btn.appendChild(createSafeEl("i", { class: "fas fa-user-circle" }));
    btn.setAttribute("title", isEn ? "Sign in / Register" : "تسجيل الدخول / إنشاء حساب");
  }
}
window.updateCustomerButtonUI = updateCustomerButtonUI;

// 21. Product Reviews & Moderation (Safe DOM Construction)
let currentReviewRating = 5;

function initStarRatingSelect() {
  const container = document.getElementById("starRatingSelect");
  if (!container || container.dataset.hasListener) return;
  container.dataset.hasListener = "true";

  const stars = container.querySelectorAll("i");
  stars.forEach(star => {
    star.addEventListener("click", () => {
      const val = parseInt(star.getAttribute("data-val") || "5", 10);
      currentReviewRating = val;
      stars.forEach(s => {
        const sVal = parseInt(s.getAttribute("data-val") || "0", 10);
        if (sVal <= val) {
          s.classList.remove("far");
          s.classList.add("fas");
          s.style.color = "#F59E0B";
        } else {
          s.classList.remove("fas");
          s.classList.add("far");
          s.style.color = "#CBD5E1";
        }
      });
    });
  });
}

function toggleReviewForm(show) {
  const form = document.getElementById("productReviewForm");
  if (!form) return;
  const isHidden = form.style.display === "none" || form.style.display === "";
  const shouldShow = show !== undefined ? show : isHidden;
  form.style.display = shouldShow ? "block" : "none";

  if (shouldShow) {
    initStarRatingSelect();
    const customer = window.KK_DB && typeof window.KK_DB.getCustomer === "function" 
      ? window.KK_DB.getCustomer() 
      : null;
    const authorInput = document.getElementById("reviewAuthorInput");
    if (customer && authorInput && !authorInput.value) {
      authorInput.value = customer.name || "";
    }
  }
}
window.toggleReviewForm = toggleReviewForm;

async function loadProductReviews(productId) {
  const container = document.getElementById("productReviewsList");
  if (!container) return;

  safeClearContainer(container);
  container.appendChild(createSafeEl("div", {
    style: "text-align: center; padding: 1.25rem; color: var(--text-muted); font-size: 0.8rem;"
  }, [
    createSafeEl("i", { class: "fas fa-spinner fa-spin", style: "margin-left: 0.35rem;" }),
    " جاري تحميل تقييمات العملاء..."
  ]));

  try {
    const reviews = (window.KK_DB && typeof window.KK_DB.getProductReviews === "function")
      ? await window.KK_DB.getProductReviews(productId)
      : [];

    safeClearContainer(container);

    if (!reviews || reviews.length === 0) {
      container.appendChild(createSafeEl("div", {
        style: "text-align: center; padding: 1.5rem 0.5rem; color: var(--text-muted); font-size: 0.82rem; background: #F8FAFC; border-radius: 4px; border: 1px dashed var(--border-light);"
      }, [
        createSafeEl("i", { class: "far fa-star", style: "font-size: 1.5rem; color: #CBD5E1; display: block; margin-bottom: 0.35rem;" }),
        "لا توجد تقييمات معتمدة لهذه الوحدة حتى الآن. كن أول من يشاركنا رأيه!"
      ]));
      return;
    }

    const frag = document.createDocumentFragment();

    reviews.forEach(rev => {
      const rating = Number.isInteger(rev.rating) && rev.rating >= 1 && rev.rating <= 5 ? rev.rating : 5;
      const starsStr = "★".repeat(rating) + "☆".repeat(5 - rating);

      const revItem = createSafeEl("div", {
        style: "padding: 0.75rem 0; border-bottom: 1px solid var(--border-light); font-size: 0.82rem;"
      });

      // Top row (author + stars)
      const topRow = createSafeEl("div", {
        style: "display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;"
      }, [
        createSafeEl("div", {
          style: "font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 0.35rem;"
        }, [
          createSafeEl("i", { class: "fas fa-circle-user", style: "color: var(--accent);" }),
          createSafeEl("span", { textContent: String(rev.author || "عميل معتمد") })
        ]),
        createSafeEl("div", {
          style: "color: #F59E0B; font-size: 0.85rem; letter-spacing: 1px;",
          textContent: starsStr
        })
      ]);
      revItem.appendChild(topRow);

      // Comment
      revItem.appendChild(createSafeEl("p", {
        style: "margin: 0; color: #475569; font-size: 0.8rem; line-height: 1.45;",
        textContent: String(rev.comment || "")
      }));

      // Date formatted
      revItem.appendChild(createSafeEl("div", {
        style: "font-size: 0.7rem; color: var(--text-muted); margin-top: 0.25rem;",
        textContent: String(rev.dateFormatted || "مراجعة معتمدة")
      }));

      // Admin reply if present
      if (rev.adminReply) {
        revItem.appendChild(createSafeEl("div", {
          style: "margin-top: 0.35rem; padding: 0.4rem 0.6rem; background: #FAF7F2; border-right: 3px solid var(--accent); border-radius: 2px; font-size: 0.76rem; color: var(--text-main);"
        }, [
          createSafeEl("strong", { textContent: "رد المعرض: " }),
          createSafeEl("span", { textContent: String(rev.adminReply) })
        ]));
      }

      frag.appendChild(revItem);
    });

    container.appendChild(frag);
  } catch (err) {
    safeClearContainer(container);
    container.appendChild(createSafeEl("div", {
      style: "text-align: center; padding: 1rem; color: #EF4444; font-size: 0.8rem;",
      textContent: "تعذر تحميل التقييمات"
    }));
  }
}
window.loadProductReviews = loadProductReviews;

async function handleReviewSubmit(e) {
  if (e) e.preventDefault();
  const product = STATE.selectedProduct;
  if (!product) {
    showToast("يرجى اختيار وحدة إضاءة أولاً");
    return;
  }

  const authorInput = document.getElementById("reviewAuthorInput");
  const commentInput = document.getElementById("reviewCommentInput");
  const submitBtn = document.getElementById("btnSubmitReview");

  const author = authorInput ? authorInput.value.trim() : "";
  const comment = commentInput ? commentInput.value.trim() : "";

  if (!author || !comment) {
    showToast("يرجى إدخال اسمك ورأيك في وحدة الإضاءة");
    return;
  }

  const origDisabled = submitBtn ? submitBtn.disabled : false;
  if (submitBtn) {
    submitBtn.disabled = true;
    safeClearContainer(submitBtn);
    submitBtn.appendChild(createSafeEl("i", { class: "fas fa-spinner fa-spin" }));
    submitBtn.appendChild(createSafeEl("span", { textContent: " جارٍ الإرسال..." }));
  }

  try {
    await window.KK_DB.submitReview(product.id, product.name, author, currentReviewRating, comment);
    showToast("✨ شكراً لتقييمك! تم إرسال تقييمك للمراجعة وسيظهر بعد الاعتماد.");
    if (commentInput) commentInput.value = "";
    toggleReviewForm(false);
  } catch (err) {
    showToast(`❌ ${err.message || "تعذر إرسال التقييم"}`);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = origDisabled;
      safeClearContainer(submitBtn);
      submitBtn.appendChild(createSafeEl("i", { class: "fas fa-paper-plane" }));
      submitBtn.appendChild(createSafeEl("span", { textContent: " إرسال التقييم" }));
    }
  }
}
window.handleReviewSubmit = handleReviewSubmit;

// -----------------------------------------------------------------------------
// 22. CENTRAL EVENT DELEGATION ARCHITECTURE (Anti-Listener Leak & CSP Clean)
// -----------------------------------------------------------------------------
let isEventDelegationInitialized = false;

function initEventDelegation() {
  if (isEventDelegationInitialized) return;
  isEventDelegationInitialized = true;

  document.addEventListener("click", function(e) {
    const trigger = e.target.closest("[data-action]");
    if (!trigger) return;

    const action = trigger.dataset.action;
    switch (action) {
      case "quickview": {
        const id = trigger.dataset.id;
        const fn = (typeof window !== "undefined" && window.openQuickView) || (typeof openQuickView === "function" ? openQuickView : null);
        if (id && fn) fn(id);
        break;
      }
      case "add-to-cart": {
        const id = trigger.dataset.id;
        const fn = (typeof window !== "undefined" && window.addToCart) || (typeof addToCart === "function" ? addToCart : null);
        if (id && fn) fn(id, 1);
        break;
      }
      case "select-subcategory": {
        const catId = trigger.dataset.catId;
        const fn = (typeof window !== "undefined" && window.selectSubcategory) || (typeof selectSubcategory === "function" ? selectSubcategory : null);
        if (catId && fn) fn(catId);
        break;
      }
      case "select-subbar-cat": {
        const catId = trigger.dataset.catId;
        const fn = (typeof window !== "undefined" && window.selectCategoryFromSubBar) || (typeof selectCategoryFromSubBar === "function" ? selectCategoryFromSubBar : null);
        if (catId && fn) fn(catId);
        break;
      }
      case "select-mobile-cat": {
        const catId = trigger.dataset.catId;
        const fn = (typeof window !== "undefined" && window.selectCategoryFromMobile) || (typeof selectCategoryFromMobile === "function" ? selectCategoryFromMobile : null);
        if (catId && fn) fn(catId);
        break;
      }
      case "select-category-tab": {
        const catId = trigger.dataset.category;
        if (catId) {
          STATE.activeCategory = catId;
          STATE.visibleCount = 6;
          renderCategoryTabs();
          renderProducts();
          if (typeof updateSubBarActiveCategory === "function") updateSubBarActiveCategory();
          if (typeof trigger.scrollIntoView === "function") {
            trigger.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
          }
        }
        break;
      }
      case "switch-thumb": {
        const imgSrc = trigger.dataset.imgSrc;
        const fn = (typeof window !== "undefined" && window.switchModalThumb) || (typeof switchModalThumb === "function" ? switchModalThumb : null);
        if (imgSrc && fn) fn(imgSrc, trigger);
        break;
      }
      case "remove-from-cart": {
        const itemId = trigger.dataset.itemId;
        const fn = (typeof window !== "undefined" && window.removeFromCart) || (typeof removeFromCart === "function" ? removeFromCart : null);
        if (itemId && fn) fn(itemId);
        break;
      }
      case "cart-qty-inc": {
        const itemId = trigger.dataset.itemId;
        if (itemId) updateCartItemQty(itemId, 1);
        break;
      }
      case "cart-qty-dec": {
        const itemId = trigger.dataset.itemId;
        if (itemId) updateCartItemQty(itemId, -1);
        break;
      }
      case "checkout-open-login": {
        if (typeof closeCheckoutModal === "function") closeCheckoutModal();
        if (typeof openCustomerAuthModal === "function") {
          openCustomerAuthModal(() => {
            if (typeof openCheckoutModal === "function") openCheckoutModal();
          });
        }
        break;
      }
      case "browse-catalog-from-empty-cart": {
        if (typeof toggleCartDrawer === "function") toggleCartDrawer(false);
        const catEl = document.getElementById("catalog");
        if (catEl) catEl.scrollIntoView({ behavior: "smooth" });
        break;
      }
      case "view-order-details": {
        const orderId = trigger.dataset.orderId;
        const fn = (typeof window !== "undefined" && window.viewCustomerOrderDetails) || (typeof viewCustomerOrderDetails === "function" ? viewCustomerOrderDetails : null);
        if (orderId && fn) fn(orderId);
        break;
      }
      case "reset-filters": {
        const fn = (typeof window !== "undefined" && window.resetFilters) || (typeof resetFilters === "function" ? resetFilters : null);
        if (fn) fn();
        break;
      }
      case "toggle-review-form": {
        const fn = (typeof window !== "undefined" && window.toggleReviewForm) || (typeof toggleReviewForm === "function" ? toggleReviewForm : null);
        if (fn) fn();
        break;
      }
      case "close-quickview": {
        const fn = (typeof window !== "undefined" && window.closeQuickView) || (typeof closeQuickView === "function" ? closeQuickView : null);
        if (fn) fn();
        break;
      }
      case "close-cart": {
        const fn = (typeof window !== "undefined" && window.toggleCartDrawer) || (typeof toggleCartDrawer === "function" ? toggleCartDrawer : null);
        if (fn) fn(false);
        break;
      }
      case "open-cart": {
        const fn = (typeof window !== "undefined" && window.toggleCartDrawer) || (typeof toggleCartDrawer === "function" ? toggleCartDrawer : null);
        if (fn) fn(true);
        break;
      }
      case "account-click": {
        const fn = (typeof window !== "undefined" && window.handleCustomerAccountClick) || (typeof handleCustomerAccountClick === "function" ? handleCustomerAccountClick : null);
        if (fn) fn();
        break;
      }
      case "toggle-language": {
        if (typeof window.toggleLanguage === "function") window.toggleLanguage();
        break;
      }
      case "toggle-collections-subbar": {
        if (typeof toggleCollectionsSubBar === "function") toggleCollectionsSubBar(e);
        break;
      }
      case "close-subbar": {
        if (typeof toggleCollectionsSubBar === "function") toggleCollectionsSubBar(false);
        break;
      }
      case "close-mobile-nav": {
        const d = document.getElementById("mobileNavDrawer");
        if (d) d.classList.remove("active");
        break;
      }
      case "toggle-mobile-accordion": {
        if (typeof toggleMobileCollectionsAccordion === "function") toggleMobileCollectionsAccordion(e);
        break;
      }
      case "open-track-modal": {
        if (trigger.dataset.closeMobile === "true") {
          const d = document.getElementById("mobileNavDrawer");
          if (d) d.classList.remove("active");
        }
        if (typeof openTrackOrderModal === "function") openTrackOrderModal();
        break;
      }
      case "load-more-products": {
        if (typeof loadMoreProducts === "function") loadMoreProducts();
        break;
      }
      case "close-review-form": {
        if (typeof toggleReviewForm === "function") toggleReviewForm(false);
        break;
      }
      case "open-checkout-modal": {
        if (typeof openCheckoutModal === "function") openCheckoutModal();
        break;
      }
      case "whatsapp-quote": {
        if (typeof sendWhatsAppQuotation === "function") sendWhatsAppQuotation();
        break;
      }
      case "print-window": {
        window.print();
        break;
      }
      case "close-checkout-modal": {
        if (typeof closeCheckoutModal === "function") closeCheckoutModal();
        break;
      }
      case "close-auth-modal": {
        if (typeof closeCustomerAuthModal === "function") closeCustomerAuthModal();
        break;
      }
      case "google-signin": {
        if (typeof handleGoogleSignIn === "function") handleGoogleSignIn();
        break;
      }
      case "auth-tab": {
        const tab = trigger.dataset.tab;
        if (tab && typeof switchCustomerAuthTab === "function") switchCustomerAuthTab(tab);
        break;
      }
      case "continue-guest": {
        if (typeof continueCheckoutAsGuest === "function") continueCheckoutAsGuest();
        break;
      }
      case "close-google-config": {
        if (typeof closeGoogleConfigModal === "function") closeGoogleConfigModal();
        break;
      }
      case "close-profile-modal": {
        if (typeof closeCustomerProfileModal === "function") closeCustomerProfileModal();
        break;
      }
      case "customer-signout": {
        if (typeof handleCustomerSignOut === "function") handleCustomerSignOut();
        break;
      }
      case "track-from-success": {
        if (typeof trackOrderFromSuccessModal === "function") trackOrderFromSuccessModal();
        break;
      }
      case "close-success-modal": {
        if (typeof closeOrderSuccessModal === "function") closeOrderSuccessModal();
        break;
      }
      case "close-track-modal": {
        if (typeof closeTrackOrderModal === "function") closeTrackOrderModal();
        break;
      }
      case "search-track-order": {
        if (typeof searchAndTrackOrder === "function") searchAndTrackOrder();
        break;
      }
      case "refresh-track-order": {
        if (typeof refreshCurrentTrackOrder === "function") refreshCurrentTrackOrder(trigger);
        break;
      }
      case "track-support-whatsapp": {
        if (typeof contactSupportAboutTrackedOrder === "function") contactSupportAboutTrackedOrder();
        break;
      }
    }
  });

  // Click outside listener to close sub-bar cleanly
  document.addEventListener("click", (e) => {
    const subBar = document.getElementById("siteSubBar");
    const toggleBtn = document.getElementById("navCollectionsBtn");
    if (subBar && subBar.classList.contains("active")) {
      if (!subBar.contains(e.target) && !toggleBtn?.contains(e.target)) {
        toggleCollectionsSubBar(false);
      }
    }
  });
}

// Initialize central event delegation immediately
if (typeof document !== "undefined") {
  initEventDelegation();
}

// Global invocation on DOMContentLoaded
if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", initApp);
}

// Expose public interface and bridges to window
if (typeof window !== "undefined") {
  window.escapeHtml = escapeHtml;
  window.safeCssEscape = safeCssEscape;
  window.sanitizeUrl = sanitizeUrl;
  window.sanitizeImageUrl = sanitizeImageUrl;
  window.setSafeImageWithFallback = setSafeImageWithFallback;
  window.safeClearContainer = safeClearContainer;
  window.createSafeEl = createSafeEl;
  window.renderProducts = renderProducts;
  window.createProductCard = createProductCard;
  window.openQuickView = openQuickView;
  window.closeQuickView = closeQuickView;
  window.switchModalThumb = switchModalThumb;
  window.addToCart = addToCart;
  window.removeFromCart = removeFromCart;
  window.saveCart = saveCart;
  window.updateCartUI = updateCartUI;
  window.toggleCartDrawer = toggleCartDrawer;
  window.resetFilters = resetFilters;
  window.renderActiveSubcategoriesStrip = renderActiveSubcategoriesStrip;
  window.renderCategoryTabs = renderCategoryTabs;
  window.renderSubBarCategories = renderSubBarCategories;
  window.renderMobileAccordionCategories = renderMobileAccordionCategories;
  window.renderFooterCategories = renderFooterCategories;
  window.applyDynamicSettings = applyDynamicSettings;
  window.initEventDelegation = initEventDelegation;
  window.initApp = initApp;
  window.loadProducts = loadProducts;
  window.loadCart = loadCart;
}
