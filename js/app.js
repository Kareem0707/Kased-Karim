/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Main E-Commerce & Interactive Application Logic
 */

// Safe HTML Escaping Utility for XSS Prevention
window.escapeHtml = window.escapeHtml || function(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
};

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
  setupCategoryTabsScroll();
  updateCartUI();
  handleHeaderScroll();
}

// 1. Load Products from Database Engine
function loadProducts() {
  if (window.KK_DB) {
    STATE.products = window.KK_DB.getProducts();
    return;
  }
  const saved = localStorage.getItem(STORAGE_KEYS.PRODUCTS);
  if (saved) {
    try {
      STATE.products = JSON.parse(saved);
    } catch (e) {
      STATE.products = [...INITIAL_PRODUCTS];
    }
  } else {
    STATE.products = [...INITIAL_PRODUCTS];
  }
}

// Save products to database
function saveCustomProducts() {
  if (window.KK_DB) {
    localStorage.setItem(DB_KEYS.PRODUCTS, JSON.stringify(STATE.products));
  }
}

// 2. Load Cart from localStorage
function loadCart() {
  const saved = localStorage.getItem(STORAGE_KEYS.CART);
  if (saved) {
    try {
      STATE.cart = JSON.parse(saved);
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

// 3. Render Category Tabs with Dynamic Item Counts & Anchored Subcategories
function renderActiveSubcategoriesStrip(parentCat, cats) {
  const strip = document.getElementById("activeSubcategoryBar");
  if (!strip) return;

  if (!parentCat || parentCat.id === "all") {
    strip.style.display = "none";
    strip.innerHTML = "";
    return;
  }

  const subCats = cats.filter(c => c.parentId === parentCat.id);
  if (!subCats || subCats.length === 0) {
    strip.style.display = "none";
    strip.innerHTML = "";
    return;
  }

  const subCatIds = subCats.map(c => c.id);
  const totalParentCount = STATE.products.filter(p => p.category === parentCat.id || subCatIds.includes(p.category)).length;
  const isParentSelected = STATE.activeCategory === parentCat.id;

  const escapeFn = typeof escapeHTML === "function" ? escapeHTML : (s => String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"));

  let html = `
    <span class="subcat-strip-label">
      <i class="fas fa-layer-group"></i>
      <span>الأقسام الفرعية لـ ${escapeFn(parentCat.name)}:</span>
    </span>
    <button type="button" class="subcat-chip ${isParentSelected ? 'active' : ''}" onclick="selectSubcategory('${parentCat.id}')" title="عرض كافة منتجات ${escapeFn(parentCat.name)}">
      <span>الكل في ${escapeFn(parentCat.name)}</span>
      <span class="subcat-count">${totalParentCount}</span>
    </button>
  `;

  subCats.forEach(sub => {
    const count = STATE.products.filter(p => p.category === sub.id).length;
    const isActive = STATE.activeCategory === sub.id;
    html += `
      <button type="button" class="subcat-chip ${isActive ? 'active' : ''}" onclick="selectSubcategory('${sub.id}')" title="قسم فرعي: ${escapeFn(sub.name)}">
        <span>${escapeFn(sub.name)}</span>
        <span class="subcat-count">${count}</span>
      </button>
    `;
  });

  strip.innerHTML = html;
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

  const cats = window.KK_DB ? window.KK_DB.getCategories() : (typeof CATEGORIES !== "undefined" ? CATEGORIES : []);
  const mainCats = cats.filter(c => !c.parentId);

  // Determine current active main category or parent of active subcategory
  const activeSub = cats.find(c => c.id === STATE.activeCategory && c.parentId);
  const activeParent = activeSub ? mainCats.find(c => c.id === activeSub.parentId) : null;
  const activeMain = mainCats.find(c => c.id === STATE.activeCategory);
  const currentFamily = activeMain || activeParent || null;

  tabsContainer.innerHTML = mainCats.map(cat => {
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
    const caretHtml = hasSubs ? `<i class="fas fa-angle-down subcat-caret" aria-hidden="true"></i>` : "";

    return `
      <button class="category-tab-btn ${activeClass} ${hasSubClass}" data-category="${cat.id}" ${hasSubs ? `title="يحتوي على أقسام فرعية - انقر أو مرر لعرض التفريعات"` : ""}>
        <span>${cat.name}</span>
        ${caretHtml}
        <span class="tab-count">${count}</span>
      </button>
    `;
  }).join("");

  // Render or update anchored subcategories strip
  renderActiveSubcategoriesStrip(currentFamily, cats);

  // Attach tab events
  const tabButtons = tabsContainer.querySelectorAll(".category-tab-btn");
  tabButtons.forEach(btn => {
    const catId = btn.dataset.category;
    const thisCat = mainCats.find(c => c.id === catId);
    const hasSubs = cats.some(c => c.parentId === catId);

    btn.addEventListener("click", () => {
      STATE.activeCategory = catId;
      STATE.visibleCount = 6;
      renderCategoryTabs();
      renderProducts();
      if (typeof updateSubBarActiveCategory === "function") updateSubBarActiveCategory();

      // Smoothly bring clicked tab into view
      btn.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
    });

    // Hover preview of subcategories for categories that have them
    if (hasSubs) {
      btn.addEventListener("mouseenter", () => {
        renderActiveSubcategoriesStrip(thisCat, cats);
      });
    }
  });

  // When mouse leaves tabs container, restore strip to the currently active category family
  tabsContainer.onmouseleave = () => {
    renderActiveSubcategoriesStrip(currentFamily, cats);
  };

  if (typeof updateCategoryScrollButtons === "function") {
    updateCategoryScrollButtons();
  }
}

// 3.1 Render Sub-Bar Categories
function renderSubBarCategories() {
  const container = document.getElementById("subBarItems");
  if (!container) return;

  const cats = window.KK_DB ? window.KK_DB.getCategories() : (typeof CATEGORIES !== "undefined" ? CATEGORIES : []);
  container.innerHTML = cats.map(cat => {
    const isSub = !!cat.parentId;
    const displayName = isSub ? `<span style="opacity: 0.6; font-size: 0.8em; margin-left: 3px;">↳</span>${cat.name}` : cat.name;
    return `
      <button class="sub-bar-cat-btn ${STATE.activeCategory === cat.id ? 'active' : ''}" onclick="selectCategoryFromSubBar('${cat.id}')">
        <span>${displayName}</span>
      </button>
    `;
  }).join("");
}

// 3.2 Render Mobile Accordion Categories
function renderMobileAccordionCategories() {
  const container = document.getElementById("mobileAccordionContent");
  if (!container) return;

  const cats = window.KK_DB ? window.KK_DB.getCategories() : (typeof CATEGORIES !== "undefined" ? CATEGORIES : []);
  container.innerHTML = cats.map(cat => {
    const isSub = !!cat.parentId;
    const displayName = isSub ? `— ${cat.name}` : cat.name;
    return `
      <button class="mobile-sub-cat-item ${STATE.activeCategory === cat.id ? 'active' : ''} ${isSub ? 'is-mobile-subcat' : ''}" onclick="selectCategoryFromMobile('${cat.id}')" style="${isSub ? 'padding-right: 1.75rem; font-size: 0.88rem; opacity: 0.9;' : ''}">
        <span>${displayName}</span>
      </button>
    `;
  }).join("");
}

// 3.3 Render Footer Collections Categories
function renderFooterCategories() {
  const container = document.querySelector(".footer-links-grid");
  if (!container) return;

  const cats = (window.KK_DB ? window.KK_DB.getCategories() : (typeof CATEGORIES !== "undefined" ? CATEGORIES : [])).filter(c => c.id !== "all");
  container.innerHTML = cats.map(cat => `
    <li><a href="#catalog" class="footer-link" onclick="selectCategoryFromSubBar('${cat.id}')">${cat.name}</a></li>
  `).join("");
}

// 3.4 Apply Dynamic Showroom Settings & Contact Links Across Website
function applyDynamicSettings() {
  const settings = window.KK_DB ? window.KK_DB.getSettings() : (typeof SHOWROOM_INFO !== "undefined" ? SHOWROOM_INFO : {});
  if (!settings) return;

  const phone = settings.phone || "01006367690";
  const whatsapp = settings.whatsapp || "201006367690";
  const location = settings.location || "الشيخ زايد - الحي الأول، سنتر الطاهرة، الجيزة";
  const hours = settings.workingHours || "يومياً من 11:00 صباحاً حتى 11:00 مساءً";
  const mapUrl = settings.mapUrl || "https://maps.app.goo.gl/EzzitFCzNSpQc7w77?g_st=ic";
  const mapEmbed = settings.mapEmbedUrl || "https://maps.google.com/maps?q=%D9%82%D8%A7%D8%B5%D8%AF%20%D9%83%D8%B1%D9%8A%D9%85%202%20%D9%84%D9%84%D8%A7%D8%AF%D9%88%D8%A7%D8%AA%20%D8%A7%D9%84%D9%83%D9%87%D8%B1%D8%A8%D8%A7%D8%A6%D9%8A%D8%A9%2C%20%D8%B1%D9%82%D9%85%2039%D8%8C%20%D8%A3%D9%88%D9%84%20%D8%A7%D9%84%D8%B4%D9%8A%D8%AE%20%D8%B2%D8%A7%D9%8A%D8%AF%D8%8C%20%D9%85%D8%AD%D8%A7%D9%81%D8%B8%D8%A9%20%D8%A7%D9%84%D8%AC%D9%8A%D8%B2%D8%A9&t=&z=14&ie=UTF8&iwloc=&output=embed";
  const social = settings.social || {};

  // Top bar phone
  const topPhone = document.getElementById("topBarPhone");
  if (topPhone) topPhone.textContent = `معرض الشيخ زايد • ${phone}`;

  // Header WhatsApp
  const headerWa = document.getElementById("headerWhatsappBtn");
  if (headerWa) headerWa.href = `https://wa.me/${whatsapp}`;

  // Floating WhatsApp
  const floatingWa = document.getElementById("floatingWhatsappBtn");
  if (floatingWa) {
    const waText = encodeURIComponent("مرحباً معرض قاصد كريم للإضاءة بالشيخ زايد، أود الاستفسار عن وحدات الإضاءة.");
    floatingWa.href = `https://wa.me/${whatsapp}?text=${waText}`;
  }

  // Mobile Drawer WhatsApp
  const mobileDrawerWa = document.getElementById("mobileDrawerWhatsappBtn");
  if (mobileDrawerWa) mobileDrawerWa.href = `https://wa.me/${whatsapp}`;

  // Showroom Section
  const showroomLoc = document.getElementById("showroomLocationText");
  if (showroomLoc) showroomLoc.textContent = location;
  const showroomHrs = document.getElementById("showroomHoursText");
  if (showroomHrs) showroomHrs.textContent = hours;
  const showroomWa = document.getElementById("showroomWhatsappBtn");
  if (showroomWa) showroomWa.href = `https://wa.me/${whatsapp}`;
  const showroomMap = document.getElementById("showroomMapBtn");
  if (showroomMap) showroomMap.href = mapUrl;

  // Footer Location & Maps
  const footerLoc = document.getElementById("footerLocationText");
  if (footerLoc) footerLoc.textContent = location;
  const footerMapIframe = document.getElementById("footerMapEmbed");
  if (footerMapIframe) footerMapIframe.src = mapEmbed;
  const footerMapLnk = document.getElementById("footerMapLink");
  if (footerMapLnk) footerMapLnk.href = mapUrl;
  const footerHrs = document.getElementById("footerHoursText");
  if (footerHrs) footerHrs.textContent = hours;

  // Footer Phone & WhatsApp
  const footerPhoneLnk = document.getElementById("footerPhoneLink");
  const footerPhoneSpn = document.getElementById("footerPhoneSpan");
  if (footerPhoneLnk) footerPhoneLnk.href = `tel:${phone}`;
  if (footerPhoneSpn) footerPhoneSpn.textContent = phone;

  const footerWaLnk = document.getElementById("footerWhatsappLink");
  const footerWaSpn = document.getElementById("footerWhatsappSpan");
  if (footerWaLnk) footerWaLnk.href = `https://wa.me/${whatsapp}`;
  if (footerWaSpn) footerWaSpn.textContent = `واتساب المعرض المباشر (${phone})`;

  // Footer Socials
  const footerInsta = document.getElementById("footerInstagramBtn");
  if (footerInsta && social.instagram) {
    footerInsta.href = social.instagram;
    footerInsta.style.display = "inline-flex";
  }
  const footerFb = document.getElementById("footerFacebookBtn");
  if (footerFb && social.facebook) {
    footerFb.href = social.facebook;
    footerFb.style.display = "inline-flex";
  }
  const footerTt = document.getElementById("footerTiktokBtn");
  if (footerTt) {
    if (social.tiktok && social.tiktok.trim()) {
      footerTt.href = social.tiktok;
      footerTt.style.display = "inline-flex";
    } else {
      footerTt.style.display = "none";
    }
  }
  const footerMapSocial = document.getElementById("footerMapSocialBtn");
  if (footerMapSocial) footerMapSocial.href = mapUrl;
  const footerWaSocial = document.getElementById("footerWhatsappSocialBtn");
  if (footerWaSocial) footerWaSocial.href = `https://wa.me/${whatsapp}`;

  // Footer Designer link
  const designerLink = document.getElementById("footerDesignerLink");
  if (designerLink && social.designerUrl) designerLink.href = social.designerUrl;
}

// 4. Render Product Cards Grid (With Luxury Pagination / Load More)
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
      item.name.toLowerCase().includes(q) || 
      item.enName.toLowerCase().includes(q) ||
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

  if (countBadge) {
    if (totalCount <= initialLimit) {
      countBadge.textContent = `${totalCount} وحدة إضاءة فاخرة`;
    } else {
      countBadge.textContent = `عرض ${visibleItems.length} من أصل ${totalCount} وحدة إضاءة`;
    }
  }

  const loadMoreContainer = document.getElementById("loadMoreContainer");
  const loadMoreRemaining = document.getElementById("loadMoreRemaining");

  if (loadMoreContainer) {
    if (totalCount > visibleItems.length) {
      loadMoreContainer.style.display = "flex";
      if (loadMoreRemaining) {
        const remaining = totalCount - visibleItems.length;
        loadMoreRemaining.textContent = `(${remaining} إضافية)`;
      }
    } else {
      loadMoreContainer.style.display = "none";
    }
  }

  if (filtered.length === 0) {
    if (loadMoreContainer) loadMoreContainer.style.display = "none";
    grid.innerHTML = `
      <div class="catalog-empty">
        <div class="catalog-empty-icon"><i class="fas fa-lightbulb"></i></div>
        <h3>لم يتم العثور على وحدات إضاءة مطابقة</h3>
        <p class="text-muted" style="margin-top: 0.5rem;">جرب البحث بكلمات أخرى أو اختر تصنيفاً آخر من القائمة أعلاه.</p>
        <button class="btn-primary" style="margin-top: 1.5rem;" onclick="resetFilters()">عرض كافة المجموعات</button>
      </div>
    `;
    return;
  }

  const isEn = isCurrentEn();
  const currencyStr = window.KK_I18N ? window.KK_I18N.t("currency") : "ج.م";

  grid.innerHTML = visibleItems.map(item => {
    const stock = item.stock !== undefined ? item.stock : 10;
    const isAvailable = stock > 0;
    const displayName = (isEn && item.enName) ? item.enName : item.name;
    const displayCategory = (isEn && item.enCategory) ? item.enCategory : item.categoryName;

    return `
    <article class="product-card ${!isAvailable ? 'is-out-of-stock' : ''}" data-id="${escapeHtml(item.id)}">
      <div class="product-media">
        <img class="product-img" src="${escapeHtml(item.image)}" alt="${escapeHtml(displayName)}" loading="lazy" onerror="this.src='https://images.unsplash.com/photo-1513506003901-1e6a229e2d15?auto=format&fit=crop&w=1200&q=80'">
        
        <div class="card-badges">
          ${item.isExclusive ? `<span class="badge-exclusive"><i class="fas fa-crown"></i> ${isEn ? 'Exclusive' : 'حصري في زايد'}</span>` : ''}
          ${item.isNew ? `<span class="badge-new">${isEn ? 'New 2026' : 'جديد 2026'}</span>` : ''}
          ${!isAvailable ? `<span class="badge-new" style="background: #EF4444;"><i class="fas fa-times-circle"></i> ${isEn ? 'Out of Stock' : 'غير متوفر'}</span>` : ''}
        </div>

        <div class="card-hover-actions">
          <button class="btn-card-quickview" onclick="openQuickView('${escapeHtml(item.id)}')">
            <i class="fas fa-expand"></i>
            <span>${isEn ? 'Specifications' : 'المواصفات الفنية'}</span>
          </button>
        </div>
      </div>

      <div class="product-body">
        <div class="product-category-row">
          <span class="product-cat-tag">${escapeHtml(displayCategory)}</span>
          <div class="product-rating">
            <i class="fas fa-star"></i>
            <span>${escapeHtml(item.rating || '5.0')}</span>
          </div>
        </div>

        <h3 class="product-name" onclick="openQuickView('${escapeHtml(item.id)}')">${escapeHtml(displayName)}</h3>
        <p class="product-en-name">${escapeHtml(isEn ? item.name : item.enName)}</p>

        <div class="product-specs-pills">
          ${item.specs?.cri ? `<span class="spec-pill">${escapeHtml(item.specs.cri)}</span>` : ''}
          ${item.specs?.colorTemp ? `<span class="spec-pill">${escapeHtml(item.specs.colorTemp.split(' ')[0])}</span>` : ''}
          ${item.style ? `<span class="spec-pill">${escapeHtml(item.style)}</span>` : ''}
        </div>

        <div class="product-footer">
          <div class="product-price-col">
            <div class="product-price-current">
              ${formatPrice(item.price)}
              <span class="product-currency">${currencyStr}</span>
            </div>
            ${item.originalPrice ? `<span class="product-price-old">${formatPrice(item.originalPrice)} ${currencyStr}</span>` : ''}
          </div>

          <button class="btn-card-quote" title="${isAvailable ? (isEn ? 'Add to Cart' : 'إضافة للسلة') : (isEn ? 'Out of Stock' : 'غير متوفر')}" ${!isAvailable ? 'disabled style="opacity: 0.5; cursor: not-allowed;"' : ''} onclick="addToCart('${escapeHtml(item.id)}', 1)">
            <i class="fas fa-plus"></i>
          </button>
        </div>
      </div>
    </article>
  `}).join("");
}

// 4.1 Load More Products Function (عرض المزيد من المنتجات)
function loadMoreProducts() {
  STATE.visibleCount = (STATE.visibleCount || 6) + 6;
  renderProducts();
}

// Reset filters helper
function resetFilters() {
  STATE.activeCategory = "all";
  STATE.searchQuery = "";
  STATE.visibleCount = 6;
  const searchInput = document.getElementById("searchInput");
  if (searchInput) searchInput.value = "";
  renderCategoryTabs();
  renderProducts();
}

// Format Currency
function formatPrice(num) {
  if (!num) return "0";
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// 5. Quick View Modal
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
  const stockEl = document.getElementById("modalStockStatusBadge");

  const isEn = isCurrentEn();
  const currencyStr = window.KK_I18N ? window.KK_I18N.t("currency") : "ج.م";
  const stock = item.stock !== undefined ? item.stock : 10;

  if (stockEl) {
    if (stock > 0) {
      stockEl.innerHTML = `<i class="fas fa-check-circle"></i> <span>${isEn ? 'In Stock (' + stock + ' units)' : 'متوفر بالمعرض (' + stock + ' قطعة)'}</span>`;
      stockEl.style.color = "#10B981";
      stockEl.style.background = "rgba(16, 185, 129, 0.1)";
    } else {
      stockEl.innerHTML = `<i class="fas fa-times-circle"></i> <span>${isEn ? 'Out of Stock' : 'غير متوفر حالياً'}</span>`;
      stockEl.style.color = "#EF4444";
      stockEl.style.background = "rgba(239, 68, 68, 0.1)";
    }
  }

  if (qtyEl) qtyEl.textContent = "1";

  if (modalImg) modalImg.src = item.image;
  if (catEl) catEl.textContent = (isEn && item.enCategory) ? item.enCategory : item.categoryName;
  if (titleEl) titleEl.textContent = (isEn && item.enName) ? item.enName : item.name;
  if (enTitleEl) enTitleEl.textContent = isEn ? item.name : item.enName;
  if (priceEl) priceEl.textContent = formatPrice(item.price);
  if (oldPriceEl) {
    oldPriceEl.textContent = item.originalPrice ? `${formatPrice(item.originalPrice)} ${currencyStr}` : "";
  }
  if (descEl) descEl.textContent = (isEn && item.enDescription) ? item.enDescription : item.description;

  // Thumbs
  if (thumbsContainer) {
    const images = [item.image];
    if (item.secondaryImage) images.push(item.secondaryImage);
    thumbsContainer.innerHTML = images.map((img, idx) => `
      <div class="modal-thumb ${idx === 0 ? 'active' : ''}" onclick="switchModalThumb('${img}', this)">
        <img src="${img}" alt="Thumbnail">
      </div>
    `).join("");
  }

  // Technical Specs Table
  if (specsTable) {
    const s = item.specs || {};
    specsTable.innerHTML = `
      ${s.dimensions ? `<tr><td>${isEn ? 'Dimensions' : 'الأبعاد والمقاسات'}</td><td>${escapeHtml(s.dimensions)}</td></tr>` : ''}
      ${s.material ? `<tr><td>${isEn ? 'Materials & Finish' : 'الخامات والتشطيب'}</td><td>${escapeHtml(s.material)}</td></tr>` : ''}
      ${s.colorTemp ? `<tr><td>${isEn ? 'Color Temperature' : 'درجة حرارة الضوء'}</td><td>${escapeHtml(s.colorTemp)}</td></tr>` : ''}
      ${s.wattage ? `<tr><td>${isEn ? 'Power Consumption' : 'الاستهلاك والقدرة'}</td><td>${escapeHtml(s.wattage)}</td></tr>` : ''}
      ${s.cri ? `<tr><td>${isEn ? 'CRI' : 'معامل وضوح الألوان'}</td><td>${escapeHtml(s.cri)}</td></tr>` : ''}
      ${s.voltage ? `<tr><td>${isEn ? 'Operating Voltage' : 'جهد التشغيل'}</td><td>${escapeHtml(s.voltage)}</td></tr>` : ''}
      ${s.warranty ? `<tr><td>${isEn ? 'Showroom Warranty' : 'الضمان المعتمد'}</td><td>${escapeHtml(s.warranty)}</td></tr>` : ''}
    `;
  }

  // PRD Section 2: Load Customer Reviews for this product
  if (typeof loadProductReviews === "function") {
    loadProductReviews(item.id);
  }
  if (typeof toggleReviewForm === "function") {
    toggleReviewForm(false);
  }

  modal.classList.add("active");
  document.body.style.overflow = "hidden";
}

function switchModalThumb(imgSrc, element) {
  const modalImg = document.getElementById("modalMainImg");
  if (modalImg) modalImg.src = imgSrc;
  document.querySelectorAll(".modal-thumb").forEach(t => t.classList.remove("active"));
  if (element) element.classList.add("active");
}

function closeQuickView() {
  const modal = document.getElementById("quickViewModal");
  if (modal) modal.classList.remove("active");
  document.body.style.overflow = "";
}

// 6. Cart / Quotation System
function addToCart(productId, qty = 1) {
  const product = STATE.products.find(p => p.id === productId);
  if (!product) return;

  // PRD Section 6: Prevent selling unavailable products & overselling
  const stock = product.stock !== undefined ? product.stock : 10;
  const isEn = isCurrentEn();

  if (stock <= 0) {
    showToast(isEn ? "Sorry, this lighting unit is currently out of stock." : "عفواً، هذه الوحدة غير متوفرة حالياً بالمعرض.");
    return;
  }

  const existingIndex = STATE.cart.findIndex(item => item.id === productId);
  const currentInCart = existingIndex > -1 ? STATE.cart[existingIndex].qty : 0;
  if (currentInCart + qty > stock) {
    showToast(isEn ? `Sorry, only ${stock} units are currently available.` : `عفواً، أقصى كمية متوفرة بالمعرض هي ${stock} وحدة.`);
    return;
  }

  if (existingIndex > -1) {
    STATE.cart[existingIndex].qty += qty;
  } else {
    STATE.cart.push({
      id: product.id,
      name: product.name,
      enName: product.enName,
      price: product.price,
      image: product.image,
      qty: qty,
      categoryName: product.categoryName
    });
  }

  saveCart();
  const displayName = (isEn && product.enName) ? product.enName : product.name;
  const successMsg = isEn 
    ? `Added "${displayName}" to your quotation cart.` 
    : `تمت إضافة "${displayName}" إلى سلة طلباتك بنجاح.`;
  showToast(successMsg);
}

function removeFromCart(productId) {
  STATE.cart = STATE.cart.filter(item => item.id !== productId);
  saveCart();
  showToast("تم حذف الوحدة من السلة.");
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
    cartList.innerHTML = "";
  } else {
    if (emptyState) emptyState.style.display = "none";
    if (footerEl) footerEl.style.display = "block";

    cartList.innerHTML = STATE.cart.map(item => `
      <div class="cart-item-row">
        <img class="cart-item-img" src="${item.image}" alt="${item.name}">
        <div class="cart-item-info">
          <div class="cart-item-name">${item.name}</div>
          <div class="cart-item-spec">${item.categoryName} • الكمية: ${item.qty}</div>
          <div class="cart-item-price-row">
            <div class="cart-item-price">${formatPrice(item.price * item.qty)} ج.م</div>
            <button class="cart-item-remove-btn" onclick="removeFromCart('${item.id}')" title="حذف">
              <i class="fas fa-trash-alt"></i>
            </button>
          </div>
        </div>
      </div>
    `).join("");
  }
}

function toggleCartDrawer(open) {
  const drawer = document.getElementById("cartDrawerBackdrop");
  if (!drawer) return;
  if (open) {
    drawer.classList.add("active");
    document.body.style.overflow = "hidden";
  } else {
    drawer.classList.remove("active");
    document.body.style.overflow = "";
  }
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
      // Save order on customer device for tracking
      if (typeof window.saveCustomerRecentOrder === "function") {
        window.saveCustomerRecentOrder(newOrder.id, savedPhone);
      }

      // Clear cart
      STATE.cart = [];
      if (typeof saveCart === "function") saveCart();
      if (typeof toggleCartDrawer === "function") toggleCartDrawer(false);

      // Open WhatsApp with complete order message & code
      if (typeof window.sendOrderViaWhatsApp === "function") {
        window.sendOrderViaWhatsApp(newOrder);
      } else {
        const phone = SHOWROOM_INFO.whatsapp || "201006367690";
        const msg = `*طلب جديد من معرض قاصد كريم للإضاءة الفاخرة* 💎\nكود الطلب المعتمد: #${newOrder.id}\nإجمالي الطلب: ${formatPrice(newOrder.total)} ج.م`;
        window.open(`https://wa.me/${phone}?text=${encodeURIComponent(msg)}`, "_blank");
      }

      // Open Success modal so they see their code and can track it
      if (typeof window.openOrderSuccessModal === "function") {
        window.openOrderSuccessModal(newOrder);
      }

      showToast(`✅ تم حجز الطلب برقم #${newOrder.id} وتجهيز محادثة الواتساب`);
    } else {
      // Direct fallback if offline
      const localId = "ORD-" + Math.floor(1000 + Math.random() * 9000);
      const totalAmount = STATE.cart.reduce((sum, item) => sum + (item.price * item.qty), 0);
      let msg = `*طلب وحدات إضاءة فاخرة - معرض Kased Karim (الشيخ زايد)*\n`;
      msg += `🏷️ *كود الطلب المبدئي:* #${localId}\n`;
      msg += `----------------------------------------\n`;
      STATE.cart.forEach((item, index) => {
        msg += `${index + 1}. *${item.name}* (كمية: ${item.qty}) - ${formatPrice(item.price * item.qty)} ج.م\n`;
      });
      msg += `----------------------------------------\n`;
      msg += `*إجمالي الطلب:* ${formatPrice(totalAmount)} جنيه مصري\n`;
      const phone = SHOWROOM_INFO.whatsapp || "201006367690";
      window.open(`https://wa.me/${phone}?text=${encodeURIComponent(msg)}`, "_blank");
    }
  } catch (err) {
    showToast(`⚠️ خطأ أثناء تجهيز الطلب: ${err.message}`);
  }
}

// 8. Add Product Assistant Modal (لوحة تسهيل إضافة وحدات جديدة)
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

  const newUnit = {
    id: "kk-" + Date.now().toString().slice(-4),
    name: form.unitName.value.trim(),
    enName: form.unitEnName.value.trim(),
    category: form.unitCategory.value,
    categoryName: CATEGORIES.find(c => c.id === form.unitCategory.value)?.name || "إضاءة فاخرة",
    style: form.unitStyle.value.trim() || "معاصر",
    price: parseFloat(form.unitPrice.value) || 0,
    originalPrice: form.unitOldPrice.value ? parseFloat(form.unitOldPrice.value) : null,
    isExclusive: form.isExclusive.checked,
    isNew: true,
    rating: 5.0,
    reviewsCount: 1,
    image: form.unitImage.value.trim() || "https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=1200&q=80",
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

  // Prepend new product
  STATE.products.unshift(newUnit);
  saveCustomProducts();
  renderCategoryTabs();
  renderProducts();

  // Show JSON snippet in the helper box for permanent copy
  const jsonBox = document.getElementById("productJsonSnippet");
  if (jsonBox) {
    jsonBox.textContent = JSON.stringify(newUnit, null, 2);
  }

  showToast(`تمت إضافة "${newUnit.name}" بنجاح إلى المعرض!`);
  form.reset();
}

// 9. Toast Notification Helper
function showToast(message) {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `
    <i class="fas fa-check-circle toast-icon"></i>
    <span>${message}</span>
  `;

  container.appendChild(toast);
  requestAnimationFrame(() => {
    toast.classList.add("show");
  });

  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 400);
  }, 3500);
}

// 11. Header Scroll Shadow
function handleHeaderScroll() {
  const header = document.querySelector(".site-header");
  window.addEventListener("scroll", () => {
    if (window.scrollY > 40) {
      header?.classList.add("scrolled");
    } else {
      header?.classList.remove("scrolled");
    }
  });
}

// Setup Event Listeners
function setupEventListeners() {
  // Search Input
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
      window.open(url, "_blank");
    });
  }

  // Add Product Form Submit
  const addProductForm = document.getElementById("addProductForm");
  if (addProductForm) {
    addProductForm.addEventListener("submit", handleAddProductSubmit);
  }

  // Mobile Menu Toggle
  const mobileToggle = document.getElementById("mobileMenuToggle");
  const mobileDrawer = document.getElementById("mobileNavDrawer");
  if (mobileToggle && mobileDrawer) {
    mobileToggle.addEventListener("click", () => {
      mobileDrawer.classList.toggle("active");
    });
  }

  // Real-time Cloud Sync Listener for Products
  window.addEventListener("kk_products_updated", () => {
    loadProducts();
    renderCategoryTabs();
    renderProducts();
  });

  // Real-time Cloud Sync Listener for Categories
  window.addEventListener("kk_categories_updated", () => {
    renderCategoryTabs();
    renderSubBarCategories();
    renderMobileAccordionCategories();
    renderFooterCategories();
    renderProducts();
  });

  // Real-time Cloud Sync Listener for Settings & Contacts
  window.addEventListener("kk_settings_updated", () => {
    applyDynamicSettings();
  });

  // Real-time Listeners for Orders & Persistent Admin Header Icon
  window.addEventListener("kk_orders_updated", () => {
    checkAndDisplayAdminHeaderIcon();
  });

  window.addEventListener("kk_new_order_placed", () => {
    checkAndDisplayAdminHeaderIcon();
  });

  // Real-time Language Change Listener (PRD Section 7)
  window.addEventListener("kk_language_changed", () => {
    renderCategoryTabs();
    renderSubBarCategories();
    renderProducts();
    if (typeof updateCustomerButtonUI === "function") updateCustomerButtonUI();
    if (window.KK_I18N) window.KK_I18N.applyLanguageToDOM();
  });

  // Customer Authentication Change Listener (PRD Section 3)
  window.addEventListener("kk_customer_auth_changed", () => {
    if (typeof updateCustomerButtonUI === "function") updateCustomerButtonUI();
  });

  // Secret Admin Device Link: 5 clicks on logo activates executive shield button
  let logoClickCount = 0;
  let logoTimer = null;
  document.querySelectorAll(".brand-link, .top-bar-brand, .brand-title-en").forEach(logo => {
    logo.addEventListener("click", () => {
      logoClickCount++;
      clearTimeout(logoTimer);
      logoTimer = setTimeout(() => { logoClickCount = 0; }, 2500);
      if (logoClickCount >= 5) {
        logoClickCount = 0;
        localStorage.setItem("kk_admin_authorized", "true");
        checkAndDisplayAdminHeaderIcon();
        if (typeof showToast === "function") {
          showToast("🛡️ تم إظهار وتثبيت أيقونة الإدارة التنفيذية في الهيدر بنجاح ✓");
        }
      }
    });
  });
}

// ----------------------------------------------------------------------------
// PERSISTENT EXECUTIVE ADMIN HEADER BUTTON CONTROLLER
// ----------------------------------------------------------------------------
function checkAndDisplayAdminHeaderIcon() {
  const adminBtn = document.getElementById("adminHeaderBtn");
  const adminBadge = document.getElementById("adminHeaderBadge");

  const token = localStorage.getItem("kk_admin_token") || sessionStorage.getItem("kk_admin_token");
  const isAuth = !!token || 
                 localStorage.getItem("kk_admin_authorized") === "true" ||
                 localStorage.getItem("kk_admin_device_linked") === "true";

  if (isAuth) {
    document.documentElement.classList.add("is-admin-device");
    if (document.body) document.body.classList.add("is-admin-device", "is-admin-user");

    if (adminBtn) {
      adminBtn.style.setProperty("display", "inline-flex", "important");
    }

    const unreadCount = window.KK_DB && typeof window.KK_DB.getUnreadOrdersCount === "function"
      ? window.KK_DB.getUnreadOrdersCount()
      : 0;

    if (adminBadge) {
      adminBadge.textContent = unreadCount;
      adminBadge.style.display = unreadCount > 0 ? "flex" : "none";
    }

    if (adminBtn) {
      if (unreadCount > 0) {
        adminBtn.classList.add("has-new-orders");
      } else {
        adminBtn.classList.remove("has-new-orders");
      }
    }
  } else {
    document.documentElement.classList.remove("is-admin-device");
    if (document.body) document.body.classList.remove("is-admin-device", "is-admin-user");
    if (adminBtn) {
      adminBtn.style.setProperty("display", "none", "important");
      adminBtn.classList.remove("has-new-orders");
    }
  }
}

// Immediate execution if script loads when DOM is already populated
if (document.readyState === "interactive" || document.readyState === "complete") {
  checkAndDisplayAdminHeaderIcon();
}

// ----------------------------------------------------------------------------
// 11b. CATEGORY TABS HORIZONTAL SCROLL & ARROW CONTROLLERS
// ----------------------------------------------------------------------------
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
    // In RTL:
    // If negative scroll (Chrome/Firefox/Edge on Windows):
    // 0 is rightmost (start of categories: الكل المعروض، أباجورات...)
    // -maxScroll is leftmost (end of categories: بانلات، كشافات، أعواد البروفايل، درج سلم)
    if (sl < 0) {
      const atRight = Math.abs(sl) < 10;
      const atLeft = Math.abs(Math.abs(sl) - maxScroll) < 15;
      if (prevBtn) prevBtn.classList.toggle("disabled", atRight);
      if (nextBtn) nextBtn.classList.toggle("disabled", atLeft);
    } else {
      // Positive scroll modes
      if (prevBtn) prevBtn.classList.toggle("disabled", sl <= 10);
      if (nextBtn) nextBtn.classList.toggle("disabled", sl >= maxScroll - 15);
    }
  };

  // Click Next (reveals the rest of categories to the left: بانلات، كشافات، أعواد البروفايل، درج سلم)
  if (nextBtn) {
    nextBtn.addEventListener("click", () => {
      const step = 340;
      const prevVal = container.scrollLeft;
      container.scrollBy({ left: -step, behavior: "smooth" });
      setTimeout(() => {
        if (container.scrollLeft === prevVal) {
          container.scrollBy({ left: step, behavior: "smooth" });
        }
        updateCategoryScrollButtons();
      }, 60);
    });
  }

  // Click Prev (returns to categories on the right: الكل المعروض، أباجورات...)
  if (prevBtn) {
    prevBtn.addEventListener("click", () => {
      const step = 340;
      const prevVal = container.scrollLeft;
      container.scrollBy({ left: step, behavior: "smooth" });
      setTimeout(() => {
        if (container.scrollLeft === prevVal) {
          container.scrollBy({ left: -step, behavior: "smooth" });
        }
        updateCategoryScrollButtons();
      }, 60);
    });
  }

  // Mouse wheel listener: roll wheel up/down to scroll categories left/right
  container.addEventListener("wheel", (e) => {
    if (Math.abs(e.deltaX) < Math.abs(e.deltaY)) {
      e.preventDefault();
      container.scrollLeft += (e.deltaY > 0 ? 90 : -90);
      updateCategoryScrollButtons();
    }
  }, { passive: false });

  // Mouse drag support
  let isDown = false;
  let startX = 0;
  let scrollPos = 0;

  container.addEventListener("mousedown", (e) => {
    if (e.target.closest("button")) return;
    isDown = true;
    container.classList.add("dragging");
    startX = e.pageX - container.offsetLeft;
    scrollPos = container.scrollLeft;
  });

  window.addEventListener("mouseup", () => {
    isDown = false;
    container.classList.remove("dragging");
  });

  container.addEventListener("mousemove", (e) => {
    if (!isDown) return;
    e.preventDefault();
    const x = e.pageX - container.offsetLeft;
    const walk = (x - startX) * 1.5;
    container.scrollLeft = scrollPos - walk;
    updateCategoryScrollButtons();
  });

  container.addEventListener("scroll", () => {
    if (updateCategoryScrollButtons) updateCategoryScrollButtons();
  }, { passive: true });

  window.addEventListener("resize", () => {
    if (updateCategoryScrollButtons) updateCategoryScrollButtons();
  }, { passive: true });

  setTimeout(updateCategoryScrollButtons, 200);
}

// ----------------------------------------------------------------------------
// 12. LIGHTING COLLECTIONS SUB-BAR & MOBILE ACCORDION CONTROLLERS
// ----------------------------------------------------------------------------
function toggleCollectionsSubBar(explicitState) {
  if (explicitState && explicitState.preventDefault) {
    explicitState.preventDefault();
    explicitState.stopPropagation();
  }

  const subBar = document.getElementById("siteSubBar");
  const arrow = document.getElementById("navSubArrow");
  if (!subBar) return;

  const willOpen = explicitState !== undefined && typeof explicitState === "boolean" 
    ? explicitState 
    : !subBar.classList.contains("active");

  if (willOpen) {
    subBar.classList.add("active");
    if (arrow) arrow.classList.add("open");
    updateSubBarActiveCategory();
  } else {
    subBar.classList.remove("active");
    if (arrow) arrow.classList.remove("open");
  }
}

function selectCategoryFromSubBar(catId) {
  STATE.activeCategory = catId;
  STATE.visibleCount = 6;
  renderCategoryTabs();
  renderProducts();
  updateSubBarActiveCategory();

  // Bring active category tab into view
  const activeTabBtn = document.querySelector(`.category-tab-btn[data-category="${catId}"]`);
  if (activeTabBtn) {
    activeTabBtn.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
  }
  
  // Smooth scroll to catalog
  const catalog = document.getElementById("catalog");
  if (catalog) {
    catalog.scrollIntoView({ behavior: "smooth" });
  }
}

function updateSubBarActiveCategory() {
  document.querySelectorAll(".sub-bar-cat-btn").forEach(btn => {
    btn.classList.remove("active");
  });
  const matchingBtn = document.querySelector(`.sub-bar-cat-btn[onclick*="'${STATE.activeCategory}'"]`);
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

  // Bring active category tab into view
  const activeTabBtn = document.querySelector(`.category-tab-btn[data-category="${catId}"]`);
  if (activeTabBtn) {
    activeTabBtn.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
  }

  // Close mobile drawer
  const drawer = document.getElementById("mobileNavDrawer");
  if (drawer) drawer.classList.remove("active");

  // Smooth scroll to catalog
  const catalog = document.getElementById("catalog");
  if (catalog) {
    catalog.scrollIntoView({ behavior: "smooth" });
  }
}

// ============================================================================
// 13. LUXURY LIGHTING CEREMONY CONTROLLER (إشعال النور والظهور السينمائي الفاخر)
// ============================================================================
let lightingCeremonyTimer = null;

function initLightingCeremony() {
  const overlay = document.getElementById("lightingCeremonyOverlay");
  if (overlay) {
    overlay.style.display = "none";
    overlay.classList.add("ignited");
  }
  document.body.classList.remove("ceremony-in-progress");
  document.body.classList.add("ceremony-illuminated");
}

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

// ============================================================================
// CUSTOMER AUTHENTICATION & PROFILE PORTAL (PRD Sections 3 & 4)
// ============================================================================
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
  window.pendingAuthCallback = onSuccessCallback || null;
  const modal = document.getElementById("customerAuthModal");
  if (modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
    switchCustomerAuthTab("signin");
  }
}
window.openCustomerAuthModal = openCustomerAuthModal;

function closeCustomerAuthModal() {
  const modal = document.getElementById("customerAuthModal");
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
}
window.closeCustomerAuthModal = closeCustomerAuthModal;

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
  }
}
window.switchCustomerAuthTab = switchCustomerAuthTab;

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

  const origHtml = submitBtn ? submitBtn.innerHTML : "";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> <span>جارٍ تسجيل الدخول...</span>`;
  }

  try {
    const res = await window.KK_DB.customerLogin(identifier, password);
    showToast(`مرحباً بك مجدداً يا ${res.customer.name}!`);
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
      submitBtn.disabled = false;
      submitBtn.innerHTML = origHtml;
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
    showToast("يرجى ملء جميع الحقول المطلوبة");
    return;
  }

  const origHtml = submitBtn ? submitBtn.innerHTML : "";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> <span>جارٍ إنشاء الحساب...</span>`;
  }

  try {
    const res = await window.KK_DB.customerRegister(name, phone, password, email);
    showToast(`أهلاً بك يا ${res.customer.name}! تم إنشاء حسابك بنجاح.`);
    closeCustomerAuthModal();
    updateCustomerButtonUI();

    if (window.pendingAuthCallback) {
      const cb = window.pendingAuthCallback;
      window.pendingAuthCallback = null;
      cb();
    }
  } catch (err) {
    showToast(`❌ ${err.message || "تعذر إنشاء الحساب"}`);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = origHtml;
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
    detailsEl.innerHTML = `
      <div style="display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
        <span style="font-weight: 800; color: var(--text-main); font-size: 1.05rem;">${escapeHtml(customer.name)}</span>
        <span style="color: var(--text-muted); font-size: 0.82rem;">• ${escapeHtml(customer.phone)}</span>
        ${customer.email ? `<span style="color: var(--text-muted); font-size: 0.82rem;">• ${escapeHtml(customer.email)}</span>` : ''}
      </div>
    `;
  }

  if (modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
  }

  if (listEl) {
    listEl.innerHTML = `
      <div style="text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.88rem;">
        <i class="fas fa-spinner fa-spin" style="margin-left: 0.5rem;"></i> جاري تحميل سجل طلباتك...
      </div>
    `;
    try {
      const orders = await window.KK_DB.getCustomerOrders();
      if (!orders || orders.length === 0) {
        listEl.innerHTML = `
          <div style="text-align: center; padding: 2.5rem 1rem; color: var(--text-muted); font-size: 0.88rem;">
            <i class="fas fa-receipt" style="font-size: 2.2rem; color: #CBD5E1; display: block; margin-bottom: 0.75rem;"></i>
            لم تسجل أي طلبات حتى الآن. استكشف المعرض وأضف وحدات الإضاءة إلى سلتك!
          </div>
        `;
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

        listEl.innerHTML = orders.map(ord => {
          const st = statusMap[ord.status] || { text: ord.status, color: "#6B7280", bg: "#F3F4F6" };
          const items = Array.isArray(ord.items) ? ord.items : Object.values(ord.items || {});
          const codNotice = ord.paymentStatus === "collected"
            ? `<span style="font-size: 0.72rem; color: #10B981; font-weight: 700;"><i class="fas fa-check-circle"></i> تم سداد النقدية</span>`
            : `<span style="font-size: 0.72rem; color: #F59E0B; font-weight: 700;"><i class="fas fa-hand-holding-dollar"></i> الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد</span>`;

          return `
            <div style="background: #FFFFFF; border: 1px solid var(--border-light); border-radius: var(--radius-sm); padding: 0.85rem 1rem; margin-bottom: 0.75rem; box-shadow: 0 1px 3px rgba(0,0,0,0.04);">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.45rem;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                  <span style="font-weight: 800; font-family: monospace; font-size: 0.88rem; color: var(--text-main);">#${escapeHtml(ord.id)}</span>
                  <span style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(ord.dateFormatted || '')}</span>
                </div>
                <span style="font-size: 0.72rem; font-weight: 800; padding: 2px 8px; border-radius: 4px; color: ${st.color}; background: ${st.bg};">
                  ${st.text}
                </span>
              </div>
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.45rem;">
                ${items.map(it => `${escapeHtml(it.name || 'وحدة')} × ${it.qty || 1}`).join(" • ")}
              </div>
              <div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px dashed var(--border-light); padding-top: 0.45rem;">
                <div>${codNotice}</div>
                <div style="font-weight: 800; color: var(--accent); font-size: 0.92rem;">
                  ${formatPrice(ord.total || 0)} ج.م
                </div>
              </div>
            </div>
          `;
        }).join("");
      }
    } catch (e) {
      listEl.innerHTML = `<div style="text-align: center; padding: 2rem; color: #EF4444; font-size: 0.85rem;">تعذر تحميل سجل الطلبات</div>`;
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

function updateCustomerButtonUI() {
  const customer = window.KK_DB && typeof window.KK_DB.getCustomer === "function" 
    ? window.KK_DB.getCustomer() 
    : null;
  const isEn = isCurrentEn();
  const btn = document.getElementById("customerAccountBtn");
  if (!btn) return;

  if (customer) {
    const firstName = customer.name ? customer.name.split(" ")[0] : (isEn ? "Account" : "حسابي");
    btn.innerHTML = `<i class="fas fa-user-check" style="color: #10B981;"></i> <span style="font-size: 0.82rem; font-weight: 700;">${escapeHtml(firstName)}</span>`;
    btn.setAttribute("title", customer.name);
  } else {
    btn.innerHTML = `<i class="fas fa-user"></i> <span style="font-size: 0.82rem; font-weight: 700;" data-i18n="navAccount">${isEn ? "Sign In" : "حسابي"}</span>`;
    btn.setAttribute("title", isEn ? "Sign in / Register" : "تسجيل الدخول / إنشاء حساب");
  }
}
window.updateCustomerButtonUI = updateCustomerButtonUI;

// ============================================================================
// PRODUCT REVIEWS & MODERATION (PRD Sections 2 & 3)
// ============================================================================
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

  container.innerHTML = `
    <div style="text-align: center; padding: 1.25rem; color: var(--text-muted); font-size: 0.8rem;">
      <i class="fas fa-spinner fa-spin" style="margin-left: 0.35rem;"></i> جاري تحميل تقييمات العملاء...
    </div>
  `;

  try {
    const reviews = (window.KK_DB && typeof window.KK_DB.getProductReviews === "function")
      ? await window.KK_DB.getProductReviews(productId)
      : [];

    if (!reviews || reviews.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 1.5rem 0.5rem; color: var(--text-muted); font-size: 0.82rem; background: #F8FAFC; border-radius: 4px; border: 1px dashed var(--border-light);">
          <i class="far fa-star" style="font-size: 1.5rem; color: #CBD5E1; display: block; margin-bottom: 0.35rem;"></i>
          لا توجد تقييمات معتمدة لهذه الوحدة حتى الآن. كن أول من يشاركنا رأيه!
        </div>
      `;
      return;
    }

    container.innerHTML = reviews.map(rev => {
      const stars = "★".repeat(rev.rating || 5) + "☆".repeat(Math.max(0, 5 - (rev.rating || 5)));
      return `
        <div style="padding: 0.75rem 0; border-bottom: 1px solid var(--border-light); font-size: 0.82rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
            <div style="font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 0.35rem;">
              <i class="fas fa-circle-user" style="color: var(--accent);"></i>
              ${escapeHtml(rev.author || 'عميل معتمد')}
            </div>
            <div style="color: #F59E0B; font-size: 0.85rem; letter-spacing: 1px;">
              ${stars}
            </div>
          </div>
          <p style="margin: 0; color: #475569; font-size: 0.8rem; line-height: 1.45;">
            ${escapeHtml(rev.comment || '')}
          </p>
          <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.25rem;">
            ${escapeHtml(rev.dateFormatted || 'مراجعة معتمدة')}
          </div>
        </div>
      `;
    }).join("");
  } catch (err) {
    container.innerHTML = `<div style="text-align: center; padding: 1rem; color: #EF4444; font-size: 0.8rem;">تعذر تحميل التقييمات</div>`;
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

  const origHtml = submitBtn ? submitBtn.innerHTML : "";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> <span>جارٍ الإرسال...</span>`;
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
      submitBtn.disabled = false;
      submitBtn.innerHTML = origHtml;
    }
  }
}
window.handleReviewSubmit = handleReviewSubmit;

// Global invocation on ready
document.addEventListener("DOMContentLoaded", initApp);
