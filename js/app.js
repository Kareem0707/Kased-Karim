/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Main E-Commerce & Interactive Application Logic
 */

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

// Storage Keys
const STORAGE_KEYS = {
  PRODUCTS: "kased_karim_custom_products",
  CART: "kased_karim_quotation_cart"
};

// Initialize Application
function initApp() {
  initLightingCeremony();
  loadProducts();
  loadCart();
  renderCategoryTabs();
  renderProducts();
  setupEventListeners();
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
  }
}

function saveCart() {
  localStorage.setItem(STORAGE_KEYS.CART, JSON.stringify(STATE.cart));
  updateCartUI();
}

// 3. Render Category Tabs with Dynamic Item Counts
function renderCategoryTabs() {
  const tabsContainer = document.getElementById("categoryTabs");
  if (!tabsContainer) return;

  tabsContainer.innerHTML = CATEGORIES.map(cat => {
    const count = cat.id === "all" 
      ? STATE.products.length 
      : STATE.products.filter(p => p.category === cat.id).length;
    
    const isActive = STATE.activeCategory === cat.id ? "active" : "";

    return `
      <button class="category-tab-btn ${isActive}" data-category="${cat.id}">
        <span>${cat.name}</span>
        <span class="tab-count">${count}</span>
      </button>
    `;
  }).join("");

  // Attach tab events
  tabsContainer.querySelectorAll(".category-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      STATE.activeCategory = btn.dataset.category;
      STATE.visibleCount = 6;
      renderCategoryTabs();
      renderProducts();
    });
  });
}

// 4. Render Product Cards Grid (With Luxury Pagination / Load More)
function renderProducts() {
  const grid = document.getElementById("productsGrid");
  const countBadge = document.getElementById("catalogResultsCount");
  if (!grid) return;

  // Filter products
  let filtered = STATE.products.filter(item => {
    const matchesCat = STATE.activeCategory === "all" || item.category === STATE.activeCategory;
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

  grid.innerHTML = visibleItems.map(item => `
    <article class="product-card" data-id="${item.id}">
      <div class="product-media">
        <img class="product-img" src="${item.image}" alt="${item.name}" loading="lazy" onerror="this.src='https://images.unsplash.com/photo-1513506003901-1e6a229e2d15?auto=format&fit=crop&w=1200&q=80'">
        
        <div class="card-badges">
          ${item.isExclusive ? '<span class="badge-exclusive"><i class="fas fa-crown"></i> حصري في زايد</span>' : ''}
          ${item.isNew ? '<span class="badge-new">جديد 2026</span>' : ''}
        </div>

        <div class="card-hover-actions">
          <button class="btn-card-quickview" onclick="openQuickView('${item.id}')">
            <i class="fas fa-expand"></i>
            <span>المواصفات الفنية</span>
          </button>
        </div>
      </div>

      <div class="product-body">
        <div class="product-category-row">
          <span class="product-cat-tag">${item.categoryName}</span>
          <div class="product-rating">
            <i class="fas fa-star"></i>
            <span>${item.rating || '5.0'}</span>
          </div>
        </div>

        <h3 class="product-name" onclick="openQuickView('${item.id}')">${item.name}</h3>
        <p class="product-en-name">${item.enName}</p>

        <div class="product-specs-pills">
          ${item.specs?.cri ? `<span class="spec-pill">${item.specs.cri}</span>` : ''}
          ${item.specs?.colorTemp ? `<span class="spec-pill">${item.specs.colorTemp.split(' ')[0]}</span>` : ''}
          ${item.style ? `<span class="spec-pill">${item.style}</span>` : ''}
        </div>

        <div class="product-footer">
          <div class="product-price-col">
            <div class="product-price-current">
              ${formatPrice(item.price)}
              <span class="product-currency">ج.م</span>
            </div>
            ${item.originalPrice ? `<span class="product-price-old">${formatPrice(item.originalPrice)} ج.م</span>` : ''}
          </div>

          <button class="btn-card-quote" title="إضافة لقائمة المقايسة" onclick="addToCart('${item.id}', 1)">
            <i class="fas fa-plus"></i>
          </button>
        </div>
      </div>
    </article>
  `).join("");
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

  if (qtyEl) qtyEl.textContent = "1";

  if (modalImg) modalImg.src = item.image;
  if (catEl) catEl.textContent = item.categoryName;
  if (titleEl) titleEl.textContent = item.name;
  if (enTitleEl) enTitleEl.textContent = item.enName;
  if (priceEl) priceEl.textContent = formatPrice(item.price);
  if (oldPriceEl) {
    oldPriceEl.textContent = item.originalPrice ? `${formatPrice(item.originalPrice)} ج.م` : "";
  }
  if (descEl) descEl.textContent = item.description;

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
      ${s.dimensions ? `<tr><td>الأبعاد والمقاسات</td><td>${s.dimensions}</td></tr>` : ''}
      ${s.material ? `<tr><td>الخامات والتشطيب</td><td>${s.material}</td></tr>` : ''}
      ${s.colorTemp ? `<tr><td>درجة حرارة الضوء</td><td>${s.colorTemp}</td></tr>` : ''}
      ${s.wattage ? `<tr><td>الاستهلاك والقدرة</td><td>${s.wattage}</td></tr>` : ''}
      ${s.cri ? `<tr><td>معامل وضوح الألوان</td><td>${s.cri}</td></tr>` : ''}
      ${s.voltage ? `<tr><td>جهد التشغيل</td><td>${s.voltage}</td></tr>` : ''}
      ${s.warranty ? `<tr><td>الضمان المعتمد</td><td>${s.warranty}</td></tr>` : ''}
    `;
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

  const existingIndex = STATE.cart.findIndex(item => item.id === productId);
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
  showToast(`تمت إضافة "${product.name}" إلى قائمة المقايسة بنجاح.`);
}

function removeFromCart(productId) {
  STATE.cart = STATE.cart.filter(item => item.id !== productId);
  saveCart();
  showToast("تم حذف الوحدة من المقايسة.");
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

// 7. Send Quotation via WhatsApp directly to Showroom
function sendWhatsAppQuotation() {
  if (STATE.cart.length === 0) {
    showToast("يرجى اختيار وحدات إضاءة أولاً لطلب المقايسة");
    return;
  }

  const totalAmount = STATE.cart.reduce((sum, item) => sum + (item.price * item.qty), 0);
  
  let msg = `*طلب مقايسة إضاءة فاخرة - معرض Kased Karim (الشيخ زايد)*\n`;
  msg += `----------------------------------------\n`;
  msg += `مرحباً مهندس قاصد كريم، أود الاستفسار وحجز مقايسة للوحدات التالية لمشروعي بالشيخ زايد:\n\n`;

  STATE.cart.forEach((item, index) => {
    msg += `${index + 1}. *${item.name}* (${item.enName})\n`;
    msg += `   • الكود: ${item.id}\n`;
    msg += `   • الكمية: ${item.qty}\n`;
    msg += `   • السعر: ${formatPrice(item.price * item.qty)} ج.م\n\n`;
  });

  msg += `----------------------------------------\n`;
  msg += `*إجمالي المقايسة التقديري:* ${formatPrice(totalAmount)} جنيه مصري\n`;
  msg += `يرجى تحديد موعد لمعاينة الوحدات بالمعرض أو إرسال المخطط الهندسي.`;

  const phone = SHOWROOM_INFO.whatsapp || "201006367690";
  const url = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;
  window.open(url, "_blank");
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
      const msg = `مرحباً، أستفسر عن وحدة الإضاءة: ${p.name} (${p.enName}) - كود: ${p.id} بسعر ${formatPrice(p.price)} ج.م من معرض Kased Karim بالشيخ زايد. هل هي متاحة للعرض في المعرض؟`;
      const url = `https://wa.me/${SHOWROOM_INFO.whatsapp}?text=${encodeURIComponent(msg)}`;
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
  renderCategoryTabs();
  renderProducts();

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
  const flash = document.getElementById("lightingFlashBurst");
  if (!overlay) return;

  // Ensure body is in initial ceremony state
  document.body.classList.add("ceremony-in-progress");
  document.body.classList.remove("ceremony-illuminated");
  overlay.classList.remove("ignited");
  if (flash) flash.classList.remove("flash-active");

  // Allow immediate skip by clicking anywhere
  overlay.onclick = () => {
    igniteLightingCeremony();
  };

  // Brief suspenseful darkness (320ms) then sudden illumination
  if (lightingCeremonyTimer) clearTimeout(lightingCeremonyTimer);
  lightingCeremonyTimer = setTimeout(() => {
    igniteLightingCeremony();
  }, 320);

  function igniteLightingCeremony() {
    if (lightingCeremonyTimer) clearTimeout(lightingCeremonyTimer);
    if (overlay.classList.contains("ignited")) return;

    // 1. Fire luminous flash blast
    if (flash) {
      flash.classList.remove("flash-active");
      void flash.offsetWidth; // Force CSS reflow
      flash.classList.add("flash-active");
    }

    // 2. Dissolve the dark overlay
    overlay.classList.add("ignited");

    // 3. Illuminate palace, chandelier, and trigger staggered text reveals
    document.body.classList.remove("ceremony-in-progress");
    document.body.classList.add("ceremony-illuminated");

    // 4. Clean up overlay from view once animation finishes
    setTimeout(() => {
      overlay.style.display = "none";
    }, 950);
  }
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

// Global invocation on ready
document.addEventListener("DOMContentLoaded", initApp);
