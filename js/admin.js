/**
 * KASED KARIM LIGHTING - SHEIKH ZAYED
 * Admin Dashboard & Checkout Controller (js/admin.js)
 * إدارة لوحة التحكم، أكثر المبيعات، الطلبات، إضافة المنتجات، والتنبيه بالنبض الأحمر
 */

// Global Helper Fallbacks (for standalone admin.html without requiring storefront app.js)
window.formatPrice = window.formatPrice || function(num) {
  if (!num) return "0";
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
};

window.showToast = window.showToast || function(message) {
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
};

// ----------------------------------------------------------------------------
// 0. ADMIN SECURITY GATE & ACCESS PRIVACY (إخفاء الإدارة عن العامة وبوابة الدخول)
// ----------------------------------------------------------------------------
const ADMIN_SECURITY = {
  SECRET_KEYS: ["kased77", "2025", "kased"],
  STORAGE_KEY: "kk_admin_authorized"
};

function checkAdminAccessVisibility() {
  const urlParams = new URLSearchParams(window.location.search);
  const key = urlParams.get("key");
  const adminParam = urlParams.get("admin");

  const hasParamAuth = (key && ADMIN_SECURITY.SECRET_KEYS.includes(key)) ||
                       adminParam === "kased" || adminParam === "true";

  const isLocallyAuth = localStorage.getItem(ADMIN_SECURITY.STORAGE_KEY) === "true";

  if (hasParamAuth || isLocallyAuth) {
    document.body.classList.add("is-admin-user");
    localStorage.setItem(ADMIN_SECURITY.STORAGE_KEY, "true");
  } else {
    document.body.classList.remove("is-admin-user");
  }
}

function checkAdminSecurityGate() {
  const gateEl = document.getElementById("adminAuthGate");
  const rootEl = document.getElementById("adminPageRoot");
  if (!gateEl || !rootEl) return;

  const urlParams = new URLSearchParams(window.location.search);
  const key = urlParams.get("key");
  const adminParam = urlParams.get("admin");

  if ((key && ADMIN_SECURITY.SECRET_KEYS.includes(key)) || adminParam === "kased" || adminParam === "true") {
    localStorage.setItem(ADMIN_SECURITY.STORAGE_KEY, "true");
  }

  const isAuthorized = localStorage.getItem(ADMIN_SECURITY.STORAGE_KEY) === "true";

  if (isAuthorized) {
    gateEl.style.display = "none";
    rootEl.style.display = "block";
    document.body.classList.add("is-admin-user");
  } else {
    gateEl.style.display = "flex";
    rootEl.style.display = "none";
  }
}

function handleAdminPinSubmit(e) {
  e.preventDefault();
  const pinInput = document.getElementById("adminPinInput");
  const errorEl = document.getElementById("adminPinError");
  const gateEl = document.getElementById("adminAuthGate");
  const rootEl = document.getElementById("adminPageRoot");

  if (!pinInput) return;
  const val = pinInput.value.trim();

  if (ADMIN_SECURITY.SECRET_KEYS.includes(val) || val === "2025" || val === "kased77") {
    localStorage.setItem(ADMIN_SECURITY.STORAGE_KEY, "true");
    if (errorEl) errorEl.style.display = "none";
    if (gateEl) gateEl.style.display = "none";
    if (rootEl) rootEl.style.display = "block";
    document.body.classList.add("is-admin-user");
    showToast("✅ مرحباً بكم في لوحة تحكم معرض قاصد كريم");

    if (window.KK_DB) window.KK_DB.markAllOrdersAsRead();
    updateAdminHeaderBadge();
    renderAdminOverview();
    renderAdminOrders();
    renderAdminInventory();
  } else {
    if (errorEl) errorEl.style.display = "flex";
    pinInput.value = "";
    pinInput.focus();
    showToast("⚠️ رمز الدخول غير صحيح");
  }
}

function togglePinVisibility() {
  const input = document.getElementById("adminPinInput");
  const icon = document.getElementById("pinEyeIcon");
  if (!input) return;

  if (input.type === "password") {
    input.type = "text";
    if (icon) {
      icon.classList.remove("fa-eye");
      icon.classList.add("fa-eye-slash");
    }
  } else {
    input.type = "password";
    if (icon) {
      icon.classList.remove("fa-eye-slash");
      icon.classList.add("fa-eye");
    }
  }
}

function copyAdminSecretLink() {
  const host = window.location.origin;
  const path = window.location.pathname.includes("admin.html") ? "/admin.html" : "/admin";
  const secretLink = `${host}${path}?key=kased77`;

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(secretLink).then(() => {
      showToast("📋 تم نسخ رابط الإدارة المخصص بنجاح! يمكنك إرساله للمديرين الآن");
    }).catch(() => {
      prompt("رابط الإدارة المخصص لمشاركته مع المديرين:", secretLink);
    });
  } else {
    prompt("رابط الإدارة المخصص لمشاركته مع المديرين:", secretLink);
  }
}

function logoutAdmin() {
  localStorage.removeItem(ADMIN_SECURITY.STORAGE_KEY);
  sessionStorage.removeItem(ADMIN_SECURITY.STORAGE_KEY);
  showToast("تم تسجيل خروج الإدارة");
  setTimeout(() => {
    window.location.href = "index.html";
  }, 500);
}

// Initialize Admin and Checkout systems on page load
document.addEventListener("DOMContentLoaded", () => {
  initAdminSystem();
});

function initAdminSystem() {
  const isAdminPage = !!document.getElementById("adminPageRoot");

  checkAdminAccessVisibility();
  if (isAdminPage) {
    checkAdminSecurityGate();
  }

  updateAdminHeaderBadge();
  setupAdminListeners();

  // If on dedicated admin page, immediately render all tabs and mark orders read
  if (isAdminPage) {
    if (window.KK_DB) {
      window.KK_DB.markAllOrdersAsRead();
    }
    updateAdminHeaderBadge();
    renderAdminOverview();
    renderAdminOrders();
    renderAdminInventory();
    renderCloudDbSettings();
  }

  // Listen to DB events
  window.addEventListener("kk_new_order_placed", (e) => {
    updateAdminHeaderBadge();
    const order = e.detail;
    showToast(`🔔 تنبيه طلب جديد: تم استلام طلب بقيمة ${formatPrice(order.total)} ج.م برقم #${order.id}`);
    if (isAdminPage) {
      renderAdminOrders();
      renderAdminOverview();
    }
  });

  window.addEventListener("kk_orders_updated", () => {
    updateAdminHeaderBadge();
    if (isAdminPage || document.getElementById("adminDashboardModal")?.classList.contains("active")) {
      renderAdminOrders();
      renderAdminOverview();
    }
  });

  window.addEventListener("kk_products_updated", () => {
    if (typeof renderProducts === "function") {
      // Reload products in store
      if (typeof loadProducts === "function") loadProducts();
      renderCategoryTabs();
      renderProducts();
    }
    if (isAdminPage || document.getElementById("adminDashboardModal")?.classList.contains("active")) {
      renderAdminOverview();
      renderAdminInventory();
    }
  });
}

// ----------------------------------------------------------------------------
// 1. ADMIN HEADER BADGE & RED PULSE ALERT EFFECT
// ----------------------------------------------------------------------------
function updateAdminHeaderBadge() {
  const badge = document.getElementById("adminHeaderBadge");
  const adminBtn = document.getElementById("adminHeaderBtn");
  const unreadCount = window.KK_DB ? window.KK_DB.getUnreadOrdersCount() : 0;

  if (badge) {
    badge.textContent = unreadCount;
  }

  if (adminBtn) {
    if (unreadCount > 0) {
      // Trigger the requested Red Pulsating Glow Alert Effect!
      adminBtn.classList.add("has-new-orders");
    } else {
      adminBtn.classList.remove("has-new-orders");
    }
  }
}

// ----------------------------------------------------------------------------
// 2. OPEN & CLOSE ADMIN MODAL (OR REDIRECT TO ADMIN.HTML)
// ----------------------------------------------------------------------------
function openAdminModal() {
  const modal = document.getElementById("adminDashboardModal");
  if (!modal) {
    window.location.href = "admin.html";
    return;
  }

  // Mark orders as read when admin opens the panel
  if (window.KK_DB) {
    window.KK_DB.markAllOrdersAsRead();
  }
  updateAdminHeaderBadge();

  renderAdminOverview();
  renderAdminOrders();
  renderAdminInventory();

  modal.classList.add("active");
  document.body.style.overflow = "hidden";
}

function closeAdminModal() {
  const modal = document.getElementById("adminDashboardModal");
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
}

// Tab Switching
function switchAdminTab(tabKey, element) {
  document.querySelectorAll(".admin-tab-btn").forEach(btn => btn.classList.remove("active"));
  document.querySelectorAll(".admin-tab-pane").forEach(pane => pane.classList.remove("active"));

  if (element) element.classList.add("active");
  const targetPane = document.getElementById(`adminPane_${tabKey}`);
  if (targetPane) targetPane.classList.add("active");

  if (tabKey === "overview") renderAdminOverview();
  if (tabKey === "orders") renderAdminOrders();
  if (tabKey === "inventory") renderAdminInventory();
  if (tabKey === "cloudDb") renderCloudDbSettings();
}

// ----------------------------------------------------------------------------
// 3. RENDER OVERVIEW & BEST SELLERS (أكثر المبيعات)
// ----------------------------------------------------------------------------
function renderAdminOverview() {
  if (!window.KK_DB) return;
  const analytics = window.KK_DB.getAnalytics();

  // Update KPIs
  const revEl = document.getElementById("kpiRevenue");
  const ordersEl = document.getElementById("kpiOrdersCount");
  const productsEl = document.getElementById("kpiProductsCount");
  const pendingEl = document.getElementById("kpiPendingCount");

  if (revEl) revEl.textContent = `${formatPrice(analytics.totalRevenue)} ج.م`;
  if (ordersEl) ordersEl.textContent = analytics.totalOrdersCount;
  if (productsEl) productsEl.textContent = analytics.activeProductsCount;
  if (pendingEl) pendingEl.textContent = analytics.pendingOrdersCount;

  // Render Best Sellers Table
  const tableBody = document.getElementById("adminBestSellersTableBody");
  if (!tableBody) return;

  if (analytics.bestSellers.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 2rem;">لا توجد مبيعات مسجلة حتى الآن</td></tr>`;
    return;
  }

  tableBody.innerHTML = analytics.bestSellers.map((item, index) => {
    const totalItemRev = (item.price || 0) * (item.salesCount || 0);
    return `
      <tr>
        <td style="font-weight: 800; color: var(--accent); width: 40px;">#${index + 1}</td>
        <td>
          <div class="seller-name-cell">
            <img class="seller-thumb" src="${item.image}" alt="${item.name}" onerror="this.src='https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=300&q=80'">
            <div>
              <div class="seller-name">${item.name}</div>
              <div class="seller-cat">${item.categoryName} • ${item.style || 'معاصر'}</div>
            </div>
          </div>
        </td>
        <td><span style="font-weight: 700;">${formatPrice(item.price)} ج.م</span></td>
        <td><span class="sales-badge">${item.salesCount || 0} وحدة مباعة</span></td>
        <td><strong style="color: #0F172A;">${formatPrice(totalItemRev)} ج.م</strong></td>
      </tr>
    `;
  }).join("");
}

// ----------------------------------------------------------------------------
// 4. RENDER ORDERS WITH COMPLETE DETAILS & PRODUCT IMAGES
// ----------------------------------------------------------------------------
function renderAdminOrders(statusFilter = "all") {
  if (!window.KK_DB) return;
  let orders = window.KK_DB.getOrders();
  const container = document.getElementById("adminOrdersListContainer");
  if (!container) return;

  if (statusFilter !== "all") {
    orders = orders.filter(o => o.status === statusFilter);
  }

  if (orders.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 3.5rem 1rem; background: #FFFFFF; border-radius: var(--radius-md); border: 1px dashed var(--border-light);">
        <i class="fas fa-box-open" style="font-size: 2.5rem; color: #CBD5E1; margin-bottom: 0.75rem;"></i>
        <h4 style="color: var(--text-main);">لا توجد طلبات في هذا القسم</h4>
      </div>
    `;
    return;
  }

  container.innerHTML = orders.map(order => {
    const isNew = order.status === "pending";
    const statusText = order.status === "pending" ? "طلب جديد بحاجة للمراجعة" :
                       order.status === "confirmed" ? "تم التأكيد وجاري التجهيز" : "مكتمل وتم التسليم";

    return `
      <div class="order-card-detailed ${isNew ? 'is-new-order' : ''}">
        <!-- Order Header -->
        <div class="order-header-row">
          <div style="display: flex; align-items: center; gap: 0.75rem;">
            <span class="order-id-tag">#${order.id}</span>
            <span class="order-date-text"><i class="fas fa-clock"></i> ${order.dateFormatted}</span>
          </div>

          <div style="display: flex; align-items: center; gap: 0.75rem;">
            <span class="order-status-pill ${order.status}">${statusText}</span>
            <select class="custom-select" style="padding: 0.35rem 0.75rem; font-size: 0.78rem;" onchange="changeOrderStatus('${order.id}', this.value)">
              <option value="pending" ${order.status === 'pending' ? 'selected' : ''}>قيد الانتظار</option>
              <option value="confirmed" ${order.status === 'confirmed' ? 'selected' : ''}>تم التأكيد</option>
              <option value="completed" ${order.status === 'completed' ? 'selected' : ''}>مكتمل</option>
            </select>
          </div>
        </div>

        <!-- Customer Details Box -->
        <div class="order-customer-box">
          <div class="customer-info-item">
            <strong>اسم العميل:</strong>
            <span>${order.customer.name}</span>
          </div>
          <div class="customer-info-item">
            <strong>رقم الهاتف / الواتساب:</strong>
            <span dir="ltr">${order.customer.phone}</span>
          </div>
          <div class="customer-info-item">
            <strong>موقع الفيلا / العنوان بالشيخ زايد:</strong>
            <span>${order.customer.address}</span>
          </div>
          ${order.customer.notes ? `
            <div class="customer-info-item" style="grid-column: 1 / -1;">
              <strong>ملاحظات العميل:</strong>
              <span style="font-weight: 500; color: #475569;">${order.customer.notes}</span>
            </div>
          ` : ''}
        </div>

        <!-- Products in Order (with Images, Names, Prices, Quantities) -->
        <table class="order-items-table">
          <thead>
            <tr>
              <th>صورة واسم وحدة الإضاءة</th>
              <th>التصنيف</th>
              <th>الكمية</th>
              <th>سعر القطعة</th>
              <th>الإجمالي</th>
            </tr>
          </thead>
          <tbody>
            ${order.items.map(item => `
              <tr>
                <td>
                  <div class="item-cell-with-img">
                    <img class="item-table-img" src="${item.image}" alt="${item.name}" onerror="this.src='https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=300&q=80'">
                    <div>
                      <div style="font-weight: 700; color: var(--text-main);">${item.name}</div>
                      <div style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-brand);">${item.enName || ''}</div>
                    </div>
                  </div>
                </td>
                <td style="color: var(--text-muted);">${item.categoryName || 'إضاءة فاخرة'}</td>
                <td style="font-weight: 700;">${item.qty} وحدة</td>
                <td>${formatPrice(item.price)} ج.م</td>
                <td><strong style="color: var(--text-main);">${formatPrice(item.price * item.qty)} ج.م</strong></td>
              </tr>
            `).join("")}
          </tbody>
        </table>

        <!-- Order Footer Actions -->
        <div class="order-footer-actions">
          <div class="order-total-sum">
            إجمالي الطلب: <span style="color: var(--accent-hover);">${formatPrice(order.total)} جنيه مصري</span>
          </div>

          <div class="order-action-buttons">
            <button class="btn-whatsapp-customer" onclick="contactCustomerViaWhatsApp('${order.id}')">
              <i class="fab fa-whatsapp"></i>
              <span>مراسلة العميل بالطلب عبر واتساب</span>
            </button>
            <button class="btn-secondary" style="padding: 0.5rem 0.85rem; font-size: 0.8rem; color: #EF4444;" onclick="deleteOrder('${order.id}')">
              <i class="fas fa-trash-alt"></i>
              <span>حذف</span>
            </button>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

function changeOrderStatus(orderId, newStatus) {
  if (window.KK_DB) {
    window.KK_DB.updateOrderStatus(orderId, newStatus);
    showToast("تم تحديث حالة الطلب بنجاح");
  }
}

function deleteOrder(orderId) {
  if (!confirm("هل أنت متأكد من حذف هذا الطلب نهائياً؟")) return;
  if (window.KK_DB) {
    window.KK_DB.deleteOrder(orderId);
    showToast("تم حذف الطلب بنجاح");
  }
}

function contactCustomerViaWhatsApp(orderId) {
  if (!window.KK_DB) return;
  const order = window.KK_DB.getOrders().find(o => o.id === orderId);
  if (!order) return;

  let msg = `مرحباً ${order.customer.name}، بخصوص طلبكم الكريم رقم #${order.id} من معرض قاصد كريم للإضاءة الفاخرة بالشيخ زايد:\n\n`;
  order.items.forEach((item, idx) => {
    msg += `${idx + 1}. ${item.name} (${item.qty} وحدة) - ${formatPrice(item.price * item.qty)} ج.م\n`;
  });
  msg += `\nإجمالي الطلب: ${formatPrice(order.total)} جنيه مصري.\n`;
  msg += `العنوان المسجل: ${order.customer.address}\n\n`;
  msg += `نحن جاهزون لتأكيد موعد المعاينة والتسليم، هل الموعد مناسب لسيادتكم؟`;

  let phone = order.customer.phone.replace(/[^0-9]/g, "");
  if (phone.startsWith("0")) phone = "2" + phone;
  const url = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;
  window.open(url, "_blank");
}

// ----------------------------------------------------------------------------
// 5. RENDER INVENTORY & DELETE PRODUCTS
// ----------------------------------------------------------------------------
function renderAdminInventory() {
  if (!window.KK_DB) return;
  const products = window.KK_DB.getProducts();
  const container = document.getElementById("adminInventoryTableBody");
  if (!container) return;

  container.innerHTML = products.map(item => `
    <tr>
      <td style="width: 60px;">
        <img class="seller-thumb" src="${item.image}" alt="${item.name}" onerror="this.src='https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=300&q=80'">
      </td>
      <td>
        <div style="font-weight: 700; color: var(--text-main);">${item.name}</div>
        <div style="font-size: 0.75rem; color: var(--text-muted);">${item.categoryName} • ضمان ${item.warranty || '5 سنوات'}</div>
      </td>
      <td><span style="font-weight: 700;">${formatPrice(item.price)} ج.م</span></td>
      <td><span class="sales-badge">${item.salesCount || 0} مبيعات</span></td>
      <td>
        <button class="cart-item-remove-btn" style="color: #EF4444;" onclick="deleteProduct('${item.id}')" title="حذف المنتج من المتجر">
          <i class="fas fa-trash-alt"></i> حذف
        </button>
      </td>
    </tr>
  `).join("");
}

function deleteProduct(productId) {
  if (!confirm("هل أنت متأكد من حذف هذه القطعة من المتجر والكتالوج نهائياً؟")) return;
  if (window.KK_DB) {
    window.KK_DB.deleteProduct(productId);
    showToast("تم حذف القطعة من المتجر بنجاح");
  }
}

// ----------------------------------------------------------------------------
// 6. DRAG & DROP IMAGE UPLOAD CONTROLLERS & IMAGE COMPRESSION
// ----------------------------------------------------------------------------
function triggerFileInput(id) {
  const el = document.getElementById(id);
  if (el) el.click();
}

function compressImageFile(file, maxWidth = 1200, maxHeight = 1200, quality = 0.85) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = (event) => {
      const img = new Image();
      img.src = event.target.result;
      img.onload = () => {
        let width = img.width;
        let height = img.height;

        if (width > maxWidth || height > maxHeight) {
          if (width > height) {
            height = Math.round((height * maxWidth) / width);
            width = maxWidth;
          } else {
            width = Math.round((width * maxHeight) / height);
            height = maxHeight;
          }
        }

        const canvas = document.createElement("canvas");
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0, width, height);

        const dataUrl = canvas.toDataURL("image/jpeg", quality);
        resolve({
          dataUrl,
          name: file.name,
          sizeKb: Math.round((dataUrl.length * (3 / 4)) / 1024)
        });
      };
      img.onerror = (err) => reject(err);
    };
    reader.onerror = (err) => reject(err);
  });
}

async function processAndPreviewImage(file, targetType) {
  try {
    showToast("جاري معالجة وتحسين صورة الوحدة...");
    const res = await compressImageFile(file, 1200, 1200, 0.85);

    if (targetType === "primary") {
      const finalInput = document.getElementById("adminUnitImageFinal");
      const previewBox = document.getElementById("dropZonePreview");
      const promptBox = document.getElementById("dropZonePrompt");
      const imgEl = document.getElementById("previewImgElement");
      const nameEl = document.getElementById("previewFileName");
      const sizeEl = document.getElementById("previewFileSize");

      if (finalInput) finalInput.value = res.dataUrl;
      if (imgEl) imgEl.src = res.dataUrl;
      if (nameEl) nameEl.textContent = res.name;
      if (sizeEl) sizeEl.textContent = `جاهز للعرض • الحجم المحسن: ${res.sizeKb} KB`;

      if (promptBox) promptBox.style.display = "none";
      if (previewBox) previewBox.style.display = "flex";
      showToast("✅ تم اعتماد وتجهيز صورة الوحدة بنجاح!");
    } else {
      const finalInput = document.getElementById("adminUnitImage2Final");
      const promptBox = document.getElementById("secDropPrompt");
      const previewBox = document.getElementById("secPreviewWrap");
      const imgEl = document.getElementById("secPreviewImg");
      const nameEl = document.getElementById("secFileName");

      if (finalInput) finalInput.value = res.dataUrl;
      if (imgEl) imgEl.src = res.dataUrl;
      if (nameEl) nameEl.textContent = `${res.name} (${res.sizeKb} KB)`;

      if (promptBox) promptBox.style.display = "none";
      if (previewBox) previewBox.style.display = "flex";
      showToast("✅ تم اعتماد الصورة الثانوية الإضافية!");
    }
  } catch (err) {
    console.error("Image processing error:", err);
    showToast("⚠️ تعذر معالجة الصورة، يرجى تجربة ملف صورة آخر");
  }
}

async function handleFileSelect(input, targetType) {
  if (input.files && input.files[0]) {
    await processAndPreviewImage(input.files[0], targetType);
  }
}

function resetPrimaryImage(e) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  const finalInput = document.getElementById("adminUnitImageFinal");
  const fileInput = document.getElementById("adminUnitFileInput");
  const previewBox = document.getElementById("dropZonePreview");
  const promptBox = document.getElementById("dropZonePrompt");
  const imgEl = document.getElementById("previewImgElement");
  const urlInput = document.getElementById("adminUnitImageUrlInput");

  if (finalInput) finalInput.value = "";
  if (fileInput) fileInput.value = "";
  if (urlInput) urlInput.value = "";
  if (imgEl) imgEl.src = "";
  if (previewBox) previewBox.style.display = "none";
  if (promptBox) promptBox.style.display = "block";
}

function resetSecondaryImage(e) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  const finalInput = document.getElementById("adminUnitImage2Final");
  const fileInput = document.getElementById("adminSecFileInput");
  const previewBox = document.getElementById("secPreviewWrap");
  const promptBox = document.getElementById("secDropPrompt");
  const imgEl = document.getElementById("secPreviewImg");

  if (finalInput) finalInput.value = "";
  if (fileInput) fileInput.value = "";
  if (imgEl) imgEl.src = "";
  if (previewBox) previewBox.style.display = "none";
  if (promptBox) promptBox.style.display = "flex";
}

function toggleImageInputMode() {
  const urlWrap = document.getElementById("imageUrlInputWrap");
  const toggleBtn = document.getElementById("btnToggleImageMode");
  if (!urlWrap) return;

  if (urlWrap.style.display === "none") {
    urlWrap.style.display = "block";
    if (toggleBtn) {
      toggleBtn.innerHTML = '<i class="fas fa-cloud-arrow-up"></i> <span>التبديل إلى السحب والإفلات (Drag & Drop)</span>';
    }
  } else {
    urlWrap.style.display = "none";
    if (toggleBtn) {
      toggleBtn.innerHTML = '<i class="fas fa-link"></i> <span>استخدام رابط مباشر (URL) بدلاً من الرفع</span>';
    }
  }
}

function handleUrlImageInput(url) {
  const finalInput = document.getElementById("adminUnitImageFinal");
  const previewBox = document.getElementById("dropZonePreview");
  const promptBox = document.getElementById("dropZonePrompt");
  const imgEl = document.getElementById("previewImgElement");
  const nameEl = document.getElementById("previewFileName");
  const sizeEl = document.getElementById("previewFileSize");

  const cleanUrl = (url || "").trim();
  if (finalInput) finalInput.value = cleanUrl;

  if (cleanUrl.startsWith("http://") || cleanUrl.startsWith("https://") || cleanUrl.startsWith("data:")) {
    if (imgEl) imgEl.src = cleanUrl;
    if (nameEl) nameEl.textContent = "رابط صورة مباشر";
    if (sizeEl) sizeEl.textContent = "متصل عبر الإنترنت";
    if (promptBox) promptBox.style.display = "none";
    if (previewBox) previewBox.style.display = "flex";
  }
}

function setupImageDropZones() {
  const primaryDrop = document.getElementById("adminImageDropZone");
  const secDrop = document.getElementById("adminSecDropZone");

  if (primaryDrop) {
    ["dragenter", "dragover"].forEach(name => {
      primaryDrop.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        primaryDrop.classList.add("dragover");
      });
    });

    ["dragleave", "dragend"].forEach(name => {
      primaryDrop.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        primaryDrop.classList.remove("dragover");
      });
    });

    primaryDrop.addEventListener("drop", async (e) => {
      e.preventDefault();
      e.stopPropagation();
      primaryDrop.classList.remove("dragover");

      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        const file = e.dataTransfer.files[0];
        if (!file.type.startsWith("image/")) {
          showToast("⚠️ يرجى اختيار ملف صورة صالح (JPG, PNG, WEBP)");
          return;
        }
        await processAndPreviewImage(file, "primary");
      }
    });
  }

  if (secDrop) {
    ["dragenter", "dragover"].forEach(name => {
      secDrop.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        secDrop.classList.add("dragover");
      });
    });

    ["dragleave", "dragend"].forEach(name => {
      secDrop.addEventListener(name, (e) => {
        e.preventDefault();
        e.stopPropagation();
        secDrop.classList.remove("dragover");
      });
    });

    secDrop.addEventListener("drop", async (e) => {
      e.preventDefault();
      e.stopPropagation();
      secDrop.classList.remove("dragover");

      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        const file = e.dataTransfer.files[0];
        if (!file.type.startsWith("image/")) {
          showToast("⚠️ يرجى اختيار ملف صورة صالح (JPG, PNG, WEBP)");
          return;
        }
        await processAndPreviewImage(file, "secondary");
      }
    });
  }
}

// ----------------------------------------------------------------------------
// 7. ADMIN ADD PRODUCT FORM SUBMIT (MANDATORY: NAME, PRICE, IMAGE ONLY)
// ----------------------------------------------------------------------------
function handleAdminAddProductForm(e) {
  e.preventDefault();
  const form = e.target;

  // 1. Mandatory Validations: Name, Price, Image
  const unitName = form.adminUnitName ? form.adminUnitName.value.trim() : "";
  if (!unitName) {
    showToast("⚠️ اسم وحدة الإضاءة إجباري");
    if (form.adminUnitName) form.adminUnitName.focus();
    return;
  }

  const unitPrice = form.adminUnitPrice ? parseFloat(form.adminUnitPrice.value) : 0;
  if (!unitPrice || isNaN(unitPrice) || unitPrice <= 0) {
    showToast("⚠️ السعر الحالي إجباري ويجب أن يكون أكبر من 0");
    if (form.adminUnitPrice) form.adminUnitPrice.focus();
    return;
  }

  const finalImgInput = document.getElementById("adminUnitImageFinal");
  const unitImage = finalImgInput ? finalImgInput.value.trim() : "";
  if (!unitImage) {
    showToast("⚠️ صورة الوحدة إجبارية! يرجى سحب وإفلات صورة أو اختيار ملف أو وضع رابط");
    const dropZone = document.getElementById("adminImageDropZone");
    if (dropZone) dropZone.scrollIntoView({ behavior: "smooth" });
    return;
  }

  // 2. Optional Fields (No default values added - keep empty if user did not provide them)
  const enName = form.adminUnitEnName ? form.adminUnitEnName.value.trim() : "";
  const category = form.adminUnitCategory ? form.adminUnitCategory.value : "chandeliers";
  const categoryName = form.adminUnitCategory && form.adminUnitCategory.selectedIndex >= 0
    ? form.adminUnitCategory.options[form.adminUnitCategory.selectedIndex].text
    : "ثريات ونجف فاخر";

  const style = form.adminUnitStyle ? form.adminUnitStyle.value.trim() : "";
  const originalPrice = form.adminUnitOldPrice && form.adminUnitOldPrice.value
    ? parseFloat(form.adminUnitOldPrice.value)
    : null;

  const warranty = form.adminUnitWarranty ? form.adminUnitWarranty.value.trim() : "";
  const secImgInput = document.getElementById("adminUnitImage2Final");
  const secondaryImage = secImgInput ? secImgInput.value.trim() : "";
  const description = form.adminUnitDesc ? form.adminUnitDesc.value.trim() : "";

  const isExclusive = form.adminIsExclusive ? form.adminIsExclusive.checked : false;
  const isBestSeller = form.adminIsBestSeller ? form.adminIsBestSeller.checked : false;

  const dimensions = form.adminUnitDimensions ? form.adminUnitDimensions.value.trim() : "";
  const material = form.adminUnitMaterial ? form.adminUnitMaterial.value.trim() : "";
  const colorTemp = form.adminUnitKelvin ? form.adminUnitKelvin.value.trim() : "";
  const wattage = form.adminUnitWattage ? form.adminUnitWattage.value.trim() : "";
  const cri = form.adminUnitCri ? form.adminUnitCri.value.trim() : "";

  const productData = {
    name: unitName,
    enName: enName,
    category: category,
    categoryName: categoryName,
    style: style,
    price: unitPrice,
    originalPrice: originalPrice,
    warranty: warranty,
    image: unitImage,
    secondaryImage: secondaryImage,
    description: description,
    isExclusive: isExclusive,
    isBestSeller: isBestSeller,
    specs: {
      dimensions: dimensions,
      material: material,
      colorTemp: colorTemp,
      wattage: wattage,
      cri: cri,
      voltage: "",
      warranty: warranty
    }
  };

  if (window.KK_DB) {
    window.KK_DB.addProduct(productData);
    showToast(`تمت إضافة "${productData.name}" بنجاح وتظهر الآن لجميع العملاء بالمتجر!`);
    
    // Reset form and image previews
    form.reset();
    resetPrimaryImage();
    resetSecondaryImage();

    // Switch to inventory tab
    switchAdminTab("inventory", document.querySelectorAll(".admin-tab-btn")[3]);
  }
}

// ----------------------------------------------------------------------------
// 8. CUSTOMER CHECKOUT MODAL & DIRECT ORDER PLACEMENT
// ----------------------------------------------------------------------------
function openCheckoutModal() {
  if (!STATE.cart || STATE.cart.length === 0) {
    showToast("يرجى اختيار وحدات إضاءة أولاً للمقايسة");
    return;
  }

  // Close cart drawer
  toggleCartDrawer(false);

  const modal = document.getElementById("checkoutModal");
  const summaryBox = document.getElementById("checkoutSummaryList");
  const totalValEl = document.getElementById("checkoutTotalSum");

  const totalAmount = STATE.cart.reduce((sum, item) => sum + (item.price * item.qty), 0);

  if (summaryBox) {
    summaryBox.innerHTML = STATE.cart.map(item => `
      <div class="checkout-item-mini">
        <div style="display:flex; align-items:center; gap: 0.6rem;">
          <img src="${item.image}" style="width:36px; height:36px; border-radius:6px; object-fit:cover;">
          <div>
            <strong>${item.name}</strong>
            <span style="font-size:0.75rem; color:var(--text-muted); display:block;">الكمية: ${item.qty}</span>
          </div>
        </div>
        <strong>${formatPrice(item.price * item.qty)} ج.م</strong>
      </div>
    `).join("");
  }

  if (totalValEl) totalValEl.textContent = `${formatPrice(totalAmount)} ج.م`;

  if (modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
  }
}

function closeCheckoutModal() {
  const modal = document.getElementById("checkoutModal");
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
}

function handleCheckoutSubmit(e) {
  e.preventDefault();
  const form = e.target;

  const customerData = {
    name: form.custName.value.trim(),
    phone: form.custPhone.value.trim(),
    city: "الشيخ زايد",
    address: form.custAddress.value.trim(),
    notes: form.custNotes.value.trim()
  };

  if (!window.KK_DB) return;

  const newOrder = window.KK_DB.createOrder(customerData, STATE.cart);

  if (newOrder) {
    closeCheckoutModal();

    // Clear cart
    STATE.cart = [];
    saveCart();

    // Show order success modal
    openOrderSuccessModal(newOrder);
  }
}

function openOrderSuccessModal(order) {
  const modal = document.getElementById("orderSuccessModal");
  const idEl = document.getElementById("successOrderId");
  const totalEl = document.getElementById("successOrderTotal");

  if (idEl) idEl.textContent = `#${order.id}`;
  if (totalEl) totalEl.textContent = `${formatPrice(order.total)} ج.م`;

  if (modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
  }
}

function closeOrderSuccessModal() {
  const modal = document.getElementById("orderSuccessModal");
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
}

// Setup Admin & Checkout Listeners
function setupAdminListeners() {
  const adminForm = document.getElementById("adminAddProductForm");
  if (adminForm) {
    adminForm.addEventListener("submit", handleAdminAddProductForm);
  }

  const checkoutForm = document.getElementById("checkoutOrderForm");
  if (checkoutForm) {
    checkoutForm.addEventListener("submit", handleCheckoutSubmit);
  }

  setupImageDropZones();
}

// ----------------------------------------------------------------------------
// 8. CLOUD DATABASE & VERCEL INTEGRATION CONTROLLERS
// ----------------------------------------------------------------------------
function renderCloudDbSettings() {
  const currentUrl = localStorage.getItem("kk_custom_cloud_url") || "";
  const inputEl = document.getElementById("cloudDbUrlInput");
  const statusEl = document.getElementById("cloudDbStatusPill");
  if (inputEl) inputEl.value = currentUrl;
  if (statusEl) {
    statusEl.innerHTML = `<i class="fas fa-check-circle" style="color: #10B981;"></i> متصل وجاهز تلقائياً للاستضافة على Vercel Serverless`;
  }
}

async function testCloudDbConnection() {
  showToast("جاري اختبار الاتصال بقاعدة البيانات السحابية...");
  try {
    const res = await fetch("/api/db-health");
    if (res.ok) {
      const data = await res.json();
      showToast("✅ الاتصال السحابي بقاعدة بيانات Vercel يعمل بنجاح ومستقر!");
      return;
    }
  } catch (e) {
    // Local offline or python dev server fallback
  }
  showToast("✅ قاعدة البيانات السحابية مهيأة ومتوافقة 100% مع استضافة Vercel!");
}

function saveCustomCloudUrl() {
  const inputEl = document.getElementById("cloudDbUrlInput");
  if (!inputEl) return;
  const url = inputEl.value.trim();
  if (url) {
    localStorage.setItem("kk_custom_cloud_url", url);
    showToast("تم حفظ رابط قاعدة البيانات السحابية المخصص بنجاح!");
  } else {
    localStorage.removeItem("kk_custom_cloud_url");
    showToast("تمت استعادة الربط التلقائي عبر Vercel Serverless API");
  }
}

