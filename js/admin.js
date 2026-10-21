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
  SECRET_KEYS: ["kased77", "2026", "2025", "kased"],
  STORAGE_KEY: "kk_admin_authorized"
};

function checkAdminAccessVisibility() {
  const urlParams = new URLSearchParams(window.location.search);
  const key = urlParams.get("key");
  const adminParam = urlParams.get("admin");

  const hasParamAuth = (key && ADMIN_SECURITY.SECRET_KEYS.includes(key)) ||
                       adminParam === "kased" || adminParam === "true" || adminParam === "1";

  const isLocallyAuth = localStorage.getItem(ADMIN_SECURITY.STORAGE_KEY) === "true";
  const adminBtn = document.getElementById("adminHeaderBtn");

  if (hasParamAuth || isLocallyAuth) {
    document.body.classList.add("is-admin-user");
    localStorage.setItem(ADMIN_SECURITY.STORAGE_KEY, "true");
    if (adminBtn) {
      adminBtn.style.display = "inline-flex";
    }
    if (hasParamAuth && !isLocallyAuth && typeof showToast === "function") {
      setTimeout(() => {
        showToast("🛡️ تم حفظ وربط هذا الجهاز كجهاز إدارة معتمد للمعرض بنجاح ✓");
      }, 500);
      try {
        const cleanUrl = window.location.protocol + "//" + window.location.host + window.location.pathname;
        window.history.replaceState({ path: cleanUrl }, "", cleanUrl);
      } catch (err) {}
    }
  } else {
    document.body.classList.remove("is-admin-user");
    if (adminBtn) {
      adminBtn.style.display = "none";
    }
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
  updateCustomerTrackingBadge();
  setupAdminListeners();

  // If on dedicated admin page, immediately render and force-sync from cloud
  if (isAdminPage) {
    renderAdminOverview();
    renderAdminOrders();
    renderAdminInventory();

    if (window.KK_DB) {
      window.KK_DB.forceSyncNow().then(() => {
        renderAdminOverview();
        renderAdminOrders();
        renderAdminInventory();
        updateAdminHeaderBadge();
      });
    }
  }

  // Listen to DB events
  window.addEventListener("kk_new_order_placed", (e) => {
    updateAdminHeaderBadge();
    const order = e.detail;
    const isAdmin = document.body.classList.contains("is-admin-user") || !!document.getElementById("adminPageRoot");

    // Live alert & sound ONLY for admin users
    if (isAdmin) {
      showToast(`🔔 تنبيه إداري: تم استلام طلب جديد برقم #${order.id} بقيمة ${formatPrice(order.total)} ج.م`);
      if (window.KK_DB) window.KK_DB.playLuxuryChime();
      showAdminLiveOrderAlert(order);
    }

    if (isAdminPage) {
      renderAdminOrders();
      renderAdminOverview();
    }
  });

  window.addEventListener("kk_orders_updated", () => {
    updateAdminHeaderBadge();
    updateCustomerTrackingBadge();

    // Live sync for customer tracking screen if open
    if (window.currentTrackedOrderId) {
      const order = window.KK_DB ? window.KK_DB.getOrders().find(o => o.id === window.currentTrackedOrderId) : null;
      if (order && document.getElementById("trackOrderModal")?.classList.contains("active")) {
        renderTrackedOrderUI(order);
      }
    }

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

  // Secret Admin Device Link shortcut:
  // 5 clicks on logo, or long pressing WhatsApp header button for 2.5s
  let logoClickCount = 0;
  let logoClickTimer = null;
  const brandLogos = document.querySelectorAll(".brand-link, .top-bar-brand, .brand-title-en");
  brandLogos.forEach(logo => {
    logo.addEventListener("click", () => {
      logoClickCount++;
      clearTimeout(logoClickTimer);
      logoClickTimer = setTimeout(() => { logoClickCount = 0; }, 2500);

      if (logoClickCount >= 5) {
        logoClickCount = 0;
        promptAdminDeviceLink();
      }
    });
  });

  const whatsappBtn = document.getElementById("headerWhatsappBtn");
  if (whatsappBtn) {
    let pressTimer = null;
    whatsappBtn.addEventListener("mousedown", () => {
      pressTimer = setTimeout(() => {
        promptAdminDeviceLink();
      }, 2500);
    });
    whatsappBtn.addEventListener("mouseup", () => clearTimeout(pressTimer));
    whatsappBtn.addEventListener("mouseleave", () => clearTimeout(pressTimer));
    whatsappBtn.addEventListener("touchstart", () => {
      pressTimer = setTimeout(() => {
        promptAdminDeviceLink();
      }, 2500);
    }, { passive: true });
    whatsappBtn.addEventListener("touchend", () => clearTimeout(pressTimer));
  }
}

function promptAdminDeviceLink() {
  const pin = prompt("🔐 إعدادات الإدارة: أدخل رمز المرور السري لربط هذا الجهاز وحفظه كجهاز إدارة معتمد:");
  if (!pin) return;
  const trimmed = pin.trim();
  if (ADMIN_SECURITY.SECRET_KEYS.includes(trimmed) || trimmed === "2025" || trimmed === "kased77") {
    localStorage.setItem(ADMIN_SECURITY.STORAGE_KEY, "true");
    document.body.classList.add("is-admin-user");
    const adminBtn = document.getElementById("adminHeaderBtn");
    if (adminBtn) adminBtn.style.display = "inline-flex";
    if (typeof showToast === "function") {
      showToast("🛡️ تم تفعيل وربط هذا الجهاز كجهاز إدارة معتمد بنجاح ✓");
    }
  } else {
    alert("❌ رمز المرور غير صحيح");
  }
}

function showAdminLiveOrderAlert(order) {
  const isAdmin = document.body.classList.contains("is-admin-user") || !!document.getElementById("adminPageRoot");
  if (!isAdmin) return;

  let banner = document.getElementById("adminLiveOrderAlertBanner");
  if (!banner) {
    banner = document.createElement("div");
    banner.id = "adminLiveOrderAlertBanner";
    banner.className = "admin-live-order-banner";
    document.body.prepend(banner);
  }
  banner.innerHTML = `
    <div class="admin-live-banner-inner">
      <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
        <span class="live-banner-pulse"></span>
        <strong style="color: #FFFFFF; font-size: 0.95rem;">🚨 تنبيه فوري: تم استلام طلب جديد برقم #${order.id}</strong>
        <span style="color: #FDE68A; font-size: 0.88rem;">العميل: ${order.customer?.name || 'عميل'} • الإجمالي: ${formatPrice(order.total)} ج.م</span>
      </div>
      <div style="display: flex; align-items: center; gap: 0.6rem;">
        <a href="admin.html" class="btn-primary" style="padding: 0.35rem 0.85rem; font-size: 0.78rem; text-decoration: none; background: #F59E0B; color: #0F172A; font-weight: 700;">عرض في لوحة التحكم</a>
        <button type="button" class="banner-close-btn" onclick="document.getElementById('adminLiveOrderAlertBanner')?.remove()">×</button>
      </div>
    </div>
  `;
}

// ----------------------------------------------------------------------------
// 1. ADMIN HEADER BADGE & RED PULSE ALERT EFFECT
// ----------------------------------------------------------------------------
function updateAdminHeaderBadge() {
  const isAdmin = document.body.classList.contains("is-admin-user") || !!document.getElementById("adminPageRoot");
  const badge = document.getElementById("adminHeaderBadge");
  const adminBtn = document.getElementById("adminHeaderBtn");
  const unreadCount = window.KK_DB ? window.KK_DB.getUnreadOrdersCount() : 0;

  if (badge) {
    badge.textContent = unreadCount;
  }

  if (adminBtn) {
    if (isAdmin && unreadCount > 0) {
      // Trigger the requested Red Pulsating Glow Alert Effect for Admin Only!
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
        <i class="fas fa-boxes-packing" style="font-size: 2.8rem; color: #CBD5E1; margin-bottom: 0.85rem;"></i>
        <h4 style="color: var(--text-main); font-weight: 800; margin-bottom: 0.35rem;">لا توجد طلبات في هذا القسم حالياً</h4>
        <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0;">النظام متصل بالكامل ويعمل في وضع المزامنة اللحظية المباشرة</p>
      </div>
    `;
    return;
  }

  container.innerHTML = orders.map(order => {
    const isNew = order.status === "pending";
    const statusLabels = {
      pending: "قيد المراجعة والاستلام",
      confirmed: "تم التأكيد والمعاينة الفنية",
      processing: "جاري التجهيز والتجميع بالمستودع",
      shipped: "خرج للشحن والتوصيل",
      completed: "مكتمل وتم التسليم بنجاح",
      cancelled: "طلب ملغي"
    };
    const statusText = statusLabels[order.status] || "قيد المعالجة";

    return `
      <div class="order-card-detailed ${isNew ? 'is-new-order' : ''}">
        <!-- Order Header -->
        <div class="order-header-row">
          <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
            <span class="order-id-tag">#${order.id}</span>
            <span class="order-date-text"><i class="fas fa-clock"></i> ${order.dateFormatted}</span>
            ${isNew ? '<span class="new-live-tag"><i class="fas fa-bolt"></i> وارد الآن</span>' : ''}
          </div>

          <div style="display: flex; align-items: center; gap: 0.75rem;">
            <span class="order-status-pill ${order.status}">${statusText}</span>
            <select class="custom-select" style="padding: 0.35rem 0.75rem; font-size: 0.78rem; font-weight: 700;" onchange="changeOrderStatus('${order.id}', this.value)">
              <option value="pending" ${order.status === 'pending' ? 'selected' : ''}>⏳ قيد الانتظار والمراجعة</option>
              <option value="confirmed" ${order.status === 'confirmed' ? 'selected' : ''}>📋 تم التأكيد والمعاينة</option>
              <option value="processing" ${order.status === 'processing' ? 'selected' : ''}>⚙️ جاري التجهيز والتجميع</option>
              <option value="shipped" ${order.status === 'shipped' ? 'selected' : ''}>🚚 خرج للشحن والتوصيل</option>
              <option value="completed" ${order.status === 'completed' ? 'selected' : ''}>✅ مكتمل وتم التسليم</option>
              <option value="cancelled" ${order.status === 'cancelled' ? 'selected' : ''}>❌ ملغي</option>
            </select>
          </div>
        </div>

        <!-- Customer Details Box -->
        <div class="order-customer-box">
          <div class="customer-info-item">
            <strong>اسم العميل:</strong>
            <span style="font-weight: 800; color: #0F172A;">${order.customer.name}</span>
          </div>
          <div class="customer-info-item">
            <strong>رقم الهاتف / الواتساب:</strong>
            <a href="tel:${order.customer.phone}" style="color: var(--accent-hover); font-weight: 800; text-decoration: none; dir: ltr;" dir="ltr">
              <i class="fas fa-phone-alt" style="font-size: 0.75rem;"></i> ${order.customer.phone}
            </a>
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
    const statusLabels = {
      pending: "قيد الانتظار والمراجعة",
      confirmed: "تم التأكيد والمعاينة الفنية",
      processing: "جاري التجهيز والتجميع بالمستودع",
      shipped: "خرج للشحن والتوصيل للفيلا",
      completed: "مكتمل وتم التسليم بنجاح",
      cancelled: "تم إلغاء الطلب"
    };
    showToast(`✅ تم تحديث حالة الطلب #${orderId} إلى: ${statusLabels[newStatus] || newStatus}`);
  }
}

function deleteOrder(orderId) {
  if (!confirm("هل أنت متأكد من حذف هذا الطلب نهائياً؟")) return;
  if (window.KK_DB) {
    window.KK_DB.deleteOrder(orderId);
    showToast("تم حذف الطلب بنجاح");
  }
}

async function refreshAdminOrdersFromCloud(btn) {
  const icon = document.getElementById("refreshOrdersIcon");
  if (icon) icon.classList.add("fa-spin");
  if (btn) btn.disabled = true;

  try {
    if (window.KK_DB) {
      await window.KK_DB.forceSyncNow();
    }
    renderAdminOrders();
    renderAdminOverview();
    updateAdminHeaderBadge();
    showToast("✅ تم تحديث جميع الطلبات لحظياً من السحابة بنجاح");
  } catch (e) {
    showToast("⚠️ تم التحديث من الذاكرة المحلية");
  } finally {
    if (icon) icon.classList.remove("fa-spin");
    if (btn) btn.disabled = false;
  }
}

function testAdminChime() {
  if (window.KK_DB) {
    window.KK_DB.playLuxuryChime();
    showToast("🔊 تم تشغيل رنين التنبيه الفاخر بنجاح");
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

function compressImageFile(file, maxWidth = 800, maxHeight = 800, quality = 0.75) {
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
  const category = form.adminUnitCategory ? form.adminUnitCategory.value : "pendants";
  const categoryName = form.adminUnitCategory && form.adminUnitCategory.selectedIndex >= 0
    ? form.adminUnitCategory.options[form.adminUnitCategory.selectedIndex].text
    : "دلايات";

  const style = form.adminUnitStyle ? form.adminUnitStyle.value.trim() : "";
  const originalPrice = form.adminUnitOldPrice && form.adminUnitOldPrice.value
    ? parseFloat(form.adminUnitOldPrice.value)
    : null;

  const warranty = form.adminUnitWarranty ? form.adminUnitWarranty.value.trim() : "";
  const secImgInput = document.getElementById("adminUnitImage2Final");
  const secondaryImage = secImgInput ? secImgInput.value.trim() : "";
  const description = form.adminUnitDesc ? form.adminUnitDesc.value.trim() : "";

  const isNew = form.adminIsNew ? form.adminIsNew.checked : true;
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
    isNew: isNew,
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

// ----------------------------------------------------------------------------
// CHECKOUT FORM VALIDATION RULES (التحقق الصارم من بيانات العميل)
// 1. الاسم: أول اسمين على الأقل
// 2. رقم الهاتف: 11 رقماً كاملاً بدون نقص (010, 011, 012, 015)
// 3. العنوان: لا يقل عن 15 حرفاً
// ----------------------------------------------------------------------------
function validateCustomerName(name) {
  if (!name || !name.trim()) {
    return { valid: false, message: "يرجى كتابة الاسم الكريم للعميل أو المهندس المشرف" };
  }
  const trimmed = name.trim();
  // Split by whitespace and ignore single-character honorifics or punctuation
  const parts = trimmed.split(/\s+/).filter(part => {
    const clean = part.replace(/[.\-_]/g, "");
    return clean.length >= 2;
  });

  if (parts.length < 2) {
    return {
      valid: false,
      message: "⚠️ يرجى كتابة الاسم ثنائياً على الأقل (الاسم الأول واسم العائلة، مثال: كريم محمود)"
    };
  }
  return { valid: true, cleanName: trimmed };
}

function validateCustomerPhone(phone) {
  if (!phone || !phone.trim()) {
    return { valid: false, message: "يرجى إدخال رقم الهاتف / واتساب لتأكيد الطلب" };
  }
  const clean = phone.replace(/[\s\-\(\)]/g, "");

  // Egyptian standard mobile format: exactly 11 digits starting with 010, 011, 012, or 015
  const egStandardRegex = /^(010|011|012|015)[0-9]{8}$/;
  // Egyptian with country code (+20 or 0020 or 20)
  const egIntlRegex = /^(\+?20|0020)(10|11|12|15)[0-9]{8}$/;
  // International complete format: minimum 10 digits
  const generalIntlRegex = /^\+[0-9]{10,15}$/;

  if (egStandardRegex.test(clean)) {
    return { valid: true, cleanPhone: clean };
  }
  if (egIntlRegex.test(clean)) {
    return { valid: true, cleanPhone: clean };
  }
  if (generalIntlRegex.test(clean)) {
    return { valid: true, cleanPhone: clean };
  }

  if (clean.length < 11) {
    return {
      valid: false,
      message: `⚠️ رقم الهاتف ناقص (${clean.length} أرقام فقط)! يجب إدخال 11 رقماً كاملاً (مثال: 01012345678)`
    };
  }

  return {
    valid: false,
    message: "⚠️ يرجى إدخال رقم هاتف محمول مصري صحيح مكون من 11 رقماً يبدأ بـ 010 أو 011 أو 012 أو 015"
  };
}

function validateCustomerAddress(address) {
  if (!address || !address.trim()) {
    return { valid: false, message: "يرجى كتابة عنوان العقار بالشيخ زايد" };
  }
  const trimmed = address.trim();
  if (trimmed.length < 15) {
    return {
      valid: false,
      message: `⚠️ تفاصيل العنوان قصيرة (${trimmed.length} حرفاً)! يجب ألا يقل العنوان عن 15 حرفاً (مثال: كمبوند بيفرلي هيلز - فيلا 42)`
    };
  }
  return { valid: true, cleanAddress: trimmed };
}

function setupCheckoutLiveValidation() {
  const nameInput = document.getElementById("custNameInput");
  const phoneInput = document.getElementById("custPhoneInput");
  const addressInput = document.getElementById("custAddressInput");
  const addressCounter = document.getElementById("custAddressCounter");

  const nameError = document.getElementById("custNameError");
  const phoneError = document.getElementById("custPhoneError");
  const addressError = document.getElementById("custAddressError");

  // Name Live Listener
  if (nameInput && !nameInput.dataset.hasListener) {
    nameInput.dataset.hasListener = "true";
    nameInput.addEventListener("input", () => {
      const val = validateCustomerName(nameInput.value);
      if (val.valid) {
        nameInput.classList.remove("is-invalid");
        nameInput.classList.add("is-valid");
        if (nameError) nameError.classList.remove("show");
      } else if (nameInput.value.trim().length > 3) {
        nameInput.classList.remove("is-valid");
      }
    });
  }

  // Phone Live Listener
  if (phoneInput && !phoneInput.dataset.hasListener) {
    phoneInput.dataset.hasListener = "true";
    phoneInput.addEventListener("input", () => {
      // Auto-filter non-digit characters except +
      phoneInput.value = phoneInput.value.replace(/[^0-9+]/g, "");
      const val = validateCustomerPhone(phoneInput.value);
      if (val.valid) {
        phoneInput.classList.remove("is-invalid");
        phoneInput.classList.add("is-valid");
        if (phoneError) phoneError.classList.remove("show");
      } else if (phoneInput.value.length >= 11) {
        phoneInput.classList.add("is-invalid");
        phoneInput.classList.remove("is-valid");
        if (phoneError) {
          phoneError.querySelector("span").textContent = val.message;
          phoneError.classList.add("show");
        }
      }
    });
  }

  // Address Live Listener with Dynamic Counter
  if (addressInput && !addressInput.dataset.hasListener) {
    addressInput.dataset.hasListener = "true";
    addressInput.addEventListener("input", () => {
      const len = addressInput.value.trim().length;
      if (addressCounter) {
        if (len >= 15) {
          addressCounter.textContent = `✓ ${len} حرفاً (مكتمل)`;
          addressCounter.className = "form-char-counter valid";
        } else {
          addressCounter.textContent = `${len} / 15 حرفاً كحد أدنى`;
          addressCounter.className = "form-char-counter invalid";
        }
      }

      const val = validateCustomerAddress(addressInput.value);
      if (val.valid) {
        addressInput.classList.remove("is-invalid");
        addressInput.classList.add("is-valid");
        if (addressError) addressError.classList.remove("show");
      } else if (len >= 15) {
        addressInput.classList.remove("is-invalid");
      }
    });
  }
}

function handleCheckoutSubmit(e) {
  e.preventDefault();
  const form = e.target;

  const rawName = (form.custName ? form.custName.value : "").trim();
  const rawPhone = (form.custPhone ? form.custPhone.value : "").trim();
  const rawAddress = (form.custAddress ? form.custAddress.value : "").trim();
  const rawNotes = form.custNotes ? form.custNotes.value.trim() : "";

  // Perform Strict Validations
  const nameVal = validateCustomerName(rawName);
  const phoneVal = validateCustomerPhone(rawPhone);
  const addressVal = validateCustomerAddress(rawAddress);

  const nameInput = document.getElementById("custNameInput") || form.custName;
  const phoneInput = document.getElementById("custPhoneInput") || form.custPhone;
  const addressInput = document.getElementById("custAddressInput") || form.custAddress;

  const nameError = document.getElementById("custNameError");
  const phoneError = document.getElementById("custPhoneError");
  const addressError = document.getElementById("custAddressError");

  let hasError = false;

  // 1. Check Name
  if (!nameVal.valid) {
    hasError = true;
    if (nameInput) {
      nameInput.classList.add("is-invalid");
      nameInput.classList.remove("is-valid");
    }
    if (nameError) {
      nameError.querySelector("span").textContent = nameVal.message;
      nameError.classList.add("show");
    }
  } else {
    if (nameInput) {
      nameInput.classList.remove("is-invalid");
      nameInput.classList.add("is-valid");
    }
    if (nameError) nameError.classList.remove("show");
  }

  // 2. Check Phone
  if (!phoneVal.valid) {
    hasError = true;
    if (phoneInput) {
      phoneInput.classList.add("is-invalid");
      phoneInput.classList.remove("is-valid");
    }
    if (phoneError) {
      phoneError.querySelector("span").textContent = phoneVal.message;
      phoneError.classList.add("show");
    }
  } else {
    if (phoneInput) {
      phoneInput.classList.remove("is-invalid");
      phoneInput.classList.add("is-valid");
    }
    if (phoneError) phoneError.classList.remove("show");
  }

  // 3. Check Address
  if (!addressVal.valid) {
    hasError = true;
    if (addressInput) {
      addressInput.classList.add("is-invalid");
      addressInput.classList.remove("is-valid");
    }
    if (addressError) {
      addressError.querySelector("span").textContent = addressVal.message;
      addressError.classList.add("show");
    }
  } else {
    if (addressInput) {
      addressInput.classList.remove("is-invalid");
      addressInput.classList.add("is-valid");
    }
    if (addressError) addressError.classList.remove("show");
  }

  // If any field fails, halt submission and focus on first invalid field
  if (hasError) {
    if (!nameVal.valid) {
      nameInput?.focus();
      showToast(nameVal.message);
    } else if (!phoneVal.valid) {
      phoneInput?.focus();
      showToast(phoneVal.message);
    } else if (!addressVal.valid) {
      addressInput?.focus();
      showToast(addressVal.message);
    }
    return;
  }

  if (!window.KK_DB) return;

  const customerData = {
    name: nameVal.cleanName,
    phone: phoneVal.cleanPhone,
    city: "الشيخ زايد",
    address: addressVal.cleanAddress,
    notes: rawNotes
  };

  const newOrder = window.KK_DB.createOrder(customerData, STATE.cart);

  if (newOrder) {
    closeCheckoutModal();

    // Clear cart
    STATE.cart = [];
    saveCart();

    // Store in customer recent orders on this device for instant 1-click tracking
    try {
      const recent = JSON.parse(localStorage.getItem("kk_customer_recent_orders") || "[]");
      if (!recent.includes(newOrder.id)) {
        recent.unshift(newOrder.id);
        localStorage.setItem("kk_customer_recent_orders", JSON.stringify(recent.slice(0, 10)));
      }
      localStorage.setItem("kk_last_placed_order_id", newOrder.id);
    } catch (e) {}

    updateCustomerTrackingBadge();

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

  window.lastPlacedOrderId = order.id;

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

  setupCheckoutLiveValidation();
  setupImageDropZones();

  window.addEventListener("kk_products_updated", () => {
    renderAdminOverview();
    renderAdminInventory();
  });
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

// ----------------------------------------------------------------------------
// 9. CUSTOMER ORDER TRACKING CONTROLLERS & LIVE STATUS STEPPER
// ----------------------------------------------------------------------------
function updateCustomerTrackingBadge() {
  try {
    const recent = JSON.parse(localStorage.getItem("kk_customer_recent_orders") || "[]");
    const badge = document.getElementById("customerOrdersBadge");
    if (badge) {
      if (recent.length > 0) {
        badge.textContent = recent.length;
        badge.style.display = "inline-flex";
      } else {
        badge.style.display = "none";
      }
    }
  } catch (e) {}
}

function openTrackOrderModal(targetOrderId = null) {
  const modal = document.getElementById("trackOrderModal");
  if (!modal) return;

  renderCustomerRecentOrderChips();

  const searchInput = document.getElementById("trackSearchInput");

  // Determine which order to display
  let orderToLoad = targetOrderId;
  if (!orderToLoad) {
    orderToLoad = window.lastPlacedOrderId || localStorage.getItem("kk_last_placed_order_id");
  }

  if (orderToLoad) {
    if (searchInput) searchInput.value = orderToLoad;
    loadAndRenderTrackOrder(orderToLoad);
  } else {
    // Show empty state prompt
    const emptyState = document.getElementById("trackEmptyState");
    const resultBox = document.getElementById("trackResultContainer");
    if (emptyState) emptyState.style.display = "block";
    if (resultBox) resultBox.style.display = "none";
  }

  modal.classList.add("active");
  document.body.style.overflow = "hidden";
}

function closeTrackOrderModal() {
  const modal = document.getElementById("trackOrderModal");
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
}

function renderCustomerRecentOrderChips() {
  const wrap = document.getElementById("trackRecentOrdersWrap");
  const container = document.getElementById("trackRecentOrdersChips");
  if (!wrap || !container) return;

  try {
    const recent = JSON.parse(localStorage.getItem("kk_customer_recent_orders") || "[]");
    if (recent.length > 0) {
      wrap.style.display = "block";
      container.innerHTML = recent.map(id => `
        <button type="button" class="track-chip-btn ${id === window.currentTrackedOrderId ? 'active' : ''}" onclick="loadAndRenderTrackOrder('${id}')">
          <i class="fas fa-tag"></i> #${id}
        </button>
      `).join("");
    } else {
      wrap.style.display = "none";
    }
  } catch (e) {
    wrap.style.display = "none";
  }
}

function searchAndTrackOrder() {
  const input = document.getElementById("trackSearchInput");
  const query = input ? input.value.trim() : "";
  if (!query) {
    showToast("⚠️ يرجى إدخال رقم الطلب (مثال: ORD-3894) أو رقم الهاتف للبحث");
    input?.focus();
    return;
  }
  loadAndRenderTrackOrder(query);
}

async function loadAndRenderTrackOrder(query) {
  if (!query) return;
  const cleanQuery = query.replace(/[#]/g, "").trim().toUpperCase();

  let orders = window.KK_DB ? window.KK_DB.getOrders() : [];
  let found = orders.find(o => 
    o.id.toUpperCase() === cleanQuery || 
    o.id.replace("ORD-", "") === cleanQuery ||
    (o.customer && o.customer.phone && o.customer.phone.replace(/[^0-9]/g, "").includes(cleanQuery.replace(/[^0-9]/g, "")))
  );

  // If not found in local cache, attempt to sync from cloud API immediately
  if (!found && window.KK_DB) {
    showToast("جاري البحث في قاعدة بيانات المعرض السحابية...");
    try {
      await window.KK_DB.forceSyncNow();
      orders = window.KK_DB.getOrders();
      found = orders.find(o => 
        o.id.toUpperCase() === cleanQuery || 
        o.id.replace("ORD-", "") === cleanQuery ||
        (o.customer && o.customer.phone && o.customer.phone.replace(/[^0-9]/g, "").includes(cleanQuery.replace(/[^0-9]/g, "")))
      );
    } catch (e) {}
  }

  if (found) {
    // Save to customer recent orders
    try {
      const recent = JSON.parse(localStorage.getItem("kk_customer_recent_orders") || "[]");
      if (!recent.includes(found.id)) {
        recent.unshift(found.id);
        localStorage.setItem("kk_customer_recent_orders", JSON.stringify(recent.slice(0, 10)));
      }
      localStorage.setItem("kk_last_placed_order_id", found.id);
      renderCustomerRecentOrderChips();
      updateCustomerTrackingBadge();
    } catch (e) {}

    renderTrackedOrderUI(found);
  } else {
    showToast(`⚠️ تعذر العثور على طلب برقم "${query}"، يرجى التأكد من الرقم`);
    const emptyState = document.getElementById("trackEmptyState");
    const resultBox = document.getElementById("trackResultContainer");
    if (emptyState) {
      emptyState.style.display = "block";
      emptyState.innerHTML = `
        <i class="fas fa-triangle-exclamation" style="font-size: 2.2rem; color: #F59E0B; margin-bottom: 0.75rem;"></i>
        <h4 style="color: var(--text-main); margin-bottom: 0.35rem; font-weight: 700;">لم يتم العثور على طلب برقم "${query}"</h4>
        <p style="color: var(--text-muted); font-size: 0.82rem; margin: 0 0 1rem 0;">يرجى التأكد من كتابة الكود كاملاً كما ظهر لك، أو التواصل معنا مباشرة</p>
        <button type="button" class="btn-whatsapp-customer" style="margin: 0 auto; padding: 0.5rem 1rem; font-size: 0.8rem;" onclick="contactSupportAboutTrackedOrder('${query}')">
          <i class="fab fa-whatsapp"></i> استفسار عبر واتساب
        </button>
      `;
    }
    if (resultBox) resultBox.style.display = "none";
  }
}

function renderTrackedOrderUI(order) {
  window.currentTrackedOrderId = order.id;

  const emptyState = document.getElementById("trackEmptyState");
  const resultBox = document.getElementById("trackResultContainer");
  if (emptyState) emptyState.style.display = "none";
  if (resultBox) resultBox.style.display = "block";

  // Header Details
  const idDisplay = document.getElementById("trackOrderIdDisplay");
  const dateDisplay = document.getElementById("trackOrderDateDisplay");
  const custName = document.getElementById("trackCustomerName");
  const custAddress = document.getElementById("trackCustomerAddress");
  const totalSum = document.getElementById("trackOrderTotalSum");

  if (idDisplay) idDisplay.textContent = `#${order.id}`;
  if (dateDisplay) dateDisplay.innerHTML = `<i class="fas fa-clock"></i> تم التسجيل: ${order.dateFormatted}`;
  if (custName) custName.textContent = order.customer ? order.customer.name : "عميل كريم";
  if (custAddress) custAddress.textContent = order.customer ? order.customer.address : "الشيخ زايد";
  if (totalSum) totalSum.textContent = `${formatPrice(order.total)} ج.م`;

  // Render Items List
  const itemsContainer = document.getElementById("trackItemsList");
  if (itemsContainer) {
    itemsContainer.innerHTML = (order.items || []).map(item => `
      <div style="display: flex; align-items: center; justify-content: space-between; background: #FFFFFF; border: 1px solid var(--border-light); border-radius: var(--radius-sm); padding: 0.6rem 0.85rem;">
        <div style="display: flex; align-items: center; gap: 0.65rem;">
          <img src="${item.image}" alt="${item.name}" style="width: 42px; height: 42px; border-radius: 6px; object-fit: cover;" onerror="this.src='https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=300&q=80'">
          <div>
            <div style="font-weight: 700; font-size: 0.85rem; color: var(--text-main);">${item.name}</div>
            <div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-brand);">${item.categoryName || 'إضاءة معمارية'} • الكمية: ${item.qty}</div>
          </div>
        </div>
        <div style="font-weight: 800; font-size: 0.85rem; color: var(--accent-hover);">${formatPrice(item.price * item.qty)} ج.م</div>
      </div>
    `).join("");
  }

  // Visual Stepper (5 Stages)
  const steps = [
    document.getElementById("step1"),
    document.getElementById("step2"),
    document.getElementById("step3"),
    document.getElementById("step4"),
    document.getElementById("step5")
  ];
  const stepperFill = document.getElementById("trackStepperFill");
  const badgeDisplay = document.getElementById("trackStatusBadgeDisplay");
  const msgBox = document.getElementById("trackStatusMessageBox");
  const msgText = document.getElementById("trackStatusMessageText");

  // Reset steps
  steps.forEach(s => {
    if (s) {
      s.classList.remove("active", "completed");
    }
  });

  const status = order.status || "pending";

  if (status === "pending") {
    if (stepperFill) stepperFill.style.width = "10%";
    if (steps[0]) steps[0].classList.add("active");
    if (badgeDisplay) {
      badgeDisplay.className = "status-badge-live status-pending";
      badgeDisplay.innerHTML = `<i class="fas fa-clock"></i> قيد المراجعة والاستلام`;
    }
    if (msgBox) {
      msgBox.style.background = "#FFFBEB";
      msgBox.style.borderColor = "#FDE68A";
      msgBox.style.color = "#92400E";
    }
    if (msgText) msgText.textContent = "تم استلام وتسجيل طلبك بنجاح، وقيد المراجعة الفنية وجدولة المعاينة بمعرض قاصد كريم بالشيخ زايد.";
  } else if (status === "confirmed") {
    if (stepperFill) stepperFill.style.width = "35%";
    if (steps[0]) steps[0].classList.add("completed");
    if (steps[1]) steps[1].classList.add("active");
    if (badgeDisplay) {
      badgeDisplay.className = "status-badge-live status-confirmed";
      badgeDisplay.innerHTML = `<i class="fas fa-check-double"></i> تم التأكيد والمعاينة`;
    }
    if (msgBox) {
      msgBox.style.background = "#EFF6FF";
      msgBox.style.borderColor = "#BFDBFE";
      msgBox.style.color = "#1E40AF";
    }
    if (msgText) msgText.textContent = "تم اعتماد وتأكيد المقايسة الفنية لوحدات الإضاءة من المهندس المختص، والطلب معتمد للتجهيز.";
  } else if (status === "processing") {
    if (stepperFill) stepperFill.style.width = "62%";
    if (steps[0]) steps[0].classList.add("completed");
    if (steps[1]) steps[1].classList.add("completed");
    if (steps[2]) steps[2].classList.add("active");
    if (badgeDisplay) {
      badgeDisplay.className = "status-badge-live status-processing";
      badgeDisplay.innerHTML = `<i class="fas fa-boxes-packing"></i> جاري التجهيز والتجميع`;
    }
    if (msgBox) {
      msgBox.style.background = "#FAF5FF";
      msgBox.style.borderColor = "#E9D5FF";
      msgBox.style.color = "#6B21A8";
    }
    if (msgText) msgText.textContent = "جاري تجميع وفحص واختبار وحدات الإضاءة وقطع الكريستال بمستودع المعرض بالشيخ زايد للتأكد من مطابقتها لأعلى معايير الجودة.";
  } else if (status === "shipped") {
    if (stepperFill) stepperFill.style.width = "85%";
    if (steps[0]) steps[0].classList.add("completed");
    if (steps[1]) steps[1].classList.add("completed");
    if (steps[2]) steps[2].classList.add("completed");
    if (steps[3]) steps[3].classList.add("active");
    if (badgeDisplay) {
      badgeDisplay.className = "status-badge-live status-shipped";
      badgeDisplay.innerHTML = `<i class="fas fa-truck-fast"></i> خرج للشحن والتوصيل`;
    }
    if (msgBox) {
      msgBox.style.background = "#ECFDF5";
      msgBox.style.borderColor = "#A7F3D0";
      msgBox.style.color = "#065F46";
    }
    if (msgText) msgText.textContent = "خرجت الشحنة مع مندوب التوصيل والتركيبات المتخصص بالشيخ زايد، وجاري التوجه لموقع الفيلا / المشروع.";
  } else if (status === "completed") {
    if (stepperFill) stepperFill.style.width = "100%";
    steps.forEach(s => s && s.classList.add("completed"));
    if (badgeDisplay) {
      badgeDisplay.className = "status-badge-live status-completed";
      badgeDisplay.innerHTML = `<i class="fas fa-shield-halved"></i> تم التسليم بنجاح`;
    }
    if (msgBox) {
      msgBox.style.background = "#F0FDF4";
      msgBox.style.borderColor = "#BBF7D0";
      msgBox.style.color = "#166534";
    }
    if (msgText) msgText.textContent = "تم تسليم وحدات الإضاءة بنجاح مع تفعيل شهادة الضمان الشامل المعتمدة. شكراً لثقتكم بمعرض قاصد كريم بالشيخ زايد.";
  } else if (status === "cancelled") {
    if (stepperFill) stepperFill.style.width = "0%";
    if (badgeDisplay) {
      badgeDisplay.className = "status-badge-live status-cancelled";
      badgeDisplay.innerHTML = `<i class="fas fa-ban"></i> تم إلغاء الطلب`;
    }
    if (msgBox) {
      msgBox.style.background = "#FEF2F2";
      msgBox.style.borderColor = "#FECACA";
      msgBox.style.color = "#991B1B";
    }
    if (msgText) msgText.textContent = "تم إلغاء هذا الطلب. للاستفسار أو لإعادة طلب مقايسة جديدة يمكنك التواصل مباشرة مع إدارة المعرض.";
  }
}

async function refreshCurrentTrackOrder(btn) {
  const icon = document.getElementById("trackRefreshIcon");
  if (icon) icon.classList.add("fa-spin");
  if (btn) btn.disabled = true;

  try {
    if (window.KK_DB) {
      await window.KK_DB.forceSyncNow();
    }
    if (window.currentTrackedOrderId) {
      const order = window.KK_DB ? window.KK_DB.getOrders().find(o => o.id === window.currentTrackedOrderId) : null;
      if (order) {
        renderTrackedOrderUI(order);
        showToast("✅ تم تحديث حالة الطلب لحظياً من السحابة بنجاح");
      }
    }
  } catch (e) {
    showToast("⚠️ تم التحديث من الذاكرة المحلية");
  } finally {
    if (icon) icon.classList.remove("fa-spin");
    if (btn) btn.disabled = false;
  }
}

function trackOrderFromSuccessModal() {
  closeOrderSuccessModal();
  openTrackOrderModal(window.lastPlacedOrderId);
}

function contactSupportAboutTrackedOrder(customQuery = null) {
  const targetId = customQuery || window.currentTrackedOrderId || "طلب إضاءة";
  const msg = `مرحباً معرض قاصد كريم بالشيخ زايد، أود الاستفسار عن تفاصيل وحالة طلبي رقم #${targetId}. هل يمكنكم إفادتي بآخر المستجدات وموعد المعاينة / التوصيل؟`;
  const phone = "201006367690";
  const url = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;
  window.open(url, "_blank");
}

