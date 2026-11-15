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

// Safe HTML Escaping Utility for XSS Prevention in Admin Interface
window.escapeHtml = window.escapeHtml || function(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
};

// ----------------------------------------------------------------------------
// 0. SERVER-SIDE ADMIN SECURITY GATE & SESSION VAULT
// ----------------------------------------------------------------------------
const ADMIN_TOKEN_KEY = "kk_admin_token";

async function checkAdminSecurityGate() {
  const gateEl = document.getElementById("adminAuthGate");
  const rootEl = document.getElementById("adminPageRoot");
  if (!gateEl || !rootEl) return;

  // Check URL params for force lock or relock (e.g. ?lock=1 or ?logout=1)
  const urlParams = new URLSearchParams(window.location.search);
  const isForceRelock = urlParams.has("logout") || urlParams.has("lock") || urlParams.has("relock");
  if (isForceRelock) {
    sessionStorage.removeItem(ADMIN_TOKEN_KEY);
    localStorage.removeItem(ADMIN_TOKEN_KEY);
    localStorage.removeItem("kk_admin_authorized");
    localStorage.removeItem("kk_admin_device_linked");
    window.history.replaceState({}, document.title, window.location.pathname);
  }

  // Enforce session-level authentication: require valid token in sessionStorage or authorized device localStorage
  let token = sessionStorage.getItem(ADMIN_TOKEN_KEY);
  if (!token) {
    token = localStorage.getItem(ADMIN_TOKEN_KEY);
    if (token) {
      sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
    }
  }

  if (!token) {
    document.body.classList.remove("is-admin-user", "is-admin-authenticated");
    gateEl.style.display = "flex";
    rootEl.style.display = "none";
    const step1 = document.getElementById("adminAuthStep1");
    const step2 = document.getElementById("adminAuthStep2");
    if (step1) step1.style.display = "block";
    if (step2) step2.style.display = "none";
    const pinInput = document.getElementById("adminPinInput");
    if (pinInput) setTimeout(() => pinInput.focus(), 150);
    return;
  }

  // Verify token with server-side authentication endpoint
  try {
    const res = await fetch("/api/auth", {
      headers: { "Authorization": `Bearer ${token}` }
    });
    const data = await res.json();

    if (res.ok && data.authenticated) {
      document.body.classList.add("is-admin-user", "is-admin-authenticated");
      gateEl.style.display = "none";
      rootEl.style.display = "block";

      if (window.KK_DB) {
        window.KK_DB.syncFromCloud(false);
      }
      updateAdminHeaderBadge();
      renderAdminOverview();
      renderAdminOrders();
      renderAdminInventory();
      populateAdminCategorySelect();
    } else {
      // Invalid or expired token: show gate
      sessionStorage.removeItem(ADMIN_TOKEN_KEY);
      localStorage.removeItem(ADMIN_TOKEN_KEY);
      document.body.classList.remove("is-admin-user", "is-admin-authenticated");
      gateEl.style.display = "flex";
      rootEl.style.display = "none";
      const step1 = document.getElementById("adminAuthStep1");
      const step2 = document.getElementById("adminAuthStep2");
      if (step1) step1.style.display = "block";
      if (step2) step2.style.display = "none";
    }
  } catch (err) {
    // On verification failure, stay securely locked behind the gate
    sessionStorage.removeItem(ADMIN_TOKEN_KEY);
    document.body.classList.remove("is-admin-user", "is-admin-authenticated");
    gateEl.style.display = "flex";
    rootEl.style.display = "none";
  }
}

let otpTimerInterval = null;

async function handleAdminPinSubmit(e) {
  if (e) e.preventDefault();
  const pinInput = document.getElementById("adminPinInput");
  const errorEl = document.getElementById("adminPinError");
  const errorTextEl = document.getElementById("adminPinErrorText") || errorEl;
  const submitBtn = document.getElementById("adminPinSubmitBtn") || document.querySelector("#adminPinForm button[type='submit']");

  if (!pinInput) return;
  const val = pinInput.value.trim();
  if (!val) {
    if (errorEl) {
      if (errorTextEl) errorTextEl.textContent = "يرجى كتابة رمز المرور الرئيسي";
      errorEl.style.display = "flex";
    }
    return;
  }

  const originalBtnHtml = submitBtn ? submitBtn.innerHTML : "";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> <span>جارٍ إرسال كود الأمان للجيميل...</span>`;
  }

  try {
    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: val })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      if (errorEl) errorEl.style.display = "none";

      // Case A: 2FA OTP Step Required (Owner requested 6-digit email security)
      if (data.step === "otp_required") {
        const step1 = document.getElementById("adminAuthStep1");
        const step2 = document.getElementById("adminAuthStep2");
        if (step1) step1.style.display = "none";
        if (step2) step2.style.display = "block";

        // Initialize and focus empty 6-digit OTP boxes
        initOtpInputs();
        startOtpCountdownTimer(600); // 10 minutes

        const boxes = document.querySelectorAll(".otp-digit-box");
        boxes.forEach(box => { box.value = ""; });
        if (boxes[0]) boxes[0].focus();
        showToast("📧 تم إرسال كود التحقق السداسي إلى بريد الإدارة المعتمد بنجاح");
        return;
      }

      // Case B: Direct Token Authorized (Emergency bypass)
      if (data.token) {
        completeAdminAuthSuccess(data.token);
      }
    } else {
      if (errorEl) {
        if (errorTextEl) errorTextEl.textContent = data.error || "رمز الدخول غير صحيح";
        errorEl.style.display = "flex";
      }
      pinInput.value = "";
      pinInput.focus();
      showToast(data.error || "⚠️ رمز الدخول غير صحيح");
    }
  } catch (err) {
    showToast("⚠️ تعذر الاتصال بخادم المصادقة السحابي");
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalBtnHtml;
    }
  }
}

async function handleAdminOtpSubmit(e) {
  if (e) e.preventDefault();
  const digitBoxes = document.querySelectorAll(".otp-digit-box");
  const errorEl = document.getElementById("adminOtpError");
  const errorTextEl = document.getElementById("adminOtpErrorText") || errorEl;
  const submitBtn = document.getElementById("adminOtpSubmitBtn");

  let code = "";
  digitBoxes.forEach(box => {
    code += box.value.trim();
  });

  if (code.length !== 6) {
    if (errorEl) {
      if (errorTextEl) errorTextEl.textContent = "يرجى كتابة رمز الأمان السداسي كاملاً (6 أرقام)";
      errorEl.style.display = "flex";
    }
    return;
  }

  const originalBtnHtml = submitBtn ? submitBtn.innerHTML : "";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> <span>جارٍ مطابقة الرمز ومصادقة الجهاز...</span>`;
  }

  try {
    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "verify_otp", otp: code })
    });

    const data = await res.json();

    if (res.ok && data.success && data.token) {
      if (errorEl) errorEl.style.display = "none";
      if (otpTimerInterval) clearInterval(otpTimerInterval);
      completeAdminAuthSuccess(data.token);
    } else {
      if (errorEl) {
        if (errorTextEl) errorTextEl.textContent = data.error || "رمز التحقق غير صحيح أو انتهت صلاحيته";
        errorEl.style.display = "flex";
      }
      // Shake animation on OTP boxes
      const container = document.getElementById("otpBoxesContainer");
      if (container) {
        container.style.animation = "adminShake 0.4s ease";
        setTimeout(() => { if (container) container.style.animation = ""; }, 450);
      }
      digitBoxes.forEach(b => b.value = "");
      if (digitBoxes[0]) digitBoxes[0].focus();
      showToast(data.error || "⚠️ رمز التحقق غير صحيح");
    }
  } catch (err) {
    showToast("⚠️ تعذر التحقق من رمز الأمان سحابياً");
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalBtnHtml;
    }
  }
}

function completeAdminAuthSuccess(token) {
  sessionStorage.setItem(ADMIN_TOKEN_KEY, token);
  localStorage.setItem(ADMIN_TOKEN_KEY, token);
  localStorage.setItem("kk_admin_authorized", "true");
  localStorage.setItem("kk_admin_device_linked", "true");

  const gateEl = document.getElementById("adminAuthGate");
  const rootEl = document.getElementById("adminPageRoot");
  if (gateEl) gateEl.style.display = "none";
  if (rootEl) rootEl.style.display = "block";
  document.body.classList.add("is-admin-user", "is-admin-authenticated");

  showToast("✅ مرحباً بكم في لوحة تحكم معرض قاصد كريم (جلسة مشفرة)");

  if (window.KK_DB) {
    window.KK_DB.markAllOrdersAsRead();
    window.KK_DB.syncFromCloud(false);
  }
  updateAdminHeaderBadge();
  renderAdminOverview();
  renderAdminOrders();
  renderAdminInventory();
  renderAdminCategories();
  renderAdminBackupView();
}

function initOtpInputs() {
  const boxes = document.querySelectorAll(".otp-digit-box");
  if (!boxes || boxes.length === 0) return;

  boxes.forEach((box, idx) => {
    box.value = "";
    box.oninput = (e) => {
      const val = e.target.value.replace(/[^0-9]/g, "");
      e.target.value = val ? val[val.length - 1] : "";
      if (e.target.value && idx < boxes.length - 1) {
        boxes[idx + 1].focus();
      }
      // If all 6 digits entered, auto-submit
      let fullCode = "";
      boxes.forEach(b => fullCode += b.value);
      if (fullCode.length === 6) {
        handleAdminOtpSubmit();
      }
    };

    box.onkeydown = (e) => {
      if (e.key === "Backspace" && !box.value && idx > 0) {
        boxes[idx - 1].focus();
      }
    };

    box.onpaste = (e) => {
      e.preventDefault();
      const pasteData = (e.clipboardData || window.clipboardData).getData("text").replace(/[^0-9]/g, "");
      if (pasteData) {
        for (let i = 0; i < boxes.length; i++) {
          boxes[i].value = pasteData[i] || "";
        }
        if (pasteData.length >= 6) {
          boxes[5].focus();
          handleAdminOtpSubmit();
        } else {
          const nextIdx = Math.min(pasteData.length, boxes.length - 1);
          boxes[nextIdx].focus();
        }
      }
    };
  });

  setTimeout(() => {
    if (boxes[0]) boxes[0].focus();
  }, 100);
}

function startOtpCountdownTimer(durationSec = 600) {
  if (otpTimerInterval) clearInterval(otpTimerInterval);
  let remaining = durationSec;
  const timerEl = document.getElementById("otpCountdownTimer");

  const update = () => {
    const mins = Math.floor(remaining / 60);
    const secs = remaining % 60;
    if (timerEl) {
      timerEl.textContent = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
    }
    if (remaining <= 0) {
      clearInterval(otpTimerInterval);
      if (timerEl) timerEl.textContent = "منتهي الصلاحية";
    }
    remaining--;
  };

  update();
  otpTimerInterval = setInterval(update, 1000);
}

async function resendAdminOtp() {
  const pinInput = document.getElementById("adminPinInput");
  const val = pinInput ? pinInput.value.trim() : "";
  if (!val) {
    backToStep1();
    return;
  }
  showToast("⏳ جاري توليد وإرسال رمز أمان جديد للجيميل...");
  try {
    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: val })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      startOtpCountdownTimer(600);
      showToast("📧 تم إرسال كود أمان جديد إلى بريدك الإلكتروني بنجاح");
      const boxes = document.querySelectorAll(".otp-digit-box");
      boxes.forEach(b => b.value = "");
      if (boxes[0]) boxes[0].focus();
    } else {
      showToast(data.error || "⚠️ تعذر إعادة الإرسال");
    }
  } catch (e) {
    showToast("⚠️ تعذر الاتصال بالسيرفر");
  }
}

function backToStep1() {
  if (otpTimerInterval) clearInterval(otpTimerInterval);
  const step1 = document.getElementById("adminAuthStep1");
  const step2 = document.getElementById("adminAuthStep2");
  if (step1) step1.style.display = "block";
  if (step2) step2.style.display = "none";
  const pinInput = document.getElementById("adminPinInput");
  if (pinInput) {
    pinInput.focus();
    pinInput.select();
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
  const adminUrl = `${host}/admin.html`;

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(adminUrl).then(() => {
      showToast("📋 تم نسخ رابط لوحة التحكم بنجاح");
    }).catch(() => {
      prompt("رابط لوحة التحكم:", adminUrl);
    });
  } else {
    prompt("رابط لوحة التحكم:", adminUrl);
  }
}

function logoutAdmin() {
  sessionStorage.removeItem(ADMIN_TOKEN_KEY);
  localStorage.removeItem(ADMIN_TOKEN_KEY);
  localStorage.removeItem("kk_admin_authorized");
  localStorage.removeItem("kk_admin_device_linked");
  document.body.classList.remove("is-admin-user", "is-admin-authenticated", "is-admin-device");
  document.documentElement.classList.remove("is-admin-user", "is-admin-authenticated", "is-admin-device");
  showToast("تم تسجيل خروج الإدارة بنجاح");
  setTimeout(() => {
    window.location.reload();
  }, 400);
}

// Initialize Admin and Checkout systems on page load
document.addEventListener("DOMContentLoaded", () => {
  initAdminSystem();
});

function initAdminSystem() {
  const isAdminPage = !!document.getElementById("adminPageRoot");

  if (isAdminPage) {
    checkAdminSecurityGate();
  }

  updateAdminHeaderBadge();
  updateCustomerTrackingBadge();
  if (typeof updateAdminUsersCountBadge === "function") updateAdminUsersCountBadge();
  setupAdminListeners();

  // Listen to DB events
  window.addEventListener("kk_new_order_placed", (e) => {
    updateAdminHeaderBadge();
    const order = e.detail;
    const isAuth = document.body.classList.contains("is-admin-authenticated");

    // Live alert & sound ONLY for authenticated admin users
    if (isAuth) {
      showToast(`🔔 تنبيه إداري: تم استلام طلب جديد برقم #${order.id} بقيمة ${formatPrice(order.total)} ج.م`);
      if (window.KK_DB) window.KK_DB.playLuxuryChime();
      showAdminLiveOrderAlert(order);
      if (isAdminPage) {
        renderAdminOrders();
        renderAdminOverview();
      }
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

    if (document.body.classList.contains("is-admin-authenticated")) {
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

  // Listen to Categories update
  window.addEventListener("kk_categories_updated", () => {
    populateAdminCategorySelect();
    if (isAdminPage) {
      renderAdminCategories();
      renderAdminInventory();
    }
  });

  // Listen to Settings update
  window.addEventListener("kk_settings_updated", () => {
    if (isAdminPage) {
      loadAdminSettingsValues();
    }
  });

  // Listen to Restore Points update
  window.addEventListener("kk_restore_points_updated", () => {
    if (isAdminPage) {
      renderAdminBackupView();
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

async function promptAdminDeviceLink() {
  const pin = prompt("🔐 إعدادات الإدارة: أدخل رمز المرور السري لتسجيل دخول الإدارة:");
  if (!pin) return;
  try {
    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pin.trim() })
    });
    const data = await res.json();
    if (res.ok && data.success && data.token) {
      sessionStorage.setItem(ADMIN_TOKEN_KEY, data.token);
      localStorage.setItem(ADMIN_TOKEN_KEY, data.token);
      document.body.classList.add("is-admin-user");
      const adminBtn = document.getElementById("adminHeaderBtn");
      if (adminBtn) adminBtn.style.display = "inline-flex";
      if (typeof showToast === "function") {
        showToast("🛡️ تم تفعيل وربط هذا الجهاز كجهاز إدارة معتمد بنجاح ✓");
      }
    } else {
      alert("❌ رمز المرور غير صحيح");
    }
  } catch (e) {
    alert("⚠️ تعذر الاتصال بمركز التحقق السحابي");
  }
}

function showAdminLiveOrderAlert(order) {
  if (!order || !order.id) return;
  const isAdmin = document.body.classList.contains("is-admin-user") || !!document.getElementById("adminPageRoot");
  if (!isAdmin) return;

  // Never alert for seed orders or test dummy names
  if (order.id === "ORD-3985" || order.id === "ORD-8941" || order.id === "ORD-8820") return;
  if (order.customer && order.customer.name && (
    order.customer.name.includes("ككك") || 
    order.customer.name.includes("منك") || 
    order.customer.name === "test"
  )) return;

  // Prevent duplicate alert across sessions
  try {
    const notified = JSON.parse(localStorage.getItem("kk_notified_orders") || "[]");
    if (notified.includes(order.id) && (Date.now() - (order.timestamp || 0) > 60000)) {
      return;
    }
  } catch (e) {}

  if (sessionStorage.getItem("kk_dismissed_alert_" + order.id)) return;

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
        <button type="button" class="banner-close-btn" onclick="dismissAdminLiveOrderAlert('${order.id}')">×</button>
      </div>
    </div>
  `;
}

function dismissAdminLiveOrderAlert(orderId) {
  if (orderId) {
    sessionStorage.setItem("kk_dismissed_alert_" + orderId, "1");
  }
  const banner = document.getElementById("adminLiveOrderAlertBanner");
  if (banner) banner.remove();
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
  if (tabKey === "googleUsers") renderAdminGoogleUsers();
  if (tabKey === "inventory") renderAdminInventory();
  if (tabKey === "addProduct") populateAdminCategorySelect();
  if (tabKey === "bulkImport" && typeof clearBulkCsvForm === "function") clearBulkCsvForm();
  if (tabKey === "deliveryAreas" && typeof renderAdminDeliveryAreas === "function") renderAdminDeliveryAreas();
  if (tabKey === "reviews" && typeof renderAdminReviews === "function") renderAdminReviews();
  if (tabKey === "categories") renderAdminCategories();
  if (tabKey === "audit" && typeof renderAdminAuditLogs === "function") renderAdminAuditLogs();
  if (tabKey === "settings") loadAdminSettingsValues();
  if (tabKey === "backup") renderAdminBackupView();
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
function updateOrdersFilterButtonsUI(activeStatus) {
  const buttons = document.querySelectorAll("[data-order-filter]");
  buttons.forEach(btn => {
    const filter = btn.getAttribute("data-order-filter");
    if (filter === activeStatus) {
      btn.classList.add("is-active-filter");
      btn.style.background = "#0F172A";
      btn.style.color = "#FFFFFF";
      btn.style.borderColor = "#0F172A";
      btn.style.fontWeight = "800";
    } else {
      btn.classList.remove("is-active-filter");
      if (filter === "cancelled") {
        btn.style.background = "#FFFFFF";
        btn.style.color = "#DC2626";
        btn.style.borderColor = "rgba(220, 38, 38, 0.35)";
        btn.style.fontWeight = "600";
      } else {
        btn.style.background = "#FFFFFF";
        btn.style.color = "var(--text-main)";
        btn.style.borderColor = "var(--border-light)";
        btn.style.fontWeight = "600";
      }
    }
  });
}

function renderAdminOrders(statusFilter = null) {
  if (!window.KK_DB) return;
  if (statusFilter !== null) {
    window.currentAdminOrdersFilter = statusFilter;
  } else {
    statusFilter = window.currentAdminOrdersFilter || "all";
  }

  updateOrdersFilterButtonsUI(statusFilter);

  let orders = window.KK_DB.getOrders();
  const container = document.getElementById("adminOrdersListContainer");
  if (!container) return;

  // Strict Chronological Sort: Newest orders ALWAYS first
  orders.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

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
    const isNew = order.status === "received" || order.status === "pending";
    const statusLabels = {
      received: "تم الاستلام والتوثيق",
      pending: "تم الاستلام والتوثيق",
      confirmed: "تم التأكيد والمعاينة الفنية",
      preparing: "جاري التجهيز والتجميع بالمستودع",
      processing: "جاري التجهيز والتجميع بالمستودع",
      packed: "تم التغليف والتأمين",
      shipped: "خرج للشحن والتوصيل",
      delivered: "تم التسليم بنجاح",
      completed: "تم التسليم بنجاح",
      cancelled: "طلب ملغي",
      failed: "تعذر التسليم"
    };
    const statusText = statusLabels[order.status] || "قيد المعالجة";

    // Safe customer data extraction
    const customer = (order.customer && typeof order.customer === "object") ? order.customer : {};
    const customerName = customer.name || "عميل الكتالوج الفاخر";
    const customerPhone = customer.phone || "";
    const customerAddress = customer.address || "الشيخ زايد";
    const customerNotes = customer.notes || "";
    const deliveryAreaName = order.deliveryAreaName || customer.deliveryAreaName || customer.city || "الشيخ زايد";
    const shippingFee = order.shippingFee !== undefined ? order.shippingFee : (order.shipping !== undefined ? order.shipping : null);

    // COD Payment Status (PRD Section 5)
    const isPaid = order.paymentStatus === "collected";
    const paymentStatusBadge = isPaid
      ? `<span class="cod-collected-badge" style="background: rgba(16,185,129,0.12); color: #059669; font-weight: 800; font-size: 0.75rem; padding: 4px 10px; border-radius: 4px; display: inline-flex; align-items: center; gap: 0.35rem;"><i class="fas fa-check-circle"></i> تم تحصيل النقدية بالكامل</span>`
      : `<span class="cod-uncollected-badge" style="background: rgba(245,158,11,0.12); color: #D97706; font-weight: 800; font-size: 0.75rem; padding: 4px 10px; border-radius: 4px; display: inline-flex; align-items: center; gap: 0.35rem;"><i class="fas fa-hand-holding-dollar"></i> الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد</span>`;

    const paymentToggleBtn = isPaid
      ? `<button type="button" class="btn-secondary" style="font-size: 0.75rem; padding: 0.35rem 0.65rem; color: #DC2626;" onclick="toggleOrderPayment('${escapeHtml(order.id)}', 'uncollected')"><i class="fas fa-undo"></i> إلغاء تسجيل السداد</button>`
      : `<button type="button" class="btn-primary" style="font-size: 0.75rem; padding: 0.35rem 0.75rem; background: #10B981; border: none; font-weight: 800;" onclick="toggleOrderPayment('${escapeHtml(order.id)}', 'collected')"><i class="fas fa-check"></i> تسجيل استلام النقدية</button>`;

    // Safe items array extraction
    const items = Array.isArray(order.items) 
      ? order.items 
      : (order.items && typeof order.items === "object" ? Object.values(order.items) : []);

    let formattedDate = "اليوم";
    if (order.timestamp) {
      const d = new Date(order.timestamp);
      const datePart = d.toLocaleDateString("ar-EG", { timeZone: "Africa/Cairo", year: "numeric", month: "short", day: "numeric" });
      const timePart = d.toLocaleTimeString("ar-EG", { timeZone: "Africa/Cairo", hour: "2-digit", minute: "2-digit" });
      formattedDate = `${datePart} - ${timePart}`;
    } else if (order.dateFormatted) {
      formattedDate = order.timeFormatted ? `${order.dateFormatted} - ${order.timeFormatted}` : order.dateFormatted;
    }

    return `
      <div class="order-card-detailed ${isNew ? 'is-new-order' : ''}">
        <!-- Order Header -->
        <div class="order-header-row">
          <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
            <span class="order-id-tag">#${escapeHtml(order.id)}</span>
            <span class="order-date-text"><i class="fas fa-clock"></i> ${escapeHtml(formattedDate)}</span>
            ${isNew ? '<span class="new-live-tag"><i class="fas fa-bolt"></i> وارد الآن</span>' : ''}
            <div>${paymentStatusBadge}</div>
          </div>

          <div style="display: flex; align-items: center; gap: 0.75rem;">
            <span class="order-status-pill ${escapeHtml(order.status)}">${escapeHtml(statusText)}</span>
            <select class="custom-select" style="padding: 0.35rem 0.75rem; font-size: 0.78rem; font-weight: 700;" onchange="changeOrderStatus('${escapeHtml(order.id)}', this.value)">
              <option value="received" ${order.status === 'received' || order.status === 'pending' ? 'selected' : ''}>⏳ تم الاستلام والتوثيق (Received)</option>
              <option value="confirmed" ${order.status === 'confirmed' ? 'selected' : ''}>📋 تم التأكيد والمعاينة (Confirmed)</option>
              <option value="preparing" ${order.status === 'preparing' || order.status === 'processing' ? 'selected' : ''}>⚙️ جاري التجهيز (Preparing)</option>
              <option value="packed" ${order.status === 'packed' ? 'selected' : ''}>📦 تم التغليف (Packed)</option>
              <option value="shipped" ${order.status === 'shipped' ? 'selected' : ''}>🚚 خرج للتوصيل (Out for delivery)</option>
              <option value="delivered" ${order.status === 'delivered' || order.status === 'completed' ? 'selected' : ''}>✅ تم التسليم (Delivered)</option>
              <option value="cancelled" ${order.status === 'cancelled' ? 'selected' : ''}>❌ ملغي (Cancelled)</option>
              <option value="failed" ${order.status === 'failed' ? 'selected' : ''}>⚠️ تعذر التسليم (Delivery failed)</option>
            </select>
          </div>
        </div>

        <!-- Customer Details Box -->
        <div class="order-customer-box">
          <div class="customer-info-item">
            <strong>اسم العميل:</strong>
            <span style="font-weight: 800; color: #0F172A;">${escapeHtml(customerName)}</span>
          </div>
          <div class="customer-info-item">
            <strong>رقم الهاتف / الواتساب:</strong>
            ${customerPhone ? `
              <a href="tel:${escapeHtml(customerPhone)}" style="color: var(--accent-hover); font-weight: 800; text-decoration: none; dir: ltr;" dir="ltr">
                <i class="fas fa-phone-alt" style="font-size: 0.75rem;"></i> ${escapeHtml(customerPhone)}
              </a>
            ` : '<span style="color: var(--text-muted); font-size: 0.85rem;">غير مسجل</span>'}
          </div>
          <div class="customer-info-item">
            <strong>منطقة التوصيل:</strong>
            <span style="font-weight: 700; color: var(--text-main);">
              ${escapeHtml(deliveryAreaName)} ${shippingFee !== null ? `<span style="font-size: 0.78rem; color: #10B981;">(رسوم الشحن: ${shippingFee === 0 ? 'مجاناً' : shippingFee + ' ج.م'})</span>` : ''}
            </span>
          </div>
          <div class="customer-info-item">
            <strong>العنوان بالتفصيل:</strong>
            <span>${escapeHtml(customerAddress)}</span>
          </div>
          ${customerNotes ? `
            <div class="customer-info-item" style="grid-column: 1 / -1;">
              <strong>ملاحظات العميل:</strong>
              <span style="font-weight: 500; color: #475569;">${escapeHtml(customerNotes)}</span>
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
            ${items.length > 0 ? items.map(item => `
              <tr class="order-item-tr">
                <td class="col-product">
                  <div class="item-cell-with-img">
                    <img class="item-table-img" src="${escapeHtml(item.image || '')}" alt="${escapeHtml(item.name || 'وحدة إضاءة')}" onerror="this.src='https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=300&q=80'">
                    <div class="item-info-meta">
                      <div class="item-name-ar">${escapeHtml(item.name || 'وحدة إضاءة فاخرة')}</div>
                      <div class="item-name-en">${escapeHtml(item.enName || '')}</div>
                      <span class="item-cat-badge">${escapeHtml(item.categoryName || 'إضاءة فاخرة')}</span>
                    </div>
                  </div>
                </td>
                <td class="col-category">${escapeHtml(item.categoryName || 'إضاءة فاخرة')}</td>
                <td class="col-qty">
                  <span class="mobile-stat-label">الكمية</span>
                  <span class="qty-val">${item.qty || 1} وحدة</span>
                </td>
                <td class="col-price">
                  <span class="mobile-stat-label">سعر القطعة</span>
                  <span class="price-val">${formatPrice(item.price || 0)} ج.م</span>
                </td>
                <td class="col-total">
                  <span class="mobile-stat-label">الإجمالي</span>
                  <span class="total-val">${formatPrice((item.price || 0) * (item.qty || 1))} ج.م</span>
                </td>
              </tr>
            `).join("") : `
              <tr>
                <td colspan="5" class="order-no-items-cell" style="text-align: center; color: var(--text-muted); padding: 1.25rem;">
                  <i class="fas fa-boxes-stacked" style="margin-left: 0.45rem; color: var(--accent);"></i>
                  وحدات إضاءة تم اختيارها من الكتالوج بقيمة إجمالية ${formatPrice(order.total)} جنيه مصري
                </td>
              </tr>
            `}
          </tbody>
        </table>

        <!-- Order Footer Actions -->
        <div class="order-footer-actions">
          <div style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;">
            <div class="order-total-sum">
              إجمالي الطلب: <span style="color: var(--accent-hover);">${formatPrice(order.total)} جنيه مصري</span>
            </div>
            <div>${paymentToggleBtn}</div>
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
      received: "تم الاستلام والتوثيق",
      pending: "تم الاستلام والتوثيق",
      confirmed: "تم التأكيد والمعاينة الفنية",
      preparing: "جاري التجهيز والتجميع",
      processing: "جاري التجهيز والتجميع",
      packed: "تم التغليف والتأمين",
      shipped: "خرج للشحن والتوصيل للفيلا",
      delivered: "تم التسليم بنجاح",
      completed: "تم التسليم بنجاح",
      cancelled: "تم إلغاء الطلب واسترجاع المخزون",
      failed: "تعذر التسليم واسترجاع المخزون"
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

  const customer = (order.customer && typeof order.customer === "object") ? order.customer : {};
  const customerName = customer.name || "العميل الكريم";
  const customerAddress = customer.address || "الشيخ زايد";
  const items = Array.isArray(order.items) 
    ? order.items 
    : (order.items && typeof order.items === "object" ? Object.values(order.items) : []);

  let msg = `مرحباً ${customerName}، بخصوص طلبكم الكريم رقم #${order.id} من معرض قاصد كريم للإضاءة الفاخرة بالشيخ زايد:\n\n`;
  if (items.length > 0) {
    items.forEach((item, idx) => {
      msg += `${idx + 1}. ${item.name || 'وحدة إضاءة'} (${item.qty || 1} وحدة) - ${formatPrice((item.price || 0) * (item.qty || 1))} ج.م\n`;
    });
  } else {
    msg += `وحدات إضاءة تم اختيارها من الكتالوج.\n`;
  }
  msg += `\nإجمالي الطلب: ${formatPrice(order.total || 0)} جنيه مصري.\n`;
  if (customerAddress) {
    msg += `العنوان المسجل: ${customerAddress}\n\n`;
  }
  msg += `نحن جاهزون لتأكيد موعد المعاينة والتسليم، هل الموعد مناسب لسيادتكم؟`;

  let phone = (customer.phone || "").replace(/[^0-9]/g, "");
  if (!phone) {
    showToast("⚠️ رقم هاتف العميل غير متوفر في بيانات هذا الطلب");
    return;
  }
  if (phone.startsWith("0")) phone = "2" + phone;
  const url = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;
  window.open(url, "_blank");
}

// ----------------------------------------------------------------------------
// 5. RENDER INVENTORY & DELETE / EDIT PRODUCTS
// ----------------------------------------------------------------------------
function renderAdminInventory() {
  if (!window.KK_DB) return;
  const products = window.KK_DB.getProducts();
  const container = document.getElementById("adminInventoryTableBody");
  if (!container) return;

  container.innerHTML = products.map(item => {
    const unitsSold = item.salesCount || 0;
    const totalRev = unitsSold * (item.price || 0);

    return `
      <tr>
        <td style="width: 60px;">
          <img class="seller-thumb" src="${escapeHtml(item.image)}" alt="${escapeHtml(item.name)}" onerror="this.src='https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=300&q=80'">
        </td>
        <td>
          <div style="font-weight: 700; color: var(--text-main);">${escapeHtml(item.name)}</div>
          <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(item.categoryName)} • ضمان ${escapeHtml(item.warranty || '5 سنوات')}</div>
        </td>
        <td><span style="font-weight: 700;">${formatPrice(item.price)} ج.م</span></td>
        <td>
          <div style="font-weight: 800; color: #10B981; font-size: 0.92rem;">${formatPrice(totalRev)} ج.م</div>
          <span class="sales-badge" style="margin-top: 0.2rem; display: inline-block;">${unitsSold} وحدة مباعة</span>
        </td>
        <td>
          <div style="display: flex; gap: 0.45rem; align-items: center; justify-content: flex-end;">
            <button type="button" class="action-btn-sm" style="color: #2563EB; background: rgba(37,99,235,0.08); border: 1px solid rgba(37,99,235,0.25); border-radius: 6px; padding: 0.35rem 0.65rem; font-weight: 700; cursor: pointer; display: inline-flex; align-items: center; gap: 0.3rem;" onclick="openEditProductModal('${escapeHtml(item.id)}')" title="تعديل كافة تفاصيل القطعة">
              <i class="fas fa-pen-to-square"></i> تعديل
            </button>
            <button type="button" class="cart-item-remove-btn" style="color: #EF4444;" onclick="deleteProduct('${escapeHtml(item.id)}')" title="حذف المنتج من المتجر">
              <i class="fas fa-trash-alt"></i> حذف
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

async function deleteProduct(productId) {
  if (!confirm("هل أنت متأكد من حذف هذه القطعة من المتجر والكتالوج نهائياً ومزامنة الحذف على جميع الأجهزة؟")) return;
  if (window.KK_DB) {
    showToast("⏳ جاري حذف القطعة ومزامنة المتجر سحابياً...");
    await window.KK_DB.deleteProduct(productId);
    showToast("✅ تم حذف القطعة وتحديث وحدات المعرض بنجاح!");
    renderAdminOverview();
    renderAdminInventory();
    renderAdminBackupView();
  }
}

// ----------------------------------------------------------------------------
// 5.1 DEDICATED LUXURY PRODUCT EDITOR STUDIO & CLOUD SYNC CONTROLLER
// ----------------------------------------------------------------------------
function openProductEditorPage(productId) {
  if (!window.KK_DB) return;
  const product = window.KK_DB.getProductById(productId);
  if (!product) {
    showToast("⚠️ لم يتم العثور على المنتج المطلوب");
    return;
  }

  // Populate Categories Select
  const catSelect = document.getElementById("editProductCategory");
  if (catSelect) {
    const cats = window.KK_DB.getCategories().filter(c => c.id !== "all");
    catSelect.innerHTML = cats.map(c => `
      <option value="${escapeHtml(c.id)}" ${c.id === product.category ? "selected" : ""}>
        ${escapeHtml(c.name)}
      </option>
    `).join("");
  }

  // Display badges & title
  const displayNameEl = document.getElementById("editorProductDisplayName");
  if (displayNameEl) displayNameEl.textContent = product.name || "";
  const idBadgeEl = document.getElementById("editorProductIdBadge");
  if (idBadgeEl) idBadgeEl.textContent = `ID: ${product.id}`;

  // Populate Basic Fields
  const setVal = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.value = (val !== undefined && val !== null) ? val : "";
  };

  setVal("editProductId", product.id);
  setVal("editProductName", product.name);
  setVal("editProductEnName", product.enName);
  setVal("editProductStyle", product.style);
  setVal("editProductPrice", product.price || 0);
  setVal("editProductOriginalPrice", product.originalPrice || "");
  setVal("editProductWarranty", product.warranty || "5 سنوات ضمان معتمد");
  setVal("editProductDescription", product.description || "");

  // Badges
  const setChk = (id, checked) => {
    const el = document.getElementById(id);
    if (el) el.checked = !!checked;
  };
  setChk("editProductIsNew", product.isNew);
  setChk("editProductIsExclusive", product.isExclusive);
  setChk("editProductIsBestSeller", product.isBestSeller);

  // Specifications
  const specs = product.specs || {};
  setVal("editProductDimensions", specs.dimensions || "");
  setVal("editProductMaterial", specs.material || "");
  setVal("editProductColorTemp", specs.colorTemp || "");
  setVal("editProductWattage", specs.wattage || "");

  // Images
  const imgUrl = product.image || "";
  const secImgUrl = product.secondaryImage || "";
  setVal("editProductImageUrl", imgUrl);
  setVal("editProductSecondaryImageUrl", secImgUrl);

  const previewEl = document.getElementById("editProductImagePreview");
  const placeholderEl = document.getElementById("editProductImagePlaceholder");
  if (previewEl && placeholderEl) {
    if (imgUrl) {
      previewEl.src = imgUrl;
      previewEl.style.display = "block";
      placeholderEl.style.display = "none";
    } else {
      previewEl.style.display = "none";
      placeholderEl.style.display = "block";
    }
  }

  const secPreviewEl = document.getElementById("editProductSecondaryImagePreview");
  const secPlaceholderEl = document.getElementById("editProductSecondaryImagePlaceholder");
  if (secPreviewEl && secPlaceholderEl) {
    if (secImgUrl) {
      secPreviewEl.src = secImgUrl;
      secPreviewEl.style.display = "block";
      secPlaceholderEl.style.display = "none";
    } else {
      secPreviewEl.style.display = "none";
      secPlaceholderEl.style.display = "block";
    }
  }

  // Update Live Preview Card
  updateLiveEditorPreview();

  // Switch to dedicated studio pane and scroll to top
  switchAdminTab("editProduct");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// Keep backwards-compatible alias so inventory table buttons work flawlessly
window.openEditProductModal = openProductEditorPage;

function closeProductEditor() {
  // Return smoothly to the inventory tab
  const invTabBtn = document.querySelectorAll(".admin-tab-btn")[3] || document.querySelector('[onclick*="inventory"]');
  switchAdminTab("inventory", invTabBtn);
  window.scrollTo({ top: 0, behavior: "smooth" });
}
window.closeEditProductModal = closeProductEditor;

function resetEditSecondaryImage(e) {
  if (e) e.preventDefault();
  const secInput = document.getElementById("editProductSecondaryImageUrl");
  if (secInput) secInput.value = "";
  const secPreview = document.getElementById("editProductSecondaryImagePreview");
  const secPlaceholder = document.getElementById("editProductSecondaryImagePlaceholder");
  if (secPreview) secPreview.style.display = "none";
  if (secPlaceholder) secPlaceholder.style.display = "block";
  updateLiveEditorPreview();
  showToast("تم إزالة الصورة الإضافية للقطعة");
}

function updateLiveEditorPreview() {
  const name = document.getElementById("editProductName")?.value?.trim() || "اسم وحدة الإضاءة";
  const enName = document.getElementById("editProductEnName")?.value?.trim() || "";
  const catSelect = document.getElementById("editProductCategory");
  const catName = catSelect?.options[catSelect.selectedIndex]?.text?.trim() || "القسم الرئيسي";
  const price = parseFloat(document.getElementById("editProductPrice")?.value) || 0;
  const origPriceVal = document.getElementById("editProductOriginalPrice")?.value?.trim();
  const origPrice = origPriceVal ? parseFloat(origPriceVal) : null;
  const imgUrl = document.getElementById("editProductImageUrl")?.value?.trim() || "https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=800&q=80";

  const isNew = document.getElementById("editProductIsNew")?.checked;
  const isExclusive = document.getElementById("editProductIsExclusive")?.checked;
  const isBestSeller = document.getElementById("editProductIsBestSeller")?.checked;

  const dims = document.getElementById("editProductDimensions")?.value?.trim();
  const material = document.getElementById("editProductMaterial")?.value?.trim();

  // Update image preview & live card
  const previewLiveImg = document.getElementById("previewLiveImg");
  if (previewLiveImg) previewLiveImg.src = imgUrl;

  const mainPreviewImg = document.getElementById("editProductImagePreview");
  const mainPlaceholder = document.getElementById("editProductImagePlaceholder");
  if (mainPreviewImg && mainPlaceholder) {
    if (imgUrl) {
      mainPreviewImg.src = imgUrl;
      mainPreviewImg.style.display = "block";
      mainPlaceholder.style.display = "none";
    } else {
      mainPreviewImg.style.display = "none";
      mainPlaceholder.style.display = "block";
    }
  }

  // Update titles & category
  const titleEl = document.getElementById("previewLiveTitle");
  if (titleEl) titleEl.textContent = name;
  const enTitleEl = document.getElementById("previewLiveEnTitle");
  if (enTitleEl) {
    enTitleEl.textContent = enName;
    enTitleEl.style.display = enName ? "block" : "none";
  }
  const catEl = document.getElementById("previewLiveCat");
  if (catEl) catEl.textContent = catName;

  // Update specs preview
  const specsEl = document.getElementById("previewLiveSpecs");
  if (specsEl) {
    const specParts = [];
    if (dims) specParts.push(`الأبعاد: ${dims}`);
    if (material) specParts.push(`الخامة: ${material}`);
    specsEl.textContent = specParts.length > 0 ? specParts.join(" • ") : "المواصفات: تصميم فندقي فاخر";
  }

  // Update price and discount
  const priceEl = document.getElementById("previewLivePrice");
  if (priceEl) priceEl.textContent = `${formatPrice(price)} ج.م`;

  const origPriceEl = document.getElementById("previewLiveOriginalPrice");
  const discountPillEl = document.getElementById("previewLiveDiscountPill");
  if (origPrice && origPrice > price) {
    if (origPriceEl) {
      origPriceEl.textContent = `${formatPrice(origPrice)} ج.م`;
      origPriceEl.style.display = "inline";
    }
    if (discountPillEl) {
      const discountPct = Math.round(((origPrice - price) / origPrice) * 100);
      discountPillEl.textContent = `خصم ${discountPct}%`;
      discountPillEl.style.display = "inline-block";
    }
  } else {
    if (origPriceEl) origPriceEl.style.display = "none";
    if (discountPillEl) discountPillEl.style.display = "none";
  }

  // Update badges
  const badgesWrap = document.getElementById("previewBadgesWrap");
  if (badgesWrap) {
    let badgesHtml = "";
    if (isNew) badgesHtml += `<span class="badge-new" style="background: #10B981; color: #fff; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.72rem; font-weight: 800;">جديد 2026</span>`;
    if (isExclusive) badgesHtml += `<span class="badge-exclusive" style="background: #D97706; color: #fff; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.72rem; font-weight: 800;">حصري</span>`;
    if (isBestSeller) badgesHtml += `<span class="badge-bestseller" style="background: #DC2626; color: #fff; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.72rem; font-weight: 800;">الأكثر طلباً</span>`;
    badgesWrap.innerHTML = badgesHtml;
  }
}

async function handleEditProductSubmit(e) {
  if (e) e.preventDefault();
  if (!window.KK_DB) return;

  const id = document.getElementById("editProductId")?.value;
  const name = document.getElementById("editProductName")?.value?.trim();
  const catSelect = document.getElementById("editProductCategory");
  const category = catSelect?.value;
  const categoryName = catSelect?.options[catSelect.selectedIndex]?.text?.trim() || "";
  const price = parseFloat(document.getElementById("editProductPrice")?.value) || 0;
  const originalPriceVal = document.getElementById("editProductOriginalPrice")?.value?.trim();
  const originalPrice = originalPriceVal ? parseFloat(originalPriceVal) : null;
  const warranty = document.getElementById("editProductWarranty")?.value?.trim() || "5 سنوات ضمان معتمد";
  const image = document.getElementById("editProductImageUrl")?.value?.trim() || "https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=800&q=80";
  const secondaryImage = document.getElementById("editProductSecondaryImageUrl")?.value?.trim();
  const description = document.getElementById("editProductDescription")?.value?.trim();
  const enName = document.getElementById("editProductEnName")?.value?.trim();
  const style = document.getElementById("editProductStyle")?.value?.trim();

  if (!id) {
    showToast("⚠️ لم يتم تحديد معرّف القطعة");
    return;
  }
  if (!name) {
    showToast("⚠️ يرجى إدخال اسم القطعة");
    return;
  }

  const updatedData = {
    name,
    enName,
    category,
    categoryName,
    style,
    price,
    originalPrice,
    warranty,
    image,
    secondaryImage,
    description,
    isNew: !!document.getElementById("editProductIsNew")?.checked,
    isExclusive: !!document.getElementById("editProductIsExclusive")?.checked,
    isBestSeller: !!document.getElementById("editProductIsBestSeller")?.checked,
    specs: {
      dimensions: document.getElementById("editProductDimensions")?.value?.trim() || "",
      material: document.getElementById("editProductMaterial")?.value?.trim() || "",
      colorTemp: document.getElementById("editProductColorTemp")?.value?.trim() || "",
      wattage: document.getElementById("editProductWattage")?.value?.trim() || ""
    }
  };

  const saveBtn = document.getElementById("saveProductEditorBtn");
  const originalSaveBtnHtml = saveBtn ? saveBtn.innerHTML : "";
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> <span>جارٍ الحفظ والمزامنة السحابية...</span>`;
  }

  showToast("⏳ جاري حفظ وتطبيق تعديلات المنتج ومزامنتها سحابياً...");

  try {
    const res = await window.KK_DB.updateProduct(id, updatedData);
    if (res && res.success) {
      showToast("✅ تم حفظ وتطبيق تعديلات المنتج ومزامنتها سحابياً بنجاح!");
      closeProductEditor();
      renderAdminOverview();
      renderAdminInventory();
      renderAdminBackupView();
    } else {
      showToast(`⚠️ ${res?.error || "تعذر حفظ التعديلات"}`);
    }
  } catch (err) {
    showToast("⚠️ حدث خطأ أثناء المزامنة السحابية");
  } finally {
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.innerHTML = originalSaveBtnHtml;
    }
  }
}

async function handleEditImageUpload(file, isSecondary = false) {
  if (!file) return;
  try {
    showToast("⏳ جاري ضغط ومعالجة الصورة...");
    const base64 = await compressImageFile(file, 900, 900, 0.78);
    if (isSecondary) {
      document.getElementById("editProductSecondaryImageUrl").value = base64;
      const previewEl = document.getElementById("editProductSecondaryImagePreview");
      const placeholderEl = document.getElementById("editProductSecondaryImagePlaceholder");
      if (previewEl && placeholderEl) {
        previewEl.src = base64;
        previewEl.style.display = "block";
        placeholderEl.style.display = "none";
      }
    } else {
      document.getElementById("editProductImageUrl").value = base64;
      const previewEl = document.getElementById("editProductImagePreview");
      const placeholderEl = document.getElementById("editProductImagePlaceholder");
      if (previewEl && placeholderEl) {
        previewEl.src = base64;
        previewEl.style.display = "block";
        placeholderEl.style.display = "none";
      }
    }
    showToast("✅ تم تحميل وضغط الصورة بنجاح");
  } catch (err) {
    showToast("⚠️ تعذر معالجة الصورة، تأكد من صيغتها");
  }
}



function exportCatalogData() {
  if (!window.KK_DB) return;
  const prods = window.KK_DB.getProducts();
  const jsonStr = "const INITIAL_PRODUCTS = " + JSON.stringify(prods, null, 2) + ";\n";
  const blob = new Blob([jsonStr], { type: "application/javascript;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `kased_karim_catalog_${new Date().toISOString().slice(0, 10)}.js`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  showToast("تم تصدير ملف الكتالوج بنجاح!");
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
  const catObj = typeof CATEGORIES !== "undefined" ? CATEGORIES.find(c => c.id === category) : null;
  const rawCatOptionText = form.adminUnitCategory && form.adminUnitCategory.selectedIndex >= 0
    ? form.adminUnitCategory.options[form.adminUnitCategory.selectedIndex].text.split("(")[0].trim()
    : "دلايات";
  const categoryName = catObj ? catObj.name : rawCatOptionText;

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
    showToast("يرجى اختيار وحدات إضاءة أولاً لتأكيد طلبك");
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
    return { valid: false, message: "يرجى كتابة الاسم الكريم للعميل" };
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
async function renderCloudDbSettings() {
  const currentUrl = localStorage.getItem("kk_custom_cloud_url") || (window.KK_DB ? window.KK_DB.getCustomCloudUrl() : "https://kased-karim-default-rtdb.firebaseio.com");
  const inputEl = document.getElementById("cloudDbUrlInput");
  const statusEl = document.getElementById("cloudDbStatusPill");
  if (inputEl) inputEl.value = currentUrl;

  if (!statusEl) return;

  if (currentUrl) {
    statusEl.innerHTML = `<i class="fas fa-spinner fa-spin" style="color: var(--accent);"></i> <span>جاري فحص الاتصال بالرابط المخصص...</span>`;
    try {
      const cleanUrl = currentUrl.trim().replace(/\/$/, "");
      const res = await fetch(`${cleanUrl}/.json?shallow=true`, { cache: "no-store" });
      if (res.ok) {
        statusEl.innerHTML = `<i class="fas fa-circle-check" style="color: #10B981;"></i> <span style="color: #065F46;">متصل ومفعل مباشرة بسحابة Firebase (جاهز 100%)</span>`;
        statusEl.style.background = "#ECFDF5";
        return;
      }
    } catch (e) {}
    statusEl.innerHTML = `<i class="fas fa-triangle-exclamation" style="color: #F59E0B;"></i> <span style="color: #92400E;">رابط مخصص مسجل (جاري التحقق من الصلاحيات)</span>`;
    statusEl.style.background = "#FFFBEB";
    return;
  }

  // Check Vercel serverless /api/db-health
  try {
    const res = await fetch("/api/db-health");
    if (res.ok) {
      const data = await res.json();
      if (data.database && (data.database.kvConnected || data.database.firebaseConnected)) {
        statusEl.innerHTML = `<i class="fas fa-circle-check" style="color: #10B981;"></i> <span style="color: #065F46;">متصل تلقائياً بقاعدة بيانات Vercel Serverless</span>`;
        statusEl.style.background = "#ECFDF5";
        return;
      }
    }
  } catch (e) {}

  statusEl.innerHTML = `<i class="fas fa-cloud" style="color: #3B82F6;"></i> <span style="color: #1E40AF;">السحابة بانتظار إدخال الرابط (أدخل رابط Firebase أدناه)</span>`;
  statusEl.style.background = "#EFF6FF";
}

async function testCloudDbConnection() {
  const currentUrl = (localStorage.getItem("kk_custom_cloud_url") || "").trim();
  showToast("جاري اختبار الاتصال اللحظي بالسحابة...");

  const startTime = Date.now();

  // Test 1: Direct Firebase RTDB ping if configured
  if (currentUrl) {
    try {
      const cleanUrl = currentUrl.replace(/\/$/, "");
      const res = await fetch(`${cleanUrl}/.json?shallow=true&t=${Date.now()}`, { cache: "no-store" });
      const latency = Date.now() - startTime;
      if (res.ok) {
        showToast(`✅ الاتصال بسحابة Firebase ممتاز ومستقر! (زمن الاستجابة: ${latency}ms)`);
        renderCloudDbSettings();
        return;
      }
    } catch (e) {}
  }

  // Test 2: Serverless Endpoint Health
  try {
    const res = await fetch(`/api/db-health?t=${Date.now()}`, {
      headers: window.KK_DB ? window.KK_DB.getCloudHeaders() : {}
    });
    const latency = Date.now() - startTime;
    if (res.ok) {
      const data = await res.json();
      if (data.database && data.database.readyForProduction) {
        showToast(`✅ الاتصال بقاعدة بيانات Vercel يعمل بنجاح! (${latency}ms)`);
        renderCloudDbSettings();
        return;
      }
    }
  } catch (e) {}

  if (currentUrl) {
    showToast("⚠️ تم إرسال الطلب للرابط ولكن يرجى التأكد من ضبط Realtime Database على (Test Mode) بالقراءة والكتابة.");
  } else {
    showToast("ℹ️ لم يتم ربط سحابة بعد. يرجى إدخال رابط Firebase Realtime Database أدناه لتفعيل المزامنة الشاملة.");
  }
  renderCloudDbSettings();
}

async function saveCustomCloudUrl() {
  const inputEl = document.getElementById("cloudDbUrlInput");
  if (!inputEl) return;
  const url = inputEl.value.trim();
  if (url) {
    localStorage.setItem("kk_custom_cloud_url", url);
    if (window.KK_DB) {
      window.KK_DB.setCustomCloudUrl(url);
    }
    showToast("✅ تم حفظ وتفعيل رابط السحابة المخصص بنجاح! جاري اختبار الاتصال...");
    await testCloudDbConnection();
    if (window.KK_DB) {
      window.KK_DB.forceSyncNow();
    }
  } else {
    clearCustomCloudUrl();
  }
}

function clearCustomCloudUrl() {
  localStorage.removeItem("kk_custom_cloud_url");
  if (window.KK_DB) {
    window.KK_DB.setCustomCloudUrl("");
  }
  const inputEl = document.getElementById("cloudDbUrlInput");
  if (inputEl) inputEl.value = "";
  showToast("تمت استعادة الربط الافتراضي عبر Vercel Serverless");
  renderCloudDbSettings();
}

async function syncAllCatalogToCloudNow(btn) {
  if (!window.KK_DB) return;
  const originalHtml = btn ? btn.innerHTML : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> جاري رفع الكتالوج للسحابة...`;
  }

  try {
    showToast("جاري إرسال جميع وحدات الإضاءة بالمعرض لقاعدة البيانات السحابية...");
    const count = await window.KK_DB.syncAllLocalProductsToCloud();
    showToast(`🎉 اكتملت المزامنة بنجاح! تم رفع ومزامنة ${count} قطعة إضاءة في السحابة لتظهر فوراً لجميع الأجهزة.`);
  } catch (e) {
    showToast("حدث خطأ أثناء المزامنة الشاملة: " + e.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
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

  // Real-time live polling while modal is open (every 3 seconds)
  if (window.trackOrderLiveInterval) {
    clearInterval(window.trackOrderLiveInterval);
  }
  window.trackOrderLiveInterval = setInterval(async () => {
    if (window.currentTrackedOrderId && document.getElementById("trackOrderModal")?.classList.contains("active")) {
      if (window.KK_DB) {
        const fresh = await window.KK_DB.fetchLiveOrder(window.currentTrackedOrderId);
        if (fresh) {
          renderTrackedOrderUI(fresh);
        }
      }
    }
  }, 3000);
}

function closeTrackOrderModal() {
  const modal = document.getElementById("trackOrderModal");
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
  if (window.trackOrderLiveInterval) {
    clearInterval(window.trackOrderLiveInterval);
    window.trackOrderLiveInterval = null;
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

function saveCustomerRecentOrder(orderId) {
  try {
    const recent = JSON.parse(localStorage.getItem("kk_customer_recent_orders") || "[]");
    if (!recent.includes(orderId)) {
      recent.unshift(orderId);
      localStorage.setItem("kk_customer_recent_orders", JSON.stringify(recent.slice(0, 10)));
    }
    localStorage.setItem("kk_last_placed_order_id", orderId);
    renderCustomerRecentOrderChips();
    updateCustomerTrackingBadge();
  } catch (e) {}
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

  // 1. Immediately render cached version for instant zero-lag response
  if (found) {
    renderTrackedOrderUI(found);
    saveCustomerRecentOrder(found.id);
  }

  // 2. ALWAYS fetch fresh live status from cloud to guarantee admin status updates are shown instantly
  if (window.KK_DB) {
    try {
      const targetId = found ? found.id : cleanQuery;
      const freshOrder = await window.KK_DB.fetchLiveOrder(targetId);
      if (freshOrder) {
        found = freshOrder;
        renderTrackedOrderUI(freshOrder);
        saveCustomerRecentOrder(freshOrder.id);
      } else if (!found) {
        // Fallback full sync
        await window.KK_DB.forceSyncNow();
        orders = window.KK_DB.getOrders();
        found = orders.find(o => 
          o.id.toUpperCase() === cleanQuery || 
          o.id.replace("ORD-", "") === cleanQuery ||
          (o.customer && o.customer.phone && o.customer.phone.replace(/[^0-9]/g, "").includes(cleanQuery.replace(/[^0-9]/g, "")))
        );
        if (found) {
          renderTrackedOrderUI(found);
          saveCustomerRecentOrder(found.id);
        }
      }
    } catch (e) {}
  }

  if (!found) {
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
            <div style="font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-brand);">${item.categoryName || 'إضاءة فاخرة'} • الكمية: ${item.qty}</div>
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
    if (msgText) msgText.textContent = "تم استلام وتسجيل طلبك بنجاح، وقيد المراجعة وتأكيد الموعد بمعرض قاصد كريم بالشيخ زايد.";
  } else if (status === "confirmed") {
    if (stepperFill) stepperFill.style.width = "35%";
    if (steps[0]) steps[0].classList.add("completed");
    if (steps[1]) steps[1].classList.add("active");
    if (badgeDisplay) {
      badgeDisplay.className = "status-badge-live status-confirmed";
      badgeDisplay.innerHTML = `<i class="fas fa-check-double"></i> تم التأكيد والحجز`;
    }
    if (msgBox) {
      msgBox.style.background = "#EFF6FF";
      msgBox.style.borderColor = "#BFDBFE";
      msgBox.style.color = "#1E40AF";
    }
    if (msgText) msgText.textContent = "تم تأكيد طلب وحدات الإضاءة بنجاح، والطلب معتمد للتجهيز والتسليم.";
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
    if (msgText) msgText.textContent = "جاري تجميع وفحص واختبار وحدات الإضاءة بمستودع المعرض بالشيخ زايد للتأكد من مطابقتها لأعلى معايير الجودة.";
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
    if (msgText) msgText.textContent = "خرجت الشحنة مع مندوب التوصيل المعتمد بالشيخ زايد، وجاري التوجه لموقع الفيلا / العقار المحدد.";
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
    if (msgText) msgText.textContent = "تم إلغاء هذا الطلب. للاستفسار أو لطلب وحدات جديدة يمكنك التواصل مباشرة مع إدارة المعرض.";
  }
}

async function refreshCurrentTrackOrder(btn) {
  const icon = document.getElementById("trackRefreshIcon");
  if (icon) icon.classList.add("fa-spin");
  if (btn) btn.disabled = true;

  try {
    if (window.KK_DB && window.currentTrackedOrderId) {
      const fresh = await window.KK_DB.fetchLiveOrder(window.currentTrackedOrderId);
      if (fresh) {
        renderTrackedOrderUI(fresh);
        showToast("✅ تم تحديث حالة الطلب لحظياً من السحابة بنجاح");
      } else {
        await window.KK_DB.forceSyncNow();
        const order = window.KK_DB.getOrders().find(o => o.id === window.currentTrackedOrderId);
        if (order) renderTrackedOrderUI(order);
        showToast("✅ تم تحديث حالة الطلب بنجاح");
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
  const settings = window.KK_DB ? window.KK_DB.getSettings() : {};
  const phone = settings.whatsapp || "201006367690";
  const url = `https://wa.me/${phone}?text=${encodeURIComponent(msg)}`;
  window.open(url, "_blank");
}

// ============================================================================
// 10. CATEGORY MANAGEMENT CONTROLLERS (إدارة أقسام وأقسام فرعية بالمعرض)
// ============================================================================
function populateAdminCategorySelect() {
  const select = document.getElementById("adminUnitCategory");
  const parentSelect = document.getElementById("newCategoryParent");
  if (!window.KK_DB) return;

  const categories = window.KK_DB.getCategories();
  const mainCats = categories.filter(c => !c.parentId && c.id !== "all");

  // 1. Populate category selector in Add Product form
  if (select) {
    const currentVal = select.value;
    let html = `<option value="" disabled ${!currentVal ? "selected" : ""}>-- اختر قسم الإضاءة من القائمة --</option>`;

    mainCats.forEach(main => {
      const subCats = categories.filter(c => c.parentId === main.id);
      if (subCats.length === 0) {
        html += `<option value="${main.id}" ${currentVal === main.id ? "selected" : ""}>${main.name}</option>`;
      } else {
        html += `<optgroup label="${main.name}">`;
        html += `<option value="${main.id}" ${currentVal === main.id ? "selected" : ""}>${main.name} (عام)</option>`;
        subCats.forEach(sub => {
          html += `<option value="${sub.id}" ${currentVal === sub.id ? "selected" : ""}>↳ ${sub.name}</option>`;
        });
        html += `</optgroup>`;
      }
    });
    select.innerHTML = html;
  }

  // 2. Populate parent category selector in Add Category form
  if (parentSelect) {
    const currentParent = parentSelect.value;
    let parentHtml = `<option value="">-- قسم رئيسي مستقل (بدون قسم رئيسي) --</option>`;
    mainCats.forEach(m => {
      parentHtml += `<option value="${m.id}" ${currentParent === m.id ? "selected" : ""}>${m.name}</option>`;
    });
    parentSelect.innerHTML = parentHtml;
  }
}

function renderAdminCategories() {
  const tbody = document.getElementById("adminCategoriesTableBody");
  const countEl = document.getElementById("adminCategoriesTotalCount");
  if (!tbody || !window.KK_DB) return;

  const categories = window.KK_DB.getCategories();
  const products = window.KK_DB.getProducts();

  if (countEl) countEl.textContent = categories.length;

  const mainCats = categories.filter(c => !c.parentId);
  const rows = [];

  mainCats.forEach(main => {
    const isAll = main.id === "all";
    const subCats = categories.filter(c => c.parentId === main.id);
    const subCatIds = subCats.map(s => s.id);
    const prodCount = isAll ? products.length : products.filter(p => p.category === main.id || subCatIds.includes(p.category)).length;

    rows.push(`
      <tr style="background: ${isAll ? '#F8FAFC' : '#FFFFFF'};">
        <td>
          <span style="display: inline-flex; align-items: center; gap: 0.35rem; background: rgba(245, 158, 11, 0.15); color: #B45309; padding: 0.25rem 0.65rem; border-radius: 6px; font-weight: 800; font-size: 0.78rem;">
            <i class="fas fa-layer-group"></i> قسم رئيسي
          </span>
        </td>
        <td>
          <div style="font-weight: 800; color: #0F172A; font-size: 0.95rem;">${main.name}</div>
          <code style="font-size: 0.72rem; color: #64748B;">ID: ${main.id}</code>
        </td>
        <td>
          <span style="color: var(--text-muted); font-size: 0.82rem;">-</span>
        </td>
        <td>
          <span style="font-weight: 800; color: var(--accent);">${prodCount} قطعة</span>
        </td>
        <td>
          <div class="action-btn-group">
            ${isAll ? `
              <span style="font-size: 0.75rem; color: var(--text-muted);">قسم أساسي ثابت</span>
            ` : `
              <button type="button" class="action-btn-sm" onclick="editCategoryPrompt('${main.id}')" title="تعديل اسم القسم">
                <i class="fas fa-pen-to-square"></i> تعديل
              </button>
              <button type="button" class="action-btn-sm btn-danger" onclick="deleteCategoryConfirm('${main.id}')" title="حذف القسم وجميع أقسامه الفرعية">
                <i class="fas fa-trash-alt"></i> حذف
              </button>
            `}
          </div>
        </td>
      </tr>
    `);

    subCats.forEach(sub => {
      const subProdCount = products.filter(p => p.category === sub.id).length;
      rows.push(`
        <tr style="background: #F8FAFC;">
          <td>
            <span style="display: inline-flex; align-items: center; gap: 0.35rem; background: rgba(59, 130, 246, 0.1); color: #1D4ED8; padding: 0.2rem 0.6rem; border-radius: 6px; font-weight: 700; font-size: 0.75rem;">
              <i class="fas fa-arrow-turn-down-right"></i> قسم فرعي
            </span>
          </td>
          <td style="padding-right: 1.5rem;">
            <div style="font-weight: 700; color: #1E293B; font-size: 0.9rem;">↳ ${sub.name}</div>
            <code style="font-size: 0.72rem; color: #94A3B8;">ID: ${sub.id}</code>
          </td>
          <td>
            <span style="font-size: 0.82rem; font-weight: 700; color: #475569;">${main.name}</span>
          </td>
          <td>
            <span style="font-weight: 700; color: #2563EB;">${subProdCount} قطعة</span>
          </td>
          <td>
            <div class="action-btn-group">
              <button type="button" class="action-btn-sm" onclick="editCategoryPrompt('${sub.id}')" title="تعديل اسم القسم الفرعي">
                <i class="fas fa-pen-to-square"></i> تعديل
              </button>
              <button type="button" class="action-btn-sm btn-danger" onclick="deleteCategoryConfirm('${sub.id}')" title="حذف القسم الفرعي">
                <i class="fas fa-trash-alt"></i> حذف
              </button>
            </div>
          </td>
        </tr>
      `);
    });
  });

  tbody.innerHTML = rows.join("");
}

async function handleAdminAddCategory(e) {
  e.preventDefault();
  const nameInput = document.getElementById("newCategoryName");
  const parentSelect = document.getElementById("newCategoryParent");

  const name = nameInput ? nameInput.value.trim() : "";
  const parentId = parentSelect ? parentSelect.value.trim() : null;

  if (!name) {
    showToast("⚠️ يرجى إدخال اسم القسم");
    return;
  }

  if (window.KK_DB) {
    showToast("⏳ جاري إضافة القسم ومزامنته سحابياً...");
    const res = await window.KK_DB.addCategory({ name, parentId });
    if (res.success) {
      showToast(`✅ تم إضافة قسم "${name}" بنجاح ومزامنته عبر جميع الأجهزة`);
      if (nameInput) nameInput.value = "";
      renderAdminCategories();
      populateAdminCategorySelect();
    } else {
      showToast(`⚠️ ${res.error || "حدث خطأ أثناء إضافة القسم"}`);
    }
  }
}

async function editCategoryPrompt(catId) {
  if (!window.KK_DB) return;
  const categories = window.KK_DB.getCategories();
  const cat = categories.find(c => c.id === catId);
  if (!cat) return;

  const newName = prompt("أدخل الاسم الجديد للقسم:", cat.name);
  if (newName === null) return;
  const cleanName = newName.trim();
  if (!cleanName) {
    showToast("⚠️ لا يمكن ترك اسم القسم فارغاً");
    return;
  }

  showToast("⏳ جاري تحديث القسم سحابياً...");
  const res = await window.KK_DB.updateCategory(catId, { name: cleanName });
  if (res.success) {
    showToast(`✅ تم تحديث قسم "${cleanName}" بنجاح ومزامنته عبر كافة الأجهزة`);
    renderAdminCategories();
    populateAdminCategorySelect();
  } else {
    showToast(`⚠️ ${res.error || "فشل التعديل"}`);
  }
}

async function deleteCategoryConfirm(catId) {
  if (!window.KK_DB) return;
  const categories = window.KK_DB.getCategories();
  const cat = categories.find(c => c.id === catId);
  if (!cat) return;

  const products = window.KK_DB.getProducts();
  const relatedCount = products.filter(p => p.category === catId).length;

  let msg = `هل أنت متأكد من حذف قسم "${cat.name}"؟`;
  if (relatedCount > 0) {
    msg += `\n\nتنبيه: يوجد ${relatedCount} منتج مرتبط بهذا القسم حالياً.\n(سيتم حفظ نقطة استرجاع تلقائية في حال أردت التراجع).`;
  }

  if (!confirm(msg)) return;

  showToast("⏳ جاري حذف القسم وتحديث السحابة...");
  const res = await window.KK_DB.deleteCategory(catId);
  if (res.success) {
    showToast(`🗑️ تم حذف قسم "${cat.name}" بنجاح (تم حفظ نقطة استرجاع تلقائية ومزامنة الأجهزة)`);
    renderAdminCategories();
    populateAdminCategorySelect();
  } else {
    showToast(`⚠️ ${res.error || "فشل الحذف"}`);
  }
}

// ============================================================================
// 11. SHOWROOM SETTINGS & CONTACT INFO CONTROLLERS
// ============================================================================
function loadAdminSettingsValues() {
  if (!window.KK_DB) return;
  const s = window.KK_DB.getSettings();
  if (!s) return;

  const phoneEl = document.getElementById("settingsPhone");
  const waEl = document.getElementById("settingsWhatsapp");
  const locEl = document.getElementById("settingsLocation");
  const hrsEl = document.getElementById("settingsWorkingHours");
  const emailEl = document.getElementById("settingsEmail");
  const mapEl = document.getElementById("settingsMapUrl");
  const mapEmbedEl = document.getElementById("settingsMapEmbedUrl");
  const googleClientIdEl = document.getElementById("settingsGoogleClientId");
  const fbEl = document.getElementById("settingsFacebook");
  const igEl = document.getElementById("settingsInstagram");
  const ttEl = document.getElementById("settingsTiktok");

  if (phoneEl) phoneEl.value = s.phone || "";
  if (waEl) waEl.value = s.whatsapp || "";
  if (locEl) locEl.value = s.location || "";
  if (hrsEl) hrsEl.value = s.workingHours || "";
  if (emailEl) emailEl.value = s.email || "";
  if (mapEl) mapEl.value = s.mapUrl || "";
  if (mapEmbedEl) mapEmbedEl.value = s.mapEmbedUrl || "";
  if (googleClientIdEl) googleClientIdEl.value = s.googleClientId || localStorage.getItem("kk_google_client_id") || "";

  const social = s.social || {};
  if (fbEl) fbEl.value = social.facebook || "";
  if (igEl) igEl.value = social.instagram || "";
  if (ttEl) ttEl.value = social.tiktok || "";
}

function handleAdminSettingsSubmit(e) {
  e.preventDefault();
  if (!window.KK_DB) return;

  const phone = (document.getElementById("settingsPhone")?.value || "").trim();
  const whatsapp = (document.getElementById("settingsWhatsapp")?.value || "").trim().replace(/[+ ]/g, "");
  const location = (document.getElementById("settingsLocation")?.value || "").trim();
  const workingHours = (document.getElementById("settingsWorkingHours")?.value || "").trim();
  const email = (document.getElementById("settingsEmail")?.value || "").trim();
  const mapUrl = (document.getElementById("settingsMapUrl")?.value || "").trim();
  const mapEmbedUrl = (document.getElementById("settingsMapEmbedUrl")?.value || "").trim();
  const googleClientId = (document.getElementById("settingsGoogleClientId")?.value || "").trim();

  const facebook = (document.getElementById("settingsFacebook")?.value || "").trim();
  const instagram = (document.getElementById("settingsInstagram")?.value || "").trim();
  const tiktok = (document.getElementById("settingsTiktok")?.value || "").trim();

  if (googleClientId) {
    try { localStorage.setItem("kk_google_client_id", googleClientId); } catch(e) {}
  }

  const newSettings = {
    phone,
    whatsapp,
    location,
    workingHours,
    email,
    mapUrl,
    mapEmbedUrl,
    googleClientId,
    social: {
      facebook,
      instagram,
      tiktok,
      designerUrl: "https://karimodesign.vercel.app/"
    }
  };

  const res = window.KK_DB.updateSettings(newSettings);
  if (res.success) {
    showToast("✅ تم حفظ وتطبيق بيانات التواصل والروابط فورياً على المعرض");
  } else {
    showToast("⚠️ حدث خطأ أثناء حفظ الإعدادات");
  }
}

// ============================================================================
// 12. DUAL BACKUP & RESTORE SYSTEM CONTROLLERS
// ============================================================================
window.pendingFileBackupData = null;

async function triggerDailyBackupDownload() {
  if (!window.KK_DB) return;
  const res = await window.KK_DB.downloadBackupFile("تحميل يدوي للمدير");
  if (res && res.canceled) {
    showToast("ℹ️ تم إلغاء تحديد مكان الملف");
    return;
  }
  if (res && res.success) {
    showToast(`🛡️ تم حفظ ملف النسخة الاحتياطية (${res.fileName}) بنجاح على جهازك`);
    checkDailyBackupSchedule();
    renderAdminBackupView();
  }
}

function checkDailyBackupSchedule() {
  const today = new Date().toISOString().slice(0, 10);
  const lastDownload = localStorage.getItem("kk_last_downloaded_backup_date");
  const autoDownloadedDate = localStorage.getItem("kk_auto_backup_downloaded_date");
  const banner = document.getElementById("adminDailyBackupBanner");
  const lastDownloadInfo = document.getElementById("adminLastDownloadInfo");
  const isAdminPage = !!document.getElementById("adminPageRoot");

  // 1. Check and create daily web restore point
  if (window.KK_DB) {
    window.KK_DB.checkAndCreateDailyRestorePoint();
  }

  // 2. AUTOMATIC DAILY BACKUP DOWNLOAD TO DEVICE (Once per day on admin visit)
  if (isAdminPage && autoDownloadedDate !== today) {
    setTimeout(() => {
      if (window.KK_DB) {
        window.KK_DB.downloadBackupFile("نسخة يومية تلقائية للجهاز");
        localStorage.setItem("kk_auto_backup_downloaded_date", today);
        localStorage.setItem("kk_last_downloaded_backup_date", today);
        showToast("🛡️ تم تنزيل النسخة الاحتياطية اليومية للمتجر والمبيعات تلقائياً على جهازك!");
        if (banner) banner.style.display = "none";
        if (lastDownloadInfo) {
          lastDownloadInfo.innerHTML = `<i class="fas fa-circle-check" style="color: #10B981;"></i> <span>تم تنزيل نسخة اليوم على جهازك تلقائياً بنجاح (${today})</span>`;
        }
      }
    }, 1500);
  }

  if (lastDownload === today || autoDownloadedDate === today) {
    if (banner) banner.style.display = "none";
    if (lastDownloadInfo) {
      lastDownloadInfo.innerHTML = `<i class="fas fa-circle-check" style="color: #10B981;"></i> <span>تم تنزيل نسخة اليوم على جهازك بنجاح (${today})</span>`;
    }
  } else {
    const isDismissed = sessionStorage.getItem("kk_dismissed_backup_banner_date") === today;
    if (banner) banner.style.display = isDismissed ? "none" : "flex";
    if (lastDownloadInfo) {
      lastDownloadInfo.innerHTML = `<i class="fas fa-triangle-exclamation" style="color: #F59E0B;"></i> <span>آخر تحميل: ${lastDownload ? lastDownload : "لم يتم التحميل اليوم بعد"}</span>`;
    }
  }
}

function dismissDailyBackupBanner() {
  const today = new Date().toISOString().slice(0, 10);
  sessionStorage.setItem("kk_dismissed_backup_banner_date", today);
  const banner = document.getElementById("adminDailyBackupBanner");
  if (banner) banner.style.display = "none";
}

function renderAdminBackupView() {
  checkDailyBackupSchedule();
  const tbody = document.getElementById("adminRestorePointsTableBody");
  if (!tbody || !window.KK_DB) return;

  const points = window.KK_DB.getWebRestorePoints();

  if (points.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align: center; padding: 2rem; color: var(--text-muted);">
          لا توجد نقاط استرجاع محفوظة حالياً. يتم إنشاء النقاط تلقائياً عند حذف العناصر أو عبر زر "حفظ نقطة استرجاع".
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = points.map(p => {
    const counts = p.counts || {};
    const pCount = counts.products || (p.data?.products?.length) || 0;
    const oCount = counts.orders || (p.data?.orders?.length) || 0;
    const cCount = counts.categories || (p.data?.categories?.length) || 0;
    const rev = p.totalRevenue || (p.data?.analytics?.totalRevenue) || 0;

    return `
      <tr>
        <td>
          <div style="font-weight: 800; color: #0F172A; font-size: 0.9rem;">${p.dateFormatted || ""}</div>
          <div style="font-size: 0.78rem; color: var(--text-muted);">${p.timeFormatted || ""}</div>
        </td>
        <td>
          <div style="font-weight: 700; color: #1E293B; font-size: 0.9rem;">${p.label}</div>
          <code style="font-size: 0.72rem; color: #64748B;">ID: ${p.id}</code>
        </td>
        <td>
          <div style="font-size: 0.85rem; color: #334155;">
            <span><strong>${pCount}</strong> منتج</span> • 
            <span><strong>${oCount}</strong> طلب</span> • 
            <span><strong>${cCount}</strong> قسم</span>
          </div>
        </td>
        <td>
          <span style="font-weight: 800; color: #10B981;">${formatPrice(rev)} ج.م</span>
        </td>
        <td>
          <div class="action-btn-group">
            <button type="button" class="action-btn-sm btn-restore" onclick="restoreWebPointById('${p.id}')" title="استرجاع هذه النقطة فوراً">
              <i class="fas fa-rotate-left"></i> استرجاع بنقرة واحدة
            </button>
            <button type="button" class="action-btn-sm btn-danger" onclick="deleteWebPointById('${p.id}')" title="حذف النقطة">
              <i class="fas fa-trash-alt"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

function createManualWebRestorePoint() {
  if (!window.KK_DB) return;
  const label = prompt("أدخل سبباً أو ملاحظة لنقطة الاسترجاع:", "نقطة يدوية - " + new Date().toLocaleTimeString("ar-EG", { hour: "2-digit", minute: "2-digit" }));
  if (label === null) return;
  const cleanLabel = label.trim() || "نقطة استرجاع يدوية";

  window.KK_DB.saveWebRestorePoint(cleanLabel);
  showToast("🛡️ تم حفظ نقطة الاسترجاع السريعة على الويب بنجاح");
  renderAdminBackupView();
}

async function restoreWebPointById(pointId) {
  if (!window.KK_DB) return;
  const points = window.KK_DB.getWebRestorePoints();
  const point = points.find(p => p.id === pointId);
  if (!point) return;

  const confirmMsg = `هل أنت متأكد من استرجاع البيانات إلى نقطة: "${point.label}" (${point.dateFormatted} - ${point.timeFormatted})؟\n\nسيتم استرجاع جميع المنتجات والطلبات والأقسام كما كانت في هذه اللحظة، ومزامنتها فورياً على جميع الأجهزة والهواتف مع حفظ نقطة أمان تلقائية للوضع الحالي.`;
  if (!confirm(confirmMsg)) return;

  showToast("⏳ جاري استرجاع البيانات ومزامنة جميع الأجهزة سحابياً...");

  try {
    const res = await window.KK_DB.restoreFromWebPoint(pointId);
    if (res.success) {
      showToast(`✅ تم استرجاع البيانات ومزامنتها بنجاح (${res.restoredCounts?.products || 0} منتج، ${res.restoredCounts?.orders || 0} طلب) على كافة الأجهزة!`);
      renderAdminOverview();
      renderAdminOrders();
      renderAdminInventory();
      renderAdminCategories();
      loadAdminSettingsValues();
      renderAdminBackupView();
      try {
        localStorage.setItem("kk_sync_ping", Date.now().toString());
      } catch (e) {}
    } else {
      showToast(`⚠️ ${res.error || "فشل الاسترجاع"}`);
    }
  } catch (err) {
    showToast(`⚠️ خطأ أثناء الاسترجاع: ${err.message}`);
  }
}

function deleteWebPointById(pointId) {
  if (!window.KK_DB) return;
  if (!confirm("هل أنت متأكد من حذف نقطة الاسترجاع هذه نهائياً؟")) return;
  window.KK_DB.deleteWebRestorePoint(pointId);
  showToast("🗑️ تم حذف نقطة الاسترجاع");
  renderAdminBackupView();
}

function handleBackupFileSelected(input) {
  const file = input.files && input.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    try {
      const data = JSON.parse(e.target.result);
      if (!data || (!data.products && !data.orders)) {
        showToast("⚠️ ملف النسخة الاحتياطية غير صالح أو فارغ");
        return;
      }

      window.pendingFileBackupData = data;

      const promptEl = document.getElementById("backupFilePrompt");
      const previewEl = document.getElementById("backupFilePreview");
      const nameEl = document.getElementById("backupFileNameDisplay");
      const statsEl = document.getElementById("backupFileStatsDisplay");

      if (promptEl) promptEl.style.display = "none";
      if (previewEl) previewEl.style.display = "block";
      if (nameEl) nameEl.textContent = file.name;
      if (statsEl) {
        const pCount = data.products?.length || 0;
        const oCount = data.orders?.length || 0;
        const cCount = data.categories?.length || 0;
        const rev = data.analytics?.totalRevenue || 0;
        statsEl.innerHTML = `يحتوي الملف على: <strong>${pCount}</strong> منتج • <strong>${oCount}</strong> طلب • <strong>${cCount}</strong> قسم • مبيعات بقيمة <strong>${formatPrice(rev)} ج.م</strong> (${data.dateFormatted || "تاريخ مجهول"})`;
      }
    } catch (err) {
      showToast("⚠️ تعذر قراءة الملف، تأكد من أنه بصيغة JSON صحيحة");
    }
  };
  reader.readAsText(file);
}

function cancelFileRestore(e) {
  if (e) e.stopPropagation();
  window.pendingFileBackupData = null;
  const input = document.getElementById("backupFileInput");
  if (input) input.value = "";
  const promptEl = document.getElementById("backupFilePrompt");
  const previewEl = document.getElementById("backupFilePreview");
  if (promptEl) promptEl.style.display = "flex";
  if (previewEl) previewEl.style.display = "none";
}

async function applyFileRestore(e) {
  if (e) e.stopPropagation();
  if (!window.pendingFileBackupData || !window.KK_DB) {
    showToast("⚠️ لا توجد بيانات محددة للاسترجاع");
    return;
  }

  if (!confirm("تحذير: هل أنت متأكد من استرجاع بيانات هذا الملف بالكامل؟ سيتم استبدال المنتجات والطلبات الحالية ومزامنتها على كافة الأجهزة مع حفظ نقطة أمان تلقائية أولاً.")) {
    return;
  }

  showToast("⏳ جاري استرجاع البيانات من الملف ومزامنتها سحابياً...");

  try {
    const res = await window.KK_DB.restoreFromData(window.pendingFileBackupData, true);
    if (res.success) {
      showToast(`✅ تم استرجاع البيانات بنجاح ومزامنتها مع كافة الأجهزة (${res.restoredCounts?.products || 0} منتج، ${res.restoredCounts?.orders || 0} طلب)!`);
      cancelFileRestore();
      renderAdminOverview();
      renderAdminOrders();
      renderAdminInventory();
      renderAdminCategories();
      loadAdminSettingsValues();
      renderAdminBackupView();
      try {
        localStorage.setItem("kk_sync_ping", Date.now().toString());
      } catch (e) {}
    } else {
      showToast(`⚠️ ${res.error || "فشل استرجاع الملف"}`);
    }
  } catch (err) {
    showToast(`⚠️ خطأ أثناء الاسترجاع: ${err.message}`);
  }
}

async function emergencyFactoryReset() {
  if (!window.KK_DB) return;
  const firstConfirm = confirm("تنبيه خطير جداً:\nهل أنت متأكد من رغبتك في إعادة ضبط المصنع ومزامنتها على جميع الأجهزة؟\nسيتم استرجاع الكتالوج الأصلي والطلبات الافتراضية مع حفظ نقطة استرجاع أمان تلقائية.");
  if (!firstConfirm) return;

  const pin = prompt("لإتمام إعادة ضبط المصنع، يرجى كتابة كلمة 'تأكيد':");
  if (pin !== "تأكيد" && pin !== "confirm") {
    showToast("⚠️ تم إلغاء العملية");
    return;
  }

  showToast("⏳ جاري استعادة ضبط المصنع ومزامنة التغييرات سحابياً...");

  try {
    const res = await window.KK_DB.restoreFactoryDefaults();
    if (res.success) {
      showToast("🔄 تم استعادة ضبط المصنع ومزامنتها بنجاح على كافة الأجهزة");
      renderAdminOverview();
      renderAdminOrders();
      renderAdminInventory();
      renderAdminCategories();
      loadAdminSettingsValues();
      renderAdminBackupView();
      try {
        localStorage.setItem("kk_sync_ping", Date.now().toString());
      } catch (e) {}
    }
  } catch (err) {
    showToast(`⚠️ خطأ: ${err.message}`);
  }
}

async function triggerFullCloudSync() {
  if (!window.KK_DB) return;
  showToast("🔄 جاري مزامنة السحابة الشاملة مع جميع الأجهزة والهواتف...");
  try {
    await window.KK_DB.forceSyncNow();
    const count = await window.KK_DB.syncAllLocalProductsToCloud();
    showToast(`✅ تمت المزامنة الشاملة بنجاح (${count} منتج تم تأكيد حفظها وتحديثها سحابياً)!`);
    renderAdminOverview();
    renderAdminOrders();
    renderAdminInventory();
    renderAdminCategories();
    renderAdminBackupView();
  } catch (err) {
    showToast(`⚠️ تعذر إتمام المزامنة: ${err.message}`);
  }
}
window.triggerFullCloudSync = triggerFullCloudSync;

// ----------------------------------------------------------------------------
// COD PAYMENT STATUS TOGGLE (PRD Section 5)
// ----------------------------------------------------------------------------
function toggleOrderPayment(orderId, newPaymentStatus) {
  if (!window.KK_DB) return;
  window.KK_DB.updateOrderPaymentStatus(orderId, newPaymentStatus);
  const msg = newPaymentStatus === "collected" 
    ? `✅ تم تسجيل تحصيل النقدية بنجاح للطلب #${orderId}`
    : `ℹ️ تم إلغاء تسجيل السداد للطلب #${orderId}`;
  showToast(msg);
  renderAdminOrders();
  renderAdminOverview();
}
window.toggleOrderPayment = toggleOrderPayment;

// ----------------------------------------------------------------------------
// DELIVERY AREAS & FEES MANAGER (PRD Sections 4 & 5)
// ----------------------------------------------------------------------------
function renderAdminDeliveryAreas() {
  const tbody = document.getElementById("adminDeliveryAreasTableBody");
  if (!tbody || !window.KK_DB) return;

  const areas = window.KK_DB.getDeliveryAreas();
  tbody.innerHTML = areas.map((area, index) => {
    const areaNamesDisplay = Array.isArray(area.names) && area.names.length > 0
      ? area.names.join("، ")
      : (area.name || area.nameAr || "");
    const isActive = area.active !== false;

    return `
      <tr data-area-id="${escapeHtml(area.id)}" class="delivery-area-tr">
        <td class="del-col-names">
          <div class="del-card-header-mobile">
            <span class="del-zone-badge"><i class="fas fa-map-marker-alt"></i> نطاق توصيل #${index + 1}</span>
            <button type="button" class="del-delete-btn-mobile" onclick="deleteDeliveryAreaRow('${escapeHtml(area.id)}')" title="حذف نطاق التوصيل">
              <i class="fas fa-trash-alt"></i> <span>حذف النطاق</span>
            </button>
          </div>
          <label class="del-field-label">المناطق والمدن المشمولة (مفصولة بفواصل):</label>
          <textarea class="form-input area-names-input" rows="2" placeholder="أدخل أسماء المناطق مفصولة بفواصل (مثال: الشيخ زايد، بيفرلي هيلز، الربوة، 6 أكتوبر)">${escapeHtml(areaNamesDisplay)}</textarea>
          <div class="del-field-hint"><i class="fas fa-info-circle"></i> اكتب أكثر من منطقة مفصولة بفاصلة (،) لتطبيق نفس رسوم الشحن ومدة التوصيل عليها</div>
        </td>
        <td class="del-col-enname">
          <label class="del-field-label">الاسم بالإنجليزية (English Name):</label>
          <input type="text" class="form-input area-enname-input" value="${escapeHtml(area.enName || area.nameEn || '')}" placeholder="e.g. Sheikh Zayed Zones">
        </td>
        <td class="del-col-fee">
          <label class="del-field-label">رسوم الشحن:</label>
          <div class="del-fee-input-group">
            <input type="number" class="form-input area-fee-input" value="${Number(area.fee) || 0}" min="0">
            <span class="del-fee-unit">ج.م</span>
          </div>
        </td>
        <td class="del-col-days">
          <label class="del-field-label">مدة التوصيل التقديرية:</label>
          <input type="text" class="form-input area-days-input" value="${escapeHtml(area.days || '1-3 أيام عمل')}" placeholder="1-3 أيام عمل">
        </td>
        <td class="del-col-status">
          <label class="del-field-label">حالة التغطية:</label>
          <label class="del-status-toggle-label">
            <input type="checkbox" class="area-active-checkbox" ${isActive ? 'checked' : ''} onchange="this.closest('.del-col-status').querySelector('.del-status-text').textContent = this.checked ? 'مدعومة للتوصيل' : 'غير مدعومة حالياً'">
            <span class="del-status-text ${isActive ? 'is-active' : 'is-inactive'}">${isActive ? 'مدعومة للتوصيل' : 'غير مدعومة حالياً'}</span>
          </label>
        </td>
        <td class="del-col-actions">
          <button type="button" class="btn-secondary del-delete-btn-desktop" onclick="deleteDeliveryAreaRow('${escapeHtml(area.id)}')" title="حذف نطاق التوصيل">
            <i class="fas fa-trash-alt"></i>
          </button>
        </td>
      </tr>
    `;
  }).join("");
}
window.renderAdminDeliveryAreas = renderAdminDeliveryAreas;

function addNewDeliveryAreaRow() {
  const currentAreas = window.KK_DB.getDeliveryAreas();
  const newId = "zone-" + Date.now().toString().slice(-5);
  currentAreas.push({
    id: newId,
    name: "منطقة جديدة",
    names: ["منطقة جديدة"],
    enName: "New Delivery Zone",
    fee: 50,
    days: "1 - 3 أيام عمل",
    active: true
  });
  window.KK_DB.updateDeliveryAreas(currentAreas);
  renderAdminDeliveryAreas();
  showToast("تمت إضافة نطاق توصيل جديد - اكتب أسماء المناطق ورسوم الشحن ثم احفظ التعديلات");
}
window.addNewDeliveryAreaRow = addNewDeliveryAreaRow;

function deleteDeliveryAreaRow(id) {
  if (!confirm("هل أنت متأكد من حذف نطاق التوصيل هذا؟")) return;
  let currentAreas = window.KK_DB.getDeliveryAreas();
  currentAreas = currentAreas.filter(a => a.id !== id);
  window.KK_DB.updateDeliveryAreas(currentAreas);
  renderAdminDeliveryAreas();
  showToast("تم حذف نطاق التوصيل بنجاح");
}
window.deleteDeliveryAreaRow = deleteDeliveryAreaRow;

function saveDeliveryAreasChanges() {
  const tbody = document.getElementById("adminDeliveryAreasTableBody");
  if (!tbody || !window.KK_DB) return;

  const rows = tbody.querySelectorAll("tr[data-area-id]");
  const currentAreas = window.KK_DB.getDeliveryAreas();
  const updatedAreas = [];

  rows.forEach(row => {
    const id = row.getAttribute("data-area-id");
    const existing = currentAreas.find(a => a.id === id) || { id };
    const namesInput = row.querySelector(".area-names-input");
    const enNameInput = row.querySelector(".area-enname-input");
    const feeInput = row.querySelector(".area-fee-input");
    const daysInput = row.querySelector(".area-days-input");
    const activeCb = row.querySelector(".area-active-checkbox");

    const rawNamesStr = namesInput ? namesInput.value.trim() : "";
    const namesArr = rawNamesStr.split(/[،,]/).map(s => s.trim()).filter(Boolean);
    const mainName = namesArr.length > 0 ? namesArr.join("، ") : (existing.name || "نطاق توصيل");

    updatedAreas.push({
      ...existing,
      id: id,
      name: mainName,
      names: namesArr.length > 0 ? namesArr : [mainName],
      nameAr: namesArr[0] || mainName,
      enName: enNameInput ? enNameInput.value.trim() : (existing.enName || ""),
      fee: feeInput ? Math.max(0, parseInt(feeInput.value, 10) || 0) : existing.fee,
      days: daysInput ? daysInput.value.trim() : existing.days,
      active: activeCb ? activeCb.checked : true
    });
  });

  window.KK_DB.updateDeliveryAreas(updatedAreas);
  showToast("✅ تم حفظ وتحديث لوائح مناطق ورسوم الشحن بنجاح");
  renderAdminDeliveryAreas();
}
window.saveDeliveryAreasChanges = saveDeliveryAreasChanges;

// ----------------------------------------------------------------------------
// REVIEWS MODERATION (PRD Sections 2 & 3)
// ----------------------------------------------------------------------------
let currentAdminReviewsFilter = "all";

async function renderAdminReviews(statusFilter = null) {
  if (statusFilter !== null) currentAdminReviewsFilter = statusFilter;
  const container = document.getElementById("adminReviewsListContainer");
  if (!container || !window.KK_DB) return;

  container.innerHTML = `
    <div style="text-align: center; padding: 2rem; color: var(--text-muted);">
      <i class="fas fa-spinner fa-spin" style="margin-left: 0.5rem;"></i> جاري تحميل التقييمات...
    </div>
  `;

  // Update filter buttons UI
  document.querySelectorAll("[data-rev-filter]").forEach(btn => {
    if (btn.getAttribute("data-rev-filter") === currentAdminReviewsFilter) {
      btn.classList.add("is-active-filter");
      btn.style.background = "#0F172A";
      btn.style.color = "#FFFFFF";
      btn.style.fontWeight = "800";
    } else {
      btn.classList.remove("is-active-filter");
      btn.style.background = "";
      btn.style.color = "";
      btn.style.fontWeight = "500";
    }
  });

  try {
    let reviews = await window.KK_DB.getAllReviewsForAdmin();
    if (currentAdminReviewsFilter !== "all") {
      reviews = reviews.filter(r => r.status === currentAdminReviewsFilter);
    }

    if (!reviews || reviews.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 3rem 1rem; background: #F8FAFC; border-radius: var(--radius-sm); border: 1px dashed var(--border-light); color: var(--text-muted);">
          <i class="far fa-star" style="font-size: 2rem; color: #CBD5E1; display: block; margin-bottom: 0.5rem;"></i>
          لا توجد تقييمات في هذا القسم حالياً
        </div>
      `;
      return;
    }

    const statusBadge = {
      pending: `<span style="font-size: 0.75rem; font-weight: 800; padding: 3px 8px; border-radius: 4px; background: rgba(245,158,11,0.15); color: #D97706;"><i class="fas fa-clock"></i> قيد المراجعة</span>`,
      approved: `<span style="font-size: 0.75rem; font-weight: 800; padding: 3px 8px; border-radius: 4px; background: rgba(16,185,129,0.15); color: #059669;"><i class="fas fa-check-circle"></i> معتمد ومنشور</span>`,
      rejected: `<span style="font-size: 0.75rem; font-weight: 800; padding: 3px 8px; border-radius: 4px; background: rgba(239,68,68,0.15); color: #DC2626;"><i class="fas fa-ban"></i> محجوب</span>`
    };

    container.innerHTML = reviews.map(rev => {
      const stars = "★".repeat(rev.rating || 5) + "☆".repeat(Math.max(0, 5 - (rev.rating || 5)));
      return `
        <div style="background: #F8FAFC; border: 1px solid var(--border-light); border-radius: var(--radius-sm); padding: 1rem 1.25rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
          <div style="max-width: 650px;">
            <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.35rem; flex-wrap: wrap;">
              <strong style="color: var(--text-main); font-size: 0.95rem;">${escapeHtml(rev.author || 'عميل')}</strong>
              <span style="font-size: 0.8rem; color: var(--text-muted);">لوحدة: <strong>${escapeHtml(rev.productName || rev.productId)}</strong></span>
              <span style="color: #F59E0B; font-size: 0.9rem; letter-spacing: 1px;">${stars}</span>
              ${statusBadge[rev.status] || ''}
            </div>
            <p style="margin: 0; color: #334155; font-size: 0.88rem; line-height: 1.5;">${escapeHtml(rev.comment || '')}</p>
            <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.35rem;">
              <span>${escapeHtml(rev.dateFormatted || '')}</span> • <span style="font-family: monospace;">#${escapeHtml(rev.id)}</span>
            </div>
          </div>

          <div style="display: flex; gap: 0.45rem; align-items: center;">
            ${rev.status !== 'approved' ? `
              <button type="button" class="btn-primary" style="font-size: 0.75rem; padding: 0.35rem 0.75rem; background: #10B981; border: none; font-weight: 700;" onclick="moderateReviewAction('${escapeHtml(rev.id)}', 'approved')">
                <i class="fas fa-check"></i> <span>اعتماد ونشر</span>
              </button>
            ` : ''}
            ${rev.status !== 'rejected' ? `
              <button type="button" class="btn-secondary" style="font-size: 0.75rem; padding: 0.35rem 0.75rem; color: #D97706;" onclick="moderateReviewAction('${escapeHtml(rev.id)}', 'rejected')">
                <i class="fas fa-eye-slash"></i> <span>حجب</span>
              </button>
            ` : ''}
            <button type="button" class="btn-secondary" style="font-size: 0.75rem; padding: 0.35rem 0.65rem; color: #DC2626;" onclick="deleteAdminReview('${escapeHtml(rev.id)}')">
              <i class="fas fa-trash-alt"></i>
            </button>
          </div>
        </div>
      `;
    }).join("");
  } catch (err) {
    container.innerHTML = `<div style="text-align: center; padding: 2rem; color: #DC2626;">تعذر تحميل التقييمات</div>`;
  }
}
window.renderAdminReviews = renderAdminReviews;

async function moderateReviewAction(reviewId, newStatus) {
  if (!window.KK_DB) return;
  try {
    await window.KK_DB.moderateReview(reviewId, newStatus);
    showToast(`✅ تم تحديث حالة التقييم إلى ${newStatus === 'approved' ? 'معتمد' : 'محجوب'}`);
    renderAdminReviews();
  } catch (err) {
    showToast(`❌ ${err.message}`);
  }
}
window.moderateReviewAction = moderateReviewAction;

async function deleteAdminReview(reviewId) {
  if (!confirm("هل أنت متأكد من حذف هذا التقييم نهائياً؟")) return;
  if (!window.KK_DB) return;
  try {
    await window.KK_DB.deleteReview(reviewId);
    showToast("🗑️ تم حذف التقييم");
    renderAdminReviews();
  } catch (err) {
    showToast(`❌ ${err.message}`);
  }
}
window.deleteAdminReview = deleteAdminReview;

// ----------------------------------------------------------------------------
// AUDIT & ACTIVITY HISTORY (PRD Section 3)
// ----------------------------------------------------------------------------
function renderAdminAuditLogs() {
  const tbody = document.getElementById("adminAuditLogsTableBody");
  if (!tbody || !window.KK_DB) return;

  const logs = window.KK_DB.getAuditLogs();
  if (!logs || logs.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="4" style="text-align: center; color: var(--text-muted); padding: 2rem;">
          لا توجد أنشطة مسجلة في السجل حتى الآن.
        </td>
      </tr>
    `;
    return;
  }

  const actionLabels = {
    order_created: "إنشاء طلب جديد",
    order_status_updated: "تحديث حالة طلب",
    order_payment_updated: "تحديث تحصيل النقدية",
    order_deleted: "حذف طلب",
    product_created: "إضافة وحدة إضاءة",
    product_updated: "تعديل وحدة إضاءة",
    product_deleted: "حذف وحدة إضاءة",
    stock_updated: "تعديل المخزون",
    delivery_areas_updated: "تحديث لوائح التوصيل",
    review_submitted: "استلام تقييم عميل",
    review_moderated: "مراجعة تقييم",
    review_deleted: "حذف تقييم",
    customer_registered: "تسجيل عميل جديد",
    bulk_csv_import: "استيراد مجمع عبر CSV"
  };

  tbody.innerHTML = logs.map(entry => `
    <tr>
      <td style="font-size: 0.8rem; color: var(--text-muted); white-space: nowrap;">
        <i class="fas fa-clock" style="margin-left: 0.25rem;"></i> ${escapeHtml(entry.dateFormatted || '')}
      </td>
      <td>
        <span style="font-weight: 700; color: var(--text-main); font-size: 0.82rem;">
          ${actionLabels[entry.action] || escapeHtml(entry.action)}
        </span>
      </td>
      <td style="font-size: 0.85rem; color: #334155;">
        ${escapeHtml(entry.details || '')}
      </td>
      <td>
        <span style="font-family: monospace; font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(entry.id)}</span>
      </td>
    </tr>
  `).join("");
}
window.renderAdminAuditLogs = renderAdminAuditLogs;

// ----------------------------------------------------------------------------
// BULK CSV PRODUCT IMPORT & VALIDATION (PRD Section 6)
// ----------------------------------------------------------------------------
let validatedBulkCsvRows = [];

function downloadSampleCsvTemplate() {
  const headers = "id,name,enName,price,originalPrice,category,stock,image,description";
  const row1 = "chand-test-101,\"ثريا فينيسيا الكريستالية\",\"Venice Imperial Chandelier\",28500,32000,chandeliers,8,\"https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?w=800\",\"ثريا كريستال عصفور فاخرة مطلية بالذهب عيار 24\"";
  const row2 = "wall-test-102,\"أبليك أونيكس جداري مضيء\",\"Onyx Marble Wall Sconce\",12800,14500,wall-lights,15,\"https://images.unsplash.com/photo-1513506003901-1e6a229e2d15?w=800\",\"رخام أونيكس طبيعي مضيء بإضاءة دافئة 3000 كلفن\"";
  const csvContent = `${headers}\n${row1}\n${row2}\n`;

  const blob = new Blob(["\uFEFF" + csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", "kased_karim_products_sample.test.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
window.downloadSampleCsvTemplate = downloadSampleCsvTemplate;

function handleCsvFileSelected(input) {
  const file = input?.files?.[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    const text = e.target.result;
    const txtArea = document.getElementById("bulkCsvTextInput");
    if (txtArea) txtArea.value = text;
    showToast(`📁 تم تحميل ملف (${file.name}) بنجاح. انقر على فحص الصفوف للتحقق.`);
    validateBulkCsvData();
  };
  reader.readAsText(file, "UTF-8");
}
window.handleCsvFileSelected = handleCsvFileSelected;

function clearBulkCsvForm() {
  const txtArea = document.getElementById("bulkCsvTextInput");
  if (txtArea) txtArea.value = "";
  const reportBox = document.getElementById("bulkCsvReportBox");
  if (reportBox) {
    reportBox.style.display = "none";
    reportBox.innerHTML = "";
  }
  validatedBulkCsvRows = [];
}
window.clearBulkCsvForm = clearBulkCsvForm;

function parseCsvLine(text) {
  const result = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      if (inQuotes && text[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (c === ',' && !inQuotes) {
      result.push(cur.trim());
      cur = "";
    } else {
      cur += c;
    }
  }
  result.push(cur.trim());
  return result;
}

function validateBulkCsvData() {
  const txtArea = document.getElementById("bulkCsvTextInput");
  const reportBox = document.getElementById("bulkCsvReportBox");
  if (!txtArea || !reportBox) return;

  const content = txtArea.value.trim();
  if (!content) {
    showToast("⚠️ يرجى لصق بيانات الـ CSV أو اختيار ملف أولاً");
    return;
  }

  const lines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length < 2) {
    reportBox.style.display = "block";
    reportBox.style.background = "#FEF2F2";
    reportBox.style.border = "1px solid #FECACA";
    reportBox.innerHTML = `
      <div style="color: #DC2626; font-weight: 800;">❌ الملف لا يحتوي على بيانات كافية (يجب توفر سطر العناوين وسطر بيانات واحد على الأقل).</div>
    `;
    return;
  }

  const rawHeaders = parseCsvLine(lines[0]).map(h => h.replace(/^["']|["']$/g, "").trim().toLowerCase());
  const requiredCols = ["id", "name", "price", "category"];
  const missingCols = requiredCols.filter(col => !rawHeaders.includes(col));

  if (missingCols.length > 0) {
    reportBox.style.display = "block";
    reportBox.style.background = "#FEF2F2";
    reportBox.style.border = "1px solid #FECACA";
    reportBox.innerHTML = `
      <div style="color: #DC2626; font-weight: 800;">❌ أعمدة إلزامية مفقودة في السطر الأول: ${missingCols.join(", ")}</div>
    `;
    return;
  }

  const validRows = [];
  const invalidRows = [];

  for (let idx = 1; idx < lines.length; idx++) {
    const rowValues = parseCsvLine(lines[idx]);
    const rowObj = {};
    rawHeaders.forEach((header, hIdx) => {
      rowObj[header] = rowValues[hIdx] !== undefined ? rowValues[hIdx] : "";
    });

    const rowNum = idx + 1;
    const errors = [];

    if (!rowObj.id) errors.push("كود المنتج (id) فارغ");
    if (!rowObj.name) errors.push("اسم المنتج (name) فارغ");

    const priceNum = parseFloat(rowObj.price);
    if (isNaN(priceNum) || priceNum <= 0) {
      errors.push(`السعر غير صالح (${rowObj.price})`);
    }

    if (!rowObj.category) {
      errors.push("التصنيف (category) فارغ");
    }

    const stockNum = parseInt(rowObj.stock !== undefined && rowObj.stock !== "" ? rowObj.stock : "10", 10);
    if (isNaN(stockNum) || stockNum < 0) {
      errors.push(`المخزون غير صالح (${rowObj.stock})`);
    }

    if (errors.length > 0) {
      invalidRows.push({ rowNum, name: rowObj.name || "(بدون اسم)", errors });
    } else {
      validRows.push({
        id: rowObj.id,
        name: rowObj.name,
        enName: rowObj.enname || rowObj.name,
        price: priceNum,
        originalPrice: parseFloat(rowObj.originalprice) || 0,
        category: rowObj.category,
        categoryName: rowObj.categoryname || rowObj.category,
        stock: stockNum,
        inStock: stockNum > 0,
        image: rowObj.image || "https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?w=800",
        description: rowObj.description || ""
      });
    }
  }

  validatedBulkCsvRows = validRows;
  reportBox.style.display = "block";

  if (invalidRows.length > 0) {
    reportBox.style.background = "#FFFBEB";
    reportBox.style.border = "1px solid #FDE68A";
    reportBox.innerHTML = `
      <div style="margin-bottom: 0.85rem;">
        <strong style="color: #92400E; font-size: 0.95rem;">
          ⚠️ تم الفحص: وُجد ${validRows.length} صف صالح، و ${invalidRows.length} صف غير صالح يجب تصحيحها:
        </strong>
      </div>
      <table class="admin-table" style="font-size: 0.82rem; margin-bottom: 1rem;">
        <thead>
          <tr>
            <th>رقم السطر</th>
            <th>اسم المنتج</th>
            <th>سبب الخطأ البرمجي</th>
          </tr>
        </thead>
        <tbody>
          ${invalidRows.map(inv => `
            <tr>
              <td style="font-weight: 800; color: #DC2626;">سطر ${inv.rowNum}</td>
              <td>${escapeHtml(inv.name)}</td>
              <td style="color: #DC2626;">${inv.errors.join(" • ")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
      ${validRows.length > 0 ? `
        <button type="button" class="btn-primary" style="background: #10B981; border: none; font-weight: 800;" onclick="executeBulkCsvImport()">
          <i class="fas fa-check-circle"></i> <span>متابعة واستيراد الصفوف الصالحة فقط (${validRows.length} منتج)</span>
        </button>
      ` : ''}
    `;
  } else {
    reportBox.style.background = "#F0FDF4";
    reportBox.style.border = "1px solid #BBF7D0";
    reportBox.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
        <div>
          <strong style="color: #166534; font-size: 1rem; display: block;">
            ✅ تم الفحص بنجاح: جميع الصفوف (${validRows.length} منتج) صحيحة 100% وخالية من أي أخطاء!
          </strong>
          <span style="font-size: 0.82rem; color: #15803D;">جاهز للاستيراد الفوري وحفظه محلياً وسحابياً.</span>
        </div>
        <button type="button" class="btn-primary" style="background: #10B981; border: none; font-weight: 800; padding: 0.65rem 1.25rem;" onclick="executeBulkCsvImport()">
          <i class="fas fa-check-circle"></i> <span>تأكيد واستيراد (${validRows.length} منتج) الآن</span>
        </button>
      </div>
    `;
  }
}
window.validateBulkCsvData = validateBulkCsvData;

async function executeBulkCsvImport() {
  if (!validatedBulkCsvRows || validatedBulkCsvRows.length === 0) {
    showToast("⚠️ لا توجد صفوف صالحة للاستيراد");
    return;
  }
  if (!window.KK_DB) return;

  const count = validatedBulkCsvRows.length;
  showToast(`⏳ جاري استيراد وحفظ ${count} منتج محلياً وسحابياً...`);

  let added = 0;
  let updated = 0;

  for (const prod of validatedBulkCsvRows) {
    const existing = window.KK_DB.getProductById(prod.id);
    if (existing) {
      window.KK_DB.updateProduct(prod.id, prod);
      updated++;
    } else {
      window.KK_DB.createProduct(prod);
      added++;
    }
  }

  window.KK_DB.logActivity("bulk_csv_import", `استيراد مجمع عبر CSV: ${added} منتج جديد، و ${updated} منتج محدث`);
  showToast(`🎉 تم الاستيراد بنجاح! (${added} منتج جديد، ${updated} منتج تم تحديثه)`);
  clearBulkCsvForm();
  renderAdminInventory();
  renderAdminOverview();
}
window.executeBulkCsvImport = executeBulkCsvImport;

// ----------------------------------------------------------------------------
// GOOGLE & REGISTERED WEB USERS DIRECTORY (دليل عملاء الويب ومستخدمي Google)
// ----------------------------------------------------------------------------
let currentAdminUsersFilter = "all";
let adminCustomersCache = [];

async function updateAdminUsersCountBadge() {
  const badge = document.getElementById("adminUsersCountBadge");
  if (!badge) return;
  try {
    const list = window.KK_DB ? await window.KK_DB.getCustomersList() : [];
    if (list && list.length > 0) {
      badge.textContent = list.length;
      badge.style.display = "inline-flex";
    } else {
      badge.style.display = "none";
    }
  } catch (e) {}
}
window.updateAdminUsersCountBadge = updateAdminUsersCountBadge;

async function renderAdminGoogleUsers() {
  const container = document.getElementById("adminGoogleUsersListContainer");
  if (!container) return;

  container.innerHTML = `
    <div style="grid-column: 1 / -1; text-align: center; padding: 3rem; color: var(--text-muted);">
      <i class="fas fa-spinner fa-spin" style="font-size: 1.5rem; margin-bottom: 0.75rem; color: #4285F4;"></i>
      <div>جاري تحميل سجل العملاء وحسابات Google المتصلة...</div>
    </div>
  `;

  try {
    const customers = window.KK_DB ? await window.KK_DB.getCustomersList() : [];
    adminCustomersCache = Array.isArray(customers) ? customers : [];
  } catch (e) {
    adminCustomersCache = [];
  }

  updateGoogleUsersKPIs();
  displayFilteredGoogleUsers();
}
window.renderAdminGoogleUsers = renderAdminGoogleUsers;

function updateGoogleUsersKPIs() {
  const totalEl = document.getElementById("kpiGoogleUsersTotal");
  const verifiedEl = document.getElementById("kpiGoogleUsersVerified");
  const todayEl = document.getElementById("kpiGoogleUsersToday");

  const total = adminCustomersCache.length;
  const verified = adminCustomersCache.filter(c => c.authProvider === "google" || c.googleId).length;
  
  const now = new Date();
  const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const today = adminCustomersCache.filter(c => {
    const t = c.createdAt || c.updatedAt || 0;
    return t >= startOfDay;
  }).length;

  if (totalEl) totalEl.textContent = total;
  if (verifiedEl) verifiedEl.textContent = verified;
  if (todayEl) todayEl.textContent = today;

  const badge = document.getElementById("adminUsersCountBadge");
  if (badge) {
    badge.textContent = total;
    badge.style.display = total > 0 ? "inline-flex" : "none";
  }
}

function setAdminGoogleUsersFilter(filterKey) {
  currentAdminUsersFilter = filterKey;
  document.querySelectorAll("[data-user-filter]").forEach(btn => {
    if (btn.getAttribute("data-user-filter") === filterKey) {
      btn.classList.add("is-active-user-filter");
      btn.style.background = "#0F172A";
      btn.style.color = "#FFFFFF";
      btn.style.fontWeight = "800";
    } else {
      btn.classList.remove("is-active-user-filter");
      btn.style.background = "";
      btn.style.color = "";
      btn.style.fontWeight = "500";
    }
  });
  displayFilteredGoogleUsers();
}
window.setAdminGoogleUsersFilter = setAdminGoogleUsersFilter;

function filterAdminGoogleUsers() {
  displayFilteredGoogleUsers();
}
window.filterAdminGoogleUsers = filterAdminGoogleUsers;

function displayFilteredGoogleUsers() {
  const container = document.getElementById("adminGoogleUsersListContainer");
  if (!container) return;

  const searchInput = document.getElementById("adminGoogleUsersSearchInput");
  const q = searchInput ? searchInput.value.trim().toLowerCase() : "";

  let filtered = adminCustomersCache.filter(c => {
    // Filter by type
    if (currentAdminUsersFilter === "google" && c.authProvider !== "google" && !c.googleId) return false;
    if (currentAdminUsersFilter === "local" && (c.authProvider === "google" || c.googleId)) return false;

    // Filter by search query
    if (q) {
      const name = (c.name || "").toLowerCase();
      const email = (c.email || "").toLowerCase();
      const phone = (c.phone || "").toLowerCase();
      return name.includes(q) || email.includes(q) || phone.includes(q);
    }
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 3rem 1.5rem; background: #F8FAFC; border: 1px dashed var(--border-light); border-radius: 12px;">
        <div style="width: 56px; height: 56px; border-radius: 50%; background: rgba(66,133,244,0.1); color: #4285F4; display: flex; align-items: center; justify-content: center; margin: 0 auto 1rem; font-size: 1.5rem;">
          <i class="fab fa-google"></i>
        </div>
        <h3 style="font-size: 1.15rem; font-weight: 800; color: var(--text-main); margin-bottom: 0.35rem;">لم يتم العثور على عملاء مسجلين</h3>
        <p style="font-size: 0.85rem; color: var(--text-muted); max-width: 480px; margin: 0 auto;">
          ${q ? "لا توجد نتائج مطابقة لبحثك، جرب البحث بكلمات أخرى." : "ستظهر هنا كافة حسابات Google والإيميلات التي قامت بتسجيل الدخول أو إتمام الطلبات على الموقع فور ربطها."}
        </p>
      </div>
    `;
    return;
  }

  container.innerHTML = filtered.map(user => {
    const isGoogle = user.authProvider === "google" || !!user.googleId;
    const name = user.name || "عميل غير معروف";
    const email = user.email || "";
    const phone = user.phone || "";
    const avatar = user.avatar || "";
    const monogram = name.trim().charAt(0).toUpperCase() || "U";
    
    // Format timestamp
    let dateStr = "غير محدد";
    const ts = user.createdAt || user.updatedAt;
    if (ts) {
      try {
        const d = new Date(ts);
        dateStr = d.toLocaleDateString("ar-EG", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
      } catch (e) {
        dateStr = String(ts);
      }
    }

    const avatarHtml = avatar 
      ? `<img src="${escapeHtml(avatar)}" alt="${escapeHtml(name)}" style="width: 54px; height: 54px; border-radius: 50%; object-fit: cover; border: 2px solid ${isGoogle ? '#4285F4' : 'var(--accent)'}; box-shadow: 0 4px 10px rgba(0,0,0,0.1); flex-shrink: 0;" onerror="this.onerror=null; this.parentElement.innerHTML='<div style=\\'width:54px;height:54px;border-radius:50%;background:linear-gradient(135deg, #1e293b, #0f172a);color:#D4AF37;font-weight:800;font-size:1.3rem;display:flex;align-items:center;justify-content:center;border:2px solid var(--accent);\\'>${escapeHtml(monogram)}</div>';">`
      : `<div style="width: 54px; height: 54px; border-radius: 50%; background: linear-gradient(135deg, ${isGoogle ? '#4285F4' : 'var(--accent)'}, ${isGoogle ? '#1a73e8' : '#9A7B2C'}); color: #FFFFFF; font-weight: 800; font-size: 1.3rem; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 10px rgba(0,0,0,0.1); flex-shrink: 0;">${escapeHtml(monogram)}</div>`;

    return `
      <div class="admin-user-card" style="background: #FFFFFF; border: 1px solid var(--border-light); border-radius: 12px; padding: 1.35rem; box-shadow: 0 2px 8px rgba(0,0,0,0.04); transition: transform 0.2s ease, box-shadow 0.2s ease; display: flex; flex-direction: column; justify-content: space-between;">
        
        <div>
          <!-- Card Header: Avatar & Info -->
          <div style="display: flex; align-items: center; gap: 0.9rem; margin-bottom: 1rem;">
            ${avatarHtml}
            <div style="flex: 1; min-width: 0;">
              <div style="font-weight: 800; color: var(--text-main); font-size: 1.05rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(name)}">
                ${escapeHtml(name)}
              </div>
              <div style="margin-top: 3px;">
                ${isGoogle 
                  ? `<span style="font-size: 0.72rem; padding: 2px 8px; border-radius: 12px; background: rgba(66,133,244,0.1); color: #1a73e8; font-weight: 700; display: inline-flex; align-items: center; gap: 4px;"><i class="fab fa-google"></i> Google Verified</span>`
                  : `<span style="font-size: 0.72rem; padding: 2px 8px; border-radius: 12px; background: rgba(16,185,129,0.1); color: #059669; font-weight: 700; display: inline-flex; align-items: center; gap: 4px;"><i class="fas fa-user-check"></i> تسجيل محلي</span>`
                }
              </div>
            </div>
          </div>

          <!-- User Details List -->
          <div style="display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.85rem; padding: 0.75rem 0; border-top: 1px solid #F1F5F9; border-bottom: 1px solid #F1F5F9; margin-bottom: 0.85rem;">
            ${email ? `
              <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;">
                <span style="color: var(--text-muted); font-size: 0.78rem;"><i class="fas fa-envelope" style="width: 14px;"></i> البريد:</span>
                <span style="font-weight: 600; color: #1E293B; direction: ltr; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(email)}">${escapeHtml(email)}</span>
              </div>
            ` : ''}

            ${phone ? `
              <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;">
                <span style="color: var(--text-muted); font-size: 0.78rem;"><i class="fas fa-phone" style="width: 14px;"></i> الهاتف:</span>
                <span style="font-weight: 600; color: #1E293B; direction: ltr;">${escapeHtml(phone)}</span>
              </div>
            ` : ''}

            <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;">
              <span style="color: var(--text-muted); font-size: 0.78rem;"><i class="fas fa-calendar-check" style="width: 14px;"></i> تاريخ الانضمام:</span>
              <span style="color: var(--text-muted); font-size: 0.78rem;">${escapeHtml(dateStr)}</span>
            </div>
          </div>
        </div>

        <!-- Card Actions -->
        <div style="display: flex; gap: 0.4rem; justify-content: flex-end; align-items: center; margin-top: 0.5rem;">
          ${email ? `
            <button type="button" class="btn-secondary" style="font-size: 0.75rem; padding: 0.35rem 0.65rem;" onclick="copyToClipboard('${escapeHtml(email)}', 'تم نسخ البريد الإلكتروني')">
              <i class="fas fa-copy"></i> <span>نسخ الإيميل</span>
            </button>
          ` : ''}
          ${phone ? `
            <a href="https://wa.me/${phone.replace(/[^0-9]/g, '')}" target="_blank" class="btn-secondary" style="font-size: 0.75rem; padding: 0.35rem 0.65rem; color: #10B981; border-color: rgba(16,185,129,0.3);">
              <i class="fab fa-whatsapp"></i> <span>واتساب</span>
            </a>
          ` : ''}
          <button type="button" class="btn-secondary" style="font-size: 0.75rem; padding: 0.35rem 0.65rem;" onclick="filterOrdersByCustomer('${escapeHtml(email || phone)}')">
            <i class="fas fa-receipt"></i> <span>الطلبات</span>
          </button>
        </div>

      </div>
    `;
  }).join("");
}

async function refreshAdminGoogleUsers() {
  showToast("⏳ جاري تحديث سجل عملاء Google والويب...");
  await renderAdminGoogleUsers();
  showToast("✅ تم تحديث سجل العملاء");
}
window.refreshAdminGoogleUsers = refreshAdminGoogleUsers;

function filterOrdersByCustomer(query) {
  if (!query) return;
  switchAdminTab("orders", document.querySelector('[onclick*="orders"]'));
  const input = document.getElementById("adminOrdersSearchInput");
  if (input) {
    input.value = query;
    input.dispatchEvent(new Event("input"));
  }
}
window.filterOrdersByCustomer = filterOrdersByCustomer;

function exportAdminGoogleUsersCSV() {
  if (!adminCustomersCache || adminCustomersCache.length === 0) {
    showToast("⚠️ لا يوجد عملاء مسجلون للتصدير");
    return;
  }

  const headers = ["ID", "Name", "Email", "Phone", "AuthProvider", "RegistrationDate"];
  const rows = adminCustomersCache.map(u => [
    `"${(u.id || '').replace(/"/g, '""')}"`,
    `"${(u.name || '').replace(/"/g, '""')}"`,
    `"${(u.email || '').replace(/"/g, '""')}"`,
    `"${(u.phone || '').replace(/"/g, '""')}"`,
    `"${(u.authProvider || 'local').replace(/"/g, '""')}"`,
    `"${new Date(u.createdAt || u.updatedAt || Date.now()).toISOString()}"`
  ]);

  const csvContent = "\uFEFF" + [headers.join(","), ...rows.map(r => r.join(","))].join("\r\n");
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", `kased_karim_customers_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  showToast("📥 تم تصدير بيانات العملاء إلى ملف CSV");
}
window.exportAdminGoogleUsersCSV = exportAdminGoogleUsersCSV;


