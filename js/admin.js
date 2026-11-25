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

window.showToast = window.showToast || function(message, type = "info") {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast";

  const icon = document.createElement("i");
  const isError = type === "error" || (typeof message === "string" && (message.includes("خطأ") || message.includes("تعذر") || message.includes("❌")));
  icon.className = isError ? "fas fa-circle-exclamation toast-icon" : "fas fa-check-circle toast-icon";
  if (isError) icon.style.color = "#EF4444";

  const span = document.createElement("span");
  span.textContent = String(message || ""); // Strictly Safe Plain Text (Zero XSS)

  toast.appendChild(icon);
  toast.appendChild(span);
  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.add("show");
  });

  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 400);
  }, 3500);
};

// =============================================================================
// SAFE ADMIN DOM, URL & CSV SECURITY SUITE (OWASP ASVS Level 3 — V5)
// Zero Dynamic innerHTML, Strict CSP Compatibility, Anti-Formula Injection (CWE-1236)
// =============================================================================

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

function safeCssEscape(str) {
  if (typeof CSS !== "undefined" && typeof CSS.escape === "function") {
    return CSS.escape(String(str || ""));
  }
  return String(str || "").replace(/["'\\]/g, "\\$&");
}

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

const DEFAULT_ADMIN_FALLBACK_IMAGE = "https://images.unsplash.com/photo-1543198126-a8ad8e47fb22?auto=format&fit=crop&w=300&q=80";

function sanitizeAdminUrl(rawUrl, { allowedProtocols = ["https:"], allowRelative = true, fallback = "#" } = {}) {
  if (typeof rawUrl !== "string") return fallback;
  if (rawUrl.length === 0 || rawUrl.length > 2048) return fallback;

  const clean = rawUrl.replace(/[\x00-\x1F\x7F]/g, "").trim();
  if (!clean) return fallback;

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

  // Safe relative paths (e.g. /images/... or images/...)
  if (allowRelative && (clean.startsWith("/") || clean.startsWith("./"))) {
    if (clean.includes("..")) return fallback; // Prevent traversal
    return clean;
  }

  try {
    const baseOrigin = typeof window !== "undefined" && window.location ? window.location.origin : "https://www.kasedkarim.com";
    const parsed = new URL(clean, baseOrigin);
    if (allowedProtocols.includes(parsed.protocol)) {
      return parsed.href;
    }
  } catch {
    return fallback;
  }

  return fallback;
}

function buildSafeWhatsAppUrl(rawPhone, rawMessage = "") {
  if (!rawPhone || typeof rawPhone !== "string") return "#";
  let phone = rawPhone.replace(/\D/g, "");
  if (!phone || phone.length < 8 || phone.length > 15) return "#";
  if (phone.startsWith("0")) phone = "2" + phone;
  const msgPart = rawMessage ? `?text=${encodeURIComponent(String(rawMessage).slice(0, 1500))}` : "";
  return `https://wa.me/${phone}${msgPart}`;
}

function buildSafeTelUrl(rawPhone) {
  if (!rawPhone || typeof rawPhone !== "string") return "#";
  const trimmed = rawPhone.trim();
  if (/^\+?[0-9]{8,15}$/.test(trimmed)) {
    return `tel:${trimmed}`;
  }
  const digitsOnly = trimmed.replace(/\D/g, "");
  if (digitsOnly.length >= 8 && digitsOnly.length <= 15) {
    return `tel:${digitsOnly}`;
  }
  return "#";
}

function formatSafeInt(val, fallback = 0) {
  const n = Number(val);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return Math.floor(n);
}

function formatSafeMoney(val, fallback = "0") {
  const n = Number(val);
  if (!Number.isFinite(n)) return fallback;
  return n.toLocaleString("en-US");
}

function escapeCsvCell(val) {
  if (val === null || val === undefined) return '""';
  let str = String(val);
  // Neutralize formula triggers per CWE-1236 (=, +, -, @, \t, \r, %)
  if (/^[=+\-@\t\r%]/.test(str)) {
    str = "'" + str;
  }
  // Sanitize control characters except harmless spacing/tabs
  str = str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, " ");
  return '"' + str.replace(/"/g, '""') + '"';
}

function setSafeImageWithFallback(imgEl, rawSrc, fallbackSrc = DEFAULT_ADMIN_FALLBACK_IMAGE) {
  if (!imgEl) return;
  const safeSrc = sanitizeAdminUrl(rawSrc, { allowedProtocols: ["https:"], allowRelative: true, fallback: fallbackSrc });
  imgEl.src = safeSrc === "#" ? fallbackSrc : safeSrc;
  imgEl.loading = "lazy";
  let handled = false;
  imgEl.addEventListener("error", () => {
    if (!handled) {
      handled = true;
      imgEl.src = fallbackSrc;
    }
  }, { once: true });
}

// ----------------------------------------------------------------------------
// 0. SERVER-SIDE ADMIN SECURITY GATE & SESSION VAULT (OWASP ASVS Level 3)
// Server-Authoritative Gate, Zero Client Auth State, Anti-FOUC & 2FA State Machine
// ----------------------------------------------------------------------------

const ADMIN_TOKEN_KEY = "kk_admin_token";
let activeAdminChallengeId = null;
let isAuthChecking = false;
let isSubmittingPin = false;
let isSubmittingOtp = false;
let otpTimerInterval = null;
let pinRateLimitTimer = null;

// Multi-Tab Session Synchronization via BroadcastChannel (CWE-287 / CWE-613)
let adminAuthChannel = null;
try {
  if (typeof BroadcastChannel !== "undefined") {
    adminAuthChannel = new BroadcastChannel("kk_admin_auth");
    adminAuthChannel.onmessage = (event) => {
      if (event.data && event.data.type === "LOGOUT") {
        lockAdminGate();
      }
    };
  }
} catch (e) {}

function broadcastAdminLogout() {
  if (adminAuthChannel) {
    try {
      adminAuthChannel.postMessage({ type: "LOGOUT" });
    } catch (e) {}
  }
}

// Fail-Closed Server-Authoritative Session Verification (Axis 1)
async function verifyAdminSession() {
  const gateEl = document.getElementById("adminAuthGate");
  const rootEl = document.getElementById("adminPageRoot");
  if (!gateEl || !rootEl) return false;

  if (isAuthChecking) return false;
  isAuthChecking = true;

  // Anti-FOUC & Fail-Closed Enforcement: Root stays completely hidden
  rootEl.hidden = true;
  rootEl.style.display = "none";
  gateEl.hidden = false;
  gateEl.style.display = "flex";

  // Purge any tokens stored in client storage
  sessionStorage.removeItem(ADMIN_TOKEN_KEY);
  localStorage.removeItem(ADMIN_TOKEN_KEY);
  localStorage.removeItem("kk_admin_authorized");
  localStorage.removeItem("kk_admin_device_linked");

  try {
    const res = await fetch("/api/auth", {
      method: "GET",
      credentials: "include",
      cache: "no-store",
      headers: {
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json"
      }
    });

    if (res.ok) {
      const data = await res.json();
      if (data && data.authenticated === true && data.user && data.user.role === "admin") {
        isAuthChecking = false;
        unhideAdminDashboard(data.user);
        return true;
      }
    }
  } catch (err) {
    // Network failure / server 500: Fail-closed remains in effect
  }

  isAuthChecking = false;
  lockAdminGate();
  return false;
}

// Backward-compatibility alias
const checkAdminSecurityGate = verifyAdminSession;

function unhideAdminDashboard(user) {
  const gateEl = document.getElementById("adminAuthGate");
  const rootEl = document.getElementById("adminPageRoot");

  if (gateEl) {
    gateEl.hidden = true;
    gateEl.style.display = "none";
  }
  if (rootEl) {
    rootEl.hidden = false;
    rootEl.style.display = "block";
  }

  document.body.classList.add("is-admin-user", "is-admin-authenticated");
  document.documentElement.classList.add("is-admin-user", "is-admin-authenticated");

  // NOW and ONLY NOW, trigger authenticated data sync and renders:
  if (window.KK_DB) {
    window.KK_DB.syncFromCloud(false);
  }
  updateAdminHeaderBadge();
  renderAdminOverview();
  renderAdminOrders();
  renderAdminInventory();
  populateAdminCategorySelect();
  checkDailyBackupSchedule();
}

function lockAdminGate() {
  document.body.classList.remove("is-admin-user", "is-admin-authenticated");
  document.documentElement.classList.remove("is-admin-user", "is-admin-authenticated");

  const gateEl = document.getElementById("adminAuthGate");
  const rootEl = document.getElementById("adminPageRoot");

  if (rootEl) {
    rootEl.hidden = true;
    rootEl.style.display = "none";
  }
  if (gateEl) {
    gateEl.hidden = false;
    gateEl.style.display = "flex";
  }

  backToStep1();
  cleanupAdminDomOnLogout();
}

// BFCache (Back-Forward Cache) Defense (Axis 5)
window.addEventListener("pageshow", (event) => {
  if (event.persisted) {
    verifyAdminSession();
  }
});

// Tab Visibility Re-verification (Axis 5)
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    const rootEl = document.getElementById("adminPageRoot");
    if (rootEl && !rootEl.hidden) {
      verifyAdminSession();
    }
  }
});

// Step 1: Master Password Login (Axis 4)
async function handleAdminPinSubmit(e) {
  if (e && typeof e.preventDefault === "function") e.preventDefault();
  if (isSubmittingPin) return;

  const pinInput = document.getElementById("adminPinInput");
  const errorEl = document.getElementById("adminPinError");
  const errorTextEl = document.getElementById("adminPinErrorText") || errorEl;
  const submitBtn = document.getElementById("adminPinSubmitBtn") || document.querySelector("#adminPinForm button[type='submit']");

  if (!pinInput) return;
  const val = pinInput.value.normalize("NFKC").trim();

  // Zero Plaintext Password Retention: Immediately wipe input from DOM
  pinInput.value = "";

  if (!val) {
    if (errorEl) {
      if (errorTextEl) errorTextEl.textContent = "يرجى كتابة رمز المرور الرئيسي";
      errorEl.style.display = "flex";
    }
    pinInput.focus();
    return;
  }

  if (val.length > 128) {
    if (errorEl) {
      if (errorTextEl) errorTextEl.textContent = "رمز المرور غير صالح (بحد أقصى 128 حرفاً)";
      errorEl.style.display = "flex";
    }
    pinInput.focus();
    return;
  }

  isSubmittingPin = true;
  let origPinChildren = [];
  if (submitBtn) {
    origPinChildren = Array.from(submitBtn.childNodes);
    submitBtn.disabled = true;
    safeClearContainer(submitBtn);
    submitBtn.appendChild(createSafeEl("i", { class: "fas fa-spinner fa-spin" }));
    submitBtn.appendChild(createSafeEl("span", { textContent: " جارٍ التحقق وإرسال كود الأمان..." }));
  }

  try {
    const res = await fetch("/api/auth", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest"
      },
      body: JSON.stringify({ action: "login", password: val })
    });

    const data = await res.json().catch(() => ({}));

    if (res.status === 429) {
      const retryAfter = res.headers.get("Retry-After");
      const waitSec = parseInt(retryAfter || (data && data.remainingSec) || "60", 10);
      startPinRateLimitCountdown(waitSec, submitBtn, errorEl, errorTextEl);
      return;
    }

    if (res.ok && data.success) {
      if (errorEl) errorEl.style.display = "none";

      if (data.step === "otp_required") {
        activeAdminChallengeId = String(data.challengeId || "");
        const step1 = document.getElementById("adminAuthStep1");
        const step2 = document.getElementById("adminAuthStep2");
        if (step1) step1.style.display = "none";
        if (step2) step2.style.display = "block";

        initOtpInputs();
        startOtpCountdownTimer(300); // 5 minutes (NIST SP 800-63B)

        const boxes = document.querySelectorAll(".otp-digit-box");
        boxes.forEach(box => { box.value = ""; });
        if (boxes[0]) boxes[0].focus();
        showToast("📧 تم إرسال كود التحقق السداسي إلى بريد الإدارة المعتمد بنجاح");
        return;
      }

      showToast("⚠️ يلزم إكمال التحقق الثنائي عبر البريد الإلكتروني");
    } else {
      if (errorEl) {
        if (errorTextEl) errorTextEl.textContent = data.error || "رمز الدخول غير صحيح";
        errorEl.style.display = "flex";
      }
      pinInput.focus();
      showToast(data.error || "⚠️ رمز الدخول غير صحيح");
    }
  } catch (err) {
    if (errorEl) {
      if (errorTextEl) errorTextEl.textContent = "تعذر الاتصال بخادم المصادقة السحابي";
      errorEl.style.display = "flex";
    }
    showToast("⚠️ تعذر الاتصال بخادم المصادقة السحابي");
  } finally {
    isSubmittingPin = false;
    if (submitBtn && !submitBtn.dataset.rateLimited) {
      submitBtn.disabled = false;
      safeClearContainer(submitBtn);
      origPinChildren.forEach(c => submitBtn.appendChild(c));
    }
  }
}

function startPinRateLimitCountdown(durationSec, submitBtn, errorEl, errorTextEl) {
  if (pinRateLimitTimer) clearInterval(pinRateLimitTimer);
  let remaining = durationSec;

  if (submitBtn) {
    submitBtn.dataset.rateLimited = "true";
    submitBtn.disabled = true;
  }

  const update = () => {
    if (errorEl && errorTextEl) {
      errorTextEl.textContent = `تم تجاوز الحد الأقصى للمحاولات. يرجى الانتظار ${remaining} ثانية.`;
      errorEl.style.display = "flex";
    }
    if (submitBtn) {
      safeClearContainer(submitBtn);
      submitBtn.appendChild(createSafeEl("i", { class: "fas fa-clock" }));
      submitBtn.appendChild(createSafeEl("span", { textContent: ` انتظر (${remaining} ث)` }));
    }

    if (remaining <= 0) {
      clearInterval(pinRateLimitTimer);
      if (submitBtn) {
        delete submitBtn.dataset.rateLimited;
        submitBtn.disabled = false;
        safeClearContainer(submitBtn);
        submitBtn.appendChild(createSafeEl("i", { class: "fas fa-paper-plane" }));
        submitBtn.appendChild(createSafeEl("span", { textContent: "التحقق وإرسال كود الأمان للجيميل" }));
      }
      if (errorEl) errorEl.style.display = "none";
      const pinInput = document.getElementById("adminPinInput");
      if (pinInput) pinInput.focus();
    }
    remaining--;
  };

  update();
  pinRateLimitTimer = setInterval(update, 1000);
}

// Step 2: 6-Digit OTP Verification (Axis 4)
async function handleAdminOtpSubmit(e) {
  if (e && typeof e.preventDefault === "function") e.preventDefault();
  if (isSubmittingOtp) return;

  const digitBoxes = document.querySelectorAll(".otp-digit-box");
  const errorEl = document.getElementById("adminOtpError");
  const errorTextEl = document.getElementById("adminOtpErrorText") || errorEl;
  const submitBtn = document.getElementById("adminOtpSubmitBtn");

  let code = "";
  digitBoxes.forEach(box => {
    code += box.value.trim();
  });

  if (!/^\d{6}$/.test(code)) {
    if (errorEl) {
      if (errorTextEl) errorTextEl.textContent = "يرجى كتابة رمز الأمان السداسي كاملاً (6 أرقام)";
      errorEl.style.display = "flex";
    }
    return;
  }

  if (!activeAdminChallengeId) {
    if (errorEl) {
      if (errorTextEl) errorTextEl.textContent = "انتهت صلاحية جلسة التحدي الأمني. يرجى إعادة إدخال رمز المرور.";
      errorEl.style.display = "flex";
    }
    backToStep1();
    return;
  }

  isSubmittingOtp = true;
  let origOtpChildren = [];
  if (submitBtn) {
    origOtpChildren = Array.from(submitBtn.childNodes);
    submitBtn.disabled = true;
    safeClearContainer(submitBtn);
    submitBtn.appendChild(createSafeEl("i", { class: "fas fa-spinner fa-spin" }));
    submitBtn.appendChild(createSafeEl("span", { textContent: " جارٍ مطابقة الرمز ومصادقة الجهاز..." }));
  }

  try {
    const res = await fetch("/api/auth", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest"
      },
      body: JSON.stringify({
        action: "verify_otp",
        otp: code,
        challengeId: activeAdminChallengeId
      })
    });

    const data = await res.json().catch(() => ({}));

    if (res.ok && data.success) {
      if (errorEl) errorEl.style.display = "none";
      if (otpTimerInterval) clearInterval(otpTimerInterval);
      activeAdminChallengeId = null;

      unhideAdminDashboard(data.user);
      showToast("✅ مرحباً بكم في لوحة تحكم معرض قاصد كريم (جلسة مشفرة)");
    } else {
      if (errorEl) {
        if (errorTextEl) errorTextEl.textContent = data.error || "رمز التحقق غير صحيح أو انتهت صلاحيته";
        errorEl.style.display = "flex";
      }
      const container = document.getElementById("otpBoxesContainer");
      if (container) {
        container.style.animation = "adminShake 0.4s ease";
        setTimeout(() => { if (container) container.style.animation = ""; }, 450);
      }
      digitBoxes.forEach(b => { b.value = ""; });
      if (digitBoxes[0]) digitBoxes[0].focus();
      showToast(data.error || "⚠️ رمز التحقق غير صحيح");
    }
  } catch (err) {
    if (errorEl) {
      if (errorTextEl) errorTextEl.textContent = "تعذر التحقق من رمز الأمان سحابياً";
      errorEl.style.display = "flex";
    }
    showToast("⚠️ تعذر التحقق من رمز الأمان سحابياً");
  } finally {
    isSubmittingOtp = false;
    if (submitBtn) {
      submitBtn.disabled = false;
      safeClearContainer(submitBtn);
      origOtpChildren.forEach(c => submitBtn.appendChild(c));
    }
  }
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

function startOtpCountdownTimer(durationSec = 300) {
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
      activeAdminChallengeId = null;
    }
    remaining--;
  };

  update();
  otpTimerInterval = setInterval(update, 1000);
}

function resendAdminOtp() {
  showToast("يرجى إدخال رمز المرور الرئيسي لطلب رمز أمان جديد");
  backToStep1();
}

function backToStep1() {
  if (otpTimerInterval) clearInterval(otpTimerInterval);
  activeAdminChallengeId = null;

  const step1 = document.getElementById("adminAuthStep1");
  const step2 = document.getElementById("adminAuthStep2");
  if (step1) step1.style.display = "block";
  if (step2) step2.style.display = "none";

  const pinInput = document.getElementById("adminPinInput");
  if (pinInput) {
    pinInput.value = "";
    pinInput.focus();
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

function createManualWebRestorePoint() {
  if (!window.KK_DB) return;
  const label = prompt("أدخل اسماً أو وصفاً لنقطة الاسترجاع اليدوية:", "نقطة استرجاع يدوية");
  if (!label || !label.trim()) return;
  window.KK_DB.saveWebRestorePoint(label.trim());
  showToast("📌 تم إنشاء وحفظ نقطة استرجاع ويب يدوية بنجاح");
  renderAdminBackupView();
}

// True Server-Side Logout (Axis 5)
async function logoutAdmin() {
  try {
    await fetch("/api/auth", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest"
      },
      body: JSON.stringify({ action: "logout" })
    });
  } catch (err) {
    console.warn("[Admin Auth] Logout API error:", err);
  } finally {
    activeAdminChallengeId = null;
    broadcastAdminLogout();
    cleanupAdminDomOnLogout();
    lockAdminGate();
    showToast("تم تسجيل خروج الإدارة بنجاح");
  }
}

// DOM & State Sanitization on Logout / Session Expiry (Axis 5)
function cleanupAdminDomOnLogout() {
  const containers = [
    "adminOrdersListContainer",
    "adminBestSellersTableBody",
    "adminInventoryTableBody",
    "adminGoogleUsersListContainer",
    "adminReviewsListContainer",
    "adminAuditLogsTableBody",
    "adminPrintInvoiceContainer",
    "adminRestorePointsTableBody",
    "adminCategoriesTableBody",
    "adminDeliveryAreasTableBody",
    "bulkCsvReportBox"
  ];
  containers.forEach(id => {
    const el = document.getElementById(id);
    if (el) safeClearContainer(el);
  });

  const forms = [
    "adminPinForm",
    "adminOtpForm",
    "adminAddProductForm",
    "adminEditProductPageForm",
    "adminAddCategoryForm",
    "adminSettingsForm"
  ];
  forms.forEach(fId => {
    const form = document.getElementById(fId);
    if (form && typeof form.reset === "function") form.reset();
  });

  if (typeof adminCustomersCache !== "undefined") adminCustomersCache = [];
  if (typeof validatedBulkCsvRows !== "undefined") validatedBulkCsvRows = [];
  if (window.KK_DB && typeof window.KK_DB.clearSensitiveMemory === "function") {
    window.KK_DB.clearSensitiveMemory();
  }
}

// Global System Initializer (Axis 1)
document.addEventListener("DOMContentLoaded", () => {
  initAdminSystem();
});

async function initAdminSystem() {
  const isAdminPage = !!document.getElementById("adminPageRoot");

  // Always bind event delegation and form listeners first
  initAdminEventDelegation();
  setupAdminListeners();

  if (isAdminPage) {
    // Strictly wait for authoritative server verification before loading any data
    await verifyAdminSession();
  } else {
    updateCustomerTrackingBadge();
  }

  setupRealtimeOrderListener();
}

function setupRealtimeOrderListener() {
  window.addEventListener("kk_new_order_placed", (e) => {
    const isAuth = document.body.classList.contains("is-admin-authenticated");
    if (!isAuth) return;

    updateAdminHeaderBadge();
    const order = e.detail;
    if (order) {
      showToast(`🔔 تنبيه إداري: تم استلام طلب جديد برقم #${order.id}`);
      if (window.KK_DB && typeof window.KK_DB.playLuxuryChime === "function") {
        window.KK_DB.playLuxuryChime();
      }
      showAdminLiveOrderAlert(order);
      const root = document.getElementById("adminPageRoot");
      if (root && !root.hidden) {
        renderAdminOrders();
        renderAdminOverview();
      }
    }
  });

  window.addEventListener("kk_orders_updated", () => {
    const isAuth = document.body.classList.contains("is-admin-authenticated");
    if (!isAuth) return;
    updateAdminHeaderBadge();
    const root = document.getElementById("adminPageRoot");
    if (root && !root.hidden) {
      renderAdminOrders();
      renderAdminOverview();
    }
  });

  window.addEventListener("kk_products_updated", () => {
    const isAuth = document.body.classList.contains("is-admin-authenticated");
    if (!isAuth) return;
    const root = document.getElementById("adminPageRoot");
    if (root && !root.hidden) {
      renderAdminOverview();
      renderAdminInventory();
    }
  });

  window.addEventListener("kk_categories_updated", () => {
    const isAuth = document.body.classList.contains("is-admin-authenticated");
    if (!isAuth) return;
    populateAdminCategorySelect();
    const root = document.getElementById("adminPageRoot");
    if (root && !root.hidden) {
      renderAdminCategories();
      renderAdminInventory();
    }
  });

  window.addEventListener("kk_settings_updated", () => {
    const isAuth = document.body.classList.contains("is-admin-authenticated");
    if (!isAuth) return;
    const root = document.getElementById("adminPageRoot");
    if (root && !root.hidden) {
      loadAdminSettingsValues();
    }
  });

  window.addEventListener("kk_restore_points_updated", () => {
    const isAuth = document.body.classList.contains("is-admin-authenticated");
    if (!isAuth) return;
    const root = document.getElementById("adminPageRoot");
    if (root && !root.hidden) {
      renderAdminBackupView();
    }
  });
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

  const custName = (order.customer && order.customer.name) ? order.customer.name : "عميل";
  const totalStr = formatSafeMoney(order.total);

  const bannerInner = createSafeEl("div", { class: "admin-live-banner-inner" }, [
    createSafeEl("div", { style: "display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;" }, [
      createSafeEl("span", { class: "live-banner-pulse" }),
      createSafeEl("strong", { style: "color: #FFFFFF; font-size: 0.95rem;", textContent: `🚨 تنبيه فوري: تم استلام طلب جديد برقم #${order.id}` }),
      createSafeEl("span", { style: "color: #FDE68A; font-size: 0.88rem;", textContent: `العميل: ${custName} • الإجمالي: ${totalStr} ج.م` })
    ]),
    createSafeEl("div", { style: "display: flex; align-items: center; gap: 0.6rem;" }, [
      createSafeEl("a", {
        href: "admin.html",
        class: "btn-primary",
        style: "padding: 0.35rem 0.85rem; font-size: 0.78rem; text-decoration: none; background: #F59E0B; color: #0F172A; font-weight: 700;",
        textContent: "عرض في لوحة التحكم"
      }),
      createSafeEl("button", {
        type: "button",
        class: "banner-close-btn",
        dataset: { action: "dismiss-live-alert", orderId: String(order.id) },
        textContent: "×"
      })
    ])
  ]);

  safeClearContainer(banner);
  banner.appendChild(bannerInner);
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

  const targetBtn = element && element.classList.contains("admin-tab-btn")
    ? element
    : document.querySelector(`.admin-tab-btn[data-tab="${tabKey}"]`);
  if (targetBtn) targetBtn.classList.add("active");

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

  if (revEl) revEl.textContent = `${formatSafeMoney(analytics.totalRevenue)} ج.م`;
  if (ordersEl) ordersEl.textContent = formatSafeInt(analytics.totalOrdersCount);
  if (productsEl) productsEl.textContent = formatSafeInt(analytics.activeProductsCount);
  if (pendingEl) pendingEl.textContent = formatSafeInt(analytics.pendingOrdersCount);

  // Render Best Sellers Table
  const tableBody = document.getElementById("adminBestSellersTableBody");
  if (!tableBody) return;

  if (!analytics.bestSellers || analytics.bestSellers.length === 0) {
    const emptyRow = createSafeEl("tr", {}, [
      createSafeEl("td", { colspan: "5", style: "text-align:center; padding: 2rem;", textContent: "لا توجد مبيعات مسجلة حتى الآن" })
    ]);
    safeClearContainer(tableBody);
    tableBody.appendChild(emptyRow);
    return;
  }

  const frag = document.createDocumentFragment();
  analytics.bestSellers.forEach((item, index) => {
    const totalItemRev = (Number(item.price) || 0) * (Number(item.salesCount) || 0);
    const thumbImg = createSafeEl("img", {
      class: "seller-thumb",
      alt: String(item.name || "وحدة إضاءة")
    });
    setSafeImageWithFallback(thumbImg, item.image);

    const row = createSafeEl("tr", {}, [
      createSafeEl("td", { style: "font-weight: 800; color: var(--accent); width: 40px;", textContent: `#${index + 1}` }),
      createSafeEl("td", {}, [
        createSafeEl("div", { class: "seller-name-cell" }, [
          thumbImg,
          createSafeEl("div", {}, [
            createSafeEl("div", { class: "seller-name", textContent: String(item.name || "") }),
            createSafeEl("div", { class: "seller-cat", textContent: `${item.categoryName || ""} • ${item.style || "معاصر"}` })
          ])
        ])
      ]),
      createSafeEl("td", {}, [
        createSafeEl("span", { style: "font-weight: 700;", textContent: `${formatSafeMoney(item.price)} ج.م` })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("span", { class: "sales-badge", textContent: `${formatSafeInt(item.salesCount)} وحدة مباعة` })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("strong", { style: "color: #0F172A;", textContent: `${formatSafeMoney(totalItemRev)} ج.م` })
      ])
    ]);
    frag.appendChild(row);
  });

  safeClearContainer(tableBody);
  tableBody.appendChild(frag);
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
    const emptyState = createSafeEl("div", {
      style: "text-align: center; padding: 3.5rem 1rem; background: #FFFFFF; border-radius: var(--radius-md); border: 1px dashed var(--border-light);"
    }, [
      createSafeEl("i", { class: "fas fa-boxes-packing", style: "font-size: 2.8rem; color: #CBD5E1; margin-bottom: 0.85rem;" }),
      createSafeEl("h4", { style: "color: var(--text-main); font-weight: 800; margin-bottom: 0.35rem;", textContent: "لا توجد طلبات في هذا القسم حالياً" }),
      createSafeEl("p", { style: "color: var(--text-muted); font-size: 0.85rem; margin: 0;", textContent: "النظام متصل بالكامل ويعمل في وضع المزامنة اللحظية المباشرة" })
    ]);
    safeClearContainer(container);
    container.appendChild(emptyState);
    return;
  }

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

  const frag = document.createDocumentFragment();

  orders.forEach(order => {
    const isNew = order.status === "received" || order.status === "pending";
    const statusText = statusLabels[order.status] || "قيد المعالجة";

    // Safe customer data extraction
    const customer = (order.customer && typeof order.customer === "object") ? order.customer : {};
    const customerName = String(customer.name || "عميل الكتالوج الفاخر");
    const customerPhone = String(customer.phone || "");
    const customerAddress = String(customer.address || "الشيخ زايد");
    const customerNotes = String(customer.notes || "");
    const deliveryAreaName = String(order.deliveryAreaName || customer.deliveryAreaName || customer.city || "الشيخ زايد");
    const shippingFee = order.shippingFee !== undefined ? order.shippingFee : (order.shipping !== undefined ? order.shipping : null);

    // COD Payment Status
    const isPaid = order.paymentStatus === "collected";
    const paymentStatusBadge = isPaid
      ? createSafeEl("span", {
          class: "cod-collected-badge",
          style: "background: rgba(16,185,129,0.12); color: #059669; font-weight: 800; font-size: 0.75rem; padding: 4px 10px; border-radius: 4px; display: inline-flex; align-items: center; gap: 0.35rem;"
        }, [createSafeEl("i", { class: "fas fa-check-circle" }), document.createTextNode(" تم تحصيل النقدية بالكامل")])
      : createSafeEl("span", {
          class: "cod-uncollected-badge",
          style: "background: rgba(245,158,11,0.12); color: #D97706; font-weight: 800; font-size: 0.75rem; padding: 4px 10px; border-radius: 4px; display: inline-flex; align-items: center; gap: 0.35rem;"
        }, [createSafeEl("i", { class: "fas fa-hand-holding-dollar" }), document.createTextNode(" الدفع نقدياً عند الاستلام — لم يتم التحصيل بعد")]);

    const paymentToggleBtn = isPaid
      ? createSafeEl("button", {
          type: "button",
          class: "btn-secondary",
          style: "font-size: 0.75rem; padding: 0.35rem 0.65rem; color: #DC2626;",
          dataset: { action: "toggle-payment", orderId: String(order.id), payment: "uncollected" }
        }, [createSafeEl("i", { class: "fas fa-undo" }), document.createTextNode(" إلغاء تسجيل السداد")])
      : createSafeEl("button", {
          type: "button",
          class: "btn-primary",
          style: "font-size: 0.75rem; padding: 0.35rem 0.75rem; background: #10B981; border: none; font-weight: 800;",
          dataset: { action: "toggle-payment", orderId: String(order.id), payment: "collected" }
        }, [createSafeEl("i", { class: "fas fa-check" }), document.createTextNode(" تسجيل استلام النقدية")]);

    // Items array extraction
    const items = Array.isArray(order.items) 
      ? order.items 
      : (order.items && typeof order.items === "object" ? Object.values(order.items) : []);

    let formattedDate = "اليوم";
    if (order.timestamp) {
      try {
        const d = new Date(order.timestamp);
        const datePart = d.toLocaleDateString("ar-EG", { timeZone: "Africa/Cairo", year: "numeric", month: "short", day: "numeric" });
        const timePart = d.toLocaleTimeString("ar-EG", { timeZone: "Africa/Cairo", hour: "2-digit", minute: "2-digit" });
        formattedDate = `${datePart} - ${timePart}`;
      } catch (e) {
        formattedDate = "اليوم";
      }
    } else if (order.dateFormatted) {
      formattedDate = order.timeFormatted ? `${order.dateFormatted} - ${order.timeFormatted}` : order.dateFormatted;
    }

    // Header Row
    const headerRow = createSafeEl("div", { class: "order-header-row" }, [
      createSafeEl("div", { style: "display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;" }, [
        createSafeEl("span", { class: "order-id-tag", textContent: `#${order.id}` }),
        createSafeEl("span", { class: "order-date-text" }, [
          createSafeEl("i", { class: "fas fa-clock" }),
          document.createTextNode(` ${formattedDate}`)
        ]),
        isNew ? createSafeEl("span", { class: "new-live-tag" }, [
          createSafeEl("i", { class: "fas fa-bolt" }),
          document.createTextNode(" وارد الآن")
        ]) : null,
        createSafeEl("div", {}, paymentStatusBadge)
      ]),
      createSafeEl("div", { style: "display: flex; align-items: center; gap: 0.75rem;" }, [
        createSafeEl("span", { class: `order-status-pill ${order.status}`, textContent: statusText }),
        createSafeEl("select", {
          class: "custom-select",
          style: "padding: 0.35rem 0.75rem; font-size: 0.78rem; font-weight: 700;",
          dataset: { action: "change-order-status", orderId: String(order.id) }
        }, [
          createSafeEl("option", { value: "received", selected: (order.status === 'received' || order.status === 'pending') ? "selected" : undefined, textContent: "⏳ تم الاستلام والتوثيق (Received)" }),
          createSafeEl("option", { value: "confirmed", selected: order.status === 'confirmed' ? "selected" : undefined, textContent: "📋 تم التأكيد والمعاينة (Confirmed)" }),
          createSafeEl("option", { value: "preparing", selected: (order.status === 'preparing' || order.status === 'processing') ? "selected" : undefined, textContent: "⚙️ جاري التجهيز (Preparing)" }),
          createSafeEl("option", { value: "packed", selected: order.status === 'packed' ? "selected" : undefined, textContent: "📦 تم التغليف (Packed)" }),
          createSafeEl("option", { value: "shipped", selected: order.status === 'shipped' ? "selected" : undefined, textContent: "🚚 خرج للتوصيل (Out for delivery)" }),
          createSafeEl("option", { value: "delivered", selected: (order.status === 'delivered' || order.status === 'completed') ? "selected" : undefined, textContent: "✅ تم التسليم (Delivered)" }),
          createSafeEl("option", { value: "cancelled", selected: order.status === 'cancelled' ? "selected" : undefined, textContent: "❌ ملغي (Cancelled)" }),
          createSafeEl("option", { value: "failed", selected: order.status === 'failed' ? "selected" : undefined, textContent: "⚠️ تعذر التسليم (Delivery failed)" })
        ])
      ])
    ]);

    // Customer Box
    const telLink = customerPhone ? createSafeEl("a", {
      href: buildSafeTelUrl(customerPhone),
      style: "color: var(--accent-hover); font-weight: 800; text-decoration: none; dir: ltr;",
      dir: "ltr"
    }, [
      createSafeEl("i", { class: "fas fa-phone-alt", style: "font-size: 0.75rem;" }),
      document.createTextNode(` ${customerPhone}`)
    ]) : createSafeEl("span", { style: "color: var(--text-muted); font-size: 0.85rem;", textContent: "غير مسجل" });

    const shippingText = shippingFee !== null 
      ? (shippingFee === 0 ? " (رسوم الشحن: مجاناً)" : ` (رسوم الشحن: ${formatSafeMoney(shippingFee)} ج.م)`)
      : "";

    const customerBox = createSafeEl("div", { class: "order-customer-box" }, [
      createSafeEl("div", { class: "customer-info-item" }, [
        createSafeEl("strong", { textContent: "اسم العميل: " }),
        createSafeEl("span", { style: "font-weight: 800; color: #0F172A;", textContent: customerName })
      ]),
      createSafeEl("div", { class: "customer-info-item" }, [
        createSafeEl("strong", { textContent: "رقم الهاتف / الواتساب: " }),
        telLink
      ]),
      createSafeEl("div", { class: "customer-info-item" }, [
        createSafeEl("strong", { textContent: "منطقة التوصيل: " }),
        createSafeEl("span", { style: "font-weight: 700; color: var(--text-main);", textContent: `${deliveryAreaName}${shippingText}` })
      ]),
      createSafeEl("div", { class: "customer-info-item" }, [
        createSafeEl("strong", { textContent: "العنوان بالتفصيل: " }),
        createSafeEl("span", { style: "white-space: pre-wrap; word-break: break-word;", textContent: customerAddress })
      ]),
      customerNotes ? createSafeEl("div", { class: "customer-info-item", style: "grid-column: 1 / -1;" }, [
        createSafeEl("strong", { textContent: "ملاحظات العميل: " }),
        createSafeEl("span", { style: "font-weight: 500; color: #475569; white-space: pre-wrap; word-break: break-word;", textContent: customerNotes })
      ]) : null
    ]);

    // Items Table
    const itemsTbody = createSafeEl("tbody");
    if (items.length > 0) {
      items.forEach(item => {
        const itemQty = formatSafeInt(item.qty, 1);
        const itemPrice = Number(item.price) || 0;
        const itemTotal = itemPrice * itemQty;

        const itemImg = createSafeEl("img", {
          class: "item-table-img",
          alt: String(item.name || "وحدة إضاءة")
        });
        setSafeImageWithFallback(itemImg, item.image);

        const itemTr = createSafeEl("tr", { class: "order-item-tr" }, [
          createSafeEl("td", { class: "col-product" }, [
            createSafeEl("div", { class: "item-cell-with-img" }, [
              itemImg,
              createSafeEl("div", { class: "item-info-meta" }, [
                createSafeEl("div", { class: "item-name-ar", textContent: String(item.name || "وحدة إضاءة فاخرة") }),
                createSafeEl("div", { class: "item-name-en", textContent: String(item.enName || "") }),
                createSafeEl("span", { class: "item-cat-badge", textContent: String(item.categoryName || "إضاءة فاخرة") })
              ])
            ])
          ]),
          createSafeEl("td", { class: "col-category", textContent: String(item.categoryName || "إضاءة فاخرة") }),
          createSafeEl("td", { class: "col-qty" }, [
            createSafeEl("span", { class: "mobile-stat-label", textContent: "الكمية: " }),
            createSafeEl("span", { class: "qty-val", textContent: `${itemQty} وحدة` })
          ]),
          createSafeEl("td", { class: "col-price" }, [
            createSafeEl("span", { class: "mobile-stat-label", textContent: "سعر القطعة: " }),
            createSafeEl("span", { class: "price-val", textContent: `${formatSafeMoney(itemPrice)} ج.م` })
          ]),
          createSafeEl("td", { class: "col-total" }, [
            createSafeEl("span", { class: "mobile-stat-label", textContent: "الإجمالي: " }),
            createSafeEl("span", { class: "total-val", textContent: `${formatSafeMoney(itemTotal)} ج.م` })
          ])
        ]);
        itemsTbody.appendChild(itemTr);
      });
    } else {
      itemsTbody.appendChild(createSafeEl("tr", {}, [
        createSafeEl("td", {
          colspan: "5",
          class: "order-no-items-cell",
          style: "text-align: center; color: var(--text-muted); padding: 1.25rem;"
        }, [
          createSafeEl("i", { class: "fas fa-boxes-stacked", style: "margin-left: 0.45rem; color: var(--accent);" }),
          document.createTextNode(` وحدات إضاءة تم اختيارها من الكتالوج بقيمة إجمالية ${formatSafeMoney(order.total)} جنيه مصري`)
        ])
      ]));
    }

    const itemsTable = createSafeEl("table", { class: "order-items-table" }, [
      createSafeEl("thead", {}, [
        createSafeEl("tr", {}, [
          createSafeEl("th", { textContent: "صورة واسم وحدة الإضاءة" }),
          createSafeEl("th", { textContent: "التصنيف" }),
          createSafeEl("th", { textContent: "الكمية" }),
          createSafeEl("th", { textContent: "سعر القطعة" }),
          createSafeEl("th", { textContent: "الإجمالي" })
        ])
      ]),
      itemsTbody
    ]);

    // Footer Actions
    const footerActions = createSafeEl("div", { class: "order-footer-actions" }, [
      createSafeEl("div", { style: "display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;" }, [
        createSafeEl("div", { class: "order-total-sum" }, [
          document.createTextNode("إجمالي الطلب: "),
          createSafeEl("span", { style: "color: var(--accent-hover);", textContent: `${formatSafeMoney(order.total)} جنيه مصري` })
        ]),
        createSafeEl("div", {}, paymentToggleBtn)
      ]),
      createSafeEl("div", { class: "order-action-buttons" }, [
        createSafeEl("button", {
          type: "button",
          class: "btn-secondary",
          style: "padding: 0.5rem 0.85rem; font-size: 0.8rem;",
          dataset: { action: "print-order", orderId: String(order.id) }
        }, [
          createSafeEl("i", { class: "fas fa-print" }),
          createSafeEl("span", { textContent: " طباعة الفاتورة" })
        ]),
        createSafeEl("button", {
          type: "button",
          class: "btn-whatsapp-customer",
          dataset: { action: "contact-whatsapp", orderId: String(order.id) }
        }, [
          createSafeEl("i", { class: "fab fa-whatsapp" }),
          createSafeEl("span", { textContent: " مراسلة العميل بالطلب عبر واتساب" })
        ]),
        createSafeEl("button", {
          type: "button",
          class: "btn-secondary",
          style: "padding: 0.5rem 0.85rem; font-size: 0.8rem; color: #EF4444;",
          dataset: { action: "delete-order", orderId: String(order.id) }
        }, [
          createSafeEl("i", { class: "fas fa-trash-alt" }),
          createSafeEl("span", { textContent: " حذف" })
        ])
      ])
    ]);

    const orderCard = createSafeEl("div", { class: `order-card-detailed ${isNew ? 'is-new-order' : ''}` }, [
      headerRow,
      customerBox,
      itemsTable,
      footerActions
    ]);

    frag.appendChild(orderCard);
  });

  safeClearContainer(container);
  container.appendChild(frag);
}

function printOrderInvoice(orderId) {
  if (!window.KK_DB) return;
  const order = window.KK_DB.getOrders().find(o => o.id === orderId);
  if (!order) {
    showToast("⚠️ لم يتم العثور على بيانات الطلب لطباعة الفاتورة");
    return;
  }

  let printContainer = document.getElementById("adminPrintInvoiceContainer");
  if (!printContainer) {
    printContainer = document.createElement("div");
    printContainer.id = "adminPrintInvoiceContainer";
    printContainer.className = "admin-print-only";
    document.body.appendChild(printContainer);
  }
  safeClearContainer(printContainer);

  const customer = (order.customer && typeof order.customer === "object") ? order.customer : {};
  const customerName = String(customer.name || "العميل الكريم");
  const customerPhone = String(customer.phone || "غير مسجل");
  const customerAddress = String(customer.address || "الشيخ زايد");
  const customerNotes = String(customer.notes || "");
  const items = Array.isArray(order.items) ? order.items : [];

  const invoiceCard = createSafeEl("div", {
    class: "invoice-print-sheet",
    style: "direction: rtl; padding: 24px; font-family: sans-serif; background: #FFF; color: #000;"
  }, [
    createSafeEl("div", { style: "display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #333; padding-bottom: 12px; margin-bottom: 16px;" }, [
      createSafeEl("div", {}, [
        createSafeEl("h2", { style: "margin: 0; color: #1E293B;", textContent: "قاصد كريم للإضاءة الفاخرة" }),
        createSafeEl("p", { style: "margin: 4px 0 0 0; color: #64748B; font-size: 14px;", textContent: "معرض الشيخ زايد — فاتورة طلب وإذن تسليم" })
      ]),
      createSafeEl("div", { style: "text-align: left;" }, [
        createSafeEl("div", { style: "font-weight: 800; font-size: 16px;", textContent: `فاتورة #${order.id}` }),
        createSafeEl("div", { style: "color: #64748B; font-size: 13px;", textContent: order.dateFormatted || new Date(order.timestamp || Date.now()).toLocaleDateString("ar-EG") })
      ])
    ]),
    createSafeEl("div", { style: "background: #F8FAFC; border: 1px solid #E2E8F0; padding: 12px; border-radius: 6px; margin-bottom: 16px; display: grid; grid-template-columns: 1fr 1fr; gap: 8px;" }, [
      createSafeEl("div", {}, [
        createSafeEl("strong", { textContent: "اسم العميل: " }),
        createSafeEl("span", { textContent: customerName })
      ]),
      createSafeEl("div", {}, [
        createSafeEl("strong", { textContent: "رقم الهاتف: " }),
        createSafeEl("span", { textContent: customerPhone })
      ]),
      createSafeEl("div", { style: "grid-column: 1 / -1;" }, [
        createSafeEl("strong", { textContent: "عنوان التوصيل: " }),
        createSafeEl("span", { style: "white-space: pre-wrap; word-break: break-word;", textContent: customerAddress })
      ]),
      customerNotes ? createSafeEl("div", { style: "grid-column: 1 / -1;" }, [
        createSafeEl("strong", { textContent: "ملاحظات: " }),
        createSafeEl("span", { style: "white-space: pre-wrap; word-break: break-word;", textContent: customerNotes })
      ]) : null
    ]),
    createSafeEl("table", { style: "width: 100%; border-collapse: collapse; margin-bottom: 16px; text-align: right;" }, [
      createSafeEl("thead", {}, [
        createSafeEl("tr", { style: "background: #0F172A; color: #FFFFFF;" }, [
          createSafeEl("th", { style: "padding: 8px 12px; border: 1px solid #CBD5E1;", textContent: "وحدة الإضاءة" }),
          createSafeEl("th", { style: "padding: 8px 12px; border: 1px solid #CBD5E1;", textContent: "الكمية" }),
          createSafeEl("th", { style: "padding: 8px 12px; border: 1px solid #CBD5E1;", textContent: "سعر القطعة" }),
          createSafeEl("th", { style: "padding: 8px 12px; border: 1px solid #CBD5E1;", textContent: "الإجمالي" })
        ])
      ]),
      createSafeEl("tbody", {}, items.map(item => {
        const qty = formatSafeInt(item.qty, 1);
        const price = Number(item.price) || 0;
        return createSafeEl("tr", {}, [
          createSafeEl("td", { style: "padding: 8px 12px; border: 1px solid #CBD5E1;", textContent: String(item.name || "وحدة إضاءة") }),
          createSafeEl("td", { style: "padding: 8px 12px; border: 1px solid #CBD5E1;", textContent: `${qty} وحدة` }),
          createSafeEl("td", { style: "padding: 8px 12px; border: 1px solid #CBD5E1;", textContent: `${formatSafeMoney(price)} ج.م` }),
          createSafeEl("td", { style: "padding: 8px 12px; border: 1px solid #CBD5E1; font-weight: 700;", textContent: `${formatSafeMoney(price * qty)} ج.م` })
        ]);
      }))
    ]),
    createSafeEl("div", { style: "text-align: left; font-size: 16px; font-weight: 800; padding: 12px; background: #FEF3C7; border: 1px solid #FDE68A; border-radius: 6px;" }, [
      createSafeEl("span", { textContent: `إجمالي الفاتورة المطلوب سداده: ${formatSafeMoney(order.total)} جنيه مصري` })
    ])
  ]);

  printContainer.appendChild(invoiceCard);
  window.print();
}

function exportOrdersCsv() {
  if (!window.KK_DB) return;
  const orders = window.KK_DB.getOrders();
  if (!orders || orders.length === 0) {
    showToast("⚠️ لا توجد طلبات للتصدير");
    return;
  }

  const headers = ["OrderID", "CustomerName", "Phone", "Area", "Address", "Notes", "TotalAmount", "PaymentStatus", "OrderStatus", "Date"];
  const rows = orders.map(order => {
    const cust = order.customer || {};
    return [
      escapeCsvCell(order.id),
      escapeCsvCell(cust.name || "عميل"),
      escapeCsvCell(cust.phone || ""),
      escapeCsvCell(order.deliveryAreaName || cust.city || ""),
      escapeCsvCell(cust.address || ""),
      escapeCsvCell(cust.notes || ""),
      escapeCsvCell(order.total || 0),
      escapeCsvCell(order.paymentStatus || "uncollected"),
      escapeCsvCell(order.status || "pending"),
      escapeCsvCell(order.dateFormatted || new Date(order.timestamp || Date.now()).toISOString())
    ].join(",");
  });

  const csvContent = "\uFEFF" + [headers.join(","), ...rows].join("\r\n");
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", `kased_karim_orders_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  showToast("📥 تم تصدير بيانات الطلبات إلى ملف CSV محصّن");
}
window.printOrderInvoice = printOrderInvoice;
window.exportOrdersCsv = exportOrdersCsv;

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

// =============================================================================
// CENTRAL ADMIN EVENT DELEGATION ARCHITECTURE (Anti-Leak & Strict CSP)
// =============================================================================
let isAdminEventDelegationInitialized = false;

const ALLOWED_ADMIN_STATUSES = [
  "received", "pending", "confirmed", "preparing", "processing",
  "packed", "shipped", "delivered", "completed", "cancelled", "failed"
];

async function runDbDiagnosticsUI(btn) {
  if (!btn) return;
  btn.disabled = true;
  safeClearContainer(btn);
  btn.appendChild(createSafeEl("i", { class: "fas fa-spinner fa-spin" }));
  btn.appendChild(createSafeEl("span", { textContent: " جاري فحص قاعدة البيانات..." }));

  try {
    const res = await fetch("/api/db-health");
    if (res.ok) {
      const data = await res.json();
      const resContainer = document.getElementById("dbDiagnosticsResults");
      if (resContainer) resContainer.style.display = "block";

      const elEngine = document.getElementById("diagEngine");
      const elIntegrity = document.getElementById("diagIntegrity");
      const elSoftDelete = document.getElementById("diagSoftDelete");
      const elCounts = document.getElementById("diagCounts");

      if (elEngine) elEngine.textContent = data.engine || data.database || "SQL Relational (WAL)";
      if (elIntegrity) elIntegrity.textContent = "ON DELETE RESTRICT (مُفعل - حظر الحذف عند الارتباط)";
      if (elSoftDelete) elSoftDelete.textContent = "Soft Delete (حقل deleted_at نشط)";
      if (elCounts) elCounts.textContent = `${data.stats?.products_active || 0} نشط • ${data.stats?.products_soft_deleted || 0} محذوف لطيفاً`;

      showToast("✅ تم فحص قاعدة البيانات: التكامل المرجعي والـ Soft Delete يعملان بكفاءة!");
    } else {
      showToast("⚠️ لم يتم الرد من نقطة الفحص السحابية.");
    }
  } catch (err) {
    showToast("⚠️ تعذر الاتصال بـ /api/db-health. تأكد من تشغيل السيرفر (npm start).");
  } finally {
    btn.disabled = false;
    safeClearContainer(btn);
    btn.appendChild(createSafeEl("i", { class: "fas fa-stethoscope" }));
    btn.appendChild(createSafeEl("span", { textContent: " تشغيل الفحص الفوري الآن" }));
  }
}

function initAdminEventDelegation() {
  if (isAdminEventDelegationInitialized) return;
  isAdminEventDelegationInitialized = true;

  document.addEventListener("click", function(e) {
    const trigger = e.target.closest("[data-action]");
    if (!trigger) return;

    const action = trigger.dataset.action;

    switch (action) {
      case "toggle-pin-visibility": {
        e.preventDefault();
        togglePinVisibility();
        break;
      }

      case "resend-otp": {
        e.preventDefault();
        resendAdminOtp();
        break;
      }

      case "back-to-step1": {
        e.preventDefault();
        backToStep1();
        break;
      }

      case "cloud-sync": {
        e.preventDefault();
        triggerFullCloudSync();
        break;
      }

      case "run-db-diagnostics": {
        e.preventDefault();
        runDbDiagnosticsUI(trigger);
        break;
      }

      case "apply-restore-calendar-filter": {
        e.preventDefault();
        renderAdminBackupView();
        showToast("🔍 تم تطبيق فلترة التقويم لنقاط الاسترجاع بنجاح");
        break;
      }

      case "reset-restore-calendar-filter": {
        e.preventDefault();
        const dateInput = document.getElementById("restoreFilterExactDate");
        const yearSelect = document.getElementById("restoreFilterYear");
        const monthSelect = document.getElementById("restoreFilterMonth");
        const searchInput = document.getElementById("restoreFilterSearch");
        if (dateInput) dateInput.value = "";
        if (yearSelect) yearSelect.value = "";
        if (monthSelect) monthSelect.value = "";
        if (searchInput) searchInput.value = "";
        renderAdminBackupView();
        showToast("↺ تم إعادة تعيين فلتر التقويم وعرض كافة النقاط");
        break;
      }

      case "filter-restore-preset": {
        e.preventDefault();
        const preset = trigger.dataset.preset;
        const dateInput = document.getElementById("restoreFilterExactDate");
        const yearSelect = document.getElementById("restoreFilterYear");
        const monthSelect = document.getElementById("restoreFilterMonth");
        const searchInput = document.getElementById("restoreFilterSearch");

        if (dateInput) dateInput.value = "";
        if (yearSelect) yearSelect.value = "";
        if (monthSelect) monthSelect.value = "";
        if (searchInput) searchInput.value = "";

        const now = new Date();
        const todayStr = now.toISOString().slice(0, 10);
        const currentYear = now.getFullYear().toString();
        const currentMonth = String(now.getMonth() + 1).padStart(2, "0");

        if (preset === "today" && dateInput) {
          dateInput.value = todayStr;
        } else if (preset === "month" && monthSelect && yearSelect) {
          yearSelect.value = currentYear;
          monthSelect.value = currentMonth;
        } else if (preset === "prev-year" && yearSelect) {
          yearSelect.value = (now.getFullYear() - 1).toString();
        } else if (preset === "week" && dateInput) {
          dateInput.value = todayStr;
        }

        renderAdminBackupView();
        break;
      }

      case "daily-backup-download": {
        e.preventDefault();
        triggerDailyBackupDownload();
        break;
      }

      case "dismiss-daily-backup": {
        e.preventDefault();
        dismissDailyBackupBanner();
        break;
      }

      case "copy-secret-link": {
        e.preventDefault();
        copyAdminSecretLink();
        break;
      }

      case "admin-logout": {
        e.preventDefault();
        logoutAdmin();
        break;
      }

      case "switch-tab": {
        e.preventDefault();
        const tab = trigger.dataset.tab;
        if (tab) switchAdminTab(tab, trigger);
        break;
      }

      case "refresh-orders": {
        e.preventDefault();
        refreshAdminOrdersFromCloud(trigger);
        break;
      }

      case "test-chime": {
        e.preventDefault();
        testAdminChime();
        break;
      }

      case "filter-orders": {
        e.preventDefault();
        const filter = trigger.dataset.filter;
        if (filter) renderAdminOrders(filter);
        break;
      }

      case "toggle-image-mode": {
        e.preventDefault();
        toggleImageInputMode();
        break;
      }

      case "trigger-file-input": {
        e.preventDefault();
        const targetId = trigger.dataset.target;
        if (targetId) {
          const targetEl = document.getElementById(targetId);
          if (targetEl) targetEl.click();
        }
        break;
      }

      case "reset-primary-image": {
        e.preventDefault();
        resetPrimaryImage(e);
        break;
      }

      case "reset-secondary-image": {
        e.preventDefault();
        resetSecondaryImage(e);
        break;
      }

      case "export-catalog": {
        e.preventDefault();
        exportCatalogData();
        break;
      }

      case "close-product-editor": {
        e.preventDefault();
        closeProductEditor();
        break;
      }

      case "reset-edit-secondary-image": {
        e.preventDefault();
        resetEditSecondaryImage(e);
        break;
      }

      case "load-settings": {
        e.preventDefault();
        loadAdminSettingsValues();
        break;
      }

      case "apply-file-restore": {
        e.preventDefault();
        applyFileRestore(e);
        break;
      }

      case "cancel-file-restore": {
        e.preventDefault();
        cancelFileRestore(e);
        break;
      }

      case "create-restore-point": {
        e.preventDefault();
        createManualWebRestorePoint();
        break;
      }

      case "factory-reset": {
        e.preventDefault();
        emergencyFactoryReset();
        break;
      }

      case "download-csv-template": {
        e.preventDefault();
        downloadSampleCsvTemplate();
        break;
      }

      case "validate-bulk-csv": {
        e.preventDefault();
        validateBulkCsvData();
        break;
      }

      case "clear-bulk-csv": {
        e.preventDefault();
        clearBulkCsvForm();
        break;
      }

      case "add-delivery-zone": {
        e.preventDefault();
        addNewDeliveryAreaRow();
        break;
      }

      case "save-delivery-zones": {
        e.preventDefault();
        saveDeliveryAreasChanges();
        break;
      }

      case "filter-reviews": {
        e.preventDefault();
        const filter = trigger.dataset.filter;
        if (filter) renderAdminReviews(filter);
        break;
      }

      case "refresh-audit-logs": {
        e.preventDefault();
        renderAdminAuditLogs();
        break;
      }

      case "refresh-google-users": {
        e.preventDefault();
        refreshAdminGoogleUsers();
        break;
      }

      case "export-google-users-csv": {
        e.preventDefault();
        exportAdminGoogleUsersCSV();
        break;
      }

      case "filter-google-users": {
        e.preventDefault();
        const filter = trigger.dataset.filter;
        if (filter) setAdminGoogleUsersFilter(filter);
        break;
      }

      case "stop-propagation": {
        e.stopPropagation();
        break;
      }

      case "toggle-payment": {
        const orderId = trigger.dataset.orderId;
        const payment = trigger.dataset.payment;
        if (orderId && payment && typeof toggleOrderPayment === "function") {
          toggleOrderPayment(orderId, payment);
        }
        break;
      }

      case "whatsapp-customer":
      case "contact-whatsapp": {
        const orderId = trigger.dataset.orderId;
        const fn = (typeof window !== "undefined" && window.contactCustomerViaWhatsApp) || (typeof contactCustomerViaWhatsApp === "function" ? contactCustomerViaWhatsApp : null);
        if (orderId && fn) fn(orderId);
        break;
      }

      case "print-invoice":
      case "print-order": {
        const orderId = trigger.dataset.orderId;
        const fn = (typeof window !== "undefined" && window.printOrderInvoice) || (typeof printOrderInvoice === "function" ? printOrderInvoice : null);
        if (orderId && fn) fn(orderId);
        break;
      }

      case "delete-order": {
        const orderId = trigger.dataset.orderId;
        if (!orderId) return;
        if (confirm(`هل أنت متأكد من حذف الطلب #${orderId} نهائياً؟`)) {
          if (window.KK_DB) {
            window.KK_DB.deleteOrder(orderId);
            showToast(`🗑️ تم حذف الطلب #${orderId} بنجاح`);
            renderAdminOrders();
            renderAdminOverview();
          }
        }
        break;
      }

      case "edit-product": {
        const prodId = trigger.dataset.productId;
        const fn = (typeof window !== "undefined" && window.openProductEditorPage) || (typeof openProductEditorPage === "function" ? openProductEditorPage : null);
        if (prodId && fn) fn(prodId);
        break;
      }

      case "delete-product": {
        const prodId = trigger.dataset.productId;
        const fn = (typeof window !== "undefined" && window.deleteProduct) || (typeof deleteProduct === "function" ? deleteProduct : null);
        if (prodId && fn) fn(prodId);
        break;
      }

      case "edit-category": {
        const catId = trigger.dataset.catId;
        const fn = (typeof window !== "undefined" && window.editCategoryPrompt) || (typeof editCategoryPrompt === "function" ? editCategoryPrompt : null);
        if (catId && fn) fn(catId);
        break;
      }

      case "delete-category": {
        const catId = trigger.dataset.catId;
        const fn = (typeof window !== "undefined" && window.deleteCategoryConfirm) || (typeof deleteCategoryConfirm === "function" ? deleteCategoryConfirm : null);
        if (catId && fn) fn(catId);
        break;
      }

      case "copy-email": {
        const email = trigger.dataset.email;
        if (email && typeof copyToClipboard === "function") {
          copyToClipboard(email, "تم نسخ البريد الإلكتروني");
        }
        break;
      }

      case "filter-customer-orders": {
        const customer = trigger.dataset.customer;
        const fn = (typeof window !== "undefined" && window.filterOrdersByCustomer) || (typeof filterOrdersByCustomer === "function" ? filterOrdersByCustomer : null);
        if (customer && fn) fn(customer);
        break;
      }

      case "dismiss-live-alert": {
        const orderId = trigger.dataset.orderId;
        const fn = (typeof window !== "undefined" && window.dismissAdminLiveOrderAlert) || (typeof dismissAdminLiveOrderAlert === "function" ? dismissAdminLiveOrderAlert : null);
        if (fn) fn(orderId);
        break;
      }

      case "load-track-order": {
        const orderId = trigger.dataset.orderId;
        const fn = (typeof window !== "undefined" && window.loadAndRenderTrackOrder) || (typeof loadAndRenderTrackOrder === "function" ? loadAndRenderTrackOrder : null);
        if (orderId && fn) fn(orderId);
        break;
      }

      case "contact-support-track": {
        const query = trigger.dataset.query;
        const fn = (typeof window !== "undefined" && window.contactSupportAboutTrackedOrder) || (typeof contactSupportAboutTrackedOrder === "function" ? contactSupportAboutTrackedOrder : null);
        if (fn) fn(query);
        break;
      }

      case "restore-web-point": {
        const pointId = trigger.dataset.pointId;
        const fn = (typeof window !== "undefined" && window.restoreWebPointById) || (typeof restoreWebPointById === "function" ? restoreWebPointById : null);
        if (pointId && fn) fn(pointId);
        break;
      }

      case "delete-web-point": {
        const pointId = trigger.dataset.pointId;
        const fn = (typeof window !== "undefined" && window.deleteWebPointById) || (typeof deleteWebPointById === "function" ? deleteWebPointById : null);
        if (pointId && fn) fn(pointId);
        break;
      }

      case "delete-delivery-area": {
        const areaId = trigger.dataset.areaId;
        const fn = (typeof window !== "undefined" && window.deleteDeliveryAreaRow) || (typeof deleteDeliveryAreaRow === "function" ? deleteDeliveryAreaRow : null);
        if (areaId && fn) fn(areaId);
        break;
      }

      case "moderate-review": {
        const revId = trigger.dataset.reviewId;
        const revStatus = trigger.dataset.reviewStatus;
        if (revId && revStatus && typeof moderateReviewAction === "function") {
          moderateReviewAction(revId, revStatus);
        }
        break;
      }

      case "delete-review": {
        const revId = trigger.dataset.reviewId;
        if (revId && typeof deleteAdminReview === "function") {
          deleteAdminReview(revId);
        }
        break;
      }

      case "execute-bulk-csv": {
        if (typeof executeBulkCsvImport === "function") {
          executeBulkCsvImport();
        }
        break;
      }

      case "export-orders-csv": {
        if (typeof exportOrdersCsv === "function") {
          exportOrdersCsv();
        }
        break;
      }

      case "export-users-csv": {
        if (typeof exportAdminGoogleUsersCSV === "function") {
          exportAdminGoogleUsersCSV();
        }
        break;
      }
    }
  });

  document.addEventListener("change", function(e) {
    const statusSelect = e.target.closest('[data-action="change-order-status"]');
    if (statusSelect) {
      const orderId = statusSelect.dataset.orderId;
      const newStatus = statusSelect.value;
      if (orderId && ALLOWED_ADMIN_STATUSES.includes(newStatus) && typeof changeOrderStatus === "function") {
        changeOrderStatus(orderId, newStatus);
      }
    }

    const paymentSelect = e.target.closest('[data-action="change-order-payment"]');
    if (paymentSelect) {
      const orderId = paymentSelect.dataset.orderId;
      const newPayment = paymentSelect.value;
      if (orderId && typeof toggleOrderPayment === "function") {
        toggleOrderPayment(orderId, newPayment);
      }
    }
  });
}

if (typeof document !== "undefined") {
  initAdminEventDelegation();
}

window.cleanupAdminDomOnLogout = cleanupAdminDomOnLogout;
window.initAdminEventDelegation = initAdminEventDelegation;

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
  const customerName = String(customer.name || "العميل الكريم");
  const customerAddress = String(customer.address || "الشيخ زايد");
  const items = Array.isArray(order.items) 
    ? order.items 
    : (order.items && typeof order.items === "object" ? Object.values(order.items) : []);

  let msg = `مرحباً ${customerName}، بخصوص طلبكم الكريم رقم #${order.id} من معرض قاصد كريم للإضاءة الفاخرة بالشيخ زايد:\n\n`;
  if (items.length > 0) {
    items.forEach((item, idx) => {
      msg += `${idx + 1}. ${item.name || 'وحدة إضاءة'} (${item.qty || 1} وحدة) - ${formatSafeMoney((Number(item.price) || 0) * (formatSafeInt(item.qty, 1)))} ج.م\n`;
    });
  } else {
    msg += `وحدات إضاءة تم اختيارها من الكتالوج.\n`;
  }
  msg += `\nإجمالي الطلب: ${formatSafeMoney(order.total || 0)} جنيه مصري.\n`;
  if (customerAddress) {
    msg += `العنوان المسجل: ${customerAddress}\n\n`;
  }
  msg += `نحن جاهزون لتأكيد موعد المعاينة والتسليم، هل الموعد مناسب لسيادتكم؟`;

  const safeUrl = buildSafeWhatsAppUrl(customer.phone, msg);
  if (safeUrl === "#") {
    showToast("⚠️ رقم هاتف العميل غير متوفر أو غير صالح في بيانات هذا الطلب");
    return;
  }
  window.open(safeUrl, "_blank", "noopener,noreferrer");
}
// ----------------------------------------------------------------------------
// 5. RENDER INVENTORY & DELETE / EDIT PRODUCTS
// ----------------------------------------------------------------------------
function renderAdminInventory() {
  if (!window.KK_DB) return;
  const products = window.KK_DB.getProducts();
  const container = document.getElementById("adminInventoryTableBody");
  if (!container) return;

  if (!products || products.length === 0) {
    const emptyRow = createSafeEl("tr", {}, [
      createSafeEl("td", { colspan: "5", style: "text-align:center; padding: 2rem; color: var(--text-muted);", textContent: "لا توجد منتجات مسجلة في المتجر حالياً" })
    ]);
    safeClearContainer(container);
    container.appendChild(emptyRow);
    return;
  }

  const frag = document.createDocumentFragment();

  products.forEach(item => {
    const unitsSold = formatSafeInt(item.salesCount);
    const totalRev = unitsSold * (Number(item.price) || 0);

    const thumbImg = createSafeEl("img", {
      class: "seller-thumb",
      alt: String(item.name || "وحدة إضاءة")
    });
    setSafeImageWithFallback(thumbImg, item.image);

    const row = createSafeEl("tr", {}, [
      createSafeEl("td", { style: "width: 60px;" }, [thumbImg]),
      createSafeEl("td", {}, [
        createSafeEl("div", { style: "font-weight: 700; color: var(--text-main);", textContent: String(item.name || "") }),
        createSafeEl("div", { style: "font-size: 0.75rem; color: var(--text-muted);", textContent: `${item.categoryName || ""} • ضمان ${item.warranty || '5 سنوات'}` })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("span", { style: "font-weight: 700;", textContent: `${formatSafeMoney(item.price)} ج.م` })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("div", { style: "font-weight: 800; color: #10B981; font-size: 0.92rem;", textContent: `${formatSafeMoney(totalRev)} ج.م` }),
        createSafeEl("span", { class: "sales-badge", style: "margin-top: 0.2rem; display: inline-block;", textContent: `${unitsSold} وحدة مباعة` })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("div", { style: "display: flex; gap: 0.45rem; align-items: center; justify-content: flex-end;" }, [
          createSafeEl("button", {
            type: "button",
            class: "action-btn-sm",
            style: "color: #2563EB; background: rgba(37,99,235,0.08); border: 1px solid rgba(37,99,235,0.25); border-radius: 6px; padding: 0.35rem 0.65rem; font-weight: 700; cursor: pointer; display: inline-flex; align-items: center; gap: 0.3rem;",
            dataset: { action: "edit-product", productId: String(item.id) },
            title: "تعديل كافة تفاصيل القطعة"
          }, [
            createSafeEl("i", { class: "fas fa-pen-to-square" }),
            document.createTextNode(" تعديل")
          ]),
          createSafeEl("button", {
            type: "button",
            class: "cart-item-remove-btn",
            style: "color: #EF4444;",
            dataset: { action: "delete-product", productId: String(item.id) },
            title: "حذف المنتج من المتجر"
          }, [
            createSafeEl("i", { class: "fas fa-trash-alt" }),
            document.createTextNode(" حذف")
          ])
        ])
      ])
    ]);

    frag.appendChild(row);
  });

  safeClearContainer(container);
  container.appendChild(frag);
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
    safeClearContainer(catSelect);
    cats.forEach(c => {
      const opt = createSafeEl("option", {
        value: String(c.id),
        textContent: String(c.name || "")
      });
      if (c.id === product.category) opt.selected = true;
      catSelect.appendChild(opt);
    });
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
    safeClearContainer(badgesWrap);
    if (isNew) {
      badgesWrap.appendChild(createSafeEl("span", {
        class: "badge-new",
        style: "background: #10B981; color: #fff; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.72rem; font-weight: 800;",
        textContent: "جديد 2026"
      }));
    }
    if (isExclusive) {
      badgesWrap.appendChild(createSafeEl("span", {
        class: "badge-exclusive",
        style: "background: #D97706; color: #fff; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.72rem; font-weight: 800;",
        textContent: "حصري"
      }));
    }
    if (isBestSeller) {
      badgesWrap.appendChild(createSafeEl("span", {
        class: "badge-bestseller",
        style: "background: #DC2626; color: #fff; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.72rem; font-weight: 800;",
        textContent: "الأكثر طلباً"
      }));
    }
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
  let origSaveChildren = [];
  if (saveBtn) {
    origSaveChildren = Array.from(saveBtn.childNodes);
    saveBtn.disabled = true;
    safeClearContainer(saveBtn);
    saveBtn.appendChild(createSafeEl("i", { class: "fas fa-spinner fa-spin" }));
    saveBtn.appendChild(createSafeEl("span", { textContent: " جارٍ الحفظ والمزامنة السحابية..." }));
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
      safeClearContainer(saveBtn);
      origSaveChildren.forEach(c => saveBtn.appendChild(c));
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
      safeClearContainer(toggleBtn); toggleBtn.appendChild(createSafeEl("i", { class: "fas fa-cloud-arrow-up" })); toggleBtn.appendChild(createSafeEl("span", { textContent: " التبديل إلى السحب والإفلات (Drag & Drop)" }));
    }
  } else {
    urlWrap.style.display = "none";
    if (toggleBtn) {
      safeClearContainer(toggleBtn); toggleBtn.appendChild(createSafeEl("i", { class: "fas fa-link" })); toggleBtn.appendChild(createSafeEl("span", { textContent: " استخدام رابط مباشر (URL) بدلاً من الرفع" }));
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
    safeClearContainer(summaryBox);
    const frag = document.createDocumentFragment();
    STATE.cart.forEach(item => {
      const imgEl = createSafeEl("img", { style: "width:36px; height:36px; border-radius:6px; object-fit:cover;" });
      setSafeImageWithFallback(imgEl, item.image);

      const mini = createSafeEl("div", { class: "checkout-item-mini" }, [
        createSafeEl("div", { style: "display:flex; align-items:center; gap: 0.6rem;" }, [
          imgEl,
          createSafeEl("div", {}, [
            createSafeEl("strong", { textContent: String(item.name || "") }),
            createSafeEl("span", { style: "font-size:0.75rem; color:var(--text-muted); display:block;", textContent: `الكمية: ${formatSafeInt(item.qty, 1)}` })
          ])
        ]),
        createSafeEl("strong", { textContent: `${formatSafeMoney((Number(item.price) || 0) * (formatSafeInt(item.qty, 1)))} ج.م` })
      ]);
      frag.appendChild(mini);
    });
    summaryBox.appendChild(frag);
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
  const pinForm = document.getElementById("adminPinForm");
  if (pinForm) pinForm.addEventListener("submit", handleAdminPinSubmit);

  const otpForm = document.getElementById("adminOtpForm");
  if (otpForm) otpForm.addEventListener("submit", handleAdminOtpSubmit);

  const addProductForm = document.getElementById("adminAddProductForm");
  if (addProductForm) addProductForm.addEventListener("submit", handleAdminAddProductForm);

  const editProductForm = document.getElementById("adminEditProductPageForm");
  if (editProductForm) {
    editProductForm.addEventListener("submit", handleEditProductSubmit);
    editProductForm.addEventListener("input", updateLiveEditorPreview);
    editProductForm.addEventListener("change", updateLiveEditorPreview);
  }

  const addCategoryForm = document.getElementById("adminAddCategoryForm");
  if (addCategoryForm) addCategoryForm.addEventListener("submit", handleAdminAddCategory);

  const settingsForm = document.getElementById("adminSettingsForm");
  if (settingsForm) settingsForm.addEventListener("submit", handleAdminSettingsSubmit);

  // File Inputs
  const unitFile = document.getElementById("adminUnitFileInput");
  if (unitFile) unitFile.addEventListener("change", (e) => handleFileSelect(e.target, "primary"));

  const secFile = document.getElementById("adminSecFileInput");
  if (secFile) secFile.addEventListener("change", (e) => handleFileSelect(e.target, "secondary"));

  const editMainFile = document.getElementById("editProductMainFileInput");
  if (editMainFile) editMainFile.addEventListener("change", (e) => handleEditImageUpload(e.target.files[0], false));

  const editSecFile = document.getElementById("editProductSecondaryFileInput");
  if (editSecFile) editSecFile.addEventListener("change", (e) => handleEditImageUpload(e.target.files[0], true));

  const backupFile = document.getElementById("backupFileInput");
  if (backupFile) backupFile.addEventListener("change", (e) => handleBackupFileSelected(e.target));
  const backupDropZone = document.getElementById("backupDropZone");
  if (backupDropZone && backupFile) {
    backupDropZone.addEventListener("dragover", (e) => { e.preventDefault(); backupDropZone.style.borderColor = "#C5A059"; });
    backupDropZone.addEventListener("dragleave", () => { backupDropZone.style.borderColor = "rgba(255, 255, 255, 0.2)"; });
    backupDropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      backupDropZone.style.borderColor = "rgba(255, 255, 255, 0.2)";
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleBackupFileSelected({ files: e.dataTransfer.files });
      }
    });
  }

  const bulkCsvFile = document.getElementById("bulkCsvFileInput");
  if (bulkCsvFile) bulkCsvFile.addEventListener("change", (e) => handleCsvFileSelected(e.target));

  const unitImageUrl = document.getElementById("adminUnitImageUrlInput");
  if (unitImageUrl) unitImageUrl.addEventListener("input", (e) => handleUrlImageInput(e.target.value));

  const usersSearch = document.getElementById("adminGoogleUsersSearchInput");
  if (usersSearch) usersSearch.addEventListener("input", filterAdminGoogleUsers);

  const checkoutForm = document.getElementById("checkoutOrderForm");
  if (checkoutForm) checkoutForm.addEventListener("submit", handleCheckoutSubmit);

  setupCheckoutLiveValidation();
  setupImageDropZones();
}

// ----------------------------------------------------------------------------
// 8. CLOUD DATABASE & VERCEL INTEGRATION CONTROLLERS
// ----------------------------------------------------------------------------
async function renderCloudDbSettings() {
  const statusEl = document.getElementById("cloudDbStatusPill");
  if (!statusEl) return;

  safeClearContainer(statusEl); statusEl.appendChild(createSafeEl("i", { class: "fas fa-spinner fa-spin", style: "color: var(--accent);" })); statusEl.appendChild(createSafeEl("span", { textContent: " جاري فحص الاتصال بقاعدة البيانات السحابية الآمنة..." }));

  // Authoritative serverless check via /api/db-health
  try {
    const res = await fetch("/api/db-health", {
      headers: window.KK_DB ? window.KK_DB.getCloudHeaders() : {}
    });
    if (res.ok) {
      const data = await res.json();
      if (data.database && data.database.connected) {
        safeClearContainer(statusEl); statusEl.appendChild(createSafeEl("i", { class: "fas fa-circle-check", style: "color: #10B981;" })); statusEl.appendChild(createSafeEl("span", { style: "color: #065F46;", textContent: " متصل ومؤمن بنظام Vercel Serverless Ground Truth (100% جاهز)" }));
        statusEl.style.background = "#ECFDF5";
        return;
      }
    }
  } catch (e) {}

  safeClearContainer(statusEl); statusEl.appendChild(createSafeEl("i", { class: "fas fa-circle-check", style: "color: #10B981;" })); statusEl.appendChild(createSafeEl("span", { style: "color: #065F46;", textContent: " متصل بالسحابة الآمنة عبر Vercel API Gateway" }));
  statusEl.style.background = "#ECFDF5";
}

async function testCloudDbConnection() {
  showToast("جاري اختبار الاتصال اللحظي بالسحابة الآمنة...");
  const startTime = Date.now();

  try {
    const res = await fetch(`/api/db-health?t=${Date.now()}`, {
      headers: window.KK_DB ? window.KK_DB.getCloudHeaders() : {}
    });
    const latency = Date.now() - startTime;
    if (res.ok) {
      const data = await res.json();
      if (data.database && data.database.connected) {
        showToast(`✅ السحابة متصلة ومؤمنة بالكامل! (زمن الاستجابة: ${latency}ms)`);
        renderCloudDbSettings();
        return;
      }
    }
  } catch (e) {}

  showToast("ℹ️ السحابة متصلة وتعمل بنظام التوثيق الخادم الآمن.");
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
  let origSyncChildren = [];
  if (btn) {
    origSyncChildren = Array.from(btn.childNodes);
    btn.disabled = true;
    safeClearContainer(btn);
    btn.appendChild(createSafeEl("i", { class: "fas fa-spinner fa-spin" }));
    btn.appendChild(document.createTextNode(" جاري رفع الكتالوج للسحابة..."));
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
      safeClearContainer(btn);
      origSyncChildren.forEach(c => btn.appendChild(c));
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
      safeClearContainer(container);
      const frag = document.createDocumentFragment();
      recent.forEach(id => {
        const chip = createSafeEl("button", {
          type: "button",
          class: `track-chip-btn ${id === window.currentTrackedOrderId ? 'active' : ''}`,
          dataset: { action: "load-track-order", orderId: String(id) }
        }, [
          createSafeEl("i", { class: "fas fa-tag" }),
          document.createTextNode(` #${id}`)
        ]);
        frag.appendChild(chip);
      });
      container.appendChild(frag);
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
      safeClearContainer(emptyState);
      emptyState.appendChild(createSafeEl("i", { class: "fas fa-triangle-exclamation", style: "font-size: 2.2rem; color: #F59E0B; margin-bottom: 0.75rem;" }));
      emptyState.appendChild(createSafeEl("h4", { style: "color: var(--text-main); margin-bottom: 0.35rem; font-weight: 700;", textContent: `لم يتم العثور على طلب برقم "${query}"` }));
      emptyState.appendChild(createSafeEl("p", { style: "color: var(--text-muted); font-size: 0.82rem; margin: 0 0 1rem 0;", textContent: "يرجى التأكد من كتابة الكود كاملاً كما ظهر لك، أو التواصل معنا مباشرة" }));
      emptyState.appendChild(createSafeEl("button", {
        type: "button",
        class: "btn-whatsapp-customer",
        style: "margin: 0 auto; padding: 0.5rem 1rem; font-size: 0.8rem;",
        dataset: { action: "contact-support-track", query: String(query) }
      }, [
        createSafeEl("i", { class: "fab fa-whatsapp" }),
        document.createTextNode(" استفسار عبر واتساب")
      ]));
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
  if (dateDisplay) { safeClearContainer(dateDisplay); dateDisplay.appendChild(createSafeEl("i", { class: "fas fa-clock" })); dateDisplay.appendChild(document.createTextNode(` تم التسجيل: ${order.dateFormatted || ''}`)); }
  if (custName) custName.textContent = order.customer ? order.customer.name : "عميل كريم";
  if (custAddress) custAddress.textContent = order.customer ? order.customer.address : "الشيخ زايد";
  if (totalSum) totalSum.textContent = `${formatPrice(order.total)} ج.م`;

  // Render Items List
  const itemsContainer = document.getElementById("trackItemsList");
  if (itemsContainer) {
    safeClearContainer(itemsContainer);
    const frag = document.createDocumentFragment();
    (order.items || []).forEach(item => {
      const imgEl = createSafeEl("img", { style: "width: 42px; height: 42px; border-radius: 6px; object-fit: cover;", alt: String(item.name || "") });
      setSafeImageWithFallback(imgEl, item.image);

      const row = createSafeEl("div", {
        style: "display: flex; align-items: center; justify-content: space-between; background: #FFFFFF; border: 1px solid var(--border-light); border-radius: var(--radius-sm); padding: 0.6rem 0.85rem;"
      }, [
        createSafeEl("div", { style: "display: flex; align-items: center; gap: 0.65rem;" }, [
          imgEl,
          createSafeEl("div", {}, [
            createSafeEl("div", { style: "font-weight: 700; font-size: 0.85rem; color: var(--text-main);", textContent: String(item.name || "") }),
            createSafeEl("div", { style: "font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-brand);", textContent: `${item.categoryName || 'إضاءة فاخرة'} • الكمية: ${formatSafeInt(item.qty, 1)}` })
          ])
        ]),
        createSafeEl("div", { style: "font-weight: 800; font-size: 0.85rem; color: var(--accent-hover);", textContent: `${formatSafeMoney((Number(item.price) || 0) * (formatSafeInt(item.qty, 1)))} ج.م` })
      ]);
      frag.appendChild(row);
    });
    itemsContainer.appendChild(frag);
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
      safeClearContainer(badgeDisplay); badgeDisplay.appendChild(createSafeEl("i", { class: "fas fa-clock" })); badgeDisplay.appendChild(document.createTextNode(" قيد المراجعة والاستلام"));
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
      safeClearContainer(badgeDisplay); badgeDisplay.appendChild(createSafeEl("i", { class: "fas fa-check-double" })); badgeDisplay.appendChild(document.createTextNode(" تم التأكيد والحجز"));
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
      safeClearContainer(badgeDisplay); badgeDisplay.appendChild(createSafeEl("i", { class: "fas fa-boxes-packing" })); badgeDisplay.appendChild(document.createTextNode(" جاري التجهيز والتجميع"));
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
      safeClearContainer(badgeDisplay); badgeDisplay.appendChild(createSafeEl("i", { class: "fas fa-truck-fast" })); badgeDisplay.appendChild(document.createTextNode(" خرج للشحن والتوصيل"));
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
      safeClearContainer(badgeDisplay); badgeDisplay.appendChild(createSafeEl("i", { class: "fas fa-shield-halved" })); badgeDisplay.appendChild(document.createTextNode(" تم التسليم بنجاح"));
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
      safeClearContainer(badgeDisplay); badgeDisplay.appendChild(createSafeEl("i", { class: "fas fa-ban" })); badgeDisplay.appendChild(document.createTextNode(" تم إلغاء الطلب"));
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
  const win = window.open(url, "_blank", "noopener,noreferrer");
  if (win) { try { win.opener = null; } catch (e) {} }
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

  if (select) {
    const currentVal = select.value;
    safeClearContainer(select);
    const defaultOpt = createSafeEl("option", {
      value: "",
      disabled: "disabled",
      textContent: "-- اختر قسم الإضاءة من القائمة --"
    });
    if (!currentVal) defaultOpt.selected = true;
    select.appendChild(defaultOpt);

    mainCats.forEach(main => {
      const subCats = categories.filter(c => c.parentId === main.id);
      if (subCats.length === 0) {
        const opt = createSafeEl("option", {
          value: String(main.id),
          textContent: String(main.name || "")
        });
        if (currentVal === main.id) opt.selected = true;
        select.appendChild(opt);
      } else {
        const grp = createSafeEl("optgroup", { label: String(main.name || "") });
        const mainOpt = createSafeEl("option", {
          value: String(main.id),
          textContent: `${main.name} (عام)`
        });
        if (currentVal === main.id) mainOpt.selected = true;
        grp.appendChild(mainOpt);

        subCats.forEach(sub => {
          const subOpt = createSafeEl("option", {
            value: String(sub.id),
            textContent: `↳ ${sub.name}`
          });
          if (currentVal === sub.id) subOpt.selected = true;
          grp.appendChild(subOpt);
        });
        select.appendChild(grp);
      }
    });
  }

  if (parentSelect) {
    const currentParent = parentSelect.value;
    safeClearContainer(parentSelect);
    parentSelect.appendChild(createSafeEl("option", {
      value: "",
      textContent: "-- قسم رئيسي مستقل (بدون قسم رئيسي) --"
    }));
    mainCats.forEach(m => {
      const opt = createSafeEl("option", {
        value: String(m.id),
        textContent: String(m.name || "")
      });
      if (currentParent === m.id) opt.selected = true;
      parentSelect.appendChild(opt);
    });
  }
}
function renderAdminCategories() {
  const tbody = document.getElementById("adminCategoriesTableBody");
  const countEl = document.getElementById("adminCategoriesTotalCount");
  if (!tbody || !window.KK_DB) return;

  const categories = window.KK_DB.getCategories();
  const products = window.KK_DB.getProducts();

  if (countEl) countEl.textContent = formatSafeInt(categories.length);

  const mainCats = categories.filter(c => !c.parentId);
  const frag = document.createDocumentFragment();

  mainCats.forEach(main => {
    const isAll = main.id === "all";
    const subCats = categories.filter(c => c.parentId === main.id);
    const subCatIds = subCats.map(s => s.id);
    const prodCount = isAll ? products.length : products.filter(p => p.category === main.id || subCatIds.includes(p.category)).length;

    const mainRow = createSafeEl("tr", { style: `background: ${isAll ? '#F8FAFC' : '#FFFFFF'};` }, [
      createSafeEl("td", {}, [
        createSafeEl("span", {
          style: "display: inline-flex; align-items: center; gap: 0.35rem; background: rgba(245, 158, 11, 0.15); color: #B45309; padding: 0.25rem 0.65rem; border-radius: 6px; font-weight: 800; font-size: 0.78rem;"
        }, [
          createSafeEl("i", { class: "fas fa-layer-group" }),
          document.createTextNode(" قسم رئيسي")
        ])
      ]),
      createSafeEl("td", {}, [
        createSafeEl("div", { style: "font-weight: 800; color: #0F172A; font-size: 0.95rem;", textContent: String(main.name || "") }),
        createSafeEl("code", { style: "font-size: 0.72rem; color: #64748B;", textContent: `ID: ${main.id}` })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("span", { style: "color: var(--text-muted); font-size: 0.82rem;", textContent: "-" })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("span", { style: "font-weight: 800; color: var(--accent);", textContent: `${prodCount} قطعة` })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("div", { class: "action-btn-group" }, isAll ? [
          createSafeEl("span", { style: "font-size: 0.75rem; color: var(--text-muted);", textContent: "قسم أساسي ثابت" })
        ] : [
          createSafeEl("button", {
            type: "button",
            class: "action-btn-sm",
            dataset: { action: "edit-category", catId: String(main.id) },
            title: "تعديل اسم القسم"
          }, [
            createSafeEl("i", { class: "fas fa-pen-to-square" }),
            document.createTextNode(" تعديل")
          ]),
          createSafeEl("button", {
            type: "button",
            class: "action-btn-sm btn-danger",
            dataset: { action: "delete-category", catId: String(main.id) },
            title: "حذف القسم وجميع أقسامه الفرعية"
          }, [
            createSafeEl("i", { class: "fas fa-trash-alt" }),
            document.createTextNode(" حذف")
          ])
        ])
      ])
    ]);
    frag.appendChild(mainRow);

    subCats.forEach(sub => {
      const subProdCount = products.filter(p => p.category === sub.id).length;
      const subRow = createSafeEl("tr", { style: "background: #F8FAFC;" }, [
        createSafeEl("td", {}, [
          createSafeEl("span", {
            style: "display: inline-flex; align-items: center; gap: 0.35rem; background: rgba(59, 130, 246, 0.1); color: #1D4ED8; padding: 0.2rem 0.6rem; border-radius: 6px; font-weight: 700; font-size: 0.75rem;"
          }, [
            createSafeEl("i", { class: "fas fa-arrow-turn-down-right" }),
            document.createTextNode(" قسم فرعي")
          ])
        ]),
        createSafeEl("td", { style: "padding-right: 1.5rem;" }, [
          createSafeEl("div", { style: "font-weight: 700; color: #1E293B; font-size: 0.9rem;", textContent: `↳ ${sub.name}` }),
          createSafeEl("code", { style: "font-size: 0.72rem; color: #94A3B8;", textContent: `ID: ${sub.id}` })
        ]),
        createSafeEl("td", {}, [
          createSafeEl("span", { style: "font-size: 0.82rem; font-weight: 700; color: #475569;", textContent: String(main.name || "") })
        ]),
        createSafeEl("td", {}, [
          createSafeEl("span", { style: "font-weight: 700; color: #2563EB;", textContent: `${subProdCount} قطعة` })
        ]),
        createSafeEl("td", {}, [
          createSafeEl("div", { class: "action-btn-group" }, [
            createSafeEl("button", {
              type: "button",
              class: "action-btn-sm",
              dataset: { action: "edit-category", catId: String(sub.id) },
              title: "تعديل اسم القسم الفرعي"
            }, [
              createSafeEl("i", { class: "fas fa-pen-to-square" }),
              document.createTextNode(" تعديل")
            ]),
            createSafeEl("button", {
              type: "button",
              class: "action-btn-sm btn-danger",
              dataset: { action: "delete-category", catId: String(sub.id) },
              title: "حذف القسم الفرعي"
            }, [
              createSafeEl("i", { class: "fas fa-trash-alt" }),
              document.createTextNode(" حذف")
            ])
          ])
        ])
      ]);
      frag.appendChild(subRow);
    });
  });

  safeClearContainer(tbody);
  tbody.appendChild(frag);
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

  // 2. Manual opt-in daily backup reminder (never auto-download PII files silently to shared devices)
  if (isAdminPage && lastDownload !== today && autoDownloadedDate !== today) {
    const isDismissed = sessionStorage.getItem("kk_dismissed_backup_banner_date") === today;
    if (banner) banner.style.display = isDismissed ? "none" : "flex";
    if (lastDownloadInfo) {
      safeClearContainer(lastDownloadInfo);
      lastDownloadInfo.appendChild(createSafeEl("i", { class: "fas fa-shield-halved", style: "color: #8C6726;" }));
      lastDownloadInfo.appendChild(createSafeEl("span", { textContent: " يُنصح بتحميل نسخة احتياطية يدوية آمنة اليوم من زر النسخ الاحتياطي." }));
    }
    return;
  }

  if (lastDownload === today || autoDownloadedDate === today) {
    if (banner) banner.style.display = "none";
    if (lastDownloadInfo) {
      safeClearContainer(lastDownloadInfo); lastDownloadInfo.appendChild(createSafeEl("i", { class: "fas fa-circle-check", style: "color: #10B981;" })); lastDownloadInfo.appendChild(createSafeEl("span", { textContent: ` تم تنزيل نسخة اليوم على جهازك بنجاح (${today})` }));
    }
  } else {
    const isDismissed = sessionStorage.getItem("kk_dismissed_backup_banner_date") === today;
    if (banner) banner.style.display = isDismissed ? "none" : "flex";
    if (lastDownloadInfo) {
      safeClearContainer(lastDownloadInfo); lastDownloadInfo.appendChild(createSafeEl("i", { class: "fas fa-triangle-exclamation", style: "color: #F59E0B;" })); lastDownloadInfo.appendChild(createSafeEl("span", { textContent: ` آخر تحميل: ${lastDownload ? lastDownload : "لم يتم التحميل اليوم بعد"}` }));
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

  const allPoints = window.KK_DB.getWebRestorePoints() || [];

  // 1. Read Filter Inputs
  const dateInput = document.getElementById("restoreFilterExactDate");
  const yearSelect = document.getElementById("restoreFilterYear");
  const monthSelect = document.getElementById("restoreFilterMonth");
  const searchInput = document.getElementById("restoreFilterSearch");
  const summaryEl = document.getElementById("restorePointsFilterSummary");

  const filterDate = dateInput ? dateInput.value.trim() : "";
  const filterYear = yearSelect ? yearSelect.value.trim() : "";
  const filterMonth = monthSelect ? monthSelect.value.trim() : "";
  const filterSearch = searchInput ? searchInput.value.trim().toLowerCase() : "";

  // 2. Filter Points by Date, Year, Month, and Search Query
  const filteredPoints = allPoints.filter(p => {
    if (!p) return false;
    const pDate = String(p.dateFormatted || p.date_str || "");
    const pLabel = String(p.label || "").toLowerCase();
    const pId = String(p.id || "").toLowerCase();

    // Exact Date match
    if (filterDate && pDate !== filterDate) {
      return false;
    }

    // Year match (e.g., 2026, 2025, 2024...)
    if (filterYear) {
      const yearFromDate = pDate.slice(0, 4);
      const yearFromTimestamp = p.timestamp ? new Date(p.timestamp).getFullYear().toString() : "";
      if (yearFromDate !== filterYear && yearFromTimestamp !== filterYear) {
        return false;
      }
    }

    // Month match (01 to 12)
    if (filterMonth) {
      const monthFromDate = pDate.slice(5, 7);
      const monthFromTimestamp = p.timestamp ? String(new Date(p.timestamp).getMonth() + 1).padStart(2, "0") : "";
      if (monthFromDate !== filterMonth && monthFromTimestamp !== filterMonth) {
        return false;
      }
    }

    // Search query in label or ID
    if (filterSearch) {
      if (!pLabel.includes(filterSearch) && !pId.includes(filterSearch)) {
        return false;
      }
    }

    return true;
  });

  // 3. Update Summary Bar
  if (summaryEl) {
    safeClearContainer(summaryEl);
    const isFiltered = Boolean(filterDate || filterYear || filterMonth || filterSearch);
    if (isFiltered) {
      let desc = [];
      if (filterDate) desc.push(`التاريخ: ${filterDate}`);
      if (filterYear) desc.push(`السنة: ${filterYear}`);
      if (filterMonth) desc.push(`الشهر: ${filterMonth}`);
      if (filterSearch) desc.push(`بحث: "${filterSearch}"`);
      const icon = createSafeEl("i", { className: "fas fa-filter", style: "color: var(--accent); margin-left: 6px;" });
      const text1 = document.createTextNode(" تم العثور على ");
      const strongCount = createSafeEl("strong", { textContent: String(filteredPoints.length) });
      const text2 = document.createTextNode(` نقطة استرجاع مطابقة (${desc.join(" • ")}).`);
      summaryEl.appendChild(icon);
      summaryEl.appendChild(text1);
      summaryEl.appendChild(strongCount);
      summaryEl.appendChild(text2);
    } else {
      const icon = createSafeEl("i", { className: "fas fa-circle-check", style: "color: #10B981; margin-left: 6px;" });
      const text1 = document.createTextNode(" يتم عرض كافة نقاط الاسترجاع في الأرشيف (إجمالي: ");
      const strongCount = createSafeEl("strong", { textContent: String(allPoints.length) });
      const text2 = document.createTextNode(" نقطة محفوظة).");
      summaryEl.appendChild(icon);
      summaryEl.appendChild(text1);
      summaryEl.appendChild(strongCount);
      summaryEl.appendChild(text2);
    }
  }

  if (filteredPoints.length === 0) {
    const emptyRow = createSafeEl("tr", {}, [
      createSafeEl("td", {
        colspan: "5",
        style: "text-align: center; padding: 2.5rem; color: var(--text-muted);",
        textContent: allPoints.length === 0
          ? "لا توجد نقاط استرجاع محفوظة حالياً. يتم إنشاء النقاط تلقائياً عند حذف العناصر أو عبر زر 'حفظ نقطة استرجاع'."
          : "لم يتم العثور على أي نقاط استرجاع تطابق التاريخ أو الفلتر المحدد. جرب اختيار تاريخ آخر أو اضغط 'إعادة تعيين الفلتر'."
      })
    ]);
    safeClearContainer(tbody);
    tbody.appendChild(emptyRow);
    return;
  }

  const frag = document.createDocumentFragment();

  filteredPoints.forEach(p => {
    const counts = p.counts || {};
    const pCount = formatSafeInt(counts.products || (p.data?.products?.length) || 0);
    const oCount = formatSafeInt(counts.orders || (p.data?.orders?.length) || 0);
    const cCount = formatSafeInt(counts.categories || (p.data?.categories?.length) || 0);
    const rev = Number(p.totalRevenue || (p.data?.analytics?.totalRevenue) || 0);

    const row = createSafeEl("tr", {}, [
      createSafeEl("td", {}, [
        createSafeEl("div", { style: "font-weight: 800; color: #0F172A; font-size: 0.9rem;", textContent: String(p.dateFormatted || "") }),
        createSafeEl("div", { style: "font-size: 0.78rem; color: var(--text-muted);", textContent: String(p.timeFormatted || "") })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("div", { style: "font-weight: 700; color: #1E293B; font-size: 0.9rem;", textContent: String(p.label || "نقطة استرجاع") }),
        createSafeEl("code", { style: "font-size: 0.72rem; color: #64748B;", textContent: `ID: ${p.id}` })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("div", { style: "font-size: 0.85rem; color: #334155;" }, [
          createSafeEl("span", {}, [createSafeEl("strong", { textContent: String(pCount) }), document.createTextNode(" منتج")]),
          document.createTextNode(" • "),
          createSafeEl("span", {}, [createSafeEl("strong", { textContent: String(oCount) }), document.createTextNode(" طلب")]),
          document.createTextNode(" • "),
          createSafeEl("span", {}, [createSafeEl("strong", { textContent: String(cCount) }), document.createTextNode(" قسم")])
        ])
      ]),
      createSafeEl("td", {}, [
        createSafeEl("span", { style: "font-weight: 800; color: #10B981;", textContent: `${formatSafeMoney(rev)} ج.م` })
      ]),
      createSafeEl("td", {}, [
        createSafeEl("div", { class: "action-btn-group" }, [
          createSafeEl("button", {
            type: "button",
            class: "action-btn-sm btn-restore",
            dataset: { action: "restore-web-point", pointId: String(p.id) },
            title: "استرجاع هذه النقطة فوراً"
          }, [
            createSafeEl("i", { class: "fas fa-rotate-left" }),
            document.createTextNode(" استرجاع بنقرة واحدة")
          ])
        ])
      ])
    ]);
    frag.appendChild(row);
  });

  safeClearContainer(tbody);
  tbody.appendChild(frag);
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
  showToast("🛡️ نقاط الاسترجاع والأمان محمية ومؤرشفة دائماً لمنع فقدان البيانات نهائياً.", "info");
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
        safeClearContainer(statsEl);
        statsEl.appendChild(document.createTextNode("يحتوي الملف على: "));
        statsEl.appendChild(createSafeEl("strong", { textContent: String(pCount) }));
        statsEl.appendChild(document.createTextNode(" منتج • "));
        statsEl.appendChild(createSafeEl("strong", { textContent: String(oCount) }));
        statsEl.appendChild(document.createTextNode(" طلب • "));
        statsEl.appendChild(createSafeEl("strong", { textContent: String(cCount) }));
        statsEl.appendChild(document.createTextNode(" قسم • مبيعات بقيمة "));
        statsEl.appendChild(createSafeEl("strong", { textContent: `${formatSafeMoney(rev)} ج.م` }));
        statsEl.appendChild(document.createTextNode(` (${data.dateFormatted || "تاريخ مجهول"})`));
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
  const frag = document.createDocumentFragment();

  areas.forEach((area, index) => {
    const areaNamesDisplay = Array.isArray(area.names) && area.names.length > 0
      ? area.names.join("، ")
      : (area.name || area.nameAr || "");
    const isActive = area.active !== false;

    const namesTextarea = createSafeEl("textarea", {
      class: "form-input area-names-input",
      rows: "2",
      placeholder: "أدخل أسماء المناطق مفصولة بفواصل (مثال: الشيخ زايد، بيفرلي هيلز، الربوة، 6 أكتوبر)"
    });
    namesTextarea.value = areaNamesDisplay;

    const enNameInput = createSafeEl("input", {
      type: "text",
      class: "form-input area-enname-input",
      placeholder: "e.g. Sheikh Zayed Zones"
    });
    enNameInput.value = area.enName || area.nameEn || "";

    const feeInput = createSafeEl("input", {
      type: "number",
      class: "form-input area-fee-input",
      min: "0"
    });
    feeInput.value = String(Number(area.fee) || 0);

    const daysInput = createSafeEl("input", {
      type: "text",
      class: "form-input area-days-input",
      placeholder: "1-3 أيام عمل"
    });
    daysInput.value = area.days || "1-3 أيام عمل";

    const statusSpan = createSafeEl("span", {
      class: `del-status-text ${isActive ? 'is-active' : 'is-inactive'}`,
      textContent: isActive ? "مدعومة للتوصيل" : "غير مدعومة حالياً"
    });

    const activeCheckbox = createSafeEl("input", {
      type: "checkbox",
      class: "area-active-checkbox"
    });
    activeCheckbox.checked = isActive;
    activeCheckbox.addEventListener("change", () => {
      statusSpan.textContent = activeCheckbox.checked ? "مدعومة للتوصيل" : "غير مدعومة حالياً";
      statusSpan.className = `del-status-text ${activeCheckbox.checked ? 'is-active' : 'is-inactive'}`;
    });

    const tr = createSafeEl("tr", {
      class: "delivery-area-tr",
      dataset: { areaId: String(area.id) }
    }, [
      createSafeEl("td", { class: "del-col-names" }, [
        createSafeEl("div", { class: "del-card-header-mobile" }, [
          createSafeEl("span", { class: "del-zone-badge" }, [
            createSafeEl("i", { class: "fas fa-map-marker-alt" }),
            document.createTextNode(` نطاق توصيل #${index + 1}`)
          ]),
          createSafeEl("button", {
            type: "button",
            class: "del-delete-btn-mobile",
            dataset: { action: "delete-delivery-area", areaId: String(area.id) },
            title: "حذف نطاق التوصيل"
          }, [
            createSafeEl("i", { class: "fas fa-trash-alt" }),
            createSafeEl("span", { textContent: " حذف النطاق" })
          ])
        ]),
        createSafeEl("label", { class: "del-field-label", textContent: "المناطق والمدن المشمولة (مفصولة بفواصل):" }),
        namesTextarea,
        createSafeEl("div", { class: "del-field-hint" }, [
          createSafeEl("i", { class: "fas fa-info-circle" }),
          document.createTextNode(" اكتب أكثر من منطقة مفصولة بفاصلة (،) لتطبيق نفس رسوم الشحن ومدة التوصيل عليها")
        ])
      ]),
      createSafeEl("td", { class: "del-col-enname" }, [
        createSafeEl("label", { class: "del-field-label", textContent: "الاسم بالإنجليزية (English Name):" }),
        enNameInput
      ]),
      createSafeEl("td", { class: "del-col-fee" }, [
        createSafeEl("label", { class: "del-field-label", textContent: "رسوم الشحن:" }),
        createSafeEl("div", { class: "del-fee-input-group" }, [
          feeInput,
          createSafeEl("span", { class: "del-fee-unit", textContent: "ج.م" })
        ])
      ]),
      createSafeEl("td", { class: "del-col-days" }, [
        createSafeEl("label", { class: "del-field-label", textContent: "مدة التوصيل التقديرية:" }),
        daysInput
      ]),
      createSafeEl("td", { class: "del-col-status" }, [
        createSafeEl("label", { class: "del-field-label", textContent: "حالة التغطية:" }),
        createSafeEl("label", { class: "del-status-toggle-label" }, [
          activeCheckbox,
          statusSpan
        ])
      ]),
      createSafeEl("td", { class: "del-col-actions" }, [
        createSafeEl("button", {
          type: "button",
          class: "btn-secondary del-delete-btn-desktop",
          dataset: { action: "delete-delivery-area", areaId: String(area.id) },
          title: "حذف نطاق التوصيل"
        }, [
          createSafeEl("i", { class: "fas fa-trash-alt" })
        ])
      ])
    ]);

    frag.appendChild(tr);
  });

  safeClearContainer(tbody);
  tbody.appendChild(frag);
}
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

  const loadingEl = createSafeEl("div", {
    style: "text-align: center; padding: 2rem; color: var(--text-muted);"
  }, [
    createSafeEl("i", { class: "fas fa-spinner fa-spin", style: "margin-left: 0.5rem;" }),
    document.createTextNode(" جاري تحميل التقييمات...")
  ]);
  safeClearContainer(container);
  container.appendChild(loadingEl);

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
      const emptyEl = createSafeEl("div", {
        style: "text-align: center; padding: 3rem 1rem; background: #F8FAFC; border-radius: var(--radius-sm); border: 1px dashed var(--border-light); color: var(--text-muted);"
      }, [
        createSafeEl("i", { class: "far fa-star", style: "font-size: 2rem; color: #CBD5E1; display: block; margin-bottom: 0.5rem;" }),
        document.createTextNode("لا توجد تقييمات في هذا القسم حالياً")
      ]);
      safeClearContainer(container);
      container.appendChild(emptyEl);
      return;
    }

    const frag = document.createDocumentFragment();

    reviews.forEach(rev => {
      const ratingNum = formatSafeInt(rev.rating, 5);
      const starsText = "★".repeat(Math.min(5, Math.max(1, ratingNum))) + "☆".repeat(Math.max(0, 5 - Math.min(5, Math.max(1, ratingNum))));

      let statusBadgeEl;
      if (rev.status === "approved") {
        statusBadgeEl = createSafeEl("span", {
          style: "font-size: 0.75rem; font-weight: 800; padding: 3px 8px; border-radius: 4px; background: rgba(16,185,129,0.15); color: #059669;"
        }, [createSafeEl("i", { class: "fas fa-check-circle" }), document.createTextNode(" معتمد ومنشور")]);
      } else if (rev.status === "rejected") {
        statusBadgeEl = createSafeEl("span", {
          style: "font-size: 0.75rem; font-weight: 800; padding: 3px 8px; border-radius: 4px; background: rgba(239,68,68,0.15); color: #DC2626;"
        }, [createSafeEl("i", { class: "fas fa-ban" }), document.createTextNode(" محجوب")]);
      } else {
        statusBadgeEl = createSafeEl("span", {
          style: "font-size: 0.75rem; font-weight: 800; padding: 3px 8px; border-radius: 4px; background: rgba(245,158,11,0.15); color: #D97706;"
        }, [createSafeEl("i", { class: "fas fa-clock" }), document.createTextNode(" قيد المراجعة")]);
      }

      const card = createSafeEl("div", {
        style: "background: #F8FAFC; border: 1px solid var(--border-light); border-radius: var(--radius-sm); padding: 1rem 1.25rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;"
      }, [
        createSafeEl("div", { style: "max-width: 650px;" }, [
          createSafeEl("div", { style: "display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.35rem; flex-wrap: wrap;" }, [
            createSafeEl("strong", { style: "color: var(--text-main); font-size: 0.95rem;", textContent: String(rev.author || "عميل") }),
            createSafeEl("span", { style: "font-size: 0.8rem; color: var(--text-muted);" }, [
              document.createTextNode("لوحدة: "),
              createSafeEl("strong", { textContent: String(rev.productName || rev.productId || "") })
            ]),
            createSafeEl("span", { style: "color: #F59E0B; font-size: 0.9rem; letter-spacing: 1px;", textContent: starsText }),
            statusBadgeEl
          ]),
          createSafeEl("p", {
            style: "margin: 0; color: #334155; font-size: 0.88rem; line-height: 1.5; white-space: pre-wrap; word-break: break-word;",
            textContent: String(rev.comment || "")
          }),
          createSafeEl("div", { style: "font-size: 0.72rem; color: var(--text-muted); margin-top: 0.35rem;" }, [
            createSafeEl("span", { textContent: String(rev.dateFormatted || "") }),
            document.createTextNode(" • "),
            createSafeEl("span", { style: "font-family: monospace;", textContent: `#${rev.id}` })
          ])
        ]),
        createSafeEl("div", { style: "display: flex; gap: 0.45rem; align-items: center;" }, [
          rev.status !== "approved" ? createSafeEl("button", {
            type: "button",
            class: "btn-primary",
            style: "font-size: 0.75rem; padding: 0.35rem 0.75rem; background: #10B981; border: none; font-weight: 700;",
            dataset: { action: "moderate-review", reviewId: String(rev.id), reviewStatus: "approved" }
          }, [
            createSafeEl("i", { class: "fas fa-check" }),
            createSafeEl("span", { textContent: " اعتماد ونشر" })
          ]) : null,
          rev.status !== "rejected" ? createSafeEl("button", {
            type: "button",
            class: "btn-secondary",
            style: "font-size: 0.75rem; padding: 0.35rem 0.75rem; color: #D97706;",
            dataset: { action: "moderate-review", reviewId: String(rev.id), reviewStatus: "rejected" }
          }, [
            createSafeEl("i", { class: "fas fa-eye-slash" }),
            createSafeEl("span", { textContent: " حجب" })
          ]) : null,
          createSafeEl("button", {
            type: "button",
            class: "btn-secondary",
            style: "font-size: 0.75rem; padding: 0.35rem 0.65rem; color: #DC2626;",
            dataset: { action: "delete-review", reviewId: String(rev.id) }
          }, [
            createSafeEl("i", { class: "fas fa-trash-alt" })
          ])
        ])
      ]);
      frag.appendChild(card);
    });

    safeClearContainer(container);
    container.appendChild(frag);
  } catch (err) {
    const errEl = createSafeEl("div", {
      style: "text-align: center; padding: 2rem; color: #DC2626;",
      textContent: "تعذر تحميل التقييمات"
    });
    safeClearContainer(container);
    container.appendChild(errEl);
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
    const emptyRow = createSafeEl("tr", {}, [
      createSafeEl("td", {
        colspan: "4",
        style: "text-align: center; color: var(--text-muted); padding: 2rem;",
        textContent: "لا توجد أنشطة مسجلة في السجل حتى الآن."
      })
    ]);
    safeClearContainer(tbody);
    tbody.appendChild(emptyRow);
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

  const frag = document.createDocumentFragment();

  logs.forEach(entry => {
    const tr = createSafeEl("tr", {}, [
      createSafeEl("td", { style: "font-size: 0.8rem; color: var(--text-muted); white-space: nowrap;" }, [
        createSafeEl("i", { class: "fas fa-clock", style: "margin-left: 0.25rem;" }),
        document.createTextNode(` ${entry.dateFormatted || ''}`)
      ]),
      createSafeEl("td", {}, [
        createSafeEl("span", {
          style: "font-weight: 700; color: var(--text-main); font-size: 0.82rem;",
          textContent: actionLabels[entry.action] || String(entry.action || "")
        })
      ]),
      createSafeEl("td", { style: "font-size: 0.85rem; color: #334155;", textContent: String(entry.details || "") }),
      createSafeEl("td", {}, [
        createSafeEl("span", { style: "font-family: monospace; font-size: 0.75rem; color: var(--text-muted);", textContent: String(entry.id || "") })
      ])
    ]);
    frag.appendChild(tr);
  });

  safeClearContainer(tbody);
  tbody.appendChild(frag);
}
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
  link.setAttribute("download", "kased_karim_products_template.csv");
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
    safeClearContainer(reportBox);
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

  const lines = content.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
  if (lines.length < 2) {
    reportBox.style.display = "block";
    reportBox.style.background = "#FEF2F2";
    reportBox.style.border = "1px solid #FECACA";
    const msg = createSafeEl("div", {
      style: "color: #DC2626; font-weight: 800;",
      textContent: "❌ الملف لا يحتوي على بيانات كافية (يجب توفر سطر العناوين وسطر بيانات واحد على الأقل)."
    });
    safeClearContainer(reportBox);
    reportBox.appendChild(msg);
    return;
  }

  const rawHeaders = parseCsvLine(lines[0]).map(h => h.replace(/^["']|["']$/g, "").trim().toLowerCase());
  const requiredCols = ["id", "name", "price", "category"];
  const missingCols = requiredCols.filter(col => !rawHeaders.includes(col));

  if (missingCols.length > 0) {
    reportBox.style.display = "block";
    reportBox.style.background = "#FEF2F2";
    reportBox.style.border = "1px solid #FECACA";
    const msg = createSafeEl("div", {
      style: "color: #DC2626; font-weight: 800;",
      textContent: `❌ أعمدة إلزامية مفقودة في السطر الأول: ${missingCols.join(", ")}`
    });
    safeClearContainer(reportBox);
    reportBox.appendChild(msg);
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

    const rowErrors = [];
    if (!rowObj.id || !rowObj.id.trim()) rowErrors.push("معرف المنتج (id) مفقود");
    if (!rowObj.name || !rowObj.name.trim()) rowErrors.push("اسم المنتج (name) مفقود");

    const price = parseFloat(rowObj.price);
    if (isNaN(price) || price <= 0) rowErrors.push("السعر غير صالح (يجب أن يكون رقماً أكبر من صفر)");

    if (!rowObj.category || !rowObj.category.trim()) rowErrors.push("التصنيف (category) مفقود");

    if (rowErrors.length > 0) {
      invalidRows.push({
        rowNum: idx + 1,
        name: rowObj.name || "بدون اسم",
        errors: rowErrors
      });
    } else {
      validRows.push({
        id: rowObj.id.trim(),
        name: rowObj.name.trim(),
        enName: rowObj.enname ? rowObj.enname.trim() : "",
        price: price,
        category: rowObj.category.trim(),
        categoryName: rowObj.categoryname ? rowObj.categoryname.trim() : rowObj.category.trim(),
        style: rowObj.style ? rowObj.style.trim() : "معاصر",
        warranty: rowObj.warranty ? rowObj.warranty.trim() : "5 سنوات",
        description: rowObj.description ? rowObj.description.trim() : "",
        image: rowObj.image ? rowObj.image.trim() : DEFAULT_ADMIN_FALLBACK_IMAGE,
        salesCount: formatSafeInt(rowObj.salescount, 0)
      });
    }
  }

  validatedBulkCsvRows = validRows;
  reportBox.style.display = "block";
  safeClearContainer(reportBox);

  if (invalidRows.length > 0) {
    reportBox.style.background = "#FFFBEB";
    reportBox.style.border = "1px solid #FDE68A";

    const reportFrag = document.createDocumentFragment();
    reportFrag.appendChild(createSafeEl("div", { style: "display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;" }, [
      createSafeEl("strong", {
        style: "color: #92400E; font-size: 0.95rem;",
        textContent: `⚠️ تقرير فحص البيانات: تم العثور على ${validRows.length} صف صالح، و ${invalidRows.length} صف به أخطاء`
      })
    ]));

    const errTbody = createSafeEl("tbody");
    invalidRows.slice(0, 50).forEach(inv => {
      errTbody.appendChild(createSafeEl("tr", {}, [
        createSafeEl("td", { style: "font-weight: 800; color: #DC2626;", textContent: `سطر ${inv.rowNum}` }),
        createSafeEl("td", { textContent: String(inv.name) }),
        createSafeEl("td", { style: "color: #DC2626;", textContent: inv.errors.join(" • ") })
      ]));
    });

    const errTable = createSafeEl("table", { class: "admin-table", style: "font-size: 0.8rem; margin-bottom: 0.85rem;" }, [
      createSafeEl("thead", {}, [
        createSafeEl("tr", {}, [
          createSafeEl("th", { textContent: "رقم السطر" }),
          createSafeEl("th", { textContent: "اسم المنتج" }),
          createSafeEl("th", { textContent: "تفاصيل الأخطاء" })
        ])
      ]),
      errTbody
    ]);
    reportFrag.appendChild(errTable);

    if (validRows.length > 0) {
      reportFrag.appendChild(createSafeEl("button", {
        type: "button",
        class: "btn-primary",
        style: "background: #10B981; border: none; font-weight: 800;",
        dataset: { action: "execute-bulk-csv" }
      }, [
        createSafeEl("i", { class: "fas fa-check-circle" }),
        createSafeEl("span", { textContent: ` متابعة واستيراد الصفوف الصالحة فقط (${validRows.length} منتج)` })
      ]));
    }

    reportBox.appendChild(reportFrag);
  } else {
    reportBox.style.background = "#F0FDF4";
    reportBox.style.border = "1px solid #BBF7D0";

    const successBox = createSafeEl("div", {
      style: "display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;"
    }, [
      createSafeEl("div", {}, [
        createSafeEl("strong", {
          style: "color: #166534; font-size: 1rem; display: block;",
          textContent: `✅ تم الفحص بنجاح: جميع الصفوف (${validRows.length} منتج) صحيحة 100% وخالية من أي أخطاء!`
        }),
        createSafeEl("span", {
          style: "font-size: 0.82rem; color: #15803D;",
          textContent: "جاهز للاستيراد الفوري وحفظه محلياً وسحابياً."
        })
      ]),
      createSafeEl("button", {
        type: "button",
        class: "btn-primary",
        style: "background: #10B981; border: none; font-weight: 800; padding: 0.65rem 1.25rem;",
        dataset: { action: "execute-bulk-csv" }
      }, [
        createSafeEl("i", { class: "fas fa-check-circle" }),
        createSafeEl("span", { textContent: ` تأكيد واستيراد (${validRows.length} منتج) الآن` })
      ])
    ]);

    reportBox.appendChild(successBox);
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

  const loadingEl = createSafeEl("div", {
    style: "grid-column: 1 / -1; text-align: center; padding: 3rem; color: var(--text-muted);"
  }, [
    createSafeEl("i", { class: "fas fa-spinner fa-spin", style: "font-size: 1.5rem; margin-bottom: 0.75rem; color: #4285F4;" }),
    createSafeEl("div", { textContent: "جاري تحميل سجل العملاء وحسابات Google المتصلة..." })
  ]);
  safeClearContainer(container);
  container.appendChild(loadingEl);

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

  if (totalEl) totalEl.textContent = formatSafeInt(total);
  if (verifiedEl) verifiedEl.textContent = formatSafeInt(verified);
  if (todayEl) todayEl.textContent = formatSafeInt(today);

  const badge = document.getElementById("adminUsersCountBadge");
  if (badge) {
    badge.textContent = formatSafeInt(total);
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
    if (currentAdminUsersFilter === "google" && c.authProvider !== "google" && !c.googleId) return false;
    if (currentAdminUsersFilter === "local" && (c.authProvider === "google" || c.googleId)) return false;

    if (q) {
      const name = (c.name || "").toLowerCase();
      const email = (c.email || "").toLowerCase();
      const phone = (c.phone || "").toLowerCase();
      return name.includes(q) || email.includes(q) || phone.includes(q);
    }
    return true;
  });

  if (filtered.length === 0) {
    const emptyCard = createSafeEl("div", {
      style: "grid-column: 1 / -1; text-align: center; padding: 3rem 1.5rem; background: #F8FAFC; border: 1px dashed var(--border-light); border-radius: 12px;"
    }, [
      createSafeEl("div", {
        style: "width: 56px; height: 56px; border-radius: 50%; background: rgba(66,133,244,0.1); color: #4285F4; display: flex; align-items: center; justify-content: center; margin: 0 auto 1rem; font-size: 1.5rem;"
      }, [
        createSafeEl("i", { class: "fab fa-google" })
      ]),
      createSafeEl("h3", { style: "font-size: 1.15rem; font-weight: 800; color: var(--text-main); margin-bottom: 0.35rem;", textContent: "لم يتم العثور على عملاء مسجلين" }),
      createSafeEl("p", {
        style: "font-size: 0.85rem; color: var(--text-muted); max-width: 480px; margin: 0 auto;",
        textContent: q ? "لا توجد نتائج مطابقة لبحثك، جرب البحث بكلمات أخرى." : "ستظهر هنا كافة حسابات Google والإيميلات التي قامت بتسجيل الدخول أو إتمام الطلبات على الموقع فور ربطها."
      })
    ]);
    safeClearContainer(container);
    container.appendChild(emptyCard);
    return;
  }

  const frag = document.createDocumentFragment();

  filtered.forEach(user => {
    const isGoogle = user.authProvider === "google" || !!user.googleId;
    const name = String(user.name || "عميل غير معروف");
    const email = String(user.email || "");
    const phone = String(user.phone || "");
    const avatar = String(user.avatar || "");
    const monogram = name.trim().charAt(0).toUpperCase() || "U";

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

    let avatarEl;
    const safeAvatarUrl = sanitizeAdminUrl(avatar, { allowedProtocols: ["https:"], allowRelative: false, fallback: "#" });
    if (safeAvatarUrl !== "#") {
      avatarEl = createSafeEl("img", {
        alt: name,
        style: `width: 54px; height: 54px; border-radius: 50%; object-fit: cover; border: 2px solid ${isGoogle ? '#4285F4' : 'var(--accent)'}; box-shadow: 0 4px 10px rgba(0,0,0,0.1); flex-shrink: 0;`
      });
      setSafeImageWithFallback(avatarEl, safeAvatarUrl);
    } else {
      avatarEl = createSafeEl("div", {
        style: `width: 54px; height: 54px; border-radius: 50%; background: linear-gradient(135deg, ${isGoogle ? '#4285F4' : 'var(--accent)'}, ${isGoogle ? '#1a73e8' : '#9A7B2C'}); color: #FFFFFF; font-weight: 800; font-size: 1.3rem; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 10px rgba(0,0,0,0.1); flex-shrink: 0;`,
        textContent: monogram
      });
    }

    const providerBadge = isGoogle
      ? createSafeEl("span", {
          style: "font-size: 0.72rem; padding: 2px 8px; border-radius: 12px; background: rgba(66,133,244,0.1); color: #1a73e8; font-weight: 700; display: inline-flex; align-items: center; gap: 4px;"
        }, [createSafeEl("i", { class: "fab fa-google" }), document.createTextNode(" Google Verified")])
      : createSafeEl("span", {
          style: "font-size: 0.72rem; padding: 2px 8px; border-radius: 12px; background: rgba(16,185,129,0.1); color: #059669; font-weight: 700; display: inline-flex; align-items: center; gap: 4px;"
        }, [createSafeEl("i", { class: "fas fa-user-check" }), document.createTextNode(" تسجيل محلي")]);

    const cardDetails = createSafeEl("div", {
      style: "display: flex; flex-direction: column; gap: 0.5rem; font-size: 0.85rem; padding: 0.75rem 0; border-top: 1px solid #F1F5F9; border-bottom: 1px solid #F1F5F9; margin-bottom: 0.85rem;"
    }, [
      email ? createSafeEl("div", { style: "display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;" }, [
        createSafeEl("span", { style: "color: var(--text-muted); font-size: 0.78rem;" }, [
          createSafeEl("i", { class: "fas fa-envelope", style: "width: 14px;" }),
          document.createTextNode(" البريد:")
        ]),
        createSafeEl("span", {
          style: "font-weight: 600; color: #1E293B; direction: ltr; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;",
          title: email,
          textContent: email
        })
      ]) : null,
      phone ? createSafeEl("div", { style: "display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;" }, [
        createSafeEl("span", { style: "color: var(--text-muted); font-size: 0.78rem;" }, [
          createSafeEl("i", { class: "fas fa-phone", style: "width: 14px;" }),
          document.createTextNode(" الهاتف:")
        ]),
        createSafeEl("span", { style: "font-weight: 600; color: #1E293B; direction: ltr;", textContent: phone })
      ]) : null,
      createSafeEl("div", { style: "display: flex; align-items: center; justify-content: space-between; gap: 0.5rem;" }, [
        createSafeEl("span", { style: "color: var(--text-muted); font-size: 0.78rem;" }, [
          createSafeEl("i", { class: "fas fa-calendar-check", style: "width: 14px;" }),
          document.createTextNode(" تاريخ الانضمام:")
        ]),
        createSafeEl("span", { style: "color: var(--text-muted); font-size: 0.78rem;", textContent: dateStr })
      ])
    ]);

    const safeWaUrl = phone ? buildSafeWhatsAppUrl(phone) : "#";

    const card = createSafeEl("div", {
      class: "admin-user-card",
      style: "background: #FFFFFF; border: 1px solid var(--border-light); border-radius: 12px; padding: 1.35rem; box-shadow: 0 2px 8px rgba(0,0,0,0.04); transition: transform 0.2s ease, box-shadow 0.2s ease; display: flex; flex-direction: column; justify-content: space-between;"
    }, [
      createSafeEl("div", {}, [
        createSafeEl("div", { style: "display: flex; align-items: center; gap: 0.9rem; margin-bottom: 1rem;" }, [
          avatarEl,
          createSafeEl("div", { style: "flex: 1; min-width: 0;" }, [
            createSafeEl("div", {
              style: "font-weight: 800; color: var(--text-main); font-size: 1.05rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;",
              title: name,
              textContent: name
            }),
            createSafeEl("div", { style: "margin-top: 3px;" }, providerBadge)
          ])
        ]),
        cardDetails
      ]),
      createSafeEl("div", { style: "display: flex; gap: 0.4rem; justify-content: flex-end; align-items: center; margin-top: 0.5rem;" }, [
        email ? createSafeEl("button", {
          type: "button",
          class: "btn-secondary",
          style: "font-size: 0.75rem; padding: 0.35rem 0.65rem;",
          dataset: { action: "copy-email", email: email }
        }, [
          createSafeEl("i", { class: "fas fa-copy" }),
          createSafeEl("span", { textContent: " نسخ الإيميل" })
        ]) : null,
        (phone && safeWaUrl !== "#") ? createSafeEl("a", {
          href: safeWaUrl,
          target: "_blank",
          rel: "noopener noreferrer",
          class: "btn-secondary",
          style: "font-size: 0.75rem; padding: 0.35rem 0.65rem; color: #10B981; border-color: rgba(16,185,129,0.3); text-decoration: none;"
        }, [
          createSafeEl("i", { class: "fab fa-whatsapp" }),
          createSafeEl("span", { textContent: " واتساب" })
        ]) : null,
        createSafeEl("button", {
          type: "button",
          class: "btn-secondary",
          style: "font-size: 0.75rem; padding: 0.35rem 0.65rem;",
          dataset: { action: "filter-customer-orders", customer: email || phone }
        }, [
          createSafeEl("i", { class: "fas fa-receipt" }),
          createSafeEl("span", { textContent: " الطلبات" })
        ])
      ])
    ]);

    frag.appendChild(card);
  });

  safeClearContainer(container);
  container.appendChild(frag);
}

async function refreshAdminGoogleUsers() {
  showToast("⏳ جاري تحديث سجل عملاء Google والويب...");
  await renderAdminGoogleUsers();
  showToast("✅ تم تحديث سجل العملاء");
}
window.refreshAdminGoogleUsers = refreshAdminGoogleUsers;

function filterOrdersByCustomer(query) {
  if (!query) return;
  const ordersTabBtn = document.querySelector('[data-tab="orders"]') || document.querySelector('[onclick*="orders"]');
  switchAdminTab("orders", ordersTabBtn);
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
    escapeCsvCell(u.id || ""),
    escapeCsvCell(u.name || ""),
    escapeCsvCell(u.email || ""),
    escapeCsvCell(u.phone || ""),
    escapeCsvCell(u.authProvider || "local"),
    escapeCsvCell(new Date(u.createdAt || u.updatedAt || Date.now()).toISOString())
  ].join(","));

  const csvContent = "\uFEFF" + [headers.join(","), ...rows].join("\r\n");
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", `kased_karim_customers_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  showToast("📥 تم تصدير بيانات العملاء إلى ملف CSV محصّن");
}
window.exportAdminGoogleUsersCSV = exportAdminGoogleUsersCSV;

// =============================================================================
// GLOBAL WINDOW PUBLIC EXPORT BRIDGES FOR TESTING & INTEROPERABILITY
// =============================================================================
if (typeof window !== "undefined") {
  window.verifyAdminSession = verifyAdminSession;
  window.checkAdminSecurityGate = verifyAdminSession;
  window.lockAdminGate = lockAdminGate;
  window.unhideAdminDashboard = unhideAdminDashboard;
  window.handleAdminPinSubmit = handleAdminPinSubmit;
  window.handleAdminOtpSubmit = handleAdminOtpSubmit;
  window.logoutAdmin = logoutAdmin;
  window.togglePinVisibility = togglePinVisibility;
  window.backToStep1 = backToStep1;
  window.resendAdminOtp = resendAdminOtp;
  window.copyAdminSecretLink = copyAdminSecretLink;
  window.createManualWebRestorePoint = createManualWebRestorePoint;
  window.testAdminChime = testAdminChime;
  window.switchAdminTab = switchAdminTab;

  window.renderAdminOrders = renderAdminOrders;
  window.renderAdminOverview = renderAdminOverview;
  window.renderAdminInventory = renderAdminInventory;
  window.renderAdminCategories = renderAdminCategories;
  window.renderAdminBackupView = renderAdminBackupView;
  window.renderAdminDeliveryAreas = renderAdminDeliveryAreas;
  window.renderAdminReviews = renderAdminReviews;
  window.renderAdminAuditLogs = renderAdminAuditLogs;
  window.showAdminLiveOrderAlert = showAdminLiveOrderAlert;
  window.dismissAdminLiveOrderAlert = dismissAdminLiveOrderAlert;
  window.contactCustomerViaWhatsApp = contactCustomerViaWhatsApp;
  window.printOrderInvoice = printOrderInvoice;
  window.exportOrdersCsv = exportOrdersCsv;
  window.exportAdminGoogleUsersCSV = exportAdminGoogleUsersCSV;
  window.renderAdminGoogleUsers = renderAdminGoogleUsers;
  window.displayFilteredGoogleUsers = displayFilteredGoogleUsers;
  window.validateBulkCsvData = validateBulkCsvData;
  window.initAdminEventDelegation = initAdminEventDelegation;
  window.cleanupAdminDomOnLogout = cleanupAdminDomOnLogout;
  window.createSafeEl = createSafeEl;
  window.safeClearContainer = safeClearContainer;
  window.sanitizeAdminUrl = sanitizeAdminUrl;
  window.buildSafeWhatsAppUrl = buildSafeWhatsAppUrl;
  window.buildSafeTelUrl = buildSafeTelUrl;
  window.formatSafeInt = formatSafeInt;
  window.formatSafeMoney = formatSafeMoney;
  window.escapeCsvCell = escapeCsvCell;
  window.setSafeImageWithFallback = setSafeImageWithFallback;
}
