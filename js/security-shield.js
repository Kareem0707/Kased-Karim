/**
 * KASED KARIM LIGHTING - EXECUTIVE SECURITY SHIELD (js/security-shield.js)
 * درع أمني تنفيذي ذكي: حماية الملكية الفكرية، إخفاء كود المصدر، ومنع الفحص
 * مصمم بدقة فائقة لمنع أي تأثير سلبي على الهواتف والأجهزة اللوحية وتجربة تصفح العملاء
 */

(function () {
  "use strict";

  // Prevent multiple executions if included multiple times
  if (window.__KK_SECURITY_SHIELD_INITIALIZED__) return;
  window.__KK_SECURITY_SHIELD_INITIALIZED__ = true;

  // 1. Device and Admin Detection
  function isMobileOrTouchDevice() {
    try {
      const userAgent = navigator.userAgent || navigator.vendor || window.opera || "";
      const isMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|Tablet/i.test(userAgent);
      const isTouch = ("ontouchstart" in window) || (navigator.maxTouchPoints > 0) || (navigator.msMaxTouchPoints > 0);
      const isNarrow = window.innerWidth <= 992;
      return isMobileUA || (isTouch && isNarrow);
    } catch (e) {
      return false;
    }
  }

  function isAuthorizedAdmin() {
    try {
      return localStorage.getItem("kk_admin_authorized") === "true" ||
             localStorage.getItem("kk_admin_device_linked") === "true" ||
             !!localStorage.getItem("kk_admin_token") ||
             !!sessionStorage.getItem("kk_admin_token");
    } catch (e) {
      return false;
    }
  }

  // If on mobile or touch device, never activate aggressive desktop traps
  const isMobile = isMobileOrTouchDevice();

  // 2. Visual Lockdown Overlay State (Desktop Only)
  let isLockedDown = false;

  function triggerSecurityLockdown() {
    // Never lockdown mobile devices or authorized administrators
    if (isMobile || isAuthorizedAdmin() || isLockedDown) return;
    isLockedDown = true;

    try {
      if (document.body) {
        document.body.style.filter = "blur(20px)";
        document.body.style.opacity = "0.1";
        document.body.style.pointerEvents = "none";
        document.body.style.userSelect = "none";
      }

      let overlay = document.getElementById("kkSecurityLockdownShield");
      if (!overlay) {
        overlay = document.createElement("div");
        overlay.id = "kkSecurityLockdownShield";
        overlay.setAttribute("style", "position:fixed;inset:0;background:#0A0E17;z-index:999999999;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#F59E0B;font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;text-align:center;padding:2rem;direction:rtl;");
        overlay.innerHTML = `
          <div style="background:#111827;border:1px solid rgba(245,158,11,0.4);border-radius:16px;padding:2.5rem;max-width:540px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.7);">
            <div style="font-size:3rem;margin-bottom:1rem;">🛡️</div>
            <h2 style="font-size:1.6rem;font-weight:800;color:#F8FAFC;margin-bottom:0.75rem;">درع الحماية مفعل</h2>
            <p style="font-size:0.98rem;color:#94A3B8;line-height:1.7;margin-bottom:1.5rem;">
              تم رصد محاولة فحص الأكواد أو فتح أدوات المطورين (DevTools).<br>
              تم تجميد العرض لحماية سرية البيانات والملكية الفكرية لمعرض <strong>قاصد كريم للإضاءة الفاخرة</strong>.
            </p>
            <button onclick="window.releaseKKSecurityShield && window.releaseKKSecurityShield()" style="font-size:0.88rem;color:#FFFFFF;background:#D97706;border:none;padding:0.7rem 1.6rem;border-radius:8px;font-weight:700;cursor:pointer;transition:all 0.2s ease;">
              العودة للتصفح الطبيعي
            </button>
          </div>
        `;
        document.documentElement.appendChild(overlay);
      } else {
        overlay.style.display = "flex";
      }
    } catch (e) {}
  }

  function releaseSecurityLockdown() {
    isLockedDown = false;
    try {
      if (document.body) {
        document.body.style.filter = "none";
        document.body.style.opacity = "1";
        document.body.style.pointerEvents = "auto";
        document.body.style.userSelect = "auto";
      }
      const overlay = document.getElementById("kkSecurityLockdownShield");
      if (overlay) {
        overlay.style.display = "none";
      }
    } catch (e) {}
  }

  window.releaseKKSecurityShield = releaseSecurityLockdown;

  // 3. Disable F12 and Common Developer Tools Keyboard Shortcuts (Desktop Only)
  function handleKeydown(e) {
    if (isMobile || isAuthorizedAdmin()) return;

    // F12 key (Key code 123)
    if (e.key === "F12" || e.keyCode === 123 || e.which === 123) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      triggerSecurityLockdown();
      return false;
    }

    const isCtrlOrMeta = e.ctrlKey || e.metaKey;

    // Ctrl + Shift + I (Inspect), Ctrl + Shift + J (Console), Ctrl + Shift + C (Element Inspector)
    if (
      isCtrlOrMeta &&
      e.shiftKey &&
      (e.key === "I" || e.key === "i" ||
       e.key === "J" || e.key === "j" ||
       e.key === "C" || e.key === "c" ||
       e.key === "K" || e.key === "k" ||
       e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67 || e.keyCode === 75)
    ) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      triggerSecurityLockdown();
      return false;
    }

    // Ctrl + U (View Page Source)
    if (isCtrlOrMeta && (e.key === "u" || e.key === "U" || e.keyCode === 85)) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      return false;
    }

    // Ctrl + S (Save Webpage)
    if (isCtrlOrMeta && (e.key === "s" || e.key === "S" || e.keyCode === 83)) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      return false;
    }
  }

  window.addEventListener("keydown", handleKeydown, true);
  document.addEventListener("keydown", handleKeydown, true);

  // 4. Disable Context Menu (Right-Click Inspect) on Desktop, while preserving form inputs
  function blockContextMenu(e) {
    if (isAuthorizedAdmin()) return;
    const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : "";
    if (tag === "input" || tag === "textarea") return; // Allow paste/copy in checkout and inputs
    e.preventDefault();
    e.stopPropagation();
    return false;
  }

  document.addEventListener("contextmenu", blockContextMenu, true);
  window.addEventListener("contextmenu", blockContextMenu, true);

  // 5. Prevent Drag & Drop of sensitive images / scripts
  document.addEventListener(
    "dragstart",
    function (e) {
      if (e.target.tagName === "IMG" || e.target.tagName === "A") {
        e.preventDefault();
      }
    },
    false
  );

  // 6. Console Neutralization & Continuous Auto-Wipe
  function printSecurityWarning() {
    try {
      if (window.console && typeof window.console.clear === "function") {
        window.console.clear();
        window.console.log(
          "%c⚠️ تنبيه أمني رفيع المستوى | KASED KARIM LUXURY LIGHTING",
          "color: #D97706; font-size: 18px; font-weight: 900; font-family: Cairo, sans-serif; background: #1E293B; padding: 10px 16px; border-radius: 6px; border: 1px solid #D97706;"
        );
      }
    } catch (e) {}
  }

  printSecurityWarning();

  if (typeof window !== "undefined" && !isAuthorizedAdmin()) {
    try {
      console.log = function () {};
      console.debug = function () {};
      console.info = function () {};
      console.dir = function () {};
      console.table = function () {};
    } catch (e) {}
  }
})();
