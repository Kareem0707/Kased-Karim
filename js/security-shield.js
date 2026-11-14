/**
 * KASED KARIM LIGHTING - EXECUTIVE SECURITY SHIELD (js/security-shield.js)
 * درع أمني فائق المستوى: تجميد وتحييد أدوات المطورين (DevTools / F12 / Inspect)
 * حماية الملكية الفكرية، إخفاء كود المصدر، وتأمين النظام ضد الهندسة العكسية
 */

(function () {
  "use strict";

  // 1. Visual Lockdown Overlay State
  let isLockedDown = false;

  function triggerSecurityLockdown() {
    if (isLockedDown) return;
    isLockedDown = true;

    try {
      if (document.body) {
        document.body.style.filter = "blur(35px)";
        document.body.style.opacity = "0.05";
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
            <h2 style="font-size:1.6rem;font-weight:800;color:#F8FAFC;margin-bottom:0.75rem;">درع الحماية الفائق مفعل</h2>
            <p style="font-size:0.98rem;color:#94A3B8;line-height:1.7;margin-bottom:1.5rem;">
              تم رصد محاولة فحص الأكواد أو فتح أدوات المطورين (DevTools).<br>
              تم تجميد العرض تلقائياً لحماية سرية البيانات والملكية الفكرية لمعرض <strong>قاصد كريم للإضاءة الفاخرة</strong>.
            </p>
            <div style="font-size:0.85rem;color:#D97706;background:rgba(217,119,6,0.1);padding:0.6rem 1rem;border-radius:8px;">
              يُرجى إغلاق أدوات التحليل أو نافذة الفحص للعودة إلى التصفح الطبيعي.
            </div>
          </div>
        `;
        document.documentElement.appendChild(overlay);
      } else {
        overlay.style.display = "flex";
      }
    } catch (e) {}
  }

  function releaseSecurityLockdown() {
    if (!isLockedDown) return;
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

  // 2. High-Frequency Anti-Debugger Traps (Locks up DevTools on execution)
  function startAntiDebuggerLoop() {
    setInterval(function () {
      try {
        (function () {
          return false;
        }["constructor"]("debugger")());
      } catch (e) {}
    }, 50);

    setInterval(function () {
      try {
        Function("debugger")();
      } catch (e) {}
    }, 100);
  }

  // 3. Disable F12 and Common Developer Tools Keyboard Shortcuts (Capture Phase)
  function handleKeydown(e) {
    // F12 key (Key code 123)
    if (e.key === "F12" || e.keyCode === 123 || e.which === 123) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      triggerSecurityLockdown();
      return false;
    }

    const isCtrlOrMeta = e.ctrlKey || e.metaKey;

    // Ctrl + Shift + I (Inspect)
    // Ctrl + Shift + J (Console)
    // Ctrl + Shift + C (Element Inspector)
    // Ctrl + Shift + K (Firefox Console)
    if (
      isCtrlOrMeta &&
      e.shiftKey &&
      (e.key === "I" ||
        e.key === "i" ||
        e.key === "J" ||
        e.key === "j" ||
        e.key === "C" ||
        e.key === "c" ||
        e.key === "K" ||
        e.key === "k" ||
        e.keyCode === 73 ||
        e.keyCode === 74 ||
        e.keyCode === 67 ||
        e.keyCode === 75)
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

  // 4. Disable Context Menu (Right-Click Inspect)
  function blockContextMenu(e) {
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
      if (window.console) {
        console.clear();
        console.log(
          "%c⚠️ تنبيه أمني رفيع المستوى | KASED KARIM LUXURY LIGHTING",
          "color: #D97706; font-size: 20px; font-weight: 900; font-family: Cairo, sans-serif; background: #1E293B; padding: 10px 16px; border-radius: 6px; border: 1px solid #D97706;"
        );
        console.log(
          "%cهذا النظام مخصص حصرياً لمعرض قاصد كريم بالشيخ زايد ومحمي بتشفير طبقي كامل ضد التلاعب والفحص غير المصرح به.",
          "color: #EF4444; font-size: 13px; font-weight: 700; font-family: Cairo, sans-serif; margin-top: 6px;"
        );
      }
    } catch (e) {}
  }

  printSecurityWarning();

  if (typeof window !== "undefined") {
    console.log = function () {};
    console.debug = function () {};
    console.info = function () {};
    console.dir = function () {};
    console.table = function () {};

    // 7. Active DevTools Size & Timing Detection Loop
    const threshold = 160;

    setInterval(function () {
      const widthDiff = window.outerWidth - window.innerWidth > threshold;
      const heightDiff = window.outerHeight - window.innerHeight > threshold;

      if (widthDiff || heightDiff) {
        triggerSecurityLockdown();
      } else if (!isLockedDown) {
        releaseSecurityLockdown();
      }
    }, 400);

    // Timing check for open debugger
    setInterval(function () {
      const start = performance.now();
      try {
        Function("debugger")();
      } catch (e) {}
      const end = performance.now();
      if (end - start > 100) {
        triggerSecurityLockdown();
      }
    }, 1000);
  }

  // Start the anti-debugger trap
  startAntiDebuggerLoop();
})();
