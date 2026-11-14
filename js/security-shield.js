/**
 * KASED KARIM LIGHTING - EXECUTIVE SOVEREIGN SECURITY SHIELD (js/security-shield.js)
 * حماية الملكية الفكرية، تجميد أدوات المطورين، ومنع فحص العناصر نهائياً
 * خفيف وسلس بنسبة 100% ولا يسبب أي بطء أو تجميد لشاشات الهواتف المحمولة
 */

(function () {
  "use strict";

  // Prevent duplicate execution
  if (window.__KK_SECURITY_SHIELD_ACTIVE__) return;
  window.__KK_SECURITY_SHIELD_ACTIVE__ = true;

  // 1. Is Real Mobile Phone Detection (Protects Mobile Experience & Battery)
  const isRealMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
    navigator.userAgent || navigator.vendor || window.opera || ""
  );

  // 2. Disable F12 and Developer Tools Keyboard Shortcuts (Capture Phase)
  function blockDevToolsKeys(e) {
    const key = e.key || "";
    const keyCode = e.keyCode || e.which || 0;
    const isCtrlOrMeta = e.ctrlKey || e.metaKey;

    // F12 Key
    if (key === "F12" || keyCode === 123) {
      e.preventDefault();
      e.stopPropagation();
      if (typeof e.stopImmediatePropagation === "function") e.stopImmediatePropagation();
      return false;
    }

    // Ctrl + Shift + I (Inspect Elements)
    // Ctrl + Shift + J (Console)
    // Ctrl + Shift + C (Element Selector)
    // Ctrl + Shift + K (Firefox Console)
    if (
      isCtrlOrMeta &&
      e.shiftKey &&
      (key.toLowerCase() === "i" ||
       key.toLowerCase() === "j" ||
       key.toLowerCase() === "c" ||
       key.toLowerCase() === "k" ||
       keyCode === 73 ||
       keyCode === 74 ||
       keyCode === 67 ||
       keyCode === 75)
    ) {
      e.preventDefault();
      e.stopPropagation();
      if (typeof e.stopImmediatePropagation === "function") e.stopImmediatePropagation();
      return false;
    }

    // Ctrl + U (View Page Source)
    if (isCtrlOrMeta && (key.toLowerCase() === "u" || keyCode === 85)) {
      e.preventDefault();
      e.stopPropagation();
      if (typeof e.stopImmediatePropagation === "function") e.stopImmediatePropagation();
      return false;
    }

    // Ctrl + S (Save Webpage)
    if (isCtrlOrMeta && (key.toLowerCase() === "s" || keyCode === 83)) {
      e.preventDefault();
      e.stopPropagation();
      if (typeof e.stopImmediatePropagation === "function") e.stopImmediatePropagation();
      return false;
    }
  }

  window.addEventListener("keydown", blockDevToolsKeys, { capture: true, passive: false });
  document.addEventListener("keydown", blockDevToolsKeys, { capture: true, passive: false });

  // 3. Disable Context Menu (Right-Click Inspect)
  function blockContextMenu(e) {
    // Preserve normal interaction for inputs and textareas (e.g. paste phone number in checkout)
    const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : "";
    if (tag === "input" || tag === "textarea") return;

    e.preventDefault();
    e.stopPropagation();
    if (typeof e.stopImmediatePropagation === "function") e.stopImmediatePropagation();
    return false;
  }

  window.addEventListener("contextmenu", blockContextMenu, { capture: true, passive: false });
  document.addEventListener("contextmenu", blockContextMenu, { capture: true, passive: false });

  // 4. Disable Drag and Drop of Images and Critical Assets
  document.addEventListener(
    "dragstart",
    function (e) {
      if (e.target && (e.target.tagName === "IMG" || e.target.tagName === "A")) {
        e.preventDefault();
      }
    },
    false
  );

  // 5. Console Protection & Data Masking
  try {
    if (window.console) {
      if (typeof console.clear === "function") console.clear();
      console.log = function () {};
      console.debug = function () {};
      console.info = function () {};
      console.dir = function () {};
      console.table = function () {};
    }
  } catch (e) {}

  // 6. Anti-Debugger Trap when DevTools is opened via browser menu (Desktop Only)
  if (!isRealMobile) {
    setInterval(function () {
      try {
        (function () {
          return false;
        }["constructor"]("debugger")());
      } catch (e) {}
    }, 400);
  }
})();
