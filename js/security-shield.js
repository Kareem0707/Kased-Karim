/**
 * KASED KARIM LIGHTING - BRAND ASSET INTEGRITY SHIELD (js/security-shield.js)
 * Lightweight asset protection for showroom images and branding
 * Note: Real security and access control are strictly enforced server-side (CWE-602 / CWE-656 compliant)
 */

(function () {
  "use strict";

  if (window.__KK_SECURITY_SHIELD_ACTIVE__) return;
  window.__KK_SECURITY_SHIELD_ACTIVE__ = true;

  // 1. Prevent accidental drag-and-drop of luxury catalog images
  document.addEventListener(
    "dragstart",
    function (e) {
      if (e.target && (e.target.tagName === "IMG" || e.target.tagName === "A")) {
        e.preventDefault();
      }
    },
    false
  );

  // 2. Prevent right-click context menu on pure decorative showroom images (preserves inputs and textareas)
  document.addEventListener(
    "contextmenu",
    function (e) {
      const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : "";
      if (tag === "img" || (e.target && e.target.classList && e.target.classList.contains("product-img"))) {
        e.preventDefault();
      }
    },
    false
  );
})();
