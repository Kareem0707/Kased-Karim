/**
 * KASED KARIM LIGHTING - PRODUCTION CLIENT RUNTIME SANITIZER (js/security-shield.js)
 * OWASP ASVS Level 3 & CWE-602 Compliance:
 * All access control, rate limiting, and business validation are enforced strictly server-side.
 * Client-side pseudo-security controls have been permanently decommissioned.
 */

(function () {
  "use strict";

  // Legacy Storage Purge Utility (Scrubber for sensitive tokens / PII in client storage)
  function purgeLegacyUnsafeStorage() {
    if (typeof localStorage === "undefined") return;
    const unsafePrefixes = [
      "kk_admin_token",
      "admin_token",
      "token",
      "auth",
      "kk_admin_authorized",
      "kk_admin_device_linked",
      "kk_customer_token",
      "customer_token",
      "kk_customer_user",
      "kk_customer_account",
      "kk_customer_name",
      "kk_customer_phone",
      "kk_customer_email",
      "kk_customer_avatar",
      "kk_customer_recent_orders",
      "kased_karim_quotation_cart",
      "kased_karim_orders",
      "kased_karim_custom_products",
      "kk_custom_cloud_url",
      "kk_last_placed_order_id"
    ];

    try {
      unsafePrefixes.forEach((key) => {
        try { localStorage.removeItem(key); } catch (e) {}
        try { if (typeof sessionStorage !== "undefined") sessionStorage.removeItem(key); } catch (e) {}
      });

      // Scan all localStorage keys for prototype poisoning or malicious keys
      const keys = Object.keys(localStorage);
      keys.forEach((k) => {
        if (k.includes("__proto__") || k.includes("constructor") || k.includes("prototype")) {
          try { localStorage.removeItem(k); } catch (e) {}
        }
      });
    } catch (err) {}
  }

  // Run purge automatically
  purgeLegacyUnsafeStorage();

  // Export clean utility to window
  if (typeof window !== "undefined") {
    window.purgeLegacyUnsafeStorage = purgeLegacyUnsafeStorage;
  }
})();
