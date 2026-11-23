/**
 * scripts/test-security.mjs
 * Comprehensive Multi-Tier End-to-End Application Security & Anti-DDoS Verification Test Suite
 * Evaluates All Three Tiers:
 * - Tier 1: Auth, Sessions, BFLA, Token Revocation
 * - Tier 2: Zero-Trust Pricing, Negative Quantity, Disposable Email Filter, Serverless Rate Limiting
 * - Tier 3: Denial of Wallet (413), Clickjacking / Frame-Ancestors, Strict CORS Isolation, Edge Caching
 *
 * Usage:
 *   node scripts/test-security.mjs [TARGET_URL]
 *   Example: node scripts/test-security.mjs http://localhost:3000
 */

import http from "node:http";
import { server } from "../server.js";
import { createCustomerToken, createAdminToken } from "../api/_auth.js";
import { resetRateLimiterClients } from "../lib/rateLimit.js";

// Ensure testing secrets are present
process.env.ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.CUSTOMER_JWT_SECRET = process.env.CUSTOMER_JWT_SECRET || "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.CRON_SECRET = process.env.CRON_SECRET || "test-cron-secret-32-bytes-minimum-length-key";
process.env.ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || "https://kasedkarim.com,https://www.kasedkarim.com";
process.env.SKIP_TURNSTILE = "true"; // Bypass Turnstile for automated API security test payloads

async function main() {
  console.log("==================================================================================");
  console.log("🛡️  KASED KARIM FULL-STACK PRODUCTION SECURITY & RESILIENCE VERIFICATION SUITE");
  console.log("==================================================================================\n");

  let targetUrl = process.env.TEST_TARGET_URL || process.argv[2];
  let localServer = null;

  // If no external URL provided, run against the server
  if (!targetUrl) {
    if (server.listening) {
      const addr = server.address();
      const port = typeof addr === "object" ? addr.port : 3000;
      targetUrl = `http://127.0.0.1:${port}`;
    } else {
      await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
      const port = server.address().port;
      targetUrl = `http://127.0.0.1:${port}`;
      localServer = server;
    }
  }

  console.log(`🎯 Target Endpoint: ${targetUrl}\n`);

  const results = [];

  function record(testId, tier, description, passed, details = "") {
    results.push({
      id: testId,
      tier,
      description,
      status: passed ? "PASS" : "FAIL",
      details
    });
    if (passed) {
      console.log(`  [ PASS ] ${testId} (${tier}): ${description}`);
    } else {
      console.error(`  [ FAIL ] ${testId} (${tier}): ${description} (${details})`);
    }
  }

  try {
    // ---------------------------------------------------------------------------
    // TEST 1 (Tier 1): BFLA / Shadow Admin Route Gate
    // ---------------------------------------------------------------------------
    console.log("🔹 1. [Tier 1] Testing BFLA & Shadow Admin Route Authorization...");
    const bflaRes = await fetch(`${targetUrl}/api/auth`, {
      method: "GET",
      headers: { "Content-Type": "application/json" }
    });
    const bflaPassed = bflaRes.status === 401;
    record("SEC-01", "Tier 1", "Unauthenticated Admin Access rejected with 401 Unauthorized", bflaPassed, `HTTP ${bflaRes.status}`);

    // ---------------------------------------------------------------------------
    // TEST 2 (Tier 1): Cryptographic Token Revocation
    // ---------------------------------------------------------------------------
    console.log("\n🔹 2. [Tier 1] Testing Server-Side Token Revocation on Logout...");
    const validAdminToken = createAdminToken(
      { sub: "executive-admin", role: "admin", ip: "127.0.0.1", verified2FA: true }
    );

    // Call logout to revoke token
    const logoutRes = await fetch(`${targetUrl}/api/auth`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${validAdminToken}`
      },
      body: JSON.stringify({ action: "logout" })
    });
    const logoutBody = await logoutRes.json().catch(() => ({}));

    // Attempt to reuse revoked token
    const reuseRes = await fetch(`${targetUrl}/api/auth`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${validAdminToken}`
      }
    });
    const revocationPassed = (logoutRes.status === 200 && reuseRes.status === 401);
    record("SEC-02", "Tier 1", "Revoked Token blocked after logout (Server-Side Revocation)", revocationPassed, `Logout HTTP ${logoutRes.status}, Reuse HTTP ${reuseRes.status}`);

    // ---------------------------------------------------------------------------
    // TEST 3 (Tier 2): Zero-Trust Pricing & Business Logic Manipulation Defense
    // ---------------------------------------------------------------------------
    console.log("\n🔹 3. [Tier 2] Testing Zero-Trust Pricing Manipulation Defense...");
    const priceTamperRes = await fetch(`${targetUrl}/api/orders`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "cf-connecting-ip": "198.51.100.201"
      },
      body: JSON.stringify({
        customerName: "عميل تجريبي",
        customerPhone: "01099887766",
        customerEmail: "pricing.audit@gmail.com",
        turnstileToken: "dummy_valid_test_token",
        subtotal: 1, // Malicious client claim
        total: 10,   // Malicious client claim
        items: [{ id: "prod_crystal_palace", qty: 1, price: 1, unitPrice: 1 }]
      })
    });
    const priceTamperBody = await priceTamperRes.json().catch(() => ({}));
    // Authoritative sale_price in DB is 42000 EGP (deliveryFee: 0)
    const priceTamperPassed = (priceTamperRes.status === 201 || priceTamperRes.status === 200) && priceTamperBody.subtotal === 42000 && priceTamperBody.total === 42000;
    record("SEC-03", "Tier 2", "Client price/total tampering ignored; Authoritative DB price enforced", priceTamperPassed, `Subtotal: ${priceTamperBody.subtotal}, Total: ${priceTamperBody.total}`);

    // ---------------------------------------------------------------------------
    // TEST 4 (Tier 2): Negative & Fractional Quantity Rejection
    // ---------------------------------------------------------------------------
    console.log("\n🔹 4. [Tier 2] Testing Negative and Fractional Quantity Rejection...");
    const negQtyRes = await fetch(`${targetUrl}/api/orders`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "cf-connecting-ip": "198.51.100.202"
      },
      body: JSON.stringify({
        customerName: "عميل تجريبي",
        customerPhone: "01099887766",
        customerEmail: "pricing.audit@gmail.com",
        turnstileToken: "dummy_valid_test_token",
        items: [{ id: "prod_crystal_palace", qty: -5 }]
      })
    });
    const negQtyBody = await negQtyRes.json().catch(() => ({}));
    const negQtyPassed = negQtyRes.status === 400 && negQtyBody.error && negQtyBody.error.includes("كمية المنتج غير صالحة");
    record("SEC-04", "Tier 2", "Negative/fractional quantity rejected with 400 Bad Request", negQtyPassed, `HTTP ${negQtyRes.status} - ${negQtyBody.error || "error"}`);

    // ---------------------------------------------------------------------------
    // TEST 5 (Tier 2): Disposable Email & Anti-Spam Gate
    // ---------------------------------------------------------------------------
    console.log("\n🔹 5. [Tier 2] Testing Disposable Email & Fake Domain Filter...");
    const disposableRes = await fetch(`${targetUrl}/api/customer`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "register",
        name: "Test Hacker",
        email: "attacker@temp-mail.org",
        phone: "01012345678",
        password: "Password123!",
        turnstileToken: "dummy_valid_test_token"
      })
    });
    const dispBody = await disposableRes.json().catch(() => ({}));
    const dispPassed = disposableRes.status === 400 && dispBody.error && (dispBody.error.includes("مؤقت") || dispBody.error.includes("وهمي") || dispBody.error.includes("Disposable"));
    record("SEC-05", "Tier 2", "Disposable burner email domain rejected with 400 Bad Request", dispPassed, `HTTP ${disposableRes.status}`);

    // ---------------------------------------------------------------------------
    // TEST 6 (Tier 2): Serverless Rate Limiting & Retry-After (429 Too Many Requests)
    // ---------------------------------------------------------------------------
    console.log("\n🔹 6. [Tier 2] Testing Upstash Sliding Window Rate Limiting...");
    const storage = new Map();
    var mockUpstashServer = http.createServer((req, res) => {
      let rawBody = "";
      req.on("data", chunk => { rawBody += chunk; });
      req.on("end", () => {
        let commands = [];
        try { commands = JSON.parse(rawBody); } catch (e) {}
        if (!Array.isArray(commands)) commands = [commands];
        const cmdResults = commands.map(cmd => {
          const cmdName = Array.isArray(cmd) ? String(cmd[0]).toLowerCase() : "";
          if (cmdName === "evalsha" || cmdName === "eval") {
            const key = Array.isArray(cmd) ? String(cmd[3] || "key") : "key";
            const currentCount = (storage.get(key) || 0) + 1;
            storage.set(key, currentCount);
            const limit = 3;
            if (currentCount <= limit) {
              return { result: [limit - currentCount, limit] };
            } else {
              return { result: [-1, limit] };
            }
          }
          return { result: "OK" };
        });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(cmdResults));
      });
    });

    await new Promise(resolve => mockUpstashServer.listen(0, "127.0.0.1", resolve));
    const mockPort = mockUpstashServer.address().port;
    process.env.UPSTASH_REDIS_REST_URL = `http://127.0.0.1:${mockPort}`;
    process.env.UPSTASH_REDIS_REST_TOKEN = "mock-token";
    resetRateLimiterClients();

    const testIp = `198.51.100.${Math.floor(Math.random() * 200) + 20}`;
    let hit429 = false;
    let retryAfterHeader = null;

    // Send 4 rapid registration requests (limit is 3 per hour)
    for (let i = 1; i <= 4; i++) {
      const rlRes = await fetch(`${targetUrl}/api/customer`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "cf-connecting-ip": testIp
        },
        body: JSON.stringify({
          action: "register",
          name: `Rate Limit User ${i}`,
          email: `valid.user.${i}@gmail.com`,
          phone: "01099998888",
          password: "Password123!",
          turnstileToken: "dummy_valid_test_token"
        })
      });

      if (rlRes.status === 429) {
        hit429 = true;
        retryAfterHeader = rlRes.headers.get("retry-after");
        break;
      }
    }
    const rlPassed = hit429 && Boolean(retryAfterHeader);
    record("SEC-06", "Tier 2", "Rate Limit threshold returns 429 with Retry-After header", rlPassed, `Triggered 429: ${hit429}, Retry-After: ${retryAfterHeader}`);

    // ---------------------------------------------------------------------------
    // TEST 7 (Tier 3): Denial of Wallet / Large Payload Defense (> 50KB -> 413)
    // ---------------------------------------------------------------------------
    console.log("\n🔹 7. [Tier 3] Testing Denial of Wallet / Large Payload Guard (> 50KB)...");
    const largePadding = "X".repeat(55 * 1024); // 55 KB
    const largePayloadRes = await fetch(`${targetUrl}/api/orders`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        items: [{ id: "prod_crystal_palace", qty: 1 }],
        customer: { name: "أحمد حسني", phone: "01012345678", address: "الشيخ زايد" },
        overflow: largePadding
      })
    });
    const largePassed = largePayloadRes.status === 413;
    record("SEC-07", "Tier 3", "Payload exceeding 50KB returns 413 Payload Too Large", largePassed, `HTTP ${largePayloadRes.status}`);

    // ---------------------------------------------------------------------------
    // TEST 8 (Tier 3): Anti-Clickjacking & Mandatory HTTP Security Headers
    // ---------------------------------------------------------------------------
    console.log("\n🔹 8. [Tier 3] Testing Anti-Clickjacking & Hardened Security Headers...");
    const publicProdRes = await fetch(`${targetUrl}/api/products`);
    const hsts = publicProdRes.headers.get("strict-transport-security");
    const nosniff = publicProdRes.headers.get("x-content-type-options");
    const xFrame = publicProdRes.headers.get("x-frame-options");
    const csp = publicProdRes.headers.get("content-security-policy");
    const permPolicy = publicProdRes.headers.get("permissions-policy");

    const headersPassed = Boolean(
      hsts && hsts.includes("max-age=") &&
      nosniff === "nosniff" &&
      xFrame === "DENY" &&
      csp && csp.includes("frame-ancestors 'none'") &&
      permPolicy && permPolicy.includes("camera=()")
    );
    record("SEC-08", "Tier 3", "Clickjacking prevented (XFO: DENY & CSP frame-ancestors 'none')", headersPassed, `XFO: ${xFrame}, CSP: ${csp ? "Active" : "None"}`);

    // ---------------------------------------------------------------------------
    // TEST 9 (Tier 3): Strict CORS & Unauthorized Origin Rejection
    // ---------------------------------------------------------------------------
    console.log("\n🔹 9. [Tier 3] Testing Strict CORS & Unauthorized Origin Rejection...");
    const unauthorizedCorsRes = await fetch(`${targetUrl}/api/customer`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": "https://malicious-attacker-domain.com"
      },
      body: JSON.stringify({ action: "register", name: "Attacker" })
    });
    const allowOriginHeader = unauthorizedCorsRes.headers.get("access-control-allow-origin");
    const corsPassed = (unauthorizedCorsRes.status === 403 || allowOriginHeader !== "https://malicious-attacker-domain.com");
    record("SEC-09", "Tier 3", "Unauthorized Origin rejected without Access-Control-Allow-Origin", corsPassed, `Status: ${unauthorizedCorsRes.status}, ACAO: ${allowOriginHeader || "none"}`);

    // ---------------------------------------------------------------------------
    // TEST 10 (Tier 3): Edge Caching vs. Private Data Anti-Caching
    // ---------------------------------------------------------------------------
    console.log("\n🔹 10. [Tier 3] Testing Edge Caching vs. Private Data Isolation...");
    const publicCacheHeader = publicProdRes.headers.get("cache-control") || "";
    const publicCachePassed = publicCacheHeader.includes("public") && publicCacheHeader.includes("s-maxage=300");

    const privateOrderRes = await fetch(`${targetUrl}/api/orders`);
    const privateCacheHeader = privateOrderRes.headers.get("cache-control") || "";
    const privateCachePassed = privateCacheHeader.includes("no-store");

    const cachingPassed = publicCachePassed && privateCachePassed;
    record("SEC-10", "Tier 3", "Edge Caching active on public products vs. no-store on private orders", cachingPassed, `Public: ${publicCacheHeader.slice(0, 30)}... | Private: ${privateCacheHeader.slice(0, 30)}...`);

  } finally {
    if (typeof mockUpstashServer !== "undefined" && mockUpstashServer && mockUpstashServer.close) {
      mockUpstashServer.close();
    }
    if (localServer && localServer.close) {
      localServer.close();
    }
  }

  // ---------------------------------------------------------------------------
  // PRINT SUMMARY TABLE
  // ---------------------------------------------------------------------------
  console.log("\n==================================================================================");
  console.log("📊  SECURITY AUDIT RESULTS SUMMARY TABLE (ALL THREE TIERS)");
  console.log("==================================================================================");
  console.log("| ID     | Tier   | Vulnerability / Defense Checked                          | Status | Details");
  console.log("|--------|--------|----------------------------------------------------------|--------|---------------------------");
  for (const r of results) {
    const idPad = r.id.padEnd(6);
    const tierPad = r.tier.padEnd(6);
    const descPad = r.description.padEnd(56);
    const statusFormatted = r.status === "PASS" ? "PASS  " : "FAIL  ";
    console.log(`| ${idPad} | ${tierPad} | ${descPad} | [${statusFormatted}] | ${r.details}`);
  }
  console.log("==================================================================================\n");

  const failedCount = results.filter(r => r.status === "FAIL").length;
  if (failedCount > 0) {
    console.error(`🚨 Verification Completed with ${failedCount} failures!`);
    process.exit(1);
  } else {
    console.log(`🎉 All ${results.length} core security checks PASSED with 100% compliance across all 3 tiers!`);
    process.exit(0);
  }
}

main().catch(err => {
  console.error("Test Suite execution error:", err);
  process.exit(1);
});
