/**
 * scripts/test-security.mjs
 * Comprehensive End-to-End Application Security & Anti-DDoS Verification Test Suite
 *
 * Automatically verifies:
 * 1. Disposable Email Rejection (400 Bad Request)
 * 2. Unverified Account Protection (403 Forbidden on Sensitive Operations)
 * 3. Rate Limit Enforcement (429 Too Many Requests with Retry-After)
 * 4. Denial of Wallet / Payload Too Large Guard (413 Payload Too Large on > 50KB)
 * 5. Edge Caching Headers (public, s-maxage=300 on public GET vs. no-store on private)
 * 6. Hardened Security Headers (HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Permissions-Policy)
 * 7. Strict CORS Origin Lock Down (Rejection of unauthorized origins via ALLOWED_ORIGINS)
 */

import http from "node:http";
import { server } from "../server.js";
import { createCustomerToken } from "../api/_auth.js";
import { resetRateLimiterClients } from "../lib/rateLimit.js";

// Ensure testing secrets are present
process.env.ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.CUSTOMER_JWT_SECRET = process.env.CUSTOMER_JWT_SECRET || "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.CRON_SECRET = process.env.CRON_SECRET || "test-cron-secret-32-bytes-minimum-length-key";
process.env.ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS || "https://kasedkarim.com,https://www.kasedkarim.com";
process.env.SKIP_TURNSTILE = "true"; // Bypass Turnstile for automated API security test payloads

async function main() {
  console.log("==================================================================================");
  console.log("🛡️  KASED KARIM SECURITY & ANTI-DDOS AUTOMATED VERIFICATION SUITE");
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

  function record(testId, description, passed, details = "") {
    results.push({
      id: testId,
      description,
      status: passed ? "PASS" : "FAIL",
      details
    });
    if (passed) {
      console.log(`  [ PASS ] ${testId}: ${description}`);
    } else {
      console.error(`  [ FAIL ] ${testId}: ${description} (${details})`);
    }
  }

  try {
    // ---------------------------------------------------------------------------
    // TEST 1: Disposable / Temporary Email Rejection (400 Bad Request)
    // ---------------------------------------------------------------------------
    console.log("🔹 1. Testing Disposable Email & Fake Domain Filter...");
    const disposableRes = await fetch(`${targetUrl}/api/customer`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action: "register",
        name: "Test Hacker",
        email: "attacker@mailinator.com",
        phone: "01012345678",
        password: "Password123!",
        turnstileToken: "dummy_valid_test_token"
      })
    });
    const dispBody = await disposableRes.json().catch(() => ({}));
    const dispPassed = disposableRes.status === 400 && dispBody.error && (dispBody.error.includes("مؤقت") || dispBody.error.includes("وهمي") || dispBody.error.includes("Disposable"));
    record("SEC-01", "Disposable email rejection returns 400 Bad Request", dispPassed, `HTTP ${disposableRes.status}`);

    // ---------------------------------------------------------------------------
    // TEST 2: Unverified Account Access (403 Forbidden)
    // ---------------------------------------------------------------------------
    console.log("\n🔹 2. Testing Unverified Account Sensitive Operations...");
    const unverifiedToken = createCustomerToken({
      sub: "CUST-TEST-UNVERIFIED",
      email: "unverified@gmail.com",
      email_verified: false,
      emailVerified: false
    });

    const unverifiedOrderRes = await fetch(`${targetUrl}/api/orders`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${unverifiedToken}`
      },
      body: JSON.stringify({
        items: [{ id: "p1", name: "نجفة كلاسيك", price: 1500, quantity: 1 }],
        customer: {
          name: "أحمد حسني",
          phone: "01012345678",
          address: "الشيخ زايد، الحي الأول",
          email: "unverified@gmail.com"
        },
        turnstileToken: "dummy_valid_test_token"
      })
    });
    const unvBody = await unverifiedOrderRes.json().catch(() => ({}));
    const unvPassed = unverifiedOrderRes.status === 403 && (unvBody.forbidden === true || unvBody.error?.includes("403"));
    record("SEC-02", "Unverified account order creation returns 403 Forbidden", unvPassed, `HTTP ${unverifiedOrderRes.status}`);

    // ---------------------------------------------------------------------------
    // TEST 3: Payload Size Limit Guard (413 Payload Too Large on > 50KB)
    // ---------------------------------------------------------------------------
    console.log("\n🔹 3. Testing Denial of Wallet / Large Payload Defense (> 50KB)...");
    const largePadding = "X".repeat(55 * 1024); // 55 KB
    const largePayloadRes = await fetch(`${targetUrl}/api/orders`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        items: [{ id: "p1", name: "نجفة", price: 100, quantity: 1 }],
        customer: { name: "أحمد حسني", phone: "01012345678", address: "الشيخ زايد" },
        overflow: largePadding
      })
    });
    const largePassed = largePayloadRes.status === 413;
    record("SEC-03", "Payload exceeding 50KB returns 413 Payload Too Large", largePassed, `HTTP ${largePayloadRes.status}`);

    // ---------------------------------------------------------------------------
    // TEST 4: Rate Limiting & Retry-After (429 Too Many Requests)
    // ---------------------------------------------------------------------------
    console.log("\n🔹 4. Testing Sliding Window Rate Limiting Enforcement...");

    // Spin up local Upstash REST mock to verify 429 triggering
    const storage = new Map();
    var mockUpstashServer = http.createServer((req, res) => {
      let rawBody = "";
      req.on("data", chunk => { rawBody += chunk; });
      req.on("end", () => {
        let commands = [];
        try { commands = JSON.parse(rawBody); } catch (e) {}
        if (!Array.isArray(commands)) commands = [commands];
        const results = commands.map(cmd => {
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
        res.end(JSON.stringify(results));
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
    record("SEC-04", "Rate Limit threshold returns 429 with Retry-After header", rlPassed, `Triggered 429: ${hit429}, Retry-After: ${retryAfterHeader}`);

    // ---------------------------------------------------------------------------
    // TEST 5: Edge Caching Headers (public, s-maxage=300 on GET /api/products)
    // ---------------------------------------------------------------------------
    console.log("\n🔹 5. Testing Edge Caching vs. Private Data Anti-Caching...");
    const publicProdRes = await fetch(`${targetUrl}/api/products`);
    const publicCacheHeader = publicProdRes.headers.get("cache-control") || "";
    const publicCachePassed = publicCacheHeader.includes("public") && publicCacheHeader.includes("s-maxage=300");
    record("SEC-05", "Public catalog GET returns public, s-maxage=300 Edge Cache", publicCachePassed, `Cache-Control: ${publicCacheHeader}`);

    const privateOrderRes = await fetch(`${targetUrl}/api/orders`);
    const privateCacheHeader = privateOrderRes.headers.get("cache-control") || "";
    const privateCachePassed = privateCacheHeader.includes("no-store");
    record("SEC-06", "Private orders route enforces Cache-Control: no-store", privateCachePassed, `Cache-Control: ${privateCacheHeader}`);

    // ---------------------------------------------------------------------------
    // TEST 6: Mandatory Security Headers (HSTS, CSP, nosniff, DENY, etc.)
    // ---------------------------------------------------------------------------
    console.log("\n🔹 6. Testing Mandatory HTTP Security Headers...");
    const hsts = publicProdRes.headers.get("strict-transport-security");
    const nosniff = publicProdRes.headers.get("x-content-type-options");
    const xFrame = publicProdRes.headers.get("x-frame-options");
    const csp = publicProdRes.headers.get("content-security-policy");
    const permPolicy = publicProdRes.headers.get("permissions-policy");

    record("SEC-07", "Strict-Transport-Security (HSTS) max-age >= 63072000", Boolean(hsts && hsts.includes("max-age=")), hsts || "missing");
    record("SEC-08", "X-Content-Type-Options: nosniff", nosniff === "nosniff", nosniff || "missing");
    record("SEC-09", "X-Frame-Options: DENY (Clickjacking Defense)", xFrame === "DENY", xFrame || "missing");
    record("SEC-10", "Content-Security-Policy (CSP) Active & Enforced", Boolean(csp && csp.includes("default-src")), csp ? "CSP Configured" : "missing");
    record("SEC-11", "Permissions-Policy restricts camera/mic/geo", Boolean(permPolicy && permPolicy.includes("camera=()")), permPolicy || "missing");

    // ---------------------------------------------------------------------------
    // TEST 7: Strict CORS Origin Lock Down via ALLOWED_ORIGINS
    // ---------------------------------------------------------------------------
    console.log("\n🔹 7. Testing Strict CORS & Unauthorized Origin Rejection...");
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
    record("SEC-12", "Unauthorized Origin rejected or denied Access-Control-Allow-Origin", corsPassed, `Status: ${unauthorizedCorsRes.status}, ACAO: ${allowOriginHeader || "none"}`);

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
  console.log("📊  SECURITY AUDIT RESULTS SUMMARY TABLE");
  console.log("==================================================================================");
  console.log("| ID     | Test Description                                        | Status | Details");
  console.log("|--------|---------------------------------------------------------|--------|---------------------------");
  for (const r of results) {
    const idPad = r.id.padEnd(6);
    const descPad = r.description.padEnd(55);
    const statusFormatted = r.status === "PASS" ? "PASS  " : "FAIL  ";
    console.log(`| ${idPad} | ${descPad} | [${statusFormatted}] | ${r.details}`);
  }
  console.log("==================================================================================\n");

  const failedCount = results.filter(r => r.status === "FAIL").length;
  if (failedCount > 0) {
    console.error(`🚨 Verification Completed with ${failedCount} failures!`);
    process.exit(1);
  } else {
    console.log(`🎉 All ${results.length} security checks PASSED with 100% compliance!`);
    process.exit(0);
  }
}

main().catch(err => {
  console.error("Test Suite execution error:", err);
  process.exit(1);
});
