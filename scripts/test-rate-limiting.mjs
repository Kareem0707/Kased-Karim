/**
 * scripts/test-rate-limiting.mjs
 * Security Verification Test Suite for Vercel Serverless Rate Limiting:
 * 1. Safe Vercel Edge Client IP Extraction (Zero remoteAddress usage)
 * 2. Sliding Window Rate Limiting via @upstash/ratelimit & @upstash/redis
 * 3. 429 Too Many Requests, Retry-After, and X-RateLimit-* Header Enforcement
 * 4. Safe Redis Degradation Handling (Zero internal error leakage)
 */

import http from "node:http";
import { getClientIp, RATE_LIMIT_TIERS, enforceRateLimit, checkRateLimit, resetRateLimiterClients } from "../lib/rateLimit.js";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

async function runRateLimitTests() {
  console.log("==================================================================");
  console.log("🛡️ RUNNING RATE LIMITING & SERVERLESS RESILIENCY TEST SUITE");
  console.log("==================================================================\n");

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✅ PASS: ${message}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${message}`);
      failed++;
    }
  }

  // -----------------------------------------------------------------------------
  // TEST 1: Safe Edge Client IP Extraction (No remoteAddress)
  // -----------------------------------------------------------------------------
  console.log("🔹 1. Testing Safe Edge Client IP Extraction:");

  // Cloudflare Header
  const reqCf = {
    headers: { "cf-connecting-ip": "203.0.113.195", "x-forwarded-for": "10.0.0.1" },
    socket: { remoteAddress: "192.168.1.99" } // Should be ignored
  };
  assert(getClientIp(reqCf) === "203.0.113.195", "Extracted cf-connecting-ip with highest priority");

  // X-Real-IP Header
  const reqReal = {
    headers: { "x-real-ip": "198.51.100.42" },
    socket: { remoteAddress: "10.0.0.2" }
  };
  assert(getClientIp(reqReal) === "198.51.100.42", "Extracted x-real-ip accurately");

  // Vercel Forwarded For Header (First IP in list)
  const reqVercel = {
    headers: { "x-vercel-forwarded-for": "192.0.2.1, 10.0.0.5, 172.16.0.1" },
    socket: { remoteAddress: "10.0.0.3" }
  };
  assert(getClientIp(reqVercel) === "192.0.2.1", "Extracted first client IP from x-vercel-forwarded-for");

  // Standard X-Forwarded-For Header (First IP in list)
  const reqXff = {
    headers: { "x-forwarded-for": "198.51.100.77, 10.0.0.1" },
    socket: { remoteAddress: "10.0.0.4" }
  };
  assert(getClientIp(reqXff) === "198.51.100.77", "Extracted first client IP from x-forwarded-for");

  // IPv4-Mapped IPv6 Strip (::ffff:192.0.2.5 -> 192.0.2.5)
  const reqMapped = {
    headers: { "cf-connecting-ip": "::ffff:192.0.2.5" }
  };
  assert(getClientIp(reqMapped) === "192.0.2.5", "Stripped ::ffff: IPv4-mapped IPv6 prefix cleanly");

  // Missing headers fallback without accessing remoteAddress
  const reqEmpty = { headers: {}, socket: { remoteAddress: "10.0.0.99" } };
  assert(getClientIp(reqEmpty) === "127.0.0.1", "Fell back safely to 127.0.0.1 without touching socket.remoteAddress");

  // -----------------------------------------------------------------------------
  // TEST 2: Sliding Window Rate Limit Tier Definitions
  // -----------------------------------------------------------------------------
  console.log("\n🔹 2. Testing Rate Limit Tier Configurations:");
  assert(RATE_LIMIT_TIERS.auth.limit === 5 && RATE_LIMIT_TIERS.auth.window === "15 m", "Auth & 2FA tier: 5 requests / 15 minutes");
  assert(RATE_LIMIT_TIERS.register.limit === 3 && RATE_LIMIT_TIERS.register.window === "1 h", "Register tier: 3 requests / 1 hour");
  assert(RATE_LIMIT_TIERS.orders.limit === 3 && RATE_LIMIT_TIERS.orders.window === "10 m", "Orders tier: 3 requests / 10 minutes");
  assert(RATE_LIMIT_TIERS.emails.limit === 3 && RATE_LIMIT_TIERS.emails.window === "10 m", "Emails tier: 3 requests / 10 minutes");
  assert(RATE_LIMIT_TIERS.read.limit === 60 && RATE_LIMIT_TIERS.read.window === "1 m", "Public read tier: 60 requests / 1 minute");

  // -----------------------------------------------------------------------------
  // TEST 3: Live Upstash REST Mock Server & Sliding Window Execution
  // -----------------------------------------------------------------------------
  console.log("\n🔹 3. Testing @upstash/ratelimit & @upstash/redis REST Execution:");

  // Spin up lightweight local mock server simulating Upstash Redis REST API
  const storage = new Map();
  const mockServer = http.createServer((req, res) => {
    let rawBody = "";
    req.on("data", chunk => { rawBody += chunk; });
    req.on("end", () => {
      const now = Date.now();
      let commands = [];
      try {
        commands = JSON.parse(rawBody);
      } catch (e) {}

      if (!Array.isArray(commands)) {
        commands = [commands];
      }

      const results = commands.map(cmd => {
        // cmd is e.g. ["evalsha", hash, keyCount, key, ...]
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

  await new Promise(resolve => mockServer.listen(0, "127.0.0.1", resolve));
  const serverPort = mockServer.address().port;
  const mockUrl = `http://127.0.0.1:${serverPort}`;

  // Configure Upstash client pointing to our test mock
  const redis = new Redis({
    url: mockUrl,
    token: "mock-test-token"
  });

  const testLimiter = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(3, "10 m"),
    prefix: "@test/ratelimit"
  });

  const testId = `test-ip-${Date.now()}`;

  // Request 1: Allowed
  const r1 = await testLimiter.limit(testId);
  assert(r1.success === true, `Request 1 allowed (Remaining: ${r1.remaining})`);

  // Request 2: Allowed
  const r2 = await testLimiter.limit(testId);
  assert(r2.success === true, `Request 2 allowed (Remaining: ${r2.remaining})`);

  // Request 3: Allowed (Last in bucket)
  const r3 = await testLimiter.limit(testId);
  assert(r3.success === true, `Request 3 allowed (Remaining: ${r3.remaining})`);

  // Request 4: Blocked (Rate Limit Exceeded)
  const r4 = await testLimiter.limit(testId);
  assert(r4.success === false, `Request 4 blocked with rate limit exceeded (Remaining: ${r4.remaining})`);

  // -----------------------------------------------------------------------------
  // TEST 4: HTTP 429 & RFC 6585 Headers Enforcement Test
  // -----------------------------------------------------------------------------
  console.log("\n🔹 4. Testing HTTP 429 & RFC 6585 Headers Enforcement:");

  // Set environment variable to test mock
  process.env.UPSTASH_REDIS_REST_URL = mockUrl;
  process.env.UPSTASH_REDIS_REST_TOKEN = "mock-test-token";
  resetRateLimiterClients();

  function createMockRes() {
    const headers = {};
    let statusCode = 200;
    let jsonBody = null;
    return {
      setHeader(name, val) { headers[name.toLowerCase()] = String(val); },
      getHeader(name) { return headers[name.toLowerCase()]; },
      status(code) { statusCode = code; return this; },
      writeHead(code, h) {
        statusCode = code;
        if (h) Object.entries(h).forEach(([k, v]) => { headers[k.toLowerCase()] = String(v); });
        return this;
      },
      json(data) { jsonBody = data; return this; },
      end(data) {
        if (typeof data === "string") {
          try { jsonBody = JSON.parse(data); } catch (e) { jsonBody = data; }
        }
        return this;
      },
      get headers() { return headers; },
      get statusCode() { return statusCode; },
      get body() { return jsonBody; }
    };
  }

  // Simulate requests through enforceRateLimit
  const targetIp = "192.0.2.88";
  const req = { headers: { "cf-connecting-ip": targetIp } };

  // First 3 requests
  for (let i = 1; i <= 3; i++) {
    const res = createMockRes();
    const allowed = await enforceRateLimit(req, res, "orders");
    assert(allowed === true, `enforceRateLimit: Request ${i} passed successfully`);
    assert(res.getHeader("x-ratelimit-limit") !== undefined, `Decorated response with X-RateLimit-Limit header`);
  }

  // 4th request: MUST trigger HTTP 429 Too Many Requests
  const resExceeded = createMockRes();
  const allowedExceeded = await enforceRateLimit(req, resExceeded, "orders");
  assert(allowedExceeded === false, "enforceRateLimit: 4th request blocked (returned false)");
  assert(resExceeded.statusCode === 429, `Returned HTTP 429 status code (got: ${resExceeded.statusCode})`);
  assert(Boolean(resExceeded.getHeader("retry-after")), `Included Retry-After header: ${resExceeded.getHeader("retry-after")}`);
  assert(resExceeded.getHeader("x-ratelimit-remaining") === "0", `Included X-RateLimit-Remaining: 0 header`);
  assert(Boolean(resExceeded.getHeader("x-ratelimit-reset")), `Included X-RateLimit-Reset header`);
  assert(
    resExceeded.body && resExceeded.body.error && resExceeded.body.error.includes("تم تجاوز الحد المسموح"),
    "Returned clear Arabic error message in response body"
  );

  // -----------------------------------------------------------------------------
  // TEST 5: Graceful Redis Degradation (Zero Stack Trace or URL Leaks)
  // -----------------------------------------------------------------------------
  console.log("\n🔹 5. Testing Graceful Redis Degradation on Downtime:");

  // Set URL to an unreachable endpoint
  process.env.UPSTASH_REDIS_REST_URL = "http://127.0.0.1:59999"; // closed port
  process.env.UPSTASH_REDIS_REST_TOKEN = "unreachable-token";
  resetRateLimiterClients();

  const degradedResult = await checkRateLimit("auth", "user-degraded-test");
  assert(degradedResult.success === true, "Allowed request to proceed when Redis is unreachable (Fail-Open)");
  assert(degradedResult.degraded === true, "Tagged result as degraded without throwing unhandled exception");

  // Close mock server
  await new Promise(resolve => mockServer.close(resolve));

  console.log("\n==================================================================");
  console.log(`📊 TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log("==================================================================");

  if (failed > 0) {
    process.exit(1);
  }
}

runRateLimitTests().catch(err => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
