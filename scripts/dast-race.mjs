// =============================================================================
// FILE: scripts/dast-race.mjs
// DAST TEST: CONCURRENCY & X-FORWARDED-FOR SPOOFING RESILIENCE
// OWASP ASVS Level 3 & CWE-400 / CWE-290
// =============================================================================

const SITE = process.env.SITE || "https://www.kasedkarim.com";

async function testRateLimitSpoof() {
  console.log(`\n🚀 [DAST] Testing Distributed Rate Limiting & X-Forwarded-For Anti-Spoofing on ${SITE}/api/track...`);
  
  const requests = Array.from({ length: 12 }, (_, i) =>
    fetch(`${SITE}/api/track`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Origin": SITE,
        // Simulated X-Forwarded-For spoofing attempting to bypass per-IP rate limiting
        "X-Forwarded-For": `203.0.113.${i + 10}`
      },
      body: JSON.stringify({
        orderId: "KK-TESTNONEXISTENT1",
        phone: `010000000${String(i).padStart(2, "0")}`
      })
    }).then(r => ({
      req: i + 1,
      status: r.status,
      retryAfter: r.headers.get("retry-after") || "none",
      result: r.status === 429 ? "BLOCKED (429 Too Many Requests)" : `HTTP ${r.status}`
    })).catch(err => ({
      req: i + 1,
      status: "ERROR",
      retryAfter: "none",
      result: err.message
    }))
  );

  const results = await Promise.all(requests);
  console.table(results);

  const blockedCount = results.filter(r => r.status === 429).length;
  console.log(`Summary: ${blockedCount}/12 requests rate-limited (HTTP 429).`);
}

testRateLimitSpoof();
