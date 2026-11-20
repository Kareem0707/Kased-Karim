# =============================================================================
# FILE: scripts/verify-dast.ps1
# AUTOMATED POST-DEPLOYMENT & DAST VERIFICATION RUNNER (POWERSHELL / WINDOWS)
# OWASP ASVS Level 3 & NIST SP 800-63B Production Verification
# =============================================================================

param(
    [string]$SITE = "https://www.kasedkarim.com",
    [string]$FB_URL = "https://kased-karim-default-rtdb.firebaseio.com",
    [string]$OLD_FB_SECRET = "REVOKED_SECRET_TEST"
)

Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "  KASED KARIM LIGHTING - PRODUCTION DAST & POST-DEPLOY VERIFICATION RUNNER" -ForegroundColor Cyan
Write-Host "  Target Site   : $SITE" -ForegroundColor Yellow
Write-Host "  Firebase RTDB : $FB_URL" -ForegroundColor Yellow
Write-Host "===============================================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# PHASE 1: Firebase Direct Database & Revoked Secret Lock
# -----------------------------------------------------------------------------
Write-Host "`n[PHASE 1] Testing Firebase Direct DB Access & Revoked Secret Lock..." -ForegroundColor Magenta
$fbEndpoints = @(
    @{ Name = "Root /.json"; Path = "/.json" },
    @{ Name = "Shallow Root"; Path = "/.json?shallow=true" },
    @{ Name = "Customers Direct"; Path = "/customers.json" },
    @{ Name = "Server Vault Direct"; Path = "/_server_vault.json" },
    @{ Name = "Old Rotated Secret"; Path = "/products.json?auth=$OLD_FB_SECRET" }
)

foreach ($ep in $fbEndpoints) {
    $url = "$FB_URL$($ep.Path)"
    $code = (curl.exe -s -o /dev/null -w "%{http_code}" "$url")
    $color = if ($code -eq "401" -or $code -eq "403") { "Green" } else { "Red" }
    Write-Host ("  {0,-25} -> HTTP {1}" -f $ep.Name, $code) -ForegroundColor $color
}

# -----------------------------------------------------------------------------
# PHASE 2: Live Security Headers, CSP & X-Robots-Tag
# -----------------------------------------------------------------------------
Write-Host "`n[PHASE 2] Inspecting Live Security Headers, CSP & X-Robots-Tag..." -ForegroundColor Magenta

Write-Host "  --- HOME (/) ---" -ForegroundColor Yellow
curl.exe -sI "$SITE/" | Select-String -Pattern "strict-transport|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|cross-origin-opener-policy"

Write-Host "`n  --- ADMIN (/admin & /admin.html) ---" -ForegroundColor Yellow
curl.exe -sI "$SITE/admin" | Select-String -Pattern "content-security-policy|x-robots-tag|cache-control|referrer-policy|cross-origin-opener-policy"

Write-Host "`n  --- API (/api/products) ---" -ForegroundColor Yellow
curl.exe -sI -X GET "$SITE/api/products" | Select-String -Pattern "content-security-policy|x-robots-tag|x-content-type-options|vary|access-control"

# -----------------------------------------------------------------------------
# PHASE 3: Static Root File Exposure on Vercel
# -----------------------------------------------------------------------------
Write-Host "`n[PHASE 3] Testing Root File Exposure & Redirect Protection..." -ForegroundColor Magenta
$sensitivePaths = @(
    "/database.rules.json",
    "/package.json",
    "/package-lock.json",
    "/vercel.json",
    "/.env",
    "/.git/config",
    "/README.md"
)

foreach ($p in $sensitivePaths) {
    $url = "$SITE$p"
    $code = (curl.exe -s -o /dev/null -w "%{http_code}" "$url")
    $color = if ($code -eq "404" -or $code -eq "403" -or $code -eq "307" -or $code -eq "308") { "Green" } else { "Red" }
    Write-Host ("  {0,-25} -> HTTP {1}" -f $p, $code) -ForegroundColor $color
}

# -----------------------------------------------------------------------------
# PHASE 4: Strict CORS & Active Rejection
# -----------------------------------------------------------------------------
Write-Host "`n[PHASE 4] Testing CORS Enforcement & Active Rejection..." -ForegroundColor Magenta

$maliciousOrigins = @(
    "https://kasedkarim.com.evil.com",
    "https://evil-kasedkarim.com",
    "https://attacker.vercel.app",
    "http://kasedkarim.com",
    "null"
)

foreach ($evil in $maliciousOrigins) {
    Write-Host "  --- Testing Forbidden Origin: $evil ---" -ForegroundColor Yellow
    curl.exe -sI -X OPTIONS "$SITE/api/auth" -H "Origin: $evil" -H "Access-Control-Request-Method: POST" | Select-String -Pattern "^HTTP/|access-control|vary"
}

Write-Host "`n  --- Testing Authorized Origin: $SITE ---" -ForegroundColor Yellow
curl.exe -sI -X OPTIONS "$SITE/api/auth" -H "Origin: $SITE" -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: Content-Type, X-Requested-With, Idempotency-Key" | Select-String -Pattern "^HTTP/|access-control|vary"

Write-Host "`n  --- Testing Sec-Fetch-Site: cross-site POST ---" -ForegroundColor Yellow
$crossCode = (curl.exe -s -o /dev/null -w "%{http_code}" -X POST "$SITE/api/orders" -H "Content-Type: application/json" -H "Sec-Fetch-Site: cross-site" -d "{}")
$color = if ($crossCode -eq "403") { "Green" } else { "Red" }
Write-Host "  Sec-Fetch-Site: cross-site -> HTTP $crossCode (Expected 403)" -ForegroundColor $color

# -----------------------------------------------------------------------------
# PHASE 5: Privileged Admin Routes & Business Logic Guard
# -----------------------------------------------------------------------------
Write-Host "`n[PHASE 5] Testing Privileged Admin Routes & Business Logic Injection..." -ForegroundColor Magenta

$adminTests = @(
    @{ Name = "GET  /api/customer?action=list"; Method = "GET"; Path = "/api/customer?action=list"; Body = $null },
    @{ Name = "GET  /api/backup"; Method = "GET"; Path = "/api/backup"; Body = $null },
    @{ Name = "GET  /api/orders"; Method = "GET"; Path = "/api/orders"; Body = $null },
    @{ Name = "GET  /api/db-health"; Method = "GET"; Path = "/api/db-health"; Body = $null },
    @{ Name = "PUT  /api/settings"; Method = "PUT"; Path = "/api/settings"; Body = '{"shippingFee":0}' },
    @{ Name = "DEL  /api/products (empty id)"; Method = "DELETE"; Path = "/api/products"; Body = $null }
)

foreach ($t in $adminTests) {
    $url = "$SITE$($t.Path)"
    $code = if ($t.Body) {
        curl.exe -s -o /dev/null -w "%{http_code}" -X $t.Method "$url" -H "Content-Type: application/json" -d $t.Body
    } else {
        curl.exe -s -o /dev/null -w "%{http_code}" -X $t.Method "$url"
    }
    $color = if ($code -eq "401" -or $code -eq "403") { "Green" } else { "Red" }
    Write-Host ("  {0,-35} -> HTTP {1} (Expected 401/403)" -f $t.Name, $code) -ForegroundColor $color
}

# Malicious Order Injection
Write-Host "`n  --- Testing Malicious Negative Quantity & Price Tampering ---" -ForegroundColor Yellow
$tamperCode = (curl.exe -s -o /dev/null -w "%{http_code}" -X POST "$SITE/api/orders" -H "Content-Type: application/json" -H "Origin: $SITE" -d '{\"items\":[{\"productId\":\"../_server_vault\",\"quantity\":-5,\"price\":0.01}],\"total\":0,\"status\":\"delivered\"}')
$color = if ($tamperCode -eq "400") { "Green" } else { "Red" }
Write-Host "  Price/Quantity Tamper POST -> HTTP $tamperCode (Expected 400)" -ForegroundColor $color

# Wrong Content-Type
Write-Host "  --- Testing Content-Type: text/plain on Write Method ---" -ForegroundColor Yellow
$ctCode = (curl.exe -s -o /dev/null -w "%{http_code}" -X POST "$SITE/api/reviews" -H "Content-Type: text/plain" -H "Origin: $SITE" -d "hello")
$color = if ($ctCode -eq "415") { "Green" } else { "Red" }
Write-Host "  Wrong Content-Type -> HTTP $ctCode (Expected 415)" -ForegroundColor $color

# -----------------------------------------------------------------------------
# PHASE 6: Concurrency & Rate Limiting Test (dast-race.mjs)
# -----------------------------------------------------------------------------
Write-Host "`n[PHASE 6] Running Concurrency & X-Forwarded-For Anti-Spoofing Test..." -ForegroundColor Magenta
$env:SITE = $SITE
node scripts/dast-race.mjs

Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host "  POST-DEPLOYMENT DAST EXECUTION COMPLETED!" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
