#!/usr/bin/env bash
# =============================================================================
# FILE: scripts/verify-dast.sh
# AUTOMATED POST-DEPLOYMENT & DAST VERIFICATION RUNNER (BASH / LINUX / MACOS)
# =============================================================================

SITE="${SITE:-https://www.kasedkarim.com}"
FB_URL="${FB_URL:-https://kased-karim-default-rtdb.firebaseio.com}"
OLD_FB_SECRET="${OLD_FB_SECRET:-REVOKED_SECRET_TEST}"

echo "==============================================================================="
echo "  KASED KARIM LIGHTING - PRODUCTION DAST & POST-DEPLOY VERIFICATION RUNNER"
echo "  Target Site   : $SITE"
echo "  Firebase RTDB : $FB_URL"
echo "==============================================================================="

# 1. Firebase Direct Database & Revoked Secret Lock
echo -e "\n[PHASE 1] Testing Firebase Direct DB Access & Revoked Secret Lock..."
curl -s -o /dev/null -w "Root /.json           -> %{http_code}\n" "$FB_URL/.json"
curl -s -o /dev/null -w "Shallow Root          -> %{http_code}\n" "$FB_URL/.json?shallow=true"
curl -s -o /dev/null -w "Customers Direct      -> %{http_code}\n" "$FB_URL/customers.json"
curl -s -o /dev/null -w "Server Vault Direct   -> %{http_code}\n" "$FB_URL/_server_vault.json"
curl -s -o /dev/null -w "Old Rotated Secret    -> %{http_code}\n" "$FB_URL/products.json?auth=$OLD_FB_SECRET"

# 2. Live Security Headers, CSP & X-Robots-Tag
echo -e "\n[PHASE 2] Inspecting Live Security Headers, CSP & X-Robots-Tag..."
echo "=== HOME (/) ==="
curl -sI "$SITE/" | grep -iE "strict-transport|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|cross-origin-opener-policy"

echo "=== ADMIN (/admin & /admin.html) ==="
curl -sI "$SITE/admin" | grep -iE "content-security-policy|x-robots-tag|cache-control|referrer-policy|cross-origin-opener-policy"
curl -sI "$SITE/admin.html" | grep -iE "content-security-policy|x-robots-tag|cache-control|referrer-policy"

echo "=== API (/api/products) ==="
curl -sI -X GET "$SITE/api/products" | grep -iE "content-security-policy|x-robots-tag|x-content-type-options|vary|access-control"

# 3. Static Root File Exposure on Vercel
echo -e "\n[PHASE 3] Testing Root File Exposure & Redirect Protection..."
for path in "/database.rules.json" "/package.json" "/package-lock.json" "/vercel.json" "/.env" "/.git/config" "/README.md"; do
  curl -s -o /dev/null -w "$path -> %{http_code}\n" "$SITE$path"
done

# 4. Strict CORS & Active Rejection
echo -e "\n[PHASE 4] Testing CORS Enforcement & Active Rejection..."
for evil in "https://kasedkarim.com.evil.com" "https://evil-kasedkarim.com" "https://attacker.vercel.app" "http://kasedkarim.com" "null"; do
  echo "--- Testing Forbidden Origin: $evil ---"
  curl -sI -X OPTIONS "$SITE/api/auth" \
    -H "Origin: $evil" \
    -H "Access-Control-Request-Method: POST" \
    | grep -iE "^HTTP/|access-control|vary"
done

echo "--- Testing Authorized Origin: $SITE ---"
curl -sI -X OPTIONS "$SITE/api/auth" \
  -H "Origin: $SITE" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type, X-Requested-With, Idempotency-Key" \
  | grep -iE "^HTTP/|access-control|vary"

curl -s -o /dev/null -w "Cross-Site POST -> %{http_code}\n" \
  -X POST "$SITE/api/orders" \
  -H "Content-Type: application/json" \
  -H "Sec-Fetch-Site: cross-site" \
  -d '{}'

# 5. Privileged Admin Routes & Business Logic Guard
echo -e "\n[PHASE 5] Testing Privileged Admin Routes & Business Logic Injection..."
curl -s -o /dev/null -w "GET  /api/customer?action=list -> %{http_code}\n" "$SITE/api/customer?action=list"
curl -s -o /dev/null -w "GET  /api/backup               -> %{http_code}\n" "$SITE/api/backup"
curl -s -o /dev/null -w "GET  /api/orders               -> %{http_code}\n" "$SITE/api/orders"
curl -s -o /dev/null -w "GET  /api/db-health            -> %{http_code}\n" "$SITE/api/db-health"
curl -s -o /dev/null -w "PUT  /api/settings             -> %{http_code}\n" -X PUT "$SITE/api/settings" -H "Content-Type: application/json" -d '{"shippingFee":0}'
curl -s -o /dev/null -w "DEL  /api/products (empty id)  -> %{http_code}\n" -X DELETE "$SITE/api/products"

curl -s -o /dev/null -w "Price/Quantity Tamper POST    -> %{http_code}\n" -X POST "$SITE/api/orders" \
  -H "Content-Type: application/json" \
  -H "Origin: $SITE" \
  -d '{"items":[{"productId":"../_server_vault","quantity":-5,"price":0.01}],"total":0,"status":"delivered"}'

curl -s -o /dev/null -w "Wrong Content-Type             -> %{http_code}\n" -X POST "$SITE/api/reviews" \
  -H "Content-Type: text/plain" \
  -H "Origin: $SITE" \
  -d 'hello'

# 6. Concurrency & Rate Limiting Test
echo -e "\n[PHASE 6] Running Concurrency & X-Forwarded-For Anti-Spoofing Test..."
export SITE
node scripts/dast-race.mjs

echo -e "\n==============================================================================="
echo "  POST-DEPLOYMENT DAST EXECUTION COMPLETED!"
echo "==============================================================================="
