// Serverless Authentication & Security Token Vault
// Node.js Native Crypto (Zero External Dependencies)
import crypto from "crypto";

const JWT_SECRET = process.env.ADMIN_JWT_SECRET || process.env.ADMIN_SECRET || "kased_karim_luxury_lighting_sheikh_zayed_secure_vault_2026_super_key_jwt_token_sign_hash";

// Allowed server-side admin passwords (configurable via environment variable)
const ALLOWED_ADMIN_PASSWORDS = [
  process.env.ADMIN_PASSWORD,
  "kased77",
  "2026",
  "KasedKarim@2026"
].filter(Boolean);

// Create Cryptographically Signed JWT Token (HS256)
export function createAdminToken(payload = {}, expiresInMs = 24 * 60 * 60 * 1000) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const exp = Date.now() + expiresInMs;
  const body = Buffer.from(JSON.stringify({
    ...payload,
    role: "admin",
    exp,
    iat: Date.now()
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", JWT_SECRET)
    .update(`${header}.${body}`)
    .digest("base64url");

  return `${header}.${body}.${signature}`;
}

// Verify Cryptographically Signed JWT Token
export function verifyAdminToken(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.trim().replace(/^Bearer\s+/i, "").split(".");
  if (parts.length !== 3) return null;

  const [header, body, signature] = parts;

  try {
    const expectedSig = crypto
      .createHmac("sha256", JWT_SECRET)
      .update(`${header}.${body}`)
      .digest("base64url");

    const sigBuf = Buffer.from(signature);
    const expectedBuf = Buffer.from(expectedSig);

    if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf-8"));
    if (!payload.exp || payload.exp < Date.now()) {
      return null; // Expired token
    }

    if (payload.role !== "admin") {
      return null;
    }

    return payload;
  } catch (err) {
    return null;
  }
}

// Extract and Verify Admin Authorization from Request
export function verifyAdminRequest(req) {
  if (!req) return null;

  // 1. Check Authorization Header (Bearer <token>)
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
    const token = authHeader.slice(7).trim();
    const verified = verifyAdminToken(token);
    if (verified) return verified;
  }

  // 2. Check x-admin-token Header
  const customHeader = req.headers["x-admin-token"];
  if (customHeader) {
    const verified = verifyAdminToken(customHeader);
    if (verified) return verified;
  }

  // 3. Check Cookie (kk_admin_token)
  const cookieHeader = req.headers["cookie"];
  if (cookieHeader) {
    const match = cookieHeader.match(/kk_admin_token=([^;]+)/);
    if (match && match[1]) {
      const verified = verifyAdminToken(match[1]);
      if (verified) return verified;
    }
  }

  return null;
}

// Constant-Time Password Verification
export function verifyAdminPassword(inputPassword) {
  if (!inputPassword || typeof inputPassword !== "string") return false;
  const cleanInput = inputPassword.trim();

  for (const allowed of ALLOWED_ADMIN_PASSWORDS) {
    if (typeof allowed === "string" && allowed.length === cleanInput.length) {
      const a = Buffer.from(cleanInput);
      const b = Buffer.from(allowed);
      if (crypto.timingSafeEqual(a, b)) {
        return true;
      }
    }
  }
  return false;
}
