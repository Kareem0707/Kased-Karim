#!/usr/bin/env node
// =============================================================================
// FILE: scripts/pre-commit.js
// LOCAL GIT PRE-COMMIT HOOK: SECRET SCANNER & REPO HYGIENE GATE
// OWASP ASVS Level 3 & CWE-798 Defense
// =============================================================================

import { execSync } from "child_process";
import fs from "fs";

console.log("\n🔒 [DevSecOps] Scanning staged files for accidental secret leakage...");

let stagedFiles = [];
try {
  const output = execSync("git diff --cached --name-only --diff-filter=ACM", { encoding: "utf8" });
  stagedFiles = output.split("\n").map(f => f.trim()).filter(Boolean);
} catch (e) {
  // If git fails, exit cleanly
  process.exit(0);
}

if (stagedFiles.length === 0) {
  process.exit(0);
}

const FORBIDDEN_FILE_PATTERNS = [
  /^\.env($|\..+)/i,
  /service-account.*\.json$/i,
  /firebase-adminsdk.*\.json$/i,
  /database\.rules\.json$/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /\.sql$/i,
  /\.bak$/i,
  /\.old$/i
];

const SECRET_PATTERNS = [
  { name: "Private Cryptographic Key", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: "Resend API Key", regex: /\bre_[a-zA-Z0-9_]{20,}\b/ },
  { name: "Brevo (Sendinblue) API Key", regex: /\bxkeysib-[a-zA-Z0-9_-]{40,}\b/ },
  { name: "Firebase Direct Database Token / Auth", regex: /[?&]auth=[a-zA-Z0-9_-]{20,}/ },
  { name: "Hardcoded High-Entropy JWT Secret", regex: /(?:ADMIN_JWT_SECRET|CUSTOMER_JWT_SECRET)\s*=\s*["'][a-fA-F0-9]{32,}["']/ }
];

let violations = 0;

for (const file of stagedFiles) {
  // 1. Check filename against forbidden patterns
  for (const pattern of FORBIDDEN_FILE_PATTERNS) {
    if (pattern.test(file)) {
      if (file === ".env.example") continue; // .env.example is permitted
      if (file.startsWith("migrations/") || file.startsWith("migrations\\")) continue; // Schema migrations are permitted
      console.error(`  ❌ [BLOCKED] Staged forbidden sensitive file: ${file}`);
      violations++;
    }
  }

  // 2. Check content of staged text files
  if (fs.existsSync(file)) {
    try {
      const stats = fs.statSync(file);
      if (stats.size > 2 * 1024 * 1024) continue; // Skip huge binaries
      const content = fs.readFileSync(file, "utf8");

      for (const rule of SECRET_PATTERNS) {
        if (rule.regex.test(content)) {
          console.error(`  ❌ [BLOCKED] Detected ${rule.name} inside: ${file}`);
          violations++;
        }
      }
    } catch {}
  }
}

if (violations > 0) {
  console.error(`\n🚫 COMMIT REJECTED: Found ${violations} security policy violation(s).`);
  console.error("👉 Please remove sensitive files or secrets before committing.\n");
  process.exit(1);
}

console.log("  ✅ Zero secrets detected in staged files. Safe to commit!\n");
process.exit(0);
