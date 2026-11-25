import { readFileSync } from 'node:fs';

const files = ['js/app.js', 'js/checkout.js'];
const patterns = [
  { name: 'innerHTML assignment', regex: /\.innerHTML\s*=/g },
  { name: 'outerHTML assignment', regex: /\.outerHTML\s*=/g },
  { name: 'insertAdjacentHTML', regex: /\.insertAdjacentHTML\s*\(/g },
  { name: 'document.write', regex: /document\.write\s*\(/g },
  { name: 'eval', regex: /\beval\s*\(/g }
];

let failed = false;
for (const file of files) {
  const source = readFileSync(file, 'utf8');
  for (const pattern of patterns) {
    pattern.regex.lastIndex = 0;
    const matches = [...source.matchAll(pattern.regex)];
    for (const match of matches) {
      const line = source.slice(0, match.index).split('\n').length;
      console.error(`FAIL ${file}:${line} — ${pattern.name}`);
      failed = true;
    }
  }
}

if (failed) process.exit(1);
console.log('PASS: no checked HTML/script injection sinks in js/app.js or js/checkout.js');
console.log('NOTE: static check only; it does not prove the whole website is XSS-free.');
