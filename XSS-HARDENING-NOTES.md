# Kased Karim — XSS hardening patch

## What this patch actually changes

- Replaces `innerHTML` clearing in `js/app.js` and `js/checkout.js` with DOM methods (`replaceChildren`).
- Builds checkout loading labels, tracking status labels, and retry/WhatsApp button contents with `createElement`, `textContent`, and text nodes instead of parsing HTML strings.
- Restores the checkout submit button from cloned DOM nodes rather than saving and reparsing its `innerHTML`.
- Adds `scripts/check-xss-sinks.mjs` and the `npm run test:xss` command as a small regression check for selected DOM/script injection sinks in `js/app.js` and `js/checkout.js`.

## How to apply

Copy these files into the same paths in the project, replacing the existing files:

- `js/app.js`
- `js/checkout.js`
- `package.json`

Add this new file:

- `scripts/check-xss-sinks.mjs`

Add this documentation file if desired:

- `XSS-HARDENING-NOTES.md`

Then run:

```bash
node --check js/app.js
node --check js/checkout.js
npm run test:xss
```

## Scope and limitations

- This is a source-code hardening change, not proof that a remotely exploitable XSS vulnerability existed or that the live production deployment has been updated.
- The regression script checks only the two named browser files and only the listed patterns. It does not replace manual testing, dependency review, server-side validation, or a full XSS assessment.
- Existing CSP directives in `vercel.json` and `server.js` were intentionally not loosened or rewritten in this patch.
- Trusted Types enforcement was not enabled here. It needs a separate compatibility pass across every script and third-party integration before enabling `require-trusted-types-for 'script'`.
- Do not add `js/security-shield.js` as a security fix. It purges customer/cart/order-related browser storage and does not prevent XSS; adding it could break customer functionality.
- No live Vercel, Cloudflare, Firebase, or production settings were changed.

## Suggested verification after deployment to staging

1. Test checkout submission, cart contents, order success, and error restoration of the submit button.
2. Test order tracking for every status (received, confirmed, preparing, packed, shipped, delivered, cancelled, failed).
3. Test retry-phone and WhatsApp buttons.
4. In a staging environment only, enter harmless XSS test strings in product names, customer-visible messages, and order status messages; verify they render as text and do not execute.
5. Re-run the external scanner and inspect browser console errors. Do not store test payloads on the live store.
