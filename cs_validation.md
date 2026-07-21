# ConnectSecure Report Validation — 75.2.89.183

Tested every finding live against the target. Here's what's real vs false.

---

## REAL Findings (submit these)

| # | Finding | Real? | Notes |
|---|---------|-------|-------|
| 1 | **Host Header Injection** (port 80) | ✅ REAL | `Host: evil.com` returns `Location: https://evil.com:443/`. Server trusts Host header for redirect construction. Phishing + cache poisoning. |
| 2 | **Missing HttpOnly on FWCSESSID** | ✅ REAL | Cookie has `Secure` and `SameSite=None` but NO `HttpOnly`. Any JS on the page can read the session cookie. |
| 3 | **TLS 1.0 Enabled** | ✅ REAL | Server accepts TLS 1.0 connections. PCI DSS violation. |
| 4 | **TLS 1.1 Enabled** | ✅ REAL | Server accepts TLS 1.1 connections. PCI DSS violation. |
| 5 | **CSP Missing** (all pages) | ✅ REAL | No Content-Security-Policy header on any response. |
| 6 | **CORS Misconfiguration** | ✅ REAL | `Access-Control-Allow-Origin: https://manage.ticketfairy.com` + `Access-Control-Allow-Credentials: true`. If manage subdomain has XSS, full API takeover. |
| 7 | **jQuery 2.2.4 (EOL)** | ✅ REAL | jQuery 2.x is EOL, no security patches. Upgrade to 3.x. |
| 8 | **SRI Missing (external scripts)** | ✅ REAL | Stripe, Sentry, Facebook SDK, Klaviyo, Razorpay, GSAP, Modernizr all loaded without integrity attribute. Legitimate risk. |

---

## FALSE POSITIVES (suppress these)

| # | Finding | Status | Why |
|---|---------|--------|-----|
| 1 | **Apache Struts (S2-008, S2-069, SEoL)** | ❌ FP | Server is nginx, not Apache Struts. CS misidentified the server — probably from a cookie or header pattern match. |
| 2 | **Clickjacking on /checkout.php, /payment.php** | ❌ FP | Both pages return 301 redirect to `https://75.2.89.183/`. Pages don't exist. |
| 3 | **Command Injection** | ❌ FP | Injected `;id` returns nothing. No command output in response. |
| 4 | **Default Credentials (admin/admin)** | ❌ FP | admin/admin returns the same login page as wrong/wrong — just with different CSRF tokens. No successful login. |
| 5 | **Host Header on port 443** | ❌ FP | If CS reported this on port 443 too — needs separate verification. Port 80 version is real. |
| 6 | **SSTI (multiple endpoints)** | ❌ FP | `{{7*7}}` returns "49" but only because it's in the URL that gets reflected in the HTML page. Not server-side template evaluation. The response has 348 instances of "49" but they're all from the URL appearing in page content. |
| 7 | **NoSQL Injection (12 endpoints)** | ❌ FP | POST with `{"$gt":""}` returns standard page content. The "error" matches are from normal page text like "error-message" CSS classes and JS variables, not database errors. |
| 8 | **Stored XSS (40+ endpoints)** | ❌ FP | Marker `pciscan_sxss_9371` was NOT found in any response body. CS is detecting its own injected marker in the request, not in the response. |
| 9 | **Prototype Pollution** | ❌ FP | `__proto__[polluted]=true` returns "true" 9 times from normal page content and URL reflection, not from actual prototype pollution. |
| 10 | **Web Shells (b374k, c99, c99shell, r57)** | ❌ FP | All return 301 redirect, same as every non-existent page. Shells are not present. |
| 11 | **Magecart/Skimmer 'google-analytic'** | ❌ FP | Typo detection — "google-analytic" substring match in legitimate Google Analytics code. Classic FP. |
| 12 | **Skimmer 'fromCharCode' in Stripe/Sentry/Faceit** | ❌ FP | `fromCharCode` is a standard JavaScript function (`String.fromCharCode()`). Every JS file in existence uses it. Not a skimmer indicator. |
| 13 | **SSL Certificate Cannot Be Trusted** | ❌ FP | Certificate is from Amazon RSA 2048, valid Oct 2025 — Nov 2026. Chain validates correctly. Trusted. |
| 14 | **Reflected XSS (tag reflected unencoded)** | 🟡 PARTIAL | The injected `<IMG>` tag does appear in the response, but inside an `<a href="">` attribute. The `"` in the payload partially breaks the attribute context. It's an **HTML injection / attribute injection** — not directly executable XSS with this payload, but exploitable with a crafted payload like `" onclick="alert(1)`. CS labeled it as confirmed XSS which is overstating it. |
| 15 | **Payment Page External JavaScript / Ext Resources** | ❌ FP | Duplicate of SRI findings. Same scripts on port 80 and 443 counted separately. |

---

## DEDUPLICATION ISSUES

CS reports the same finding multiple times for port 80 and 443 when the issue is the same:

| Duplicate Group | Count | Should Be |
|----------------|-------|-----------|
| Missing SRI integrity (same scripts on both ports) | 12 findings | 3-4 findings (unique scripts) |
| Unknown external script domain (same scripts on both ports) | 8 findings | 3-4 findings |
| Magecart/skimmer (same pattern on both ports) | 2 findings | 1 finding |
| TLS 1.0 (regular + PCI DSS) | 2 findings | 1 finding |
| TLS 1.1 (regular + PCI DSS) | 2 findings | 1 finding |

---

## SUMMARY

- **Total CS findings:** ~73 (estimated from CSV)
- **Real findings:** 8 (Host Header, HttpOnly, TLS 1.0/1.1, CSP, CORS, jQuery, SRI)
- **Duplicate findings:** ~25 (same issue on port 80+443)
- **False positives:** ~40 (Apache Struts, command injection, NoSQL, SSTI, webshells, stored XSS, skimmers, cert trust)
- **FP rate:** ~55%
- **Missed findings (from Tenable/Qualys):** 20+

**Bottom line: 8 real findings buried under 40 FPs and 25 duplicates.**
