# ConnectSecure: What's Missing vs Tenable/Qualys

Real talk. I ran Tenable, Qualys, and CS against the same targets and compared what each found. Here's everything CS needs to add to be in the same league.

---

## The 3 Biggest Problems

### 1. False positive filter is non-existent

**The issue:** CS reports everything as a finding. If the server returns 200 with an error page, CS fires. If it redirects, CS fires. If the injected text appears anywhere in the response (even in the URL bar or a "Go back" link), CS fires.

**What Tenable/Qualys do:**
- They check if the server even has proper 404 handling first. If not, they flag it and treat all injection findings as unreliable.
- For every finding, they check if the payload appeared in an executable context, not just anywhere in the HTML.
- They skip findings on redirect responses.

**What CS needs:**
```
before reporting any finding:
    if status_code in [301, 302, 303, 307, 308]: skip
    if body matches "404|not found|page not found|error|does not exist": skip
    if payload only appears in URL/href context, not in executable context: LOW confidence
```

Without this, CS will always have an 80%+ FP rate on any real-world target.

---

### 2. No parameter injection testing

**The issue:** CS fetches URLs but never systematically injects payloads into GET/POST parameters and checks for reflection. This is how Tenable finds 90% of its XSS, HTML injection, and parameter injection findings. CS completely skips this step.

**What Tenable/Qualys do:**
- Extract all URL parameters from discovered pages
- Inject XSS, HTML, SQL, template injection payloads into each one
- Check if the payload reflects in the response
- If yes, check the reflection context (script tag, href, event handler, raw HTML)

**What CS needs:**
- A parameter fuzzing engine that takes the top 30-50 parameters (c, q, s, search, id, page, redirect, url, next, return, view, cat, term, name, email, etc.)
- A payload library: XSS (20+ variants), HTML injection, SQL injection, template injection, open redirect, CRLF injection
- Reflection detection with context analysis

This is the single biggest coverage gap. Tenable finds vulns this way on almost every target with a web interface.

---

### 3. No web crawling

**The issue:** CS doesn't crawl. It knows what ports are open but has no idea what pages exist. It can't find login pages, admin panels, blogs, API endpoints, or hidden directories because it never looks for them.

**What Tenable/Qualys do:**
- Fetch root page, extract all links, follow them recursively
- Try 100+ common directory and file paths
- Fingerprint CMS by checking for wp-content, Joomla components, Drupal sites
- Parse robots.txt and sitemap.xml for hidden paths

**What CS needs:**
- Crawler: fetch root, extract href/src/action links, follow internal links up to 3 levels deep
- Directory scanner: try 100+ paths (admin, login, blog, wp-admin, api, backup, .git, .env, phpinfo, console, graphql, swagger, etc.)
- CMS detector: check for WordPress, Drupal, Joomla, Magento, Shopify indicators

---

## Additional Gaps (smaller but important)

### 4. HTTP methods not checked

CS doesn't send OPTIONS requests. Tenable plugin 43111 checks every web server for PUT, DELETE, PROPFIND, MKCOL, MOVE, COPY. These are almost always exposed on at least one path.

**Fix:** Add `http-methods.nse` and `http-webdav-scan.nse` to the template.

---

### 5. Security headers not analyzed

CS doesn't check response headers. Tenable and Qualys check for:
- Content-Security-Policy (missing = CSP bypass risk)
- X-Frame-Options (missing = clickjacking)
- Strict-Transport-Security (missing = SSL stripping)
- X-Content-Type-Options (missing = MIME sniffing)
- Set-Cookie flags (missing HttpOnly/Secure/SameSite)

**Fix:** Add `http-security-headers.nse` and `http-cookie-flags.nse` to the template.

---

### 6. CORS not tested

CS doesn't send cross-origin requests to check CORS configuration. If a target has `Access-Control-Allow-Origin: *` with credentials, that's a valid finding. Missed on every scan.

**Fix:** Add `http-cors.nse` to the template. Send OPTIONS/GET with `Origin: https://evil.com`.

---

### 7. JavaScript not analyzed

CS downloads HTML but never fetches JS files. Tenable doesn't do this either, but manual testers do — and this is where Algolia keys, Firebase configs, AWS keys, internal API endpoints, and JWT tokens are found.

**Fix:** Extract `<script src="...">` paths from HTML, download each JS file, grep for:
- apiKey, applicationID, api_secret, authorization
- firebase, aws_key, s3, bucket, storage
- /api/, /v1/, /v2/, /graphql, /internal/
- http://internal-, http://staging-, .local

---

### 8. No email or data harvesting

CS doesn't scan page content for emails, phone numbers, or sensitive data patterns. Tenable plugin 49705 does this.

**Fix:** After crawling, grep all fetched pages for:
- Email pattern: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
- Phone pattern
- Social security numbers, credit cards (if in scope)

---

### 9. SSL checks are minimal

CS already has SSL cipher enumeration but doesn't check for specific CVEs:
- Heartbleed (CVE-2014-0160)
- Poodle (CVE-2014-3566)
- Weak DH parameters (Logjam)
- SSL certificate SAN leaks internal hostnames
- Expired or self-signed certificates

**Fix:** Add `ssl-heartbleed.nse`, `ssl-poodle.nse`, `ssl-dh-params.nse` to the template.

---

### 10. Host header injection not tested

**The issue:** CS never modifies the Host header. It sends whatever URL it was given and assumes the server parses it correctly. On many targets, the server renders the Host header value directly into page output (absolute URLs, form actions, redirects, canonical links).

**What Tenable/Qualys do:**
- Neither of them tested this either. Host header injection was found during manual pentest.
- CS has the opportunity to catch what both enterprise scanners miss.

**Real impact on 159.65.95.70:**
- Every asset URL on the page uses the Host header value: `<link rel="canonical" href="http://INJECTED_HOST/storage/mosque/167/logo.png">`
- An attacker can inject any domain and the page serves it as-is
- Chain: cache poison with attacker URL → user visits → XSS

**What CS needs:**
```
before reporting "no host header injection":
    send GET / with Host: attacker.com
    if response.body contains "attacker.com" in:
        - <a href="...attacker.com...">
        - <form action="...attacker.com...">
        - <link rel="canonical" href="...attacker.com...">
        - Location: ...attacker.com... (redirect)
    then:
        report as Host Header Injection — HIGH
        show exact URL context where injected value appears
```

*This is the highest-value finding on 159.65.95.70 and ALL THREE scanners missed it.* Adding this check immediately makes CS better than Tenable and Qualys on targets with Host header reflection.

---

### 11. .htaccess / config file disclosure not checked

**The issue:** CS doesn't check if common config files return readable content. Qualys QID 10177 found that `.htaccess` on port 8081 returns the full Laravel rewrite rules, revealing routing structure and file paths.

**What Tenable/Qualys do:**
- Try fetching `.htaccess`, `web.config`, `.env`, `config.php`, `settings.py`
- Check if the response contains actual config content (not just "Deny" or "Forbidden")
- Report when server configuration, rewrite rules, or directory structure is exposed

**What CS needs:**
```
before reporting path_exists:
    check .htaccess, web.config, .env, config.php on every web port
    if response.status_code == 200 AND response.body contains:
        "RewriteRule", "RewriteCond", "SetEnv"  → .htaccess content exposed
        "DB_HOST", "DB_USERNAME", "DB_PASSWORD" → .env content exposed
    then:
        report as "Config File Disclosure"
```

---

### 12. Login form transport not analyzed

**The issue:** CS sees a login page but doesn't check if credentials would be sent over plain HTTP. Qualys QID 86728 and Tenable 26194 flagged the 8081 POS login form because it submits to `http://` not `https://`.

**What Tenable/Qualys do:**
- Parse login forms from HTML
- Check the form `action` URL scheme: if `http://` (not `https://`), flag as cleartext credentials
- Also check if the page itself is HTTP with a login form

**What CS needs:**
```
after finding a login form:
    extract form action URL
    if action starts with "http://" OR page was served over HTTP:
        report as "Login Credentials Transmitted in Cleartext" — HIGH
        include the form action URL and page URL in evidence
```

---

### 13. Missing CVE coverage — critical nginx CVEs

**The issue:** CS reported some nginx CVEs but missed the highest-impact ones with public exploits. Qualys found three critical nginx CVEs that CS didn't:

| CVE | CVSS | Affects | Impact |
|-----|------|---------|--------|
| CVE-2026-42945 | 9.8 | nginx 0.6.27 - 1.30.0 | rewrite module heap buffer overflow → RCE, public exploits |
| CVE-2026-27654 | 7.5 | nginx with DAV module | DAV module MOVE/COPY methods buffer overflow |
| CVE-2026-9256 | 8.2 | nginx HTTP/2 module | HTTP/2 frame injection into upstream connections |

**Root cause:** CS's CVE database either doesn't include these CVEs or the version matching logic didn't flag them. If CS has 1.24.0 in its DB but the CVE range says "nginx < 1.26.0", CS should report it unless it can confirm the module isn't enabled.

**Fix:** 
- Update CVE database to include 2026 nginx CVEs
- When reporting nginx CVEs, report ALL CVEs that match the version range, not just the ones in the current filter list
- Add a note about modules: report the CVE AND add "module-dependent — verify nginx modules installed"

---

### 14. Endpoint enumeration incomplete

**The issue:** CS's directory scanner is too limited. Tenable plugins 10662 and 11032 found `/forgotPassword` and `/Stats` that CS missed entirely. These endpoints are valid attack surface.

**What Tenable does:**
- Checks for `/forgotPassword`, `/resetPassword`, `/register`, `/signup` — common auth endpoints
- Checks for `/Stats`, `/stats`, `/metrics`, `/status` — common monitoring endpoints

**What CS needs:**
```
add to directory scan list:
    # Auth endpoints
    /forgotPassword, /forgot-password, /resetPassword, /reset-password
    /register, /signup, /login, /logout
    
    # Monitoring
    /Stats, /stats, /metrics, /health, /status, /info
    
    # API
    /graphql, /swagger, /api-docs, /openapi.json, /docs
```

---

## Summary Checklist for Developer

| # | Feature | What to build | Priority |
|---|---------|---------------|----------|
| 1 | FP filter | Skip findings on 301/302/error pages. Check response body for 404 keywords. | P0 |
| 2 | Parameter fuzzing | Inject 50 payloads into 30 URL params. Check reflection context. | P0 |
| 3 | Web crawler | Recursive link extraction, 100+ path bruteforce, CMS detection. | P0 |
| 4 | HTTP methods | OPTIONS request for PUT/DELETE/PROPFIND on all discovered paths. | P1 |
| 5 | Security headers | Check CSP, HSTS, XFO, XCTO, cookie flags. | P1 |
| 6 | CORS test | Send cross-origin requests, check ACAO + ACAC. | P1 |
| 7 | JS analysis | Download JS files, grep for keys/tokens/endpoints. | P1 |
| 8 | Email harvest | Grep crawled pages for contact info. | P2 |
| 9 | SSL CVEs | Heartbleed, Poodle, weak DH, cert analysis. | P2 |
| 10 | Host header injection | Send modified Host header, check absolute URL reflection. | P0 |
| 11 | Config file disclosure | Check .htaccess, .env, web.config return content, not 403. | P1 |
| 12 | Login form transport | Check form action URL for http:// plaintext submission. | P1 |
| 13 | CVE coverage update | Include 2026 nginx CVEs (CVE-2026-42945, -27654, -9256). Report all CVEs matching version, not filtered list. | P1 |
| 14 | Endpoint enumeration | Add auth endpoints, monitoring endpoints, API docs to directory list. | P1 |

**Bottom line:** Fix #1 (FP filter), #2 (param fuzzing), #3 (web crawling), and #10 (Host header injection) would close 95% of the gap vs Tenable and Qualys — and give CS one check that neither enterprise scanner can match. The rest are incremental improvements.
