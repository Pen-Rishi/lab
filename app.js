// ============================================================
// ⚔️  AVENGERS ARMORY - OWASP TOP 10 SECURITY LAB ⚔️
// Supports: SQLite (local) or Supabase PostgreSQL (Mgmt API)
// ============================================================

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const axios = require('axios');
const expressLayouts = require('express-ejs-layouts');
const { exec } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const config = require('./config');

// Choose database backend
const dbModule = config.usePostgres ? require('./database-mgmt') : require('./database');
const { initDb, getReadyDb, saveDatabase } = dbModule;
const { seed } = require('./seed');

const app = express();
const PORT = config.port;

// ---- Middleware ----
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false, secure: false, sameSite: 'none' }
}));

// Expose vulnerable headers + CORS reflection on ALL routes (nuclei: tech detection + missing headers + cors-misconfig)
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'Express');
  res.setHeader('Server', 'Apache/2.4.49 (Unix) OpenSSL/1.1.1k');
  res.setHeader('X-Jenkins', '2.375.1');
  res.removeHeader('X-Frame-Options');
  res.removeHeader('X-Content-Type-Options');
  res.removeHeader('Content-Security-Policy');
  res.removeHeader('X-XSS-Protection');
  res.removeHeader('Referrer-Policy');
  res.removeHeader('Permissions-Policy');
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});

// CVE-2021-43798: Grafana LFI - raw URL middleware (Express resolves ../ before routing)
app.use((req, res, next) => {
  const rawUrl = req.originalUrl || req.url;
  if (rawUrl.includes('/public/plugins/') && rawUrl.includes('..')) {
    if (rawUrl.includes('etc/passwd')) {
      return res.type('text/plain').send(`root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
grafana:x:472:472:grafana:/usr/share/grafana:/bin/false`);
    }
    return res.type('text/plain').send('root:x:0:0:root:/root:/bin/bash\n');
  }
  next();
});

// ---- NUCLEI-DETECTABLE EXPOSED FILES & CONFIGS ----

// .git/config exposure (nuclei: git-config)
app.get('/.git/config', (req, res) => {
  res.type('text/plain').send(`[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/Pen-Rishi/lab.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tmerge = refs/heads/main
\tremote = origin
[user]
\temail = admin@avengers-armory.local
\tname = Admin`);
});
app.get('/.git/HEAD', (req, res) => {
  res.type('text/plain').send('ref: refs/heads/main\n');
});
app.get('/.gitignore', (req, res) => {
  res.type('text/plain').send('node_modules/\n.env\n*.log\n.DS_Store\n');
});

// package.json exposure (nuclei: package-json)
app.get('/package.json', (req, res) => {
  res.json({
    name: "avengers-armory",
    version: "1.0.0",
    description: "OWASP Top 10 Security Lab",
    main: "app.js",
    scripts: { start: "node server.js", dev: "nodemon app.js" },
    dependencies: {
      express: "4.18.2", "express-session": "1.17.3", ejs: "3.1.9",
      axios: "1.6.2", "body-parser": "1.20.2", "cookie-parser": "1.4.6",
      "better-sqlite3": "9.4.3", dotenv: "16.3.1", crypto: "1.0.1"
    }
  });
});
app.get('/package-lock.json', (req, res) => {
  res.json({ name: "avengers-armory", version: "1.0.0", lockfileVersion: 3 });
});

// .htpasswd exposure (nuclei: htpasswd-detection)
app.get('/.htpasswd', (req, res) => {
  res.type('text/plain').send('admin:$apr1$xyz$hashed_password_here\ntony:$apr1$abc$another_hashed_pass\n');
});
app.get('/.htaccess', (req, res) => {
  res.type('text/plain').send('AuthType Basic\nAuthName "Restricted"\nAuthUserFile /etc/apache2/.htpasswd\nRequire valid-user\n');
});

// robots.txt with sensitive paths (nuclei: robots-txt-endpoint)
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(`User-agent: *
Disallow: /admin
Disallow: /api/
Disallow: /backup/
Disallow: /.env
Disallow: /.git/
Disallow: /debug
Disallow: /server-status
Disallow: /phpinfo.php
Disallow: /wp-admin/
Disallow: /api/v1/users
Disallow: /logs/
Disallow: /config/
`);
});

// sitemap.xml (nuclei: sitemap)
app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://avengers-armory.local/</loc></url>
  <url><loc>https://avengers-armory.local/admin</loc></url>
  <url><loc>https://avengers-armory.local/login</loc></url>
  <url><loc>https://avengers-armory.local/api/users</loc></url>
  <url><loc>https://avengers-armory.local/backup/db.sql</loc></url>
</urlset>`);
});

// Swagger/API docs exposure (nuclei: swagger-api)
app.get(['/api-docs', '/swagger-ui.js', '/v1/api-docs', '/v2/api-docs', '/swagger.json', '/api/swagger.json'], (req, res) => {
  res.json({
    swagger: "2.0",
    info: { title: "Avengers Armory API", version: "1.0.0", description: "Internal API - DO NOT EXPOSE" },
    host: "localhost:3001",
    basePath: "/api",
    schemes: ["http"],
    paths: {
      "/login": { post: { summary: "User login", parameters: [{ name: "username", in: "body" }, { name: "password", in: "body" }] } },
      "/users": { get: { summary: "List all users (requires admin)" } },
      "/search": { get: { summary: "Search products", parameters: [{ name: "q", in: "query" }] } },
      "/download": { get: { summary: "Download file", parameters: [{ name: "file", in: "query" }] } },
      "/payment/process": { post: { summary: "Process payment with card" } },
      "/admin/users": { get: { summary: "Admin user management" } },
      "/fetch-url": { get: { summary: "Fetch remote URL" } },
      "/import-config": { post: { summary: "Import XML config" } },
      "/deserialize": { post: { summary: "Deserialize user data" } }
    }
  });
});

// Error logs exposure (nuclei: error-logs, access-log-file)
app.get(['/error.log', '/errors.log', '/logs/error.log', '/admin/error.log', '/debug.log'], (req, res) => {
  res.type('text/plain').send(`[2026-07-20 14:32:11] ERROR: Database connection failed - postgres://admin:P@ssw0rd123@db.internal:5432/armory
[2026-07-20 14:32:15] ERROR: Authentication failed for user 'admin' from IP 192.168.1.100
[2026-07-20 14:33:01] WARN: SQL query took 3200ms: SELECT * FROM users WHERE id = '1 OR 1=1'
[2026-07-20 14:33:45] ERROR: File not found: /etc/passwd (requested by 10.0.0.5)
[2026-07-20 14:34:22] CRITICAL: Unhandled exception in /api/deserialize - possible code injection
[2026-07-20 14:35:00] ERROR: SMTP credentials exposed: smtp://mailer:M@ilP@ss@smtp.internal:587
[2026-07-20 14:36:11] WARN: Session fixation attempt detected from 203.0.113.50
[2026-07-20 15:01:33] ERROR: AWS_SECRET_ACCESS_KEY found in environment: AKIAIOSFODNN7EXAMPLE
`);
});
app.get(['/access.log', '/logs/access.log', '/log/access.log'], (req, res) => {
  res.type('text/plain').send(`"GET /admin HTTP/1.1" 200 3421 "-" "Mozilla/5.0"
"POST /api/login HTTP/1.1" 200 156 "-" "curl/7.68.0"
"GET /.env HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
"GET /api/users HTTP/1.1" 200 8732 "-" "Python-urllib/3.9"
"POST /api/payment/process HTTP/1.1" 200 423 "-" "Mozilla/5.0"
"GET /admin?user=../../../etc/passwd HTTP/1.1" 200 2341 "-" "Nikto/2.1"
`);
});

// Backup files (nuclei: backup file detection)
app.get(['/backup.sql', '/backup/db.sql', '/database.sql', '/db.sql', '/dump.sql', '/backup.zip', '/site.tar.gz'], (req, res) => {
  res.type('text/plain').send(`-- MySQL dump
-- Host: localhost    Database: avengers_armory
-- Server version: 8.0.32

CREATE TABLE users (
  id int NOT NULL AUTO_INCREMENT,
  username varchar(255) NOT NULL,
  password varchar(255) NOT NULL,
  email varchar(255),
  role varchar(50) DEFAULT 'user',
  PRIMARY KEY (id)
);

INSERT INTO users VALUES (1,'admin','admin123','admin@armory.local','admin');
INSERT INTO users VALUES (2,'tony','ironman','tony@stark.com','user');
INSERT INTO users VALUES (3,'steve','america','steve@avengers.com','user');

CREATE TABLE credit_cards (
  id int NOT NULL AUTO_INCREMENT,
  user_id int,
  card_number varchar(19),
  cvv varchar(4),
  expiry varchar(7),
  PRIMARY KEY (id)
);

INSERT INTO credit_cards VALUES (1,1,'4111111111111111','123','12/2027');
INSERT INTO credit_cards VALUES (2,2,'5500000000000004','456','06/2028');
`);
});

// .env file (nuclei: laravel-env, javascript-env, dotenv)
app.get(['/.env', '/.env.bak', '/.env.local', '/.env.production', '/.env.development'], (req, res) => {
  res.type('text/plain').send(`APP_NAME=AvengersArmory
APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:dGhpc2lzYXZlcnlzZWNyZXRrZXkxMjM0NTY3ODk=
APP_URL=http://localhost:3001

DB_CONNECTION=postgres
DB_HOST=db.internal.supabase.co
DB_PORT=5432
DB_DATABASE=avengers_armory
DB_USERNAME=postgres
DB_PASSWORD=SuperSecretDbPass123!

REDIS_HOST=redis.internal
REDIS_PASSWORD=RedisP@ss2024
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=587
MAIL_USERNAME=mailer@armory.local
MAIL_PASSWORD=MailP@ssw0rd!

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=avengers-armory-uploads

STRIPE_KEY=sk_test_51ABC123DEF456
STRIPE_SECRET=sk_live_FAKE_KEY_DO_NOT_USE

JWT_SECRET=super-secret-jwt-key-avengers-2024
SESSION_SECRET=keyboard-cat-avengers

SUPABASE_URL=https://example.supabase.co
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.token
`);
});

// AWS credentials (nuclei: aws-credentials)
app.get(['/.aws/credentials', '/aws/credentials'], (req, res) => {
  res.type('text/plain').send(`[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[production]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
region = us-west-2
`);
});

// Docker config exposure (nuclei: docker-compose-config)
app.get(['/docker-compose.yml', '/docker-compose.yaml', '/Dockerfile'], (req, res) => {
  if (req.path.includes('Dockerfile')) {
    return res.type('text/plain').send(`FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ENV DB_PASSWORD=SuperSecretDbPass123!
ENV JWT_SECRET=super-secret-jwt-key
EXPOSE 3001
CMD ["node", "server.js"]
`);
  }
  res.type('text/yaml').send(`version: '3.8'
services:
  web:
    build: .
    ports:
      - "3001:3001"
    environment:
      - DB_PASSWORD=SuperSecretDbPass123!
      - JWT_SECRET=super-secret-jwt-key
      - AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    depends_on:
      - db
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: SuperSecretDbPass123!
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
`);
});

// SSH keys exposure (nuclei: ssh-authorized-keys)
app.get(['/.ssh/authorized_keys', '/.ssh/id_rsa', '/.ssh/id_rsa.pub'], (req, res) => {
  if (req.path.includes('id_rsa.pub')) {
    return res.type('text/plain').send('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... admin@avengers-armory\n');
  }
  if (req.path.includes('id_rsa')) {
    return res.type('text/plain').send(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGcY5unA1FKfSFCj
FAKE_PRIVATE_KEY_FOR_TESTING_ONLY_NOT_REAL
xK9h9VmPTgNblQ+2YTvCnKGfNtpYEL3TQfCnY2jSk8eLMCfhGE+CnKe
-----END RSA PRIVATE KEY-----
`);
  }
  res.type('text/plain').send('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... admin@avengers-armory\n');
});

// Server status (nuclei: server-status)
app.get('/server-status', (req, res) => {
  res.type('text/html').send(`<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Apache Status</title></head>
<body><h1>Apache Server Status for localhost</h1>
<dl><dt>Server Version: Apache/2.4.49 (Unix) OpenSSL/1.1.1k</dt>
<dt>Server MPM: prefork</dt>
<dt>Server Built: 2024-01-15T10:30:00</dt></dl>
<pre>Total accesses: 48291 - Total Traffic: 124.5 MB
CPU Usage: u.5 s.3 - .00128% CPU load
12.3 requests/sec - 32.7 kB/second - 2.66 kB/request
5 requests currently being processed, 3 idle workers</pre>
<table><tr><th>Srv</th><th>PID</th><th>Acc</th><th>M</th><th>SS</th><th>Req</th><th>Conn</th><th>Child</th><th>Slot</th><th>Client</th><th>VHost</th><th>Request</th></tr>
<tr><td>0-0</td><td>1234</td><td>0/127/3421</td><td>W</td><td>0</td><td>0</td><td>0.0</td><td>0.46</td><td>5.�21</td><td>192.168.1.100</td><td>avengers-armory.local</td><td>GET /api/users HTTP/1.1</td></tr>
</table></body></html>`);
});

// phpinfo (nuclei: phpinfo-files - checks 25 paths)
app.get(['/phpinfo.php', '/info.php', '/php_info.php', '/phpinfo', '/php.php', '/php2.php',
  '/test.php', '/i.php', '/a.php', '/p.php', '/pi.php', '/pinfo.php', '/phpversion.php',
  '/temp.php', '/old_phpinfo.php', '/infophp.php', '/asdf.php', '/inf0.php', '/time.php'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head>
<style type="text/css">body {background-color: #fff; color: #222;} table {border-collapse: collapse;} .e {background-color: #ccf;} .v {background-color: #ddd;} td, th {border: 1px solid #666;}</style>
<title>phpinfo()</title></head>
<body><div class="center">
<table><tr class="h"><td><a href="http://www.php.net/"><img border="0" src="/phpinfo.php?=PHPE9568F36-D428-11d2-A769-00AA001ACF42" alt="PHP logo" /></a><h1 class="p">PHP Version 8.2.12</h1></td></tr></table>
<table><tr><td class="e">System </td><td class="v">Linux avengers-server 5.15.0-91-generic #101-Ubuntu SMP x86_64</td></tr>
<tr><td class="e">Build Date </td><td class="v">Oct 24 2023 12:15:30</td></tr>
<tr><td class="e">Server API </td><td class="v">Apache 2.0 Handler</td></tr>
<tr><td class="e">Document Root </td><td class="v">/var/www/html</td></tr>
<tr><td class="e">REMOTE_ADDR </td><td class="v">${req.ip}</td></tr>
<tr><td class="e">SERVER_SOFTWARE </td><td class="v">Apache/2.4.49 (Unix) OpenSSL/1.1.1k</td></tr>
</table>
<h2>Environment</h2>
<table><tr><td class="e">DB_PASSWORD</td><td class="v">SuperSecretDbPass123!</td></tr>
<tr><td class="e">AWS_SECRET_ACCESS_KEY</td><td class="v">wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</td></tr>
<tr><td class="e">STRIPE_SECRET</td><td class="v">sk_live_FAKE_KEY_DO_NOT_USE</td></tr>
<tr><td class="e">JWT_SECRET</td><td class="v">super-secret-jwt-key-avengers-2024</td></tr>
</table>
</div></body></html>`);
});

// Express stack trace handler moved to end of file

// Debug/actuator endpoints (nuclei: spring actuator, debug)
app.get(['/actuator', '/actuator/env', '/actuator/health', '/actuator/info', '/actuator/configprops'], (req, res) => {
  if (req.path === '/actuator/health') return res.json({ status: "UP" });
  if (req.path === '/actuator/env') return res.json({
    activeProfiles: ["production"],
    propertySources: [
      { name: "systemEnvironment", properties: {
        DB_PASSWORD: { value: "SuperSecretDbPass123!" },
        JWT_SECRET: { value: "super-secret-jwt-key-avengers-2024" },
        AWS_ACCESS_KEY_ID: { value: "AKIAIOSFODNN7EXAMPLE" }
      }}
    ]
  });
  if (req.path === '/actuator/info') return res.json({
    app: { name: "avengers-armory", version: "1.0.0", encoding: "UTF-8" },
    git: { branch: "main", commit: { id: "abc1234" } }
  });
  res.json({ _links: {
    self: { href: "/actuator" },
    health: { href: "/actuator/health" },
    env: { href: "/actuator/env" },
    info: { href: "/actuator/info" },
    configprops: { href: "/actuator/configprops" }
  }});
});

// GraphQL endpoint (nuclei: graphql-detect)
app.get('/graphql', (req, res) => {
  res.json({ data: { __schema: { queryType: { name: "Query" }, types: [
    { name: "User", fields: [{ name: "id" }, { name: "username" }, { name: "password" }, { name: "email" }, { name: "role" }] },
    { name: "CreditCard", fields: [{ name: "card_number" }, { name: "cvv" }, { name: "expiry" }] }
  ]}}});
});
app.post('/graphql', (req, res) => {
  const query = (req.body && req.body.query) || '';
  if (query.includes('__schema') || query.includes('IntrospectionQuery')) {
    return res.json({ data: { __schema: { queryType: { name: "Query" }, mutationType: { name: "Mutation" },
      types: [
        { name: "User", fields: [{ name: "id" }, { name: "username" }, { name: "password" }, { name: "email" }, { name: "role" }, { name: "credit_card" }] },
        { name: "Query", fields: [{ name: "users" }, { name: "user" }, { name: "creditCards" }] }
      ]
    }}});
  }
  res.json({ data: { users: [{ id: 1, username: "admin", role: "admin" }, { id: 2, username: "tony", role: "user" }] }});
});

// WordPress paths (nuclei: wp-config, wp-login, xmlrpc)
app.get(['/wp-config.php', '/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.save'], (req, res) => {
  res.type('text/plain').send(`<?php
define('DB_NAME', 'avengers_armory');
define('DB_USER', 'admin');
define('DB_PASSWORD', 'SuperSecretDbPass123!');
define('DB_HOST', 'localhost');
define('AUTH_KEY', 'put-your-unique-phrase-here');
define('SECURE_AUTH_KEY', 'another-unique-phrase');
$table_prefix = 'wp_';
`);
});
app.get('/wp-login.php', (req, res) => {
  res.type('text/html').send('<html><body><form method="post"><h1>WordPress Login</h1><input name="log" placeholder="Username"><input name="pwd" type="password" placeholder="Password"><button>Log In</button></form></body></html>');
});
app.all('/xmlrpc.php', (req, res) => {
  res.type('text/xml').send(`<?xml version="1.0"?>
<methodResponse><params><param><value><array><data>
<value><string>system.multicall</string></value>
<value><string>system.listMethods</string></value>
<value><string>demo.sayHello</string></value>
<value><string>wp.getUsersBlogs</string></value>
<value><string>wp.getUsers</string></value>
<value><string>wp.getPost</string></value>
<value><string>pingback.ping</string></value>
</data></array></value></param></params></methodResponse>`);
});

// CORS misconfiguration endpoint (nuclei: cors-misconfig)
app.get('/api/cors-data', (req, res) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.json({ secret: "CORS allows any origin with credentials", api_key: "sk_live_FAKE", users: ["admin", "tony", "steve"] });
});

// Open redirect (nuclei: open-redirect)
app.get('/redirect', (req, res) => {
  const url = req.query.url || req.query.redirect || req.query.next || req.query.to || '/';
  res.redirect(url);
});
app.get('/login/callback', (req, res) => {
  const returnTo = req.query.returnTo || req.query.return_to || req.query.next || '/';
  res.redirect(returnTo);
});

// CRLF injection (nuclei: crlf-injection)
app.get('/api/set-language', (req, res) => {
  const lang = req.query.lang || 'en';
  res.setHeader('X-Custom-Lang', lang);
  res.setHeader('Set-Cookie', `lang=${lang}; Path=/`);
  res.json({ language: lang });
});

// Directory listing (nuclei: directory-listing)
app.get(['/uploads/', '/images/', '/files/', '/backup/', '/config/'], (req, res) => {
  res.type('text/html').send(`<html><head><title>Index of ${req.path}</title></head>
<body><h1>Index of ${req.path}</h1>
<pre><a href="../">../</a>
<a href="admin_backup.sql">admin_backup.sql</a>          2026-07-20 14:32    245K
<a href="users_export.csv">users_export.csv</a>          2026-07-19 09:15    12K
<a href="config.yml">config.yml</a>                2026-07-18 16:45    3.2K
<a href="credentials.txt">credentials.txt</a>           2026-07-15 11:20    1.1K
<a href="database_dump.sql">database_dump.sql</a>         2026-07-14 08:30    892K
<a href="private_key.pem">private_key.pem</a>           2026-07-10 22:00    1.7K
</pre><address>Apache/2.4.49 Server at avengers-armory.local Port 80</address></body></html>`);
});

// crossdomain.xml (nuclei: crossdomain-xml)
app.get('/crossdomain.xml', (req, res) => {
  res.type('application/xml').send(`<?xml version="1.0"?>
<cross-domain-policy>
  <allow-access-from domain="*"/>
  <allow-http-request-headers-from domain="*" headers="*"/>
</cross-domain-policy>`);
});

// security.txt (nuclei: security-txt)
app.get(['/.well-known/security.txt', '/security.txt'], (req, res) => {
  res.type('text/plain').send(`Contact: admin@avengers-armory.local
Expires: 2024-12-31T23:59:59.000Z
Preferred-Languages: en
Canonical: https://avengers-armory.local/.well-known/security.txt
`);
});

// Trace method enabled with full header reflection (nuclei: cross-site-tracing-xss)
app.use((req, res, next) => {
  if (req.method === 'TRACE') {
    res.setHeader('Content-Type', 'message/http');
    let headers = '';
    for (const [key, value] of Object.entries(req.rawHeaders || req.headers)) {
      headers += `${value}\r\n`;
    }
    const rawPairs = req.rawHeaders || [];
    let rawStr = '';
    for (let i = 0; i < rawPairs.length; i += 2) {
      rawStr += `${rawPairs[i]}: ${rawPairs[i+1]}\r\n`;
    }
    return res.send(`TRACE ${req.url} HTTP/1.1\r\n${rawStr}\r\n`);
  }
  if (req.method === 'OPTIONS') {
    res.setHeader('Allow', 'GET, POST, PUT, DELETE, OPTIONS, TRACE, HEAD, PATCH');
    return res.sendStatus(200);
  }
  next();
});

app.get('/api/legacy/products', (req, res) => {
  res.json({ error: 'Legacy XML API deprecated.' });
});

app.post('/api/legacy/parse-xml', bodyParser.text({ type: 'text/xml' }), (req, res) => {
  const xml = req.body || req.query.xml || '';
  if (!xml) return res.send('<error>No XML provided</error>');
  try {
    // Simulate XXE by checking for DOCTYPE + ENTITY patterns
    const hasExternalEntity = /<!DOCTYPE[^>]*ENTITY[^>]*SYSTEM/i.test(xml);
    const hasFileRead = /file:\/\//i.test(xml);
    const hasHttp = /http[s]?:\/\//i.test(xml);
    if (hasExternalEntity && hasFileRead) {
      return res.type('text/xml').send(`<?xml version="1.0"?><result><data>${fs.readFileSync('/etc/passwd', 'utf8').substring(0, 500).replace(/</g, '&lt;')}</data></result>`);
    }
    if (hasExternalEntity && hasHttp) {
      return res.type('text/xml').send('<?xml version="1.0"?><result><data>SSRF triggered via XXE!</data></result>');
    }
    res.type('text/xml').send(`<?xml version="1.0"?><result><processed>${xml.substring(0, 200).replace(/</g, '&lt;')}</processed></result>`);
  } catch (e) {
    res.type('text/xml').send(`<?xml version="1.0"?><error>${e.message}</error>`);
  }
});

app.get('/api/check-versions', (req, res) => {
  res.json({
    express: '4.16.0 (CVE-2022-24999: qs vulnerable to prototype pollution)',
    packages: [
      { name: 'express', version: '4.16.0', knownCVEs: ['CVE-2022-24999', 'CVE-2024-29041'] },
      { name: 'sql.js', version: '1.6.0', knownCVEs: ['CVE-2023-12345'] },
      { name: 'axios', version: '0.21.0', knownCVEs: ['CVE-2023-45857'] }
    ]
  });
});

app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

app.use((req, res, next) => {
  res.locals.path = req.path;
  res.locals.user = req.session.user || null;
  res.locals.cartCount = req.session.cartCount || 0;
  res.locals.store = config.store;
  next();
});

// Headers set in global middleware above

function isAuth(req) { return req.session && req.session.userId; }

// Async handler wrapper for Supabase routes
function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

// Database access helper
const db = () => getReadyDb();

// ---- Wrap a sync handler if using SQLite, or use async if Supabase ----
function wrap(fn) {
  return config.usePostgres ? asyncHandler(fn) : fn;
}

// ============================================================
// XSS REFLECTION ENDPOINTS (nuclei: top-xss-params, xss-fuzz)
// ============================================================

// Reflected search page - reflects ALL query params in HTML (nuclei: top-xss-params)
app.get('/search', (req, res) => {
  const q = req.query.q || req.query.s || req.query.search || req.query.query || req.query.keyword || '';
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Search Results</title></head><body>
<h1>Search Results for: ${q}</h1>
<form><input name="q" value="${q}"><button>Search</button></form>
<p>No results found for "${q}"</p>
</body></html>`);
});

// Reflects ALL query params in HTML for nuclei top-xss-params on root
app.get('/xss-test', (req, res) => {
  let html = '<html><head><title>XSS Test</title></head><body><h1>Parameter Reflection Test</h1>';
  for (const [key, value] of Object.entries(req.query)) {
    html += `<p>${key}: ${value}</p>\n`;
  }
  html += '</body></html>';
  res.type('text/html').send(html);
});

// SSTI test endpoint (nuclei: reflection-ssti)
app.get('/template', (req, res) => {
  const name = req.query.name || req.query.template || 'World';
  res.type('text/html').send(`<html><body><h1>Hello ${name}!</h1><p>Template rendered: ${name}</p></body></html>`);
});
app.post('/template', (req, res) => {
  const name = req.body.name || req.body.template || 'World';
  res.type('text/html').send(`<html><body><h1>Hello ${name}!</h1><p>Template rendered: ${name}</p></body></html>`);
});

// SSRF endpoint (nuclei: response-ssrf)
app.get('/api/fetch', (req, res) => {
  const url = req.query.url || req.query.target || '';
  if (!url) return res.json({ error: 'Provide ?url= parameter' });
  axios.get(url, { timeout: 5000 }).then(r => {
    res.type('text/html').send(r.data);
  }).catch(e => {
    res.json({ error: e.message, url: url });
  });
});
app.post('/api/fetch', (req, res) => {
  const url = req.body.url || req.body.target || '';
  if (!url) return res.json({ error: 'Provide url in body' });
  axios.get(url, { timeout: 5000 }).then(r => {
    res.type('text/html').send(r.data);
  }).catch(e => {
    res.json({ error: e.message, url: url });
  });
});

// LFI endpoint (nuclei: lfi-keyed, linux-lfi-fuzz)
app.get('/api/read-file', (req, res) => {
  const file = req.query.file || req.query.path || req.query.filename || '';
  if (!file) return res.json({ error: 'Provide ?file= parameter' });
  try {
    const content = fs.readFileSync(file, 'utf8');
    res.type('text/plain').send(content);
  } catch(e) {
    res.status(404).type('text/plain').send(`File not found: ${file}`);
  }
});

// Command injection endpoint (nuclei: blind-oast-polyglots)
app.get('/api/ping', (req, res) => {
  const host = req.query.host || req.query.ip || '127.0.0.1';
  exec(`ping -c 1 ${host}`, { timeout: 5000 }, (err, stdout, stderr) => {
    res.type('text/plain').send(stdout || stderr || err?.message || 'No output');
  });
});
app.post('/api/ping', (req, res) => {
  const host = req.body.host || req.body.ip || '127.0.0.1';
  exec(`ping -c 1 ${host}`, { timeout: 5000 }, (err, stdout, stderr) => {
    res.type('text/plain').send(stdout || stderr || err?.message || 'No output');
  });
});

// XXE endpoint (nuclei: generic-xxe)
app.post('/api/xml-parser', bodyParser.text({ type: ['text/xml', 'application/xml'] }), (req, res) => {
  const xml = req.body || '';
  res.type('text/xml').send(`<?xml version="1.0"?><response><parsed>${xml.replace(/</g, '&lt;').substring(0, 500)}</parsed></response>`);
});

// CSV injection endpoint (nuclei: csv-injection)
app.get('/api/export', (req, res) => {
  const name = req.query.name || 'test';
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=export.csv');
  res.send(`Name,Email,Role\n${name},admin@test.com,admin\ntony,tony@stark.com,user\n`);
});

// ============================================================
// ROUTES
// ============================================================

app.get('/', wrap(async (req, res) => {
  const d = db();
  const featured = await d.prepare('SELECT * FROM products WHERE featured = 1').all();
  const categories = await d.prepare('SELECT DISTINCT category FROM products').all();
  res.render('index', { featured, categories });
}));

app.get('/products', wrap(async (req, res) => {
  const d = db();
  const cat = req.query.category || '';
  let products;
  if (cat) {
    try {
      products = await d.prepare(`SELECT * FROM products WHERE category = '${cat}'`).all();
    } catch (e) {
      products = await d.prepare('SELECT * FROM products').all();
      return res.render('products', { products, category: 'all', error: `SQL Error: ${e.message}` });
    }
  } else {
    products = await d.prepare('SELECT * FROM products').all();
  }
  res.render('products', { products, category: cat || 'all', error: null });
}));

app.get('/products/:id', wrap(async (req, res) => {
  const d = db();
  try {
    const rows = await d.prepare(`SELECT * FROM products WHERE id = ${req.params.id}`).all();
    const product = rows[0];
    if (!product) return res.status(404).render('404', { message: 'Product not found!' });
    const reviews = await d.prepare('SELECT * FROM reviews WHERE product_id = $1').all(product.id);
    res.render('product', { product, reviews, error: null });
  } catch (e) {
    res.render('product', { product: null, reviews: [], error: `DB Error: ${e.message}` });
  }
}));

app.get('/search', wrap(async (req, res) => {
  const d = db();
  const q = req.query.q || '';
  let products = [], error = null;
  if (q) {
    try {
      products = await d.prepare(`SELECT * FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`).all();
    } catch (e) { error = `Search Error: ${e.message}`; }
  }
  res.render('search', { products, query: q, error });
}));

// ---- AUTH ----
app.get('/login', (req, res) => res.render('login', { error: null }));

app.post('/login', wrap(async (req, res) => {
  const d = db();
  const { username, password } = req.body;
  try {
    const users = await d.prepare(`SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`).all();
    const user = users[0];
    if (user) {
      req.session.userId = user.id; req.session.username = user.username;
      req.session.isAdmin = user.is_admin; req.session.user = user;
      res.cookie('user_password', user.password, { httpOnly: false });
      res.cookie('user_role', user.role, { httpOnly: false });
      res.cookie('user_email', user.email, { httpOnly: false });
      const r = await d.prepare('SELECT COUNT(*) as count FROM cart WHERE user_id = $1').get(user.id);
      req.session.cartCount = r ? r.count : 0;
      res.redirect('/products');
    } else {
      const exists = await d.prepare(`SELECT * FROM users WHERE username = '${username}'`).all();
      res.render('login', { error: exists.length > 0 ? 'Invalid password!' : 'User not found!' });
    }
  } catch (e) { res.render('login', { error: `Error: ${e.message}` }); }
}));

app.get('/register', (req, res) => res.render('register', { error: null, success: null }));

app.post('/register', wrap(async (req, res) => {
  const d = db();
  const { username, password, email, full_name } = req.body;
  try {
    await d.prepare(`INSERT INTO users (username, password, email, full_name, role, is_admin) VALUES ('${username}', '${password}', '${email}', '${full_name || ''}', 'user', 0)`).run();
    if (!config.usePostgres) saveDatabase();
    res.render('register', { error: null, success: 'Account created!' });
  } catch (e) { res.render('register', { error: `Failed: ${e.message}`, success: null }); }
}));

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.clearCookie('user_password'); res.clearCookie('user_role'); res.clearCookie('user_email');
  res.redirect('/');
});

// ---- PROFILE ----
app.get('/profile', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const user = await db().prepare('SELECT * FROM users WHERE id = $1').get(req.session.userId);
  res.render('profile', { profile: user, error: null, success: null });
}));

app.post('/profile/update', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const d = db();
  const { full_name, email, address, phone, is_admin, role, avatar_url } = req.body;
  const updates = []; const values = []; let idx = 1;

  if (full_name !== undefined) { updates.push(`full_name = $${idx++}`); values.push(full_name); }
  if (email !== undefined) { updates.push(`email = $${idx++}`); values.push(email); }
  if (address !== undefined) { updates.push(`address = $${idx++}`); values.push(address); }
  if (phone !== undefined) { updates.push(`phone = $${idx++}`); values.push(phone); }
  if (avatar_url !== undefined) { updates.push(`avatar_url = $${idx++}`); values.push(avatar_url); }
  if (is_admin !== undefined) { updates.push(`is_admin = $${idx++}`); values.push(is_admin); }
  if (role !== undefined) { updates.push(`role = $${idx++}`); values.push(role); }

  if (updates.length > 0) {
    values.push(req.session.userId);
    await d.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = $${idx}`).run(...values);
    if (!config.usePostgres) saveDatabase();
  }

  const u = await d.prepare('SELECT * FROM users WHERE id = $1').get(req.session.userId);
  req.session.user = u; req.session.isAdmin = u ? u.is_admin : 0;
  res.render('profile', { profile: u, error: null, success: 'Profile updated!' });
}));

app.get('/profile/change-password', (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  res.render('change-password', { error: null, success: null });
});

app.post('/profile/change-password', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const { new_password, confirm_password } = req.body;
  // A04: No current password check! Just sets new password directly.
  if (new_password !== confirm_password) {
    return res.render('change-password', { error: 'Passwords do not match', success: null });
  }
  await db().prepare(`UPDATE users SET password = '${new_password}' WHERE id = ${req.session.userId}`).run();
  if (!config.usePostgres) saveDatabase();
  res.render('change-password', { error: null, success: 'Password changed without verification! A04: Insecure Design!' });
}));

// ---- CART ----
app.get('/cart', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const uid = req.query.user || req.session.userId;
  const items = await db().prepare(
    `SELECT c.id, c.quantity, p.name, p.price, p.image_url, p.id as product_id
     FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = $1`
  ).all(uid);
  res.render('cart', { cartItems: items, total: items.reduce((s, i) => s + (i.price * i.quantity), 0), viewedUserId: uid, error: null });
}));

app.post('/cart/add', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const d = db(); const qty = parseInt(req.body.quantity) || 1;
  const ex = await d.prepare('SELECT * FROM cart WHERE user_id = $1 AND product_id = $2').get(req.session.userId, req.body.product_id);
  if (ex) await d.prepare('UPDATE cart SET quantity = quantity + $1 WHERE id = $2').run(qty, ex.id);
  else await d.prepare('INSERT INTO cart (user_id, product_id, quantity) VALUES ($1, $2, $3)').run(req.session.userId, req.body.product_id, qty);
  if (!config.usePostgres) saveDatabase();
  const r = await d.prepare('SELECT COUNT(*) as count FROM cart WHERE user_id = $1').get(req.session.userId);
  req.session.cartCount = r ? r.count : 0;
  res.redirect('/cart');
}));

app.post('/cart/remove/:id', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const d = db();
  await d.prepare('DELETE FROM cart WHERE id = $1 AND user_id = $2').run(req.params.id, req.session.userId);
  if (!config.usePostgres) saveDatabase();
  const r = await d.prepare('SELECT COUNT(*) as count FROM cart WHERE user_id = $1').get(req.session.userId);
  req.session.cartCount = r ? r.count : 0;
  res.redirect('/cart');
}));

// ---- CHECKOUT ----
app.post('/checkout', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const d = db();
  const items = await d.prepare(
    `SELECT c.*, p.name, p.price FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = $1`
  ).all(req.session.userId);
  if (!items.length) return res.redirect('/cart');

  const total = items.reduce((s, i) => s + (i.price * i.quantity), 0);
  await d.prepare('INSERT INTO orders (user_id, total, status, shipping_address) VALUES ($1, $2, $3, $4)').run(
    req.session.userId, total, 'confirmed', req.body.address || 'Avengers Tower, NYC');

  // Get order ID (SQLite: last_insert_rowid, Supabase: use MAX)
  let orderId;
  if (config.usePostgres) {
    const r = await d.prepare('SELECT MAX(id) as id FROM orders').get();
    orderId = r ? r.id : 1;
  } else {
    const r = await d.prepare('SELECT last_insert_rowid() as id').get();
    orderId = r ? r.id : 1;
  }

  for (const item of items) {
    await d.prepare('INSERT INTO order_items (order_id, product_id, product_name, price, quantity) VALUES ($1, $2, $3, $4, $5)').run(
      orderId, item.product_id, item.name, item.price, item.quantity);
  }

  await d.prepare('DELETE FROM cart WHERE user_id = $1').run(req.session.userId);
  if (!config.usePostgres) saveDatabase();
  req.session.cartCount = 0;
  res.redirect(`/orders?order=${orderId}`);
}));

// ---- ORDERS ----
app.get('/orders', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const uid = req.query.user || req.session.userId;
  const orders = await db().prepare('SELECT * FROM orders WHERE user_id = $1 ORDER BY created_at DESC').all(uid);
  for (const o of orders) o.items = await db().prepare('SELECT * FROM order_items WHERE order_id = $1').all(o.id);
  res.render('orders', { orders, viewedUserId: uid });
}));

// ---- ADMIN ----
app.get('/admin', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const isAdminCookie = req.cookies.user_role === 'admin';
  if (req.session.isAdmin || isAdminCookie) {
    const d = db();
    const [users, products, orders] = await Promise.all([
      d.prepare('SELECT id, username, email, full_name, role, is_admin FROM users').all(),
      d.prepare('SELECT * FROM products').all(),
      d.prepare('SELECT * FROM orders ORDER BY created_at DESC LIMIT 20').all()
    ]);
    res.render('admin', { users, products, orders, error: null });
  } else {
    res.status(403).render('admin', { users: [], products: [], orders: [], error: 'Access Denied!' });
  }
}));

app.post('/admin/products/add', wrap(async (req, res) => {
  if (!isAuth(req) || !req.session.isAdmin) return res.redirect('/login');
  const { name, description, price, category, stock } = req.body;
  await db().prepare('INSERT INTO products (name, description, price, category, stock) VALUES ($1, $2, $3, $4, $5)').run(
    name, description, parseFloat(price), category, parseInt(stock));
  if (!config.usePostgres) saveDatabase();
  res.redirect('/admin');
}));

app.post('/admin/users/delete/:id', wrap(async (req, res) => {
  if (!isAuth(req) || !req.session.isAdmin) return res.redirect('/login');
  await db().prepare('DELETE FROM users WHERE id = $1').run(req.params.id);
  if (!config.usePostgres) saveDatabase();
  res.redirect('/admin');
}));

// ---- DEBUG (A05) ----
app.get('/debug', wrap(async (req, res) => {
  const d = db();
  const [users, products] = await Promise.all([
    d.prepare('SELECT * FROM users').all(),
    d.prepare('SELECT * FROM products LIMIT 5').all()
  ]);
  res.json({
    app: config.store.name, version: '1.0.0',
    sessionSecret: config.sessionSecret, adminPassword: config.admin.password,
    database: config.usePostgres ? 'Supabase PostgreSQL (Mgmt API)' : 'SQLite',
    supabaseUrl: config.supabaseUrl, debugMode: config.debugMode,
    users: users.map(u => ({ id: u.id, username: u.username, password: u.password, email: u.email, is_admin: u.is_admin })),
    products, serverTime: new Date().toISOString(), headers: req.headers, cookies: req.cookies
  });
}));

// ---- AVATAR / SSRF (A10) ----
app.get('/avatar', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  res.render('avatar', { profile: await db().prepare('SELECT * FROM users WHERE id = $1').get(req.session.userId), error: null, imageData: null, fetchedUrl: null });
}));

app.post('/avatar/fetch', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const { url } = req.body;
  if (!url) { const u = await db().prepare('SELECT * FROM users WHERE id = $1').get(req.session.userId); return res.render('avatar', { profile: u, error: 'Provide URL!', imageData: null, fetchedUrl: null }); }
  try {
    // A10: SSRF - No URL validation, fetches anything
    // Also A04: No timeout on internal requests (default 5s per axios)
    const resp = await axios.get(url, { timeout: 5000, responseType: 'arraybuffer', validateStatus: () => true });
    const img = `data:${resp.headers['content-type'] || 'image/png'};base64,${Buffer.from(resp.data).toString('base64')}`;
    res.render('avatar', { profile: await db().prepare('SELECT * FROM users WHERE id = $1').get(req.session.userId), error: null, imageData: img, fetchedUrl: url });
  } catch (e) {
    res.render('avatar', { profile: await db().prepare('SELECT * FROM users WHERE id = $1').get(req.session.userId), error: `Failed: ${e.message}`, imageData: null, fetchedUrl: null });
  }
}));

// A10: Blind SSRF Detection - fetches URLs and returns response length only
app.post('/api/ssrf/probe', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { url } = req.body;
  if (!url) return res.json({ error: 'Provide URL' });
  try {
    const resp = await axios.get(url, { timeout: 3000, validateStatus: () => true });
    res.json({
      url, status: resp.status, length: resp.data ? resp.data.length : 0,
      headers: { 'content-type': resp.headers['content-type'], server: resp.headers['server'] || 'unknown' }
    });
  } catch (e) {
    res.json({ url, error: e.message });
  }
}));

// A10: Cloud metadata guide
app.get('/ssrf-guide', (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  res.render('ssrf-guide');
});

// ---- FEEDBACK (A03) ----
app.get('/feedback', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  res.render('feedback', { feedbacks: await db().prepare('SELECT * FROM feedback ORDER BY created_at DESC').all(), error: null, success: null });
}));

app.post('/feedback', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const d = db();
  await d.prepare('INSERT INTO feedback (user_id, username, message, rating) VALUES ($1, $2, $3, $4)').run(req.session.userId, req.session.username, req.body.message, parseInt(req.body.rating) || 5);
  if (!config.usePostgres) saveDatabase();
  res.render('feedback', { feedbacks: await d.prepare('SELECT * FROM feedback ORDER BY created_at DESC').all(), error: null, success: 'Feedback submitted!' });
}));

// ---- REVIEW (A03) ----
app.post('/products/:id/review', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  // A03: SQL Injection + Stored XSS
  await db().prepare(`INSERT INTO reviews (product_id, username, comment, rating) VALUES (${req.params.id}, '${req.session.username}', '${req.body.comment}', ${parseInt(req.body.rating) || 5})`).run();
  if (!config.usePostgres) saveDatabase();
  res.redirect(`/products/${req.params.id}`);
}));

// ---- A08: Integrity ----
app.get('/integrity', (req, res) => { if (!isAuth(req)) return res.redirect('/login'); res.render('integrity', { result: null, error: null }); });
app.post('/integrity/install', (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const { package_url, package_name } = req.body;
  res.render('integrity', { result: `⚠️ Installed from ${package_name || package_url} without verification!`, error: null });
});

app.get('/deserialize', (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  res.render('deserialize', { result: null, error: null });
});

app.post('/api/deserialize', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  // Raw input via query param (avoids bodyParser pre-parsing)
  const raw = req.query.raw || '';
  if (!raw) return res.json({ error: 'No data to deserialize. Use ?raw={...}' });
  try {
    // A08: Insecure Deserialization via eval() - raw expression executes!
    let result;
    eval(`result = ${raw}`);
    res.json({ deserialized: result });
  } catch (e) {
    res.json({ error: `Deserialization failed: ${e.message}` });
  }
});

app.get('/api/check-update', (req, res) => {
  res.json({
    update_available: true, version: '2.0.0',
    download_url: 'http://malicious-update-server.com/payload.exe',
    signature: 'unsigned',
  });
});

// ---- A09: No Logging / Audit ----
app.post('/api/transfer', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  // A09: Zero logging on financial transactions - no timestamp, no user tracking, no IP
  res.json({ success: true, message: `Transferred $${req.body.amount} to ${req.body.to_username}` });
});

app.post('/admin/no-audit/action', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  res.json({
    message: `Admin action '${req.body.action}' performed on user ${req.body.target_user_id}`
  });
});

app.get('/api/audit-trail', (req, res) => {
  // A09 + A05: The audit trail SHOULD exist but doesn't
  res.json({ login_failures: 'NOT LOGGED', admin_actions: 'NOT LOGGED', transfers: 'NOT LOGGED' });
});

// ---- REFLECTED XSS ----
app.get('/xss/search', (req, res) => {
  const q = req.query.q || '';
  res.send(`<html><body style="background:#0a0a0f;color:#e8e8f0;font-family:sans-serif;padding:40px;text-align:center;"><h1>🔍 Results</h1><p>Search: ${q}</p><a href="/" style="color:#1e90ff;">← Back</a></body></html>`);
});

app.get('/api/tools/ping', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const host = req.query.host || 'localhost';
  // A03: Command Injection - user input passed directly to exec()
  exec(`ping -c 3 ${host} 2>&1`, { timeout: 5000 }, (err, stdout, stderr) => {
    if (err) return res.json({ error: err.message, output: stderr });
    res.type('text/plain').send(stdout);
  });
});

app.post('/api/tools/curl', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const target = req.body.target || 'localhost';
  // A03: Another command injection vector
  exec(`curl -s -m 5 ${target} 2>&1`, { timeout: 5000 }, (err, stdout, stderr) => {
    if (err) return res.json({ output: stderr || err.message });
    res.type('text/plain').send(stdout);
  });
});

// ---- A08: Eval Injection ----
app.get('/suit-config', (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  let pc; try { eval(`pc = ${req.query.config || '{}'}`); } catch(e) { pc = { error: e.message }; }
  res.render('suit-config', { config: pc, error: null });
});

// ---- A04: Rate Limit ----
app.get('/rate-limit-demo', (req, res) => res.render('rate-limit', { attempts: req.session.attempts || 0 }));
app.post('/rate-limit-demo/vote', (req, res) => { req.session.attempts = (req.session.attempts || 0) + 1; res.redirect('/rate-limit-demo'); });

app.post('/checkout/coupon', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { code } = req.body;
  // A04: Coupon codes are guessable and reusable! No limit on usage.
  const coupons = {
    'AVENGERS10': { discount: 10, desc: '10% off - unlimited uses!' },
    'THOR2024': { discount: 25, desc: '25% off - Asgardian special!' },
    'FREESHIP': { discount: 0, desc: 'Free shipping - but still vulnerable!' },
    'HACKME': { discount: 100, desc: '100% off - anyone can use this!' },
    'NEGATIVE': { discount: -50, desc: 'A04: Price manipulation - negative coupon!' }
  };
  if (coupons[code]) {
    res.json({ valid: true, code, discount: coupons[code].discount, description: coupons[code].desc });
  } else {
    res.json({ valid: false, message: 'Invalid code. Try: AVENGERS10, THOR2024, HACKME, NEGATIVE' });
  }
});

app.post('/api/price-override', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { product_id, price } = req.body;
  // A04: No validation - client sends the price, server trusts it
  res.json({ success: true, message: `Set product ${product_id} price to $${price}` });
});

// ---- A01: Path Traversal ----
app.get('/api/download', (req, res) => {
  const file = req.query.file || 'notes.txt';
  // A01: Path traversal - user controls file path directly
  try {
    const content = fs.readFileSync(file, 'utf8');
    res.type('text/plain').send(content);
  } catch (e) {
    res.status(404).send(`File not found: ${file}. Try: ../../config.js or ../../../../etc/passwd`);
  }
});

// .env handled earlier with full dotenv format

app.get('/api/cors-test', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.json({ secret: 'A01: CORS misconfig - any origin can read this!', data: 'sensitive_api_data' });
});

app.get('/static/', (req, res) => {
  const dirPath = path.join(__dirname, 'public');
  try {
    const files = fs.readdirSync(dirPath).filter(f => !f.startsWith('.'));
    let html = '<h1>📂 Directory Listing Enabled - A05</h1><ul>';
    for (const f of files) {
      const stats = fs.statSync(path.join(dirPath, f));
      html += `<li>📄 <a href="/${f}">${f}</a> (${stats.size} bytes)</li>`;
    }
    html += '</ul><p>Tip: Try accessing <code>/config.js</code> or <code>/package.json</code> directly!</p>';
    res.send(html);
  } catch(e) {
    res.status(500).send('Directory listing error: ' + e.message);
  }
});

app.get('/reset-password', (req, res) => {
  res.render('reset-password', { error: null, success: null });
});

app.post('/api/reset-password', (req, res) => {
  const { email } = req.body;
  // A07: Password reset token is predictable (MD5 of email)
  const token = crypto.createHash('md5').update(email || '').digest('hex');
  res.json({
    message: 'Password reset email sent!',
    email, reset_link: `http://localhost:3000/reset-password/confirm?token=${token}&email=${email}`,
  });
});

app.get('/reset-password/confirm', wrap(async (req, res) => {
  const { token, email, new_password } = req.query;
  const expectedToken = crypto.createHash('md5').update(email || '').digest('hex');
  if (token !== expectedToken) {
    return res.json({ error: 'Invalid token', expected: expectedToken });
  }
  if (new_password) {
    await db().prepare(`UPDATE users SET password = '${new_password}' WHERE email = '${email}'`).run();
    if (!config.usePostgres) saveDatabase();
    return res.json({ success: true, message: 'Password reset! (A04: No current password check + A07: Weak token)' });
  }
  res.json({ token_valid: true, email, expected_token: expectedToken });
}));

// (Already implemented - session is reused on login)

app.get('/config.js', (req, res) => {
  // A05: Source code / config exposed!
  res.send(`// WARNING: This should NOT be accessible!
// But the static file serve exposes it.
// Check /debug for the actual config.
`);
});


app.get('/api/sqli/union', wrap(async (req, res) => {
  const col = req.query.col || 'username';
  // A03: UNION-based SQL Injection - cast to text for PostgreSQL compat
  const result = await db().prepare(`SELECT ${col}::text FROM users UNION SELECT password::text FROM users`).all();
  res.json({ data: result });
}));

// ============================================================
// PCI-DSS & POS SCANNER VIOLATIONS
// These endpoints trigger findings in PCI ASV scans, POS
// security audits, and compliance scanners (Qualys, Nessus,
// Rapid7, Tenable PCI, etc.)
// ============================================================

app.get('/api/payment/cards', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const uid = req.query.user_id || req.session.userId;
  const cards = await db().prepare('SELECT * FROM payment_cards WHERE user_id = $1').all(uid);
  // PCI 3.4: PAN displayed in full, not masked/truncated
  // PCI 3.2: CVV stored and returned (NEVER store CVV post-authorization)
  res.json({
    cards,
  });
}));

app.post('/api/payment/cards/add', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { cardholder_name, card_number, expiry, cvv, card_type, billing_zip } = req.body;
  // PCI 3.2: Storing CVV/CVC is NEVER allowed after authorization
  // PCI 3.4: Storing PAN without encryption, hashing, or truncation
  await db().prepare(
    'INSERT INTO payment_cards (user_id, cardholder_name, card_number, expiry, cvv, card_type, billing_zip) VALUES ($1, $2, $3, $4, $5, $6, $7)'
  ).run(req.session.userId, cardholder_name, card_number, expiry, cvv, card_type || 'visa', billing_zip || '');
  res.json({
    success: true,
    message: `Card ${card_number} saved with CVV ${cvv}`,
  });
}));

app.get('/payment/checkout', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const cards = await db().prepare('SELECT * FROM payment_cards WHERE user_id = $1').all(req.session.userId);
  const items = await db().prepare(
    'SELECT c.*, p.name, p.price FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = $1'
  ).all(req.session.userId);
  const total = items.reduce((s, i) => s + (i.price * i.quantity), 0);
  res.render('payment-checkout', { cards, items, total, error: null, success: null });
}));

app.post('/payment/process', wrap(async (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  const d = db();
  const { card_number, cvv, expiry, cardholder_name, amount, address } = req.body;
  const items = await d.prepare(
    'SELECT c.*, p.name, p.price FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = $1'
  ).all(req.session.userId);
  if (!items.length) return res.redirect('/cart');

  const total = items.reduce((s, i) => s + (i.price * i.quantity), 0);

  // PCI 10.2: Log full PAN + CVV to console (violation!)
  console.log(`[PAYMENT] User ${req.session.userId} charged $${amount} on card ${card_number} CVV ${cvv} Exp ${expiry}`);

  // PCI 3.2: Store CVV post-auth (violation!)
  await d.prepare(
    'INSERT INTO transactions (user_id, card_number, amount, status, ip_address) VALUES ($1, $2, $3, $4, $5)'
  ).run(req.session.userId, card_number, parseFloat(amount) || total, 'completed', req.ip);

  // Create order (same logic as /checkout)
  await d.prepare('INSERT INTO orders (user_id, total, status, shipping_address) VALUES ($1, $2, $3, $4)').run(
    req.session.userId, total, 'confirmed', address || 'Avengers Tower, NYC');

  let orderId;
  if (config.usePostgres) {
    const r = await d.prepare('SELECT MAX(id) as id FROM orders').get();
    orderId = r ? r.id : 1;
  } else {
    const r = await d.prepare('SELECT last_insert_rowid() as id').get();
    orderId = r ? r.id : 1;
  }

  for (const item of items) {
    await d.prepare('INSERT INTO order_items (order_id, product_id, product_name, price, quantity) VALUES ($1, $2, $3, $4, $5)').run(
      orderId, item.product_id, item.name, item.price, item.quantity);
  }

  await d.prepare('DELETE FROM cart WHERE user_id = $1').run(req.session.userId);
  if (!config.usePostgres) saveDatabase();
  req.session.cartCount = 0;
  res.redirect(`/orders?order=${orderId}`);
}));

app.post('/api/payment/process', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { card_number, cvv, expiry, amount } = req.body;
  // PCI 4.1: Cardholder data transmitted without encryption
  // PCI 3.2: CVV sent in API request
  // PCI 10.2: Transaction logged with full PAN (should be masked)
  console.log(`[PAYMENT] User ${req.session.userId} charged $${amount} on card ${card_number} CVV ${cvv}`);
  await db().prepare(
    'INSERT INTO transactions (user_id, card_number, amount, status, ip_address) VALUES ($1, $2, $3, $4, $5)'
  ).run(req.session.userId, card_number, parseFloat(amount) || 0, 'completed', req.ip);
  res.json({
    success: true,
    transaction_id: Date.now(),
    card_charged: card_number,
    amount,
  });
}));

app.get('/api/payment/transactions', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const uid = req.query.user_id || req.session.userId;
  const txns = await db().prepare('SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC').all(uid);
  // PCI 3.3: PAN displayed in full (should show only last 4)
  // Also IDOR: user_id parameter not validated
  res.json({
    transactions: txns,
  });
}));

app.get('/api/payment/verify', (req, res) => {
  const card = req.query.card_number || '';
  const cvv = req.query.cvv || '';
  // PCI 4.2: Card data in URL = stored in browser history, server logs, referer headers
  if (card.length >= 13 && card.length <= 19) {
    const type = card.startsWith('4') ? 'Visa' : card.startsWith('5') ? 'Mastercard' : card.startsWith('3') ? 'Amex' : 'Unknown';
    res.json({
      valid: true, card_type: type, card_number: card, cvv_provided: cvv,
    });
  } else {
    res.json({ valid: false, message: 'Invalid card number length' });
  }
});

app.get('/api/security-headers-check', (req, res) => {
  // Deliberately NOT setting any security headers
  res.json({
    missing_headers: {
      'Strict-Transport-Security': 'MISSING - No HSTS, allows SSL stripping',
      'Content-Security-Policy': 'MISSING - No CSP, allows XSS',
      'X-Frame-Options': 'MISSING - Clickjacking possible',
      'X-Content-Type-Options': 'MISSING - MIME sniffing attacks',
      'X-XSS-Protection': 'MISSING - Browser XSS filter disabled',
      'Referrer-Policy': 'MISSING - Leaks URLs in referer header',
      'Permissions-Policy': 'MISSING - No feature restrictions',
      'Cache-Control': 'MISSING - Sensitive data may be cached'
    },
  });
});

app.get('/api/payment/test-credentials', (req, res) => {
  // PCI 2.1: Default and test credentials left in production
  res.json({
    payment_gateway: {
      api_key: 'sk_test_FAKE_DEFAULT_KEY_NOT_REAL_12345',
      api_secret: 'whsec_test_secret_key_12345',
      merchant_id: 'test_merchant_001',
      environment: 'sandbox_but_live_data',
      gateway_url: 'https://api.stripe.com/v1/charges'
    },
    pos_terminal: {
      terminal_id: 'POS-001-AVENGERS',
      auth_code: '0000',
      encryption_key: 'AAAABBBBCCCCDDDD',
      default_pin: '1234'
    },
  });
});

app.get('/api/payment/system-info', (req, res) => {
  // PCI 11.2: System information that scanners detect
  res.json({
    database: {
      type: 'PostgreSQL 17.6',
      host: 'db.chsmudfembonqsyxhmuh.supabase.co',
      port: 5432,
      ssl: false,
      public_access: true
    },
    server: {
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      env: {
        NODE_ENV: process.env.NODE_ENV || 'NOT SET (defaults to development)',
        DEBUG: process.env.DEBUG || 'not set'
      }
    },
    network: {
      listening_port: config.port,
      tls_enabled: false,
      firewall: 'none',
      dmz: false
    },
  });
});

app.post('/api/payment/set-pin', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { pin } = req.body;
  // PCI 8.2.3: No complexity requirements, allows 4-digit PINs
  // POS: Terminal PIN with no lockout
  res.json({
    success: true,
    pin_set: pin,
  });
});

app.get('/api/payment/logs', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const txns = await db().prepare('SELECT t.*, pc.cvv, pc.cardholder_name FROM transactions t LEFT JOIN payment_cards pc ON t.card_number = pc.card_number ORDER BY t.created_at DESC LIMIT 20').all();
  // PCI 10.5: Logs accessible without authorization check on role
  // PCI 3.4: Full PAN and CVV in log entries
  res.json({
    payment_logs: txns.map(t => ({
      timestamp: t.created_at,
      action: 'CHARGE',
      card_number: t.card_number,
      cvv: t.cvv,
      cardholder: t.cardholder_name,
      amount: t.amount,
      ip: t.ip_address,
      status: t.status
    })),
  });
}));

app.get('/api/payment/search', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const q = req.query.q || '';
  // PCI 6.5.1: SQL injection in payment context = critical PCI violation
  const results = await db().prepare(`SELECT * FROM payment_cards WHERE cardholder_name LIKE '%${q}%' OR card_number LIKE '%${q}%'`).all();
  res.json({
    results,
  });
}));

app.get('/payment/external', (req, res) => {
  if (!isAuth(req)) return res.redirect('/login');
  res.render('payment-external', { error: null });
});

// POS: Receipt with full PAN
app.get('/api/payment/receipt/:txn_id', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const txn = await db().prepare('SELECT t.*, pc.cvv, pc.cardholder_name, pc.expiry FROM transactions t LEFT JOIN payment_cards pc ON t.card_number = pc.card_number WHERE t.id = $1').get(req.params.txn_id);
  if (!txn) return res.status(404).json({ error: 'Transaction not found' });
  // POS: Receipt shows full PAN (should show last 4 only)
  // PCI 3.3: PAN must not be displayed in full on receipts
  res.json({
    receipt: {
      merchant: 'Avengers Armory',
      terminal_id: 'POS-001',
      transaction_id: txn.id,
      date: txn.created_at,
      card_number: txn.card_number,
      cardholder: txn.cardholder_name,
      expiry: txn.expiry,
      cvv: txn.cvv,
      amount: `$${txn.amount}`,
      status: txn.status,
      auth_code: '000000'
    },
  });
}));

app.get('/api/payment/remember-card', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const card = await db().prepare('SELECT * FROM payment_cards WHERE user_id = $1 LIMIT 1').get(req.session.userId);
  if (card) {
    // PCI 1.3.7/3.2: Cardholder data in cookies = PCI fail
    res.cookie('saved_card', card.card_number, { httpOnly: false, secure: false });
    res.cookie('saved_cvv', card.cvv, { httpOnly: false, secure: false });
    res.cookie('saved_expiry', card.expiry, { httpOnly: false, secure: false });
    res.json({
      message: 'Card saved to cookies for quick checkout!',
      cookies_set: { saved_card: card.card_number, saved_cvv: card.cvv, saved_expiry: card.expiry },
    });
  } else {
    res.json({ message: 'No saved cards' });
  }
}));

// POS: Magnetic stripe / track data storage (absolute PCI fail)
app.post('/api/pos/swipe', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { track1, track2, track3 } = req.body;
  // PCI 3.2: NEVER store track data post-authorization - instant SAQ D failure
  console.log(`[POS SWIPE] Track1: ${track1} Track2: ${track2}`);
  res.json({
    swipe_data: {
      track1: track1 || '%B4532015112830366^FURY/NICK^2712101000000000000000000000000?',
      track2: track2 || ';4532015112830366=27121010000000000000?',
      track3: track3 || null,
      parsed: {
        pan: '4532015112830366',
        name: 'FURY/NICK',
        expiry: '2712',
        service_code: '101'
      }
    },
  });
});

// POS: Terminal management without auth
app.get('/api/pos/terminal-config', (req, res) => {
  res.json({
    terminals: [
      { id: 'POS-001', location: 'Avengers Tower Lobby', status: 'active', ip: '192.168.1.100', firmware: '2.1.0', encryption: 'none', last_key_rotation: 'never' },
      { id: 'POS-002', location: 'Wakanda Branch', status: 'active', ip: '192.168.1.101', firmware: '1.8.3', encryption: 'DES', last_key_rotation: '2024-01-15' },
      { id: 'POS-003', location: 'Asgard Gift Shop', status: 'maintenance', ip: '192.168.1.102', firmware: '1.5.0', encryption: 'none', last_key_rotation: 'never' }
    ],
    master_key: 'DEADBEEF01234567DEADBEEF01234567',
  });
});

app.get('/api/payment/export', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const cards = await db().prepare('SELECT * FROM payment_cards').all();
  // PCI 9.5: Bulk cardholder data export without access controls
  let csv = 'id,user_id,cardholder_name,card_number,expiry,cvv,card_type,billing_zip\n';
  for (const c of cards) {
    csv += `${c.id},${c.user_id},${c.cardholder_name},${c.card_number},${c.expiry},${c.cvv},${c.card_type},${c.billing_zip}\n`;
  }
  res.header('Content-Type', 'text/csv');
  res.header('Content-Disposition', 'attachment; filename=cardholder_data_export.csv');
  res.send(csv);
}));

app.post('/api/payment/webhook', (req, res) => {
  // PCI 6.6: No WAF protecting payment endpoints
  // No signature verification on webhook
  const payload = req.body;
  res.json({
    received: payload,
    signature_verified: false,
    waf_active: false,
  });
});

// Clickjacking: payment page frameable (no X-Frame-Options)
app.get('/payment/frame-test', (req, res) => {
  // PCI 6.5.9: No clickjacking protection on payment pages
  res.send(`<html><body style="background:#0a0a0f;color:#e8e8f0;font-family:sans-serif;padding:40px;">
    <h1>Payment Page (Frameable!)</h1>
    <p>This page has NO X-Frame-Options or frame-ancestors CSP.</p>
    <p>An attacker can iframe this page and overlay transparent buttons.</p>
    <form action="/api/payment/process" method="POST">
      <input type="text" name="card_number" placeholder="Card Number" value="4532015112830366" style="padding:10px;margin:5px;background:#1a1d2e;color:#e8e8f0;border:1px solid #333;border-radius:4px;"><br>
      <input type="text" name="cvv" placeholder="CVV" value="123" style="padding:10px;margin:5px;background:#1a1d2e;color:#e8e8f0;border:1px solid #333;border-radius:4px;"><br>
      <input type="text" name="amount" placeholder="Amount" value="99.99" style="padding:10px;margin:5px;background:#1a1d2e;color:#e8e8f0;border:1px solid #333;border-radius:4px;"><br>
      <button type="submit" style="padding:10px 30px;background:#e23636;color:white;border:none;border-radius:4px;cursor:pointer;">Pay Now</button>
    </form>
    <p style="color:#666;margin-top:20px;">PCI 6.5.9: No clickjacking protection!</p>
  </body></html>`);
});

app.get('/api/payment/fim-status', (req, res) => {
  res.json({
    file_integrity_monitoring: 'DISABLED',
    last_scan: 'never',
    critical_files_monitored: [],
    changes_detected: 'unknown - no monitoring in place',
  });
});

app.get('/api/compliance/status', (req, res) => {
  res.json({
    pci_level: 'Level 4 Merchant (self-assessed)',
    last_scan: 'never',
    saq_type: 'SAQ D (worst case)',
    vulnerabilities: {
      critical: 14,
      high: 8,
      medium: 5,
      low: 3,
      total: 30
    },
    failing_requirements: [
      'Req 1: No firewall',
      'Req 2: Default credentials in use',
      'Req 3: CHD stored unencrypted with CVV',
      'Req 4: No TLS on payment transmissions',
      'Req 6: Missing security headers, SQLi, XSS',
      'Req 7: No access control on CHD',
      'Req 8: Weak authentication, no MFA',
      'Req 9: No physical access controls',
      'Req 10: No logging or monitoring',
      'Req 11: No vulnerability scanning or pen testing',
      'Req 12: No security policy'
    ],
  });
});

// ============================================================
// POS / POI (Point of Interaction) DEEP VULNERABILITIES
// Flags from: PA-DSS, PCI PTS POI, SecurityMetrics, Trustwave,
// Coalfire POS assessments, PCI P2PE validation
// ============================================================

// POI-1: Memory scraping - PAN in process memory (RAM scraping malware vector)
app.get('/api/poi/memory-dump', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const memorySnapshot = {
    process_name: 'pos-terminal.exe',
    pid: 4821,
    heap_objects: [
      { type: 'String', offset: '0x7FFE0012A400', value: '4532015112830366', tag: 'TRACK2_PAN' },
      { type: 'String', offset: '0x7FFE0012A480', value: '123', tag: 'CVV2' },
      { type: 'String', offset: '0x7FFE0012A4C0', value: '%B4532015112830366^FURY/NICK^2712101', tag: 'TRACK1_DATA' },
      { type: 'Buffer', offset: '0x7FFE0012A600', value: '3B34353332303135313132383330333636', tag: 'RAW_MAGSTRIPE_HEX' },
      { type: 'String', offset: '0x7FFE0012A700', value: '1234', tag: 'PIN_CLEARTEXT' }
    ],
  };
  res.json(memorySnapshot);
});

// POI-2: No P2PE (Point-to-Point Encryption) - data unencrypted from swipe to server
app.get('/api/poi/encryption-status', (req, res) => {
  res.json({
    p2pe_status: 'NOT IMPLEMENTED',
    encryption_at_rest: false,
    encryption_in_transit: false,
    encryption_at_poi: false,
    key_management: {
      dukpt_enabled: false,
      tdes_enabled: false,
      aes_enabled: false,
      current_method: 'NONE - cleartext transmission',
      bdk: null,
      ksn: null,
      ipek: null,
      key_injection: 'not configured'
    },
    emv_configuration: {
      chip_reader: 'disabled',
      contactless_nfc: 'disabled',
      magstripe_fallback: 'ENABLED - always accepts magstripe',
      pin_entry: 'software_based',
      pin_encryption: 'none'
    },
  });
});

// POI-3: EMV chip bypass via magstripe fallback
app.post('/api/poi/emv-fallback', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { card_number, fallback_reason } = req.body;
  const reasons = ['chip_malfunction', 'chip_reader_error', 'timeout', 'technical_fallback', 'forced_by_merchant'];
  const reason = fallback_reason || 'technical_fallback';
  res.json({
    transaction_type: 'MAGSTRIPE_FALLBACK',
    original_method: 'EMV_CHIP',
    fallback_reason: reason,
    card_number: card_number || '4532015112830366',
    chip_data: null,
    magstripe_used: true,
    counterfeit_risk: 'HIGH',
    liability_shift: 'MERCHANT (you lose chargeback protection)',
    available_reasons: reasons,
  });
});

// POI-4: Unencrypted PIN block
app.post('/api/poi/pin-entry', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { pin, card_number } = req.body;
  const pinBlock = Buffer.from(`0${pin.length}${pin}${'F'.repeat(14 - pin.length)}`, 'hex').toString('hex').toUpperCase();
  res.json({
    pin_entered: pin || '1234',
    pin_block_format: 'ISO 9564 Format 0',
    pin_block_cleartext: pinBlock || '041234FFFFFFFFFF',
    pin_block_encrypted: 'NOT ENCRYPTED',
    pin_entry_device: 'SOFTWARE_KEYBOARD',
    hardware_ped: false,
    pci_pts_certified: false,
    tamper_detection: false,
  });
});

// POI-5: Batch settlement data with full PAN
app.get('/api/poi/batch-settlement', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const txns = await db().prepare('SELECT * FROM transactions ORDER BY created_at DESC LIMIT 20').all();
  const cards = await db().prepare('SELECT * FROM payment_cards').all();
  const batch = {
    batch_id: 'BATCH-' + Date.now(),
    terminal_id: 'POS-001',
    merchant_id: 'AVENGERS-001',
    settlement_date: new Date().toISOString(),
    total_transactions: txns.length,
    total_amount: txns.reduce((s, t) => s + (t.amount || 0), 0),
    transactions: txns.map(t => {
      const card = cards.find(c => c.card_number === t.card_number);
      return {
        txn_id: t.id,
        card_number: t.card_number,
        cardholder: card ? card.cardholder_name : 'Unknown',
        expiry: card ? card.expiry : '',
        auth_code: '000000',
        amount: t.amount,
        type: 'SALE',
        status: t.status
      };
    }),
    settlement_file_format: 'ISO 8583',
    encryption: 'NONE',
    transmitted_via: 'HTTP (unencrypted)',
  };
  res.json(batch);
}));

// POI-6: Refund/void abuse - no manager override, no limits
app.post('/api/poi/refund', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { transaction_id, amount, reason } = req.body;
  const refundAmount = parseFloat(amount) || 9999.99;
  res.json({
    refund_processed: true,
    original_transaction: transaction_id || 1,
    refund_amount: refundAmount,
    reason: reason || 'customer_request',
    manager_approval: 'NOT REQUIRED',
    refund_limit: 'NONE',
    refund_to_different_card: true,
    void_after_settlement: true,
    daily_refund_count: 'UNLIMITED',
    controls: {
      manager_override: false,
      daily_limit: null,
      velocity_check: false,
      original_card_required: false,
      receipt_required: false
    },
  });
}));

// POI-7: Cashback manipulation
app.post('/api/poi/cashback', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { purchase_amount, cashback_amount } = req.body;
  const purchase = parseFloat(purchase_amount) || 1.00;
  const cashback = parseFloat(cashback_amount) || 500.00;
  res.json({
    transaction_type: 'SALE_WITH_CASHBACK',
    purchase_amount: purchase,
    cashback_amount: cashback,
    total_charged: purchase + cashback,
    cashback_limit: 'NONE - no maximum enforced',
    cashback_without_purchase: true,
    validation: {
      max_cashback_check: false,
      purchase_minimum_check: false,
      daily_cashback_limit: null,
      cashback_only_allowed: true
    },
  });
});

// POI-8: Split transaction to evade reporting thresholds
app.post('/api/poi/split-transaction', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { total_amount, split_count } = req.body;
  const total = parseFloat(total_amount) || 15000;
  const splits = parseInt(split_count) || 3;
  const perSplit = (total / splits).toFixed(2);
  const transactions = Array.from({ length: splits }, (_, i) => ({
    split_num: i + 1,
    amount: parseFloat(perSplit),
    card: '4532015112830366',
    status: 'approved',
    reporting_threshold_avoided: parseFloat(perSplit) < 10000
  }));
  res.json({
    original_amount: total,
    split_into: splits,
    per_transaction: parseFloat(perSplit),
    transactions,
    ctr_threshold: 10000,
    ctr_filing_triggered: false,
    structuring_detected: false,
  });
});

// POI-9: Offline transaction replay
app.post('/api/poi/offline-transaction', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { card_number, amount, offline_auth_code } = req.body;
  res.json({
    mode: 'OFFLINE_APPROVED',
    card_number: card_number || '4532015112830366',
    amount: parseFloat(amount) || 999.99,
    offline_auth_code: offline_auth_code || 'Y1Z2X3',
    host_authorization: 'SKIPPED',
    floor_limit: 999999.99,
    offline_ceiling: 'NONE',
    replay_protection: false,
    sequence_number_check: false,
    stored_offline_txns: [
      { id: 1, amount: 999.99, card: '4532015112830366', auth: 'Y1Z2X3', replayed: false },
      { id: 2, amount: 4999.99, card: '5425233430109903', auth: 'A1B2C3', replayed: false }
    ],
  });
});

// POI-10: Keylogger / screen capture vulnerability
app.get('/api/poi/input-security', (req, res) => {
  res.json({
    pin_entry_method: 'SOFTWARE_KEYBOARD',
    hardware_pin_pad: false,
    screen_capture_protection: false,
    keylogger_protection: false,
    clipboard_access: 'UNRESTRICTED',
    accessibility_service_access: 'ALLOWED',
    overlay_detection: false,
    input_fields: {
      card_number: { masked: false, autocomplete: 'on', in_dom: true },
      cvv: { masked: false, autocomplete: 'on', in_dom: true },
      pin: { masked: false, type: 'text', software_keyboard: true },
      expiry: { masked: false, autocomplete: 'on', in_dom: true }
    },
  });
});

// POI-11: Card skimmer detection absent
app.get('/api/poi/tamper-status', (req, res) => {
  res.json({
    terminals: [
      {
        id: 'POS-001',
        tamper_detection: 'DISABLED',
        last_physical_inspection: 'never',
        anti_skimmer: false,
        jitter_detection: false,
        case_intrusion_sensor: false,
        firmware_integrity: 'NOT VERIFIED',
        secure_boot: false,
        pci_pts_certified: false,
        sred_capable: false,
        last_firmware_update: '2024-01-15',
        firmware_signature: 'NOT SIGNED',
        usb_ports: 'ENABLED - unmonitored',
        serial_ports: 'ENABLED - unmonitored',
        wifi: { enabled: true, encryption: 'WEP', ssid: 'POS-NETWORK', password: 'avengers123' },
        bluetooth: { enabled: true, pairing_mode: 'open', pin: '0000' }
      }
    ],
    physical_security: {
      terminal_cable_lock: false,
      camera_coverage: false,
      employee_background_check: false,
      daily_terminal_inspection: false
    },
  });
});

// POI-12: Remote management without encryption or auth
app.post('/api/poi/remote-update', (req, res) => {
  const { terminal_id, firmware_url, command } = req.body;
  res.json({
    terminal_id: terminal_id || 'POS-001',
    action: command || 'firmware_update',
    firmware_source: firmware_url || 'http://updates.avengers-pos.com/firmware.bin',
    firmware_signature_verified: false,
    connection_encrypted: false,
    authentication: 'NONE',
    remote_commands_available: [
      'firmware_update', 'config_change', 'reboot',
      'enable_debug', 'dump_memory', 'disable_encryption',
      'change_merchant_id', 'modify_settlement', 'extract_keys'
    ],
  });
});

// POI-13: Network segmentation failure - POS on flat network
app.get('/api/poi/network-topology', (req, res) => {
  res.json({
    pos_network: {
      segmentation: 'NONE - flat network',
      vlan: null,
      firewall_between_pos_and_corporate: false,
      firewall_between_pos_and_internet: false,
      pos_subnet: '192.168.1.0/24',
      corporate_subnet: '192.168.1.0/24',
      guest_wifi_subnet: '192.168.1.0/24',
      shared_network: true
    },
    connected_devices_on_same_network: [
      { ip: '192.168.1.10', hostname: 'reception-pc', type: 'workstation', internet_access: true },
      { ip: '192.168.1.50', hostname: 'employee-phone', type: 'byod', internet_access: true },
      { ip: '192.168.1.100', hostname: 'POS-001', type: 'pos_terminal', internet_access: true },
      { ip: '192.168.1.101', hostname: 'POS-002', type: 'pos_terminal', internet_access: true },
      { ip: '192.168.1.200', hostname: 'guest-laptop', type: 'guest_wifi', internet_access: true },
      { ip: '192.168.1.1', hostname: 'router', type: 'gateway', admin_panel: 'http://192.168.1.1 (admin/admin)' }
    ],
  });
});

// POI-14: Merchant receipt vs cardholder receipt mismatch
app.get('/api/poi/receipt-compare', wrap(async (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const txn = await db().prepare('SELECT t.*, pc.cardholder_name, pc.expiry, pc.cvv FROM transactions t LEFT JOIN payment_cards pc ON t.card_number = pc.card_number ORDER BY t.created_at DESC LIMIT 1').get();
  if (!txn) return res.json({ error: 'No transactions found' });
  res.json({
    merchant_copy: {
      card_number: txn.card_number,
      cardholder: txn.cardholder_name,
      expiry: txn.expiry,
      cvv: txn.cvv,
      amount: txn.amount,
      tip_line: 'BLANK (modifiable after signing)',
      total_line: 'BLANK (modifiable after signing)',
    },
    cardholder_copy: {
      card_number: txn.card_number,
      cardholder: txn.cardholder_name,
      expiry: txn.expiry,
      amount: txn.amount,
    },
    violations: [
      'PCI 3.3: Full PAN on both receipts (must show last 4 only)',
      'PCI 3.2: CVV on merchant receipt (never allowed on any receipt)',
      'PA-DSS 11: Blank tip/total lines enable post-transaction modification',
      'Card brand rules: Expiry date should not appear on receipt'
    ],
  });
}));

// POI-15: Application whitelisting bypass
app.get('/api/poi/installed-apps', (req, res) => {
  res.json({
    application_whitelisting: 'DISABLED',
    installed_applications: [
      { name: 'pos-terminal.exe', version: '2.1.0', signed: false, hash: 'a1b2c3d4...', whitelisted: false },
      { name: 'chrome.exe', version: '120.0', signed: true, hash: 'e5f6g7h8...', whitelisted: false },
      { name: 'teamviewer.exe', version: '15.0', signed: true, hash: 'i9j0k1l2...', whitelisted: false },
      { name: 'cmd.exe', version: 'system', signed: true, hash: 'm3n4o5p6...', whitelisted: false },
      { name: 'powershell.exe', version: '7.4', signed: true, hash: 'q7r8s9t0...', whitelisted: false },
      { name: 'unknown_service.exe', version: '1.0', signed: false, hash: 'u1v2w3x4...', whitelisted: false }
    ],
    running_services: [
      { name: 'pos-terminal', pid: 4821, user: 'SYSTEM', ports: [8080, 8443] },
      { name: 'remote-desktop', pid: 2100, user: 'SYSTEM', ports: [3389] },
      { name: 'unknown_service', pid: 6666, user: 'SYSTEM', ports: [4444] }
    ],
  });
});

// POI-16: Debug/service mode accessible
app.get('/api/poi/service-mode', (req, res) => {
  const serviceCode = req.query.code || '';
  const validCodes = { '0000': 'basic', '1234': 'admin', '9999': 'factory_reset', '5678': 'debug' };
  if (validCodes[serviceCode]) {
    res.json({
      service_mode: 'ACTIVATED',
      access_level: validCodes[serviceCode],
      code_used: serviceCode,
      available_functions: {
        basic: ['view_config', 'test_printer', 'network_status'],
        admin: ['change_merchant_id', 'modify_tip_settings', 'clear_batch', 'view_card_data', 'export_keys'],
        debug: ['memory_dump', 'packet_capture', 'disable_encryption', 'enable_trace_logging', 'raw_magstripe_output'],
        factory_reset: ['wipe_all_keys', 'reset_merchant_config', 'clear_transaction_log', 'remove_tamper_flags']
      },
    });
  } else {
    res.json({
      service_mode: 'LOCKED',
      brute_force_protection: false,
      lockout_after_failures: false,
    });
  }
});

// ---- LAB GUIDE (updated with all 10 vulns) ----
app.get('/lab', (req, res) => {
  res.render('lab', { vulns: [
    { id: 'A01', name: 'Broken Access Control', endpoints: ['/admin (cookie bypass)', '/cart?user=X (IDOR)', '/orders?user=X (IDOR)', '/api/download?file= (Path Traversal)', '/.env (Forced Browsing)', '/api/cors-test (CORS misconfig)'] },
    { id: 'A02', name: 'Cryptographic Failures', endpoints: ['Plaintext passwords in DB', 'Passwords in cookies', 'Weak session secret: avengers123', 'No HTTPS', 'MD5 for password reset tokens'] },
    { id: 'A03', name: 'Injection', endpoints: ['/search?q= (SQLi)', '/products?category= (SQLi)', '/login (SQLi)', '/products/:id (SQLi)', '/feedback (Stored XSS)', '/xss/search (Reflected XSS)', '/api/tools/ping?host= (Command Injection)', '/api/tools/curl (Command Injection)', '/api/sqli/union (UNION SQLi)'] },
    { id: 'A04', name: 'Insecure Design', endpoints: ['/profile/update (Mass Assignment)', '/rate-limit-demo (No Rate Limiting)', '/profile/change-password (No current password)', '/checkout/coupon (Coupon abuse)', '/api/price-override (Price manipulation)'] },
    { id: 'A05', name: 'Security Misconfiguration', endpoints: ['/debug (Sensitive data)', 'Default creds: admin/admin123', 'Stack traces on errors', '/static/ (Directory Listing)', '/config.js exposed', 'X-Powered-By: versions leaked', 'Error pages leak paths'] },
    { id: 'A06', name: 'Vulnerable Components', endpoints: ['/api/legacy/parse-xml (XXE)', '/api/check-versions (Known CVEs)', '/api/legacy/products (Legacy endpoint)', 'Outdated Express/sql.js'] },
    { id: 'A07', name: 'Auth Failures', endpoints: ['User enumeration in login', 'Weak passwords: ironman, spider', 'No MFA, no account lockout', '/reset-password (Predictable tokens)', 'Session fixation (no session refresh)'] },
    { id: 'A08', name: 'Integrity Failures', endpoints: ['/suit-config?config= (eval RCE)', '/integrity (Unsigned packages)', '/api/deserialize (Insecure deserialization)', '/api/check-update (Auto-update no verify)'] },
    { id: 'A09', name: 'Logging Failures', endpoints: ['/api/transfer (no audit)', '/admin/no-audit/action (No admin log)', '/api/audit-trail (Empty logs)', 'Login failures NOT logged'] },
    { id: 'A10', name: 'SSRF', endpoints: ['/avatar/fetch (Server-side URL fetch)', '/api/ssrf/probe (Blind SSRF detection)', 'Cloud metadata: 169.254.169.254', '/ssrf-guide (Exploitation guide)'] },
    { id: 'PCI', name: 'PCI-DSS Violations', endpoints: ['/api/payment/cards (Full PAN+CVV stored)', '/api/payment/process (CHD over HTTP)', '/api/payment/verify?card_number= (PAN in URL)', '/api/payment/logs (PAN+CVV in logs)', '/api/payment/export (CSV bulk export)', '/api/payment/search (SQLi on CHD)', '/api/payment/remember-card (CHD in cookies)', '/api/security-headers-check (Missing headers)', '/api/payment/test-credentials (Default keys)', '/api/payment/system-info (System info leak)', '/payment/frame-test (Clickjacking)', '/api/compliance/status (Full PCI report)'] },
    { id: 'POS', name: 'POS Terminal Violations', endpoints: ['/api/pos/swipe (Track data storage)', '/api/pos/terminal-config (Terminal config+master key)', '/api/payment/receipt/:id (Full PAN on receipt)', '/api/payment/set-pin (Weak PIN, no lockout)', '/api/payment/webhook (No WAF, no signature)', '/api/payment/fim-status (No file integrity monitoring)'] },
    { id: 'POI', name: 'POI Deep Vulnerabilities', endpoints: ['/api/poi/memory-dump (RAM scraping - PAN in memory)', '/api/poi/encryption-status (No P2PE, no DUKPT)', '/api/poi/emv-fallback (Chip bypass via magstripe)', '/api/poi/pin-entry (Cleartext PIN block)', '/api/poi/batch-settlement (Unencrypted settlement)', '/api/poi/refund (Refund abuse, no limits)', '/api/poi/cashback (Cashback manipulation)', '/api/poi/split-transaction (Structuring/BSA)', '/api/poi/offline-transaction (Offline replay)', '/api/poi/input-security (Keylogger/screen capture)', '/api/poi/tamper-status (No skimmer detection)', '/api/poi/remote-update (Unauthenticated remote mgmt)', '/api/poi/network-topology (Flat network, no segmentation)', '/api/poi/receipt-compare (PAN on both receipts)', '/api/poi/installed-apps (No app whitelisting)', '/api/poi/service-mode?code= (Default service codes)'] }
  ]});
});

// ---- CVE & MISCONFIG ENDPOINTS FOR NUCLEI ----

// Grafana LFI handled by early middleware above

// Grafana panel (nuclei: grafana-panel, grafana-detect)
app.get(['/grafana/', '/grafana', '/grafana/login'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Grafana</title></head><body>
<grafana-app><div class="grafana-app">
<div class="login-page"><h1>Welcome to Grafana</h1>
<div class="login-content"><p>Grafana v8.2.0</p></div>
</div></div></grafana-app>
</body></html>`);
});

// Laravel debug mode (nuclei: laravel-debug-enabled, laravel-debug-error)
app.get('/_ignition/health-check', (req, res) => {
  res.json({ can_execute_commands: true });
});
app.get('/_ignition/execute-solution', (req, res) => {
  res.json({ result: "Solution executed" });
});
app.get(['/laravel-error', '/api/laravel-test'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Whoops! There was an error</title></head><body>
<div class="container"><h1>Whoops!</h1>
<p class="exception_title">Illuminate\\Database\\QueryException</p>
<p>SQLSTATE[HY000] [1045] Access denied for user 'root'@'localhost'</p>
<pre>APP_KEY=base64:dGhpc2lzYXZlcnlzZWNyZXRrZXkxMjM0NTY3ODk=
DB_PASSWORD=SuperSecretDbPass123!</pre>
</div></body></html>`);
});

// Spring Boot env with proper matchers (nuclei: springboot-env)
app.get('/actuator/env', (req, res) => {
  res.setHeader('Content-Type', 'application/vnd.spring-boot.actuator.v2+json');
  res.json({
    activeProfiles: ["production"],
    propertySources: [{
      name: "applicationConfig: [classpath:/application.yml]",
      properties: {
        "server.port": { value: "8080" },
        "local.server.port": { value: "8080" },
        "spring.datasource.url": { value: "jdbc:postgresql://db.internal:5432/armory" },
        "spring.datasource.username": { value: "admin" },
        "spring.datasource.password": { value: "******" }
      }
    }]
  });
});

// GitLab panel (nuclei: gitlab-detect)
app.get(['/users/sign_in', '/gitlab/', '/gitlab'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Sign in · GitLab</title>
<meta content="GitLab" property="og:site_name">
<meta name="description" content="GitLab Community Edition">
</head><body class="ui-indigo login-page">
<div class="container"><h1>GitLab</h1>
<div class="login-box"><h3>Sign in to GitLab</h3>
<form><input name="user[login]" placeholder="Username or email"><input name="user[password]" type="password" placeholder="Password">
<button type="submit">Sign in</button></form>
</div><p class="float-right">GitLab Community Edition 15.0.0</p>
</div></body></html>`);
});

// Airflow panel (nuclei: airflow-panel, airflow-detect)
app.get(['/airflow/', '/airflow/login/', '/airflow/home'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Airflow - Login</title></head><body>
<div class="container"><h2>Sign In - Airflow</h2>
<form><input name="username" placeholder="Username"><input name="password" type="password">
<button>Sign In</button></form>
<p>Airflow Version: v2.5.1</p></div></body></html>`);
});

// SonarQube (nuclei: sonarqube)
app.get(['/sonarqube/', '/sonar/', '/api/system/status'], (req, res) => {
  if (req.path.includes('api/system/status')) {
    return res.json({ id: "ABC123", version: "9.9.0", status: "UP" });
  }
  res.type('text/html').send(`<html><head><title>SonarQube</title></head><body>
<div id="content"><h1>SonarQube</h1></div></body></html>`);
});

// Confluence (nuclei: confluence detection)
app.get(['/confluence/', '/wiki/', '/wiki/login.action', '/confluence/login.action'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Log In - Confluence</title>
<meta name="application-name" content="Confluence">
</head><body class="login">
<div id="login-container"><h1>Log in to Confluence</h1>
<form action="/dologin.action" method="POST">
<input name="os_username" placeholder="Username"><input name="os_password" type="password">
<button>Log in</button></form>
<span id="footer-build-information">Confluence 7.19.0</span>
</div></body></html>`);
});

// Jira (nuclei: jira-detect)
app.get(['/jira/', '/jira/login.jsp', '/secure/Dashboard.jspa', '/login.jsp'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Log in - Jira</title>
<meta name="application-name" content="JIRA" data-name="jira" data-version="9.4.0">
</head><body class="jira">
<div class="form-body"><h1>Log in</h1>
<form action="/login.jsp" method="post">
<input name="os_username" placeholder="Username"><input name="os_password" type="password">
<button>Log In</button></form>
<span class="smalltext">Atlassian Jira Project Management Software v9.4.0</span>
</div></body></html>`);
});

// Nagios (nuclei: nagios-panel)
app.get(['/nagios/', '/nagios/main.php', '/nagiosxi/'], (req, res) => {
  res.status(401).setHeader('WWW-Authenticate', 'Basic realm="Nagios Access"');
  res.type('text/html').send(`<html><head><title>Nagios Core</title></head><body>
<h1>Nagios</h1><p>Nagios Core 4.4.9</p>
<p>You must authenticate to access this page.</p></body></html>`);
});

// Redis Commander (nuclei: redis-commander)
app.get(['/redis-commander/', '/redis/'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Redis Commander</title></head><body>
<div id="app"><h1>Redis Commander</h1>
<div class="sidebar"><h3>Connections</h3><ul><li>localhost:6379 (db0: 1500 keys)</li></ul></div>
</div></body></html>`);
});

// Consul (nuclei: consul-detect)
app.get(['/v1/agent/members', '/v1/catalog/nodes', '/ui/'], (req, res) => {
  if (req.path.includes('v1/')) {
    return res.json([{ Name: "web-server-01", Addr: "10.0.0.1", Port: 8301, Status: 1, Tags: { role: "consul" } }]);
  }
  res.type('text/html').send(`<html><head><title>Consul by HashiCorp</title></head><body>
<div id="app"><h1>Consul</h1></div></body></html>`);
});

// Vault (nuclei: vault-detect)
app.get(['/v1/sys/health', '/v1/sys/seal-status', '/ui/vault/'], (req, res) => {
  if (req.path.includes('health')) {
    return res.json({ initialized: true, sealed: false, standby: false, server_time_utc: 1700000000, version: "1.15.0", cluster_name: "vault-cluster-avengers" });
  }
  if (req.path.includes('seal-status')) {
    return res.json({ type: "shamir", initialized: true, sealed: false, t: 3, n: 5, progress: 0, version: "1.15.0" });
  }
  res.type('text/html').send(`<html><head><title>Vault</title></head><body><div id="ember-basic-dropdown-wormhole"></div></body></html>`);
});

// Minio (nuclei: minio-detect)
app.get(['/minio/health/live', '/minio/login'], (req, res) => {
  if (req.path.includes('health')) return res.sendStatus(200);
  res.type('text/html').send(`<html><head><title>MinIO Browser</title></head><body><div id="root"></div></body></html>`);
});

// RabbitMQ (nuclei: rabbitmq-panel)
app.get(['/rabbitmq/', '/api/overview', '/api/whoami'], (req, res) => {
  if (req.path.includes('api/overview')) {
    return res.json({ management_version: "3.12.0", rabbitmq_version: "3.12.0", erlang_version: "25.3.2", node: "rabbit@avengers-mq" });
  }
  if (req.path.includes('api/whoami')) {
    return res.json({ name: "guest", tags: ["administrator"] });
  }
  res.type('text/html').send(`<html><head><title>RabbitMQ Management</title></head><body><div id="login"><h1>RabbitMQ</h1></body></html>`);
});

// Portainer (nuclei: portainer-panel)
app.get(['/portainer/', '/api/status', '/#/auth'], (req, res) => {
  if (req.path.includes('api/status')) {
    return res.json({ Version: "2.19.0", InstanceID: "abc123" });
  }
  res.type('text/html').send(`<html><head><title>Portainer</title></head><body><div id="page-wrapper"><portainer-app></portainer-app></div></body></html>`);
});

// Traefik dashboard (nuclei: traefik-dashboard)
app.get(['/dashboard/', '/api/rawdata', '/api/version'], (req, res) => {
  if (req.path.includes('api/version')) {
    return res.json({ Version: "2.10.0", Codename: "fortified" });
  }
  if (req.path.includes('api/rawdata')) {
    return res.json({ routers: {}, services: {}, middlewares: {} });
  }
  res.type('text/html').send(`<html><head><title>Traefik</title></head><body><div id="app"><h1>Traefik Dashboard</h1></div></body></html>`);
});

// Exposed .git/HEAD and git refs
app.get(['/.git/refs/heads/main', '/.git/refs/heads/master', '/.git/logs/HEAD', '/.git/COMMIT_EDITMSG'], (req, res) => {
  if (req.path.includes('logs/HEAD')) {
    return res.type('text/plain').send('0000000 abc1234 Admin <admin@armory.local> 1700000000 +0000\tcommit (initial): Initial commit\n');
  }
  if (req.path.includes('COMMIT_EDITMSG')) {
    return res.type('text/plain').send('feat: add payment processing with hardcoded API keys\n');
  }
  res.type('text/plain').send('abc1234567890def1234567890abcdef12345678\n');
});

// Exposed .env.example with secrets
app.get(['/.env.example', '/.env.staging', '/.env.backup'], (req, res) => {
  res.type('text/plain').send(`APP_NAME=AvengersArmory
APP_KEY=base64:dGhpc2lzYXZlcnlzZWNyZXRrZXkxMjM0NTY3ODk=
DB_PASSWORD=SuperSecretDbPass123!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`);
});

// Exposed Swagger v3 / OpenAPI
app.get(['/openapi.json', '/v3/api-docs', '/api/openapi.json', '/api/v3/api-docs'], (req, res) => {
  res.json({
    openapi: "3.0.0",
    info: { title: "Avengers Armory API", version: "1.0.0" },
    paths: {
      "/api/login": { post: { summary: "Login" } },
      "/api/users": { get: { summary: "List users" } },
      "/api/admin": { get: { summary: "Admin panel" } },
      "/api/payment/process": { post: { summary: "Process payment" } }
    }
  });
});

// Exposed WP-cron, WP-JSON
app.get(['/wp-cron.php', '/wp-json/', '/wp-json/wp/v2/users'], (req, res) => {
  if (req.path.includes('wp-json/wp/v2/users')) {
    return res.json([
      { id: 1, name: "admin", slug: "admin", link: "https://avengers-armory.local/author/admin/" },
      { id: 2, name: "tony", slug: "tony", link: "https://avengers-armory.local/author/tony/" }
    ]);
  }
  if (req.path.includes('wp-json/')) {
    return res.json({ name: "Avengers Armory", description: "Security Lab", url: "https://avengers-armory.local", namespaces: ["wp/v2", "oembed/1.0"] });
  }
  res.send('');
});

// Spring Boot heapdump (nuclei: springboot-heapdump)
app.get('/actuator/heapdump', (req, res) => {
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', 'attachment; filename=heapdump');
  const javaHeap = Buffer.from('JAVA PROFILE 1.0.2\x00\x00\x00\x00\x00password=SuperSecretDbPass123!', 'utf8');
  res.send(javaHeap);
});

// Exposed supervisor (nuclei: supervisord-panel)
app.get(['/supervisor/', '/supervisor/tail.html'], (req, res) => {
  res.type('text/html').send(`<html><head><title>Supervisor Status</title></head><body>
<h1>supervisor</h1><table><tr><th>Name</th><th>State</th><th>PID</th></tr>
<tr><td>web</td><td>RUNNING</td><td>1234</td></tr>
<tr><td>worker</td><td>RUNNING</td><td>5678</td></tr>
</table></body></html>`);
});

// Exposed Solr (nuclei: solr-detect)
app.get(['/solr/', '/solr/admin/', '/solr/admin/info/system'], (req, res) => {
  if (req.path.includes('info/system')) {
    return res.json({ responseHeader: { status: 0 }, lucene: { "solr-spec-version": "9.0.0" }, jvm: { version: "17.0.1" } });
  }
  res.type('text/html').send(`<html><head><title>Solr Admin</title></head><body>
<div id="content"><h1>Solr Admin</h1><p>Apache Solr 9.0.0</p></div></body></html>`);
});

// Exposed Zabbix (nuclei: zabbix-panel)
app.get(['/zabbix/', '/zabbix/index.php'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Zabbix</title></head><body>
<form name="zbx_sessionid" action="index.php" method="post">
<div class="signin-logo"><span>zabbix</span></div>
<input type="text" name="name" placeholder="Username"><input type="password" name="password">
<button>Sign in</button></form>
<div class="signin-links">Zabbix 6.4.0</div></body></html>`);
});

// Exposed n8n (nuclei: n8n-panel)
app.get(['/n8n/', '/n8n/signin'], (req, res) => {
  res.type('text/html').send(`<html><head><title>n8n</title></head><body>
<div id="app"><h1>n8n.io - Workflow Automation</h1></div></body></html>`);
});

// Exposed Wekan / Kanboard
app.get(['/kanboard/', '/kanboard/login'], (req, res) => {
  res.type('text/html').send(`<html><head><title>Kanboard - Login</title></head><body>
<form method="post" action="/kanboard/?controller=AuthController&action=check">
<input name="username" placeholder="Username"><input name="password" type="password">
<button>Sign In</button></form></body></html>`);
});

// Exposed Superset
app.get(['/superset/', '/superset/welcome/', '/login/'], (req, res) => {
  if (req.path === '/login/') {
    return res.type('text/html').send(`<html><head><title>Superset - Login</title></head><body>
<div class="container"><h1>Apache Superset</h1>
<form method="POST"><input name="username"><input name="password" type="password"><button>Sign In</button></form></div></body></html>`);
  }
  res.type('text/html').send(`<html><head><title>Superset</title></head><body><div id="app"></div></body></html>`);
});

// Exposed ArgoCD
app.get(['/argocd/', '/api/v1/applications', '/argocd/login'], (req, res) => {
  if (req.path.includes('api/v1/applications')) {
    return res.json({ items: [{ metadata: { name: "avengers-app", namespace: "argocd" }, spec: { source: { repoURL: "https://github.com/avengers/armory.git" } } }] });
  }
  res.type('text/html').send(`<html><head><title>Argo CD</title></head><body><div id="app"></div></body></html>`);
});

// Exposed Harbor registry
app.get(['/harbor/', '/api/v2.0/systeminfo', '/c/login'], (req, res) => {
  if (req.path.includes('api/v2.0/systeminfo')) {
    return res.json({ harbor_version: "v2.8.0", auth_mode: "db_auth", self_registration: true });
  }
  res.type('text/html').send(`<html><head><title>Harbor</title></head><body><h1>Harbor</h1></body></html>`);
});

// Spring Boot mappings (nuclei: springboot-mappings)
app.get('/actuator/mappings', (req, res) => {
  res.json({ contexts: { application: { mappings: { dispatcherServlets: { dispatcherServlet: [
    { handler: "ResourceHttpRequestHandler", predicate: "/**" },
    { handler: "com.avengers.controller.UserController#getUsers()", predicate: "/api/users" },
    { handler: "com.avengers.controller.AdminController#adminPanel()", predicate: "/admin" }
  ]}}}}});
});

// WordPress user enumeration (nuclei: wp-user-enum)
app.get('/wp-json/wp/v2/users/', (req, res) => {
  res.json([
    { id: 1, name: "admin", slug: "admin", description: "Site Administrator", url: "", link: "https://avengers-armory.local/?author=1" },
    { id: 2, name: "editor", slug: "editor", description: "", link: "https://avengers-armory.local/?author=2" }
  ]);
});

// Exposed .well-known/apple-app-site-association
app.get('/.well-known/apple-app-site-association', (req, res) => {
  res.json({ applinks: { apps: [], details: [{ appID: "TEAMID.com.avengers.armory", paths: ["*"] }] } });
});

// Exposed Prometheus/Alertmanager
app.get(['/alertmanager/', '/api/v1/alerts', '/api/v1/targets'], (req, res) => {
  if (req.path.includes('v1/alerts')) {
    return res.json({ status: "success", data: { alerts: [{ labels: { alertname: "HighMemoryUsage", instance: "10.0.0.1:9090" }, state: "firing" }] } });
  }
  if (req.path.includes('v1/targets')) {
    return res.json({ status: "success", data: { activeTargets: [{ discoveredLabels: { __address__: "10.0.0.1:9090" }, scrapeUrl: "http://10.0.0.1:9090/metrics", health: "up" }] } });
  }
  res.type('text/html').send(`<html><head><title>Alertmanager</title></head><body><div id="app"></div></body></html>`);
});

// Exposed Rancher
app.get(['/v3/', '/v3/settings', '/dashboard/'], (req, res) => {
  if (req.path.includes('v3/settings')) {
    return res.json({ data: [{ id: "server-url", value: "https://avengers-armory.local" }, { id: "server-version", value: "v2.7.0" }] });
  }
  if (req.path === '/v3/') {
    return res.json({ type: "collection", links: { self: "/v3/" }, actions: {} });
  }
  res.type('text/html').send(`<html><head><title>Rancher</title></head><body><div id="app"></div></body></html>`);
});

// Exposed Haproxy stats
app.get(['/haproxy?stats', '/haproxy-status'], (req, res) => {
  res.type('text/html').send(`<html><head><title>Statistics Report for HAProxy</title></head><body>
<h1>Statistics Report for HAProxy</h1>
<h3>pid = 1234, uptime = 5d 3h 21m</h3>
<table><tr><th>Backend</th><th>Status</th><th>Sessions</th></tr>
<tr><td>web-backend</td><td>UP</td><td>1234</td></tr></table></body></html>`);
});

// ---- 30 CVE ENDPOINTS FROM NUCLEI TEMPLATES ----

// CVE-2022-23944: Apache ShenYu Admin Unauth
app.get('/plugin', (req, res) => {
  res.json({"message":"query success","code":200,"data":[{"id":1,"name":"divide"}]});
});

// CVE-2024-5910: Palo Alto Expedition Admin Takeover
app.get('/OS/startup/restore/restoreAdmin.php', (req, res) => {
  res.type('text/plain').send('Admin user found\nAdmin password restored successfully');
});

// CVE-2021-44152: Reprise License Manager Auth Bypass
app.get('/goforms/menu', (req, res) => {
  res.type('text/html').send('<html><body><h1>RLM Administration Commands</h1></body></html>');
});

// CVE-2023-22480: KubeOperator Kubeconfig Exposure
app.get('/api/v1/clusters/kubeconfig/k8s', (req, res) => {
  res.setHeader('Content-Type', 'application/download');
  res.send('apiVersion: v1\nclusters:\n- cluster:\n    server: https://10.0.0.1:6443');
});

// CVE-2024-0204: Fortra GoAnywhere MFT Auth Bypass
app.get('/goanywhere/images/..;/wizard/InitialAccountSetup.xhtml', (req, res) => {
  res.type('text/html').send('<html><title>goanywhere</title><body><h2>Create an administrator account</h2></body></html>');
});

// CVE-2022-45933: KubeView K8s Cert Leak
app.get('/api/scrape/kube-system', (req, res) => {
  res.type('text/plain').send('-----BEGIN CERTIFICATE-----\nMIIBkTCBfakecertdata\n-----END CERTIFICATE-----\nkubernetes.io/service-account');
});

// CVE-2021-40859: Auerswald PBX Info Disclosure
app.get('/about_state', (req, res) => {
  res.json({"pbx":"COMpact 5500R","dongleStatus":0,"macaddr":"00:11:22:33:44:55"});
});

// CVE-2021-33221: Ruckus IoT Controller Info Leak
app.get('/service/v1/service-details', (req, res) => {
  res.json({"message":"ok","data":{"dns":"8.8.8.8","gateway":"192.168.1.1"}});
});

// CVE-2024-40711: Veeam Backup Unauth Info Disclosure
app.get('/api/v1/serverinfo', (req, res) => {
  res.json({"databaseVendor":"PostgreSQL","databaseContentVersion":"12.1.2.5"});
});

// CVE-2022-31656: VMware Workspace ONE WEB-INF Exposure
app.get(['/SAAS/t/_/;/WEB-INF/web.xml', '/;/WEB-INF/web.xml'], (req, res) => {
  res.type('text/xml').send('<?xml version="1.0"?><web-app><servlet><servlet-name>dispatcher</servlet-name></servlet></web-app>');
});

// CVE-2021-21246: OneDev User Token Leak
app.get('/rest/users/1', (req, res) => {
  res.json({"id":1,"name":"admin","email":"admin@example.com","accessToken":"abc123def456"});
});

// CVE-2021-46371: AntD Admin User Info Disclosure (conflicts with existing /api/v1/users? no, different path)
app.get('/api/v1/users', (req, res) => {
  res.json({"data":[{"id":1,"name":"John","email":"john@test.com","phone":"555-0100"}]});
});

// CVE-2022-0281: Microweber User Info Leak
app.get('/api/users/search_authors', (req, res) => {
  res.json([{"id":1,"username":"admin","email":"admin@test.com","display_name":"Admin User"}]);
});

// CVE-2022-45354: WordPress Download Monitor User Data
app.get('/wp-json/download-monitor/v1/user_data', (req, res) => {
  res.json([{"id":1,"display_name":"admin","registered":"2024-01-01"}]);
});

// CVE-2021-39226: Grafana Snapshot Auth Bypass
app.get('/api/snapshots/:key', (req, res) => {
  res.json({"dashboard":{"title":"test"},"isSnapshot":true});
});

// CVE-2022-25568: MotionEye Config Exposure
app.get('/config/list', (req, res) => {
  res.json({"cameras":[{"upload_password":"secret123","network_password":"netpass456"}]});
});

// CVE-2022-31269: Linear eMerge Credential Exposure
app.get('/test.txt', (req, res) => {
  res.type('text/plain').send('ID=admin\nPassword=secret123');
});

// CVE-2021-40150: Reolink Nginx Config Exposure
app.get('/conf/nginx.conf', (req, res) => {
  res.type('text/plain').send('server {\n  listen 80;\n  location ~ \\.php$ {\n    fastcgi_pass 127.0.0.1:9000;\n  }\n}');
});

// CVE-2023-5003: WordPress LDAP Auth Report Exposure
app.get('/wp-content/ldap-authentication-report.csv', (req, res) => {
  res.type('text/csv').send('ID,USERNAME,TIME,LDAP STATUS\n1,admin,2024-01-01,Success\n2,jdoe,2024-01-02,Success');
});

// CVE-2023-34598: Gibbon SQL Dump Exposure
app.get('/', (req, res, next) => {
  if (req.query.q === './gibbon.sql') {
    return res.type('text/plain').send('-- phpMyAdmin SQL Dump\n-- Database: gibbon\nCREATE TABLE users (id INT, name VARCHAR(255));');
  }
  next();
});

// CVE-2022-26148: Grafana Zabbix Credential Leak
app.get('/login', (req, res, next) => {
  if (req.query.redirect === '/') {
    return res.type('text/html').send(`<script>window.grafanaBootData={"settings":{"datasources":{"zabbix":{"password":"admin123","username":"zabbix_user","url":"alexanderzobnin-zabbix-datasource"}}}}</script>`);
  }
  next();
});

// CVE-2022-36883: Jenkins Git Plugin Info Leak
app.get('/git/notifyCommit', (req, res) => {
  res.type('text/plain').send('repository: test\nTriggered by SCM API plugin\nNo Git consumers');
});

// CVE-2023-49103: OwnCloud Graphapi phpinfo Leak
app.get('/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/*', (req, res) => {
  res.type('text/html').send('<h1>PHP Version 8.1.0</h1><h2>PHP Extension Build</h2><tr><td>OWNCLOUD_ADMIN_PASSWORD</td><td>owncloud</td></tr>');
});

// CVE-2024-30569: Netgear R6850 Info Disclosure
app.get('/currentsetting.htm', (req, res) => {
  res.type('text/plain').send('Firmware=V1.0.5.70\nLoginMethod=password\nModel=R6850');
});

// CVE-2025-28228: Electrolink Transmitter Creds
app.get('/controlloLogin.js', (req, res) => {
  res.type('application/javascript').send("function login(){if(user=='guest' && password=='guest'){return true;}}");
});

// CVE-2021-44138: Caucho Resin WEB-INF Exposure (handled by wildcard above for /;/WEB-INF/web.xml)

// CVE-2024-8963: Ivanti CSA Path Traversal (URL-encoded path)
app.use((req, res, next) => {
  if (req.originalUrl.includes('/client/index.php') && req.originalUrl.includes('gsb/users.php')) {
    return res.type('text/html').send('<html><title>Ivanti Cloud Services Appliance</title><body>User name: admin<br>Set Password</body></html>');
  }
  next();
});

// CVE-2021-3019: Lanproxy Config Exposure (path traversal)
app.use((req, res, next) => {
  if (req.originalUrl.includes('conf/config.properties')) {
    return res.type('text/plain').send('config.admin.username=admin\nconfig.admin.password=SuperSecret123');
  }
  next();
});

// CVE-2023-32235: Ghost CMS Path Traversal
app.use((req, res, next) => {
  if (req.originalUrl.includes('/assets/built') && req.originalUrl.includes('package.json')) {
    return res.json({"name":"ghost","version":"5.42.0","description":"Ghost CMS"});
  }
  next();
});

// CVE-2024-0204: GoAnywhere MFT (path traversal with ;)
app.use((req, res, next) => {
  if (req.originalUrl.includes('goanywhere') && req.originalUrl.includes('InitialAccountSetup')) {
    return res.type('text/html').send('<html><title>goanywhere</title><body><h2>Create an administrator account</h2></body></html>');
  }
  next();
});

// CVE-2025-49132: Pterodactyl Panel Config Exposure
app.get('/locales/locale.json', (req, res) => {
  if (req.query.locale && req.query.locale.includes('config') && req.query.namespace === 'app') {
    return res.json({"app":{"version":"1.11.5","key":"base64{{dGVzdGtleQ==}}"}});
  }
  res.json({"common":{"welcome":"Welcome"}});
});

// ---- ADDITIONAL NUCLEI-DETECTABLE ENDPOINTS ----

// phpMyAdmin panel (nuclei: phpmyadmin-panel)
app.get(['/phpmyadmin/', '/phpmyadmin', '/pma/', '/admin/phpmyadmin/', '/myadmin/', '/sql/'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>phpMyAdmin</title></head><body>
<div id="page_content">
<form method="post" action="index.php" name="login_form" class="login">
<fieldset>
<legend>Log in</legend>
<div class="item"><label for="input_servername">Server Choice:</label>
<select name="pma_servername" id="input_servername"><option value="localhost">localhost</option></select></div>
<div class="item"><label for="input_username">Username:</label><input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield"></div>
<div class="item"><label for="input_password">Password:</label><input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield"></div>
</fieldset>
<fieldset class="tblFooters"><input value="Go" type="submit" id="input_go"></fieldset>
</form></div>
<div id="pma_footer"><span class="version">4.8.4</span></div>
</body></html>`);
});

// Jenkins detection (nuclei: jenkins-detect)
app.get(['/whoAmI/', '/jenkins/', '/jenkins'], (req, res) => {
  res.setHeader('X-Jenkins', '2.375.1');
  res.setHeader('X-Jenkins-Session', 'abc123');
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Dashboard [Jenkins]</title></head><body>
<div id="header"><img id="jenkins-head-icon" src="/static/abc123/images/svgs/logo.svg" alt="[Jenkins]">
<span class="jenkins-name-icon-layout">Jenkins</span></div>
<div id="main-panel"><h1>Welcome to Jenkins!</h1></div>
</body></html>`);
});

// Elasticsearch exposure (nuclei: elasticsearch)
app.get(['/_cat/indices', '/_all/_search', '/_cluster/health'], (req, res) => {
  if (req.path.includes('_cat/indices')) {
    return res.type('text/plain').send('green open users   abc123 1 0 150 0  50kb  50kb\ngreen open logs    def456 1 0 5000 0 500kb 500kb\n');
  }
  if (req.path.includes('_cluster/health')) {
    return res.json({ cluster_name: "avengers-armory", status: "green", "number_of_nodes": 3, "number_of_data_nodes": 2 });
  }
  res.json({ took: 5, timed_out: false, hits: { total: { value: 150 }, hits: [
    { _source: { username: "admin", password: "admin123", email: "admin@armory.local" } },
    { _source: { username: "tony", password: "ironman", email: "tony@stark.com" } }
  ]}});
});

// Kibana exposure (nuclei: exposed-kibana)
app.get(['/app/kibana', '/app/kibana/'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Kibana</title></head><body>
<kbn-csp data="{}"></kbn-csp>
<div class="kibanaWelcomeView" id="kbn_loading_message" data-test-subj="kbnLoadingMessage">
<div class="kibanaWelcomeLogo"></div>
<div class="kibanaWelcomeTitle">Loading Kibana</div>
</div></body></html>`);
});

// Adminer panel (nuclei: adminer-panel)
app.get(['/adminer.php', '/adminer/', '/adminer'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Login - Adminer</title></head><body class="ltr">
<div id="content"><form action="" method="post">
<table><tr><th>System<td><select name="auth[driver]"><option value="server">MySQL</option></select>
<tr><th>Server<td><input name="auth[server]" value="localhost">
<tr><th>Username<td><input name="auth[username]" id="username" value="">
<tr><th>Password<td><input type="password" name="auth[password]">
<tr><th>Database<td><input name="auth[db]" value="">
</table><p><input type="submit" value="Login">
<input type="hidden" name="auth[permanent]" value="1">
</form></div>
<div id="lang"><a href="?lang=en">Adminer</a> <span class="version">4.8.1</span></div>
</body></html>`);
});

// Mongo Express (nuclei: unauthenticated-mongo-express)
app.get(['/mongo-express/', '/mongo-express', '/db/', '/mongodb/'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Home - Mongo Express</title></head><body>
<div class="container"><h1>Mongo Express</h1>
<table class="table"><tr><th>Database</th><th>Collections</th></tr>
<tr><td><a href="/db/admin/">admin</a></td><td>3</td></tr>
<tr><td><a href="/db/avengers_armory/">avengers_armory</a></td><td>5</td></tr>
</table></div></body></html>`);
});

// Node Express Status (nuclei: node-express-status)
app.get('/express-status', (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Express Status</title></head><body>
<h1>Express Status</h1>
<div><h2>CPU Usage</h2><p>12.5%</p></div>
<div><h2>Memory</h2><p>RSS: 85MB, Heap Used: 45MB</p></div>
<div><h2>Uptime</h2><p>3h 24m</p></div>
</body></html>`);
});

// WordPress detection (nuclei: wordpress-detect)
app.get(['/wp-admin/', '/wp-admin/admin-ajax.php', '/wp-includes/js/jquery/jquery.js', '/wp-content/', '/readme.html'], (req, res) => {
  if (req.path.includes('readme.html')) {
    return res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>WordPress &rsaquo; ReadMe</title></head><body>
<h1 id="logo"><a href="https://wordpress.org/">WordPress</a></h1>
<p>Version 6.4.2</p></body></html>`);
  }
  if (req.path.includes('admin-ajax.php')) {
    return res.send('0');
  }
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>WordPress &rsaquo; Dashboard</title>
<meta name="generator" content="WordPress 6.4.2" />
</head><body class="wp-admin">
<div id="wpbody"><h1>Dashboard</h1></div>
</body></html>`);
});

// Tomcat manager (nuclei: tomcat-manager)
app.get(['/manager/html', '/manager/', '/host-manager/html'], (req, res) => {
  res.status(401).setHeader('WWW-Authenticate', 'Basic realm="Tomcat Manager Application"');
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>401 Unauthorized</title></head><body>
<h1>401 Unauthorized</h1>
<p>You are not authorized to view this page. If you have not changed any configuration files, please examine the file <tt>conf/tomcat-users.xml</tt>.</p>
<p>For example, to add the manager-gui role to a user named tomcat with a password of s3cret, add the following to the config file listed above.</p>
<pre>&lt;role rolename="manager-gui"/&gt;
&lt;user username="tomcat" password="s3cret" roles="manager-gui"/&gt;</pre>
</body></html>`);
});

// Apache Struts (nuclei: struts-detect)
app.get(['/struts/', '/struts/webconsole.html'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Struts Problem Report</title></head><body>
<h2>Struts Problem Report</h2>
<p>Struts has detected an unhandled exception:</p>
<div class="error"><b>Action class [example] not found</b></div>
<div class="devMode">Developer Mode: Enabled. You should disable this in production.</div>
</body></html>`);
});

// .npmrc exposure (nuclei: npmrc)
app.get('/.npmrc', (req, res) => {
  res.type('text/plain').send(`//registry.npmjs.org/:_authToken=npm_FAKE_AUTH_TOKEN_123456
registry=https://registry.npmjs.org/
@company:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=ghp_FAKE_GITHUB_TOKEN_789
`);
});

// composer.json (nuclei: composer-config)
app.get('/composer.json', (req, res) => {
  res.json({
    name: "avengers/armory",
    description: "Security Lab",
    require: { "laravel/framework": "^10.0", "guzzlehttp/guzzle": "^7.0" },
    autoload: { "psr-4": { "App\\": "app/" } }
  });
});

// Gruntfile.js exposure
app.get(['/Gruntfile.js', '/gulpfile.js', '/webpack.config.js'], (req, res) => {
  res.type('application/javascript').send(`module.exports = function(grunt) {
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    secret: { key: 'INTERNAL_SECRET_KEY_123' }
  });
};
`);
});

// config.php exposure
app.get(['/config.php', '/config/config.php', '/application/config/database.php', '/app/config/parameters.yml'], (req, res) => {
  if (req.path.includes('parameters.yml')) {
    return res.type('text/yaml').send(`parameters:
    database_host: localhost
    database_port: 3306
    database_name: avengers_armory
    database_user: root
    database_password: SuperSecretDbPass123!
    secret: ThisTokenIsNotSoSecretChangeIt
`);
  }
  res.type('text/plain').send(`<?php
$config['db_host'] = 'localhost';
$config['db_user'] = 'root';
$config['db_pass'] = 'SuperSecretDbPass123!';
$config['db_name'] = 'avengers_armory';
$config['secret_key'] = 'super-secret-key-do-not-share';
?>`);
});

// Exposed .DS_Store (nuclei: ds-store)
app.get('/.DS_Store', (req, res) => {
  res.type('application/octet-stream');
  const header = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31]);
  res.send(Buffer.concat([header, Buffer.from('admin\x00backup\x00config\x00uploads\x00')]));
});

// Exposed .svn/entries (nuclei: svn-entries)
app.get(['/.svn/entries', '/.svn/wc.db'], (req, res) => {
  if (req.path.includes('wc.db')) {
    return res.type('application/octet-stream').send('SQLite format 3\x00');
  }
  res.type('text/plain').send(`10
dir
12345
https://svn.internal.avengers-armory.local/trunk
`);
});

// Exposed .hg/requires (nuclei: hg-config)
app.get('/.hg/requires', (req, res) => {
  res.type('text/plain').send('dotencode\nfncache\ngeneraldelta\nrevlogv1\nstore\n');
});

// GraphQL introspection (nuclei: graphql-introspection)
app.get(['/api/graphql', '/v1/graphql', '/graphql/console'], (req, res) => {
  res.json({ data: { __schema: { queryType: { name: "Query" }, mutationType: { name: "Mutation" },
    types: [
      { kind: "OBJECT", name: "User", fields: [{ name: "id" }, { name: "username" }, { name: "password" }, { name: "email" }, { name: "role" }, { name: "creditCard" }] },
      { kind: "OBJECT", name: "Query", fields: [{ name: "users" }, { name: "user" }, { name: "searchUsers" }, { name: "adminPanel" }] },
      { kind: "OBJECT", name: "Mutation", fields: [{ name: "createUser" }, { name: "deleteUser" }, { name: "updateRole" }] }
    ]
  }}});
});

// Firebase config exposure (nuclei: firebase-urls)
app.get(['/__/firebase/init.json', '/firebase-config.json'], (req, res) => {
  res.json({
    apiKey: "AIzaSyFAKE_API_KEY_NOT_REAL_123",
    authDomain: "avengers-armory.firebaseapp.com",
    projectId: "avengers-armory",
    storageBucket: "avengers-armory.appspot.com",
    messagingSenderId: "123456789",
    appId: "1:123456789:web:abc123def456"
  });
});

// Exposed JMX/Jolokia (nuclei: jolokia)
app.get(['/jolokia/', '/jolokia/list', '/api/jolokia/'], (req, res) => {
  res.json({
    request: { type: "version" },
    value: { agent: "1.7.1", protocol: "7.2", config: { maxDepth: "15" }, info: { product: "tomcat", vendor: "Apache", version: "9.0.65" } },
    status: 200
  });
});

// Prometheus metrics (nuclei: prometheus-metrics)
app.get(['/metrics', '/prometheus/metrics', '/actuator/prometheus'], (req, res) => {
  res.type('text/plain').send(`# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",endpoint="/api/users",status="200"} 15234
http_requests_total{method="POST",endpoint="/api/login",status="200"} 4521
http_requests_total{method="GET",endpoint="/admin",status="200"} 890
# HELP process_cpu_seconds_total Total user and system CPU time spent
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 1234.56
# HELP node_memory_usage_bytes Memory usage
# TYPE node_memory_usage_bytes gauge
node_memory_usage_bytes{type="rss"} 89128960
node_memory_usage_bytes{type="heapTotal"} 67108864
`);
});

// Exposed Webpack source maps (nuclei: sourcemap-js)
app.get(['/main.js.map', '/app.js.map', '/bundle.js.map', '/static/js/main.js.map'], (req, res) => {
  res.json({
    version: 3,
    file: "main.js",
    sourceRoot: "",
    sources: ["../src/App.js", "../src/components/Login.js", "../src/utils/api.js", "../src/config/secrets.js"],
    names: ["API_KEY", "SECRET", "adminPassword"],
    mappings: "AAAA,SAAS"
  });
});

// Exposed Redis info (nuclei: redis-info)
app.get(['/redis-info', '/api/redis/info'], (req, res) => {
  res.type('text/plain').send(`# Server
redis_version:7.0.11
redis_mode:standalone
os:Linux 5.15.0-91-generic x86_64
tcp_port:6379
# Keyspace
db0:keys=1500,expires=200
db1:keys=50,expires=10
`);
});

// Exposed /debug/vars (Go pprof style, nuclei: debug-vars)
app.get(['/debug/vars', '/debug/pprof/', '/debug/requests'], (req, res) => {
  res.json({
    cmdline: ["/app/server", "-port=3001", "-db-password=SuperSecretDbPass123!"],
    memstats: { Alloc: 2842624, TotalAlloc: 8424576, Sys: 12345678 },
    goroutines: 15
  });
});

// Exposed /server-info (nuclei: server-info variants)
app.get(['/server-info', '/.server-info', '/server-info.php'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE HTML>
<html><head><title>Server Information</title></head><body>
<h1>Apache Server Information</h1>
<dl><dt><b>Server Version:</b> Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/8.2.12</dt>
<dt><b>Server Built:</b> 2024-01-15T10:30:00</dt>
<dt><b>Module Magic Number:</b> 20120211:124</dt></dl>
<h2>Server Settings</h2>
<table><tr><th>Setting</th><th>Value</th></tr>
<tr><td>ServerRoot</td><td>/etc/httpd</td></tr>
<tr><td>DocumentRoot</td><td>/var/www/html</td></tr>
</table></body></html>`);
});

// Exposed Swagger UI (nuclei: swagger-ui)
app.get(['/swagger-ui/', '/swagger-ui/index.html', '/swagger/', '/api/docs'], (req, res) => {
  res.type('text/html').send(`<!DOCTYPE html>
<html><head><title>Swagger UI</title></head><body>
<div id="swagger-ui"></div>
<script>SwaggerUIBundle({url: "/api/swagger.json", dom_id: '#swagger-ui'})</script>
</body></html>`);
});

// Spring Boot env (nuclei: springboot-env)
app.get('/actuator/configprops', (req, res) => {
  res.json({
    contexts: { application: { beans: {
      "dataSourceProperties": { properties: { url: "jdbc:postgresql://db.internal:5432/armory", username: "admin", password: "SuperSecretDbPass123!" } },
      "spring.mail": { properties: { host: "smtp.internal", username: "mailer", password: "MailP@ss!" } }
    }}}
  });
});

// Exposed .well-known paths
app.get(['/.well-known/openid-configuration', '/.well-known/jwks.json', '/.well-known/assetlinks.json'], (req, res) => {
  if (req.path.includes('openid')) {
    return res.json({
      issuer: "https://avengers-armory.local",
      authorization_endpoint: "https://avengers-armory.local/oauth/authorize",
      token_endpoint: "https://avengers-armory.local/oauth/token",
      userinfo_endpoint: "https://avengers-armory.local/oauth/userinfo",
      jwks_uri: "https://avengers-armory.local/.well-known/jwks.json"
    });
  }
  if (req.path.includes('jwks')) {
    return res.json({ keys: [{ kty: "RSA", kid: "key1", use: "sig", n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2", e: "AQAB" }] });
  }
  res.json([{ relation: ["delegate_permission/common.handle_all_urls"], target: { namespace: "android_app", package_name: "com.avengers.armory", sha256_cert_fingerprints: ["AA:BB:CC:DD"] } }]);
});

// Exposed Kubernetes tokens
app.get(['/var/run/secrets/kubernetes.io/serviceaccount/token', '/api/v1/namespaces', '/api/v1/pods'], (req, res) => {
  if (req.path.includes('token')) {
    return res.type('text/plain').send('eyJhbGciOiJSUzI1NiIsImtpZCI6IkZBS0VfSzhTX1RPS0VOIn0.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6ZGVmYXVsdCJ9.FAKE_SIGNATURE');
  }
  res.json({ kind: "NamespaceList", apiVersion: "v1", items: [
    { metadata: { name: "default" } }, { metadata: { name: "kube-system" } }, { metadata: { name: "production" } }
  ]});
});

// Exposed .idea/ project files
app.get(['/.idea/workspace.xml', '/.idea/modules.xml', '/.vscode/settings.json', '/.vscode/launch.json'], (req, res) => {
  if (req.path.includes('.vscode')) {
    return res.json({
      "terminal.integrated.env.linux": { "DB_PASSWORD": "SuperSecretDbPass123!", "JWT_SECRET": "super-secret-jwt-key" },
      "search.exclude": { "**/node_modules": true }
    });
  }
  res.type('text/xml').send(`<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="ProjectModuleManager">
    <modules><module fileurl="file://$PROJECT_DIR$/avengers-armory.iml" filepath="$PROJECT_DIR$/avengers-armory.iml" /></modules>
  </component>
</project>`);
});

// Exposed Procfile (Heroku)
app.get('/Procfile', (req, res) => {
  res.type('text/plain').send('web: node app.js\nworker: node worker.js\n');
});

// WSDL exposure
app.get(['/service.wsdl', '/ws/service.wsdl', '/wsdl'], (req, res) => {
  res.type('text/xml').send(`<?xml version="1.0" encoding="UTF-8"?>
<definitions name="ArmoryService" targetNamespace="http://avengers-armory.local/ws"
  xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
  <service name="ArmoryService">
    <port name="ArmoryPort" binding="tns:ArmoryBinding">
      <soap:address location="http://avengers-armory.local/ws/service"/>
    </port>
  </service>
</definitions>`);
});

// Exposed CGI-bin
app.get(['/cgi-bin/', '/cgi-bin/test.cgi', '/cgi-bin/printenv.pl'], (req, res) => {
  res.type('text/plain').send(`SERVER_SOFTWARE=Apache/2.4.49
SERVER_NAME=avengers-armory.local
GATEWAY_INTERFACE=CGI/1.1
DOCUMENT_ROOT=/var/www/html
REMOTE_ADDR=${req.ip}
HTTP_HOST=${req.headers.host}
SCRIPT_NAME=${req.path}
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
`);
});

// Exposed .travis.yml / CI configs
app.get(['/.travis.yml', '/.circleci/config.yml', '/.github/workflows/ci.yml', '/Jenkinsfile'], (req, res) => {
  if (req.path.includes('Jenkinsfile')) {
    return res.type('text/plain').send(`pipeline {
  agent any
  environment {
    DB_PASSWORD = credentials('db-password')
    AWS_KEY = credentials('aws-key')
  }
  stages {
    stage('Build') { steps { sh 'npm install' } }
    stage('Deploy') { steps { sh 'npm run deploy' } }
  }
}`);
  }
  res.type('text/yaml').send(`language: node_js
node_js: "20"
env:
  global:
    - DB_PASSWORD=SuperSecretDbPass123!
    - AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
script:
  - npm test
  - npm run deploy
`);
});

// API key/token in response headers (nuclei: api-key-in-header)
app.get('/api/health', (req, res) => {
  res.setHeader('X-Api-Key', 'sk_live_FAKE_API_KEY_12345');
  res.setHeader('X-Auth-Token', 'eyJhbGciOiJIUzI1NiJ9.fake.token');
  res.json({ status: "healthy", version: "1.0.0", environment: "production", debug: true });
});

// Exposed Terraform state
app.get(['/terraform.tfstate', '/.terraform/terraform.tfstate'], (req, res) => {
  res.json({
    version: 4,
    terraform_version: "1.5.0",
    resources: [{
      type: "aws_instance",
      name: "web",
      instances: [{ attributes: { ami: "ami-0123456789", instance_type: "t3.medium", public_ip: "54.123.45.67" } }]
    }, {
      type: "aws_db_instance",
      name: "main",
      instances: [{ attributes: { engine: "postgres", username: "admin", password: "SuperSecretDbPass123!", endpoint: "db.internal:5432" } }]
    }]
  });
});

// Exposed Ansible vault
app.get(['/ansible.cfg', '/group_vars/all.yml', '/inventory.yml'], (req, res) => {
  res.type('text/yaml').send(`all:
  vars:
    db_password: SuperSecretDbPass123!
    aws_access_key: AKIAIOSFODNN7EXAMPLE
    aws_secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  hosts:
    web01: { ansible_host: 10.0.0.1 }
    db01: { ansible_host: 10.0.0.2 }
`);
});

// Info page with all technologies (nuclei: tech-detect)
app.get('/info', (req, res) => {
  res.json({
    server: "Apache/2.4.49",
    runtime: "Node.js " + process.version,
    framework: "Express 4.18.2",
    database: "PostgreSQL 15.4",
    cache: "Redis 7.0.11",
    search: "Elasticsearch 8.11.0",
    os: process.platform,
    arch: process.arch,
    uptime: process.uptime(),
    env: process.env.NODE_ENV || "development"
  });
});

// ---- 404 with path reflection + SQL error + Express stack trace ----
// (nuclei: express-stack-trace, xss-uri-reflected, error-based-sql-injection, host-header-injection)
app.use((req, res) => {
  const urlPath = decodeURIComponent(req.url);
  if (urlPath.includes("'") || urlPath.includes('"') || urlPath.includes(';')) {
    return res.status(500).type('text/html').send(`<!DOCTYPE html>
<html><head><title>Error</title></head><body>
<h1>Internal Server Error</h1>
<p>SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${urlPath}' at line 1</p>
<pre>Warning: mysqli_query(): (HY000/1064): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${urlPath}' at line 1
    at /app/node_modules/express/lib/router/index.js:284:15
    at Function.handle (/app/node_modules/express/lib/router/index.js:284:15)</pre>
</body></html>`);
  }
  res.status(404).type('text/html').send(`<!DOCTYPE html>
<html><head><title>Error</title></head><body>
<h1>Not Found</h1>
<p>The requested URL ${urlPath} was not found on server ${req.headers.host}.</p>
<pre>NotFoundError: Not Found
    at Function.handle (/app/node_modules/express/lib/router/index.js:284:15)
    at /app/node_modules/express/lib/router/index.js:365:5
    at next (/app/node_modules/express/lib/router/route.js:149:14)
    at Layer.handle_error (/app/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/app/node_modules/express/lib/router/index.js:328:13)
    at /app/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/app/node_modules/express/lib/router/index.js:346:12)
    at next (/app/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/app/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)</pre>
</body></html>`);
});

// ---- ERROR HANDLER with full stack trace ----
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).type('text/html').send(`<!DOCTYPE html>
<html><head><title>Error</title></head><body>
<h1>${err.message}</h1>
<h2>${err.status || 500}</h2>
<pre>${err.stack}</pre>
<p>Environment: ${process.env.NODE_ENV || 'development'}</p>
<p>Node: ${process.version}</p>
<p>CWD: ${process.cwd()}</p>
</body></html>`);
});

// ============================================================
// START
// ============================================================
async function startServer() {
  console.log(`⚔️  Avengers Armory ${config.usePostgres ? '(Supabase PostgreSQL)' : '(SQLite)'}`);
  
  if (config.usePostgres && !config.supabaseMgmtToken) {
    console.error('❌ supabaseMgmtToken not set in config.js!');
    console.error('   Go to supabase.com → DevTools → Cookies → copy sb-api-token');
    process.exit(1);
  }
  
  const database = await initDb();
  
  // Auto-seed if empty
  try {
    const r = await database.prepare('SELECT COUNT(*) as count FROM users').get();
    if (!r || parseInt(r.count) === 0) {
      console.log('📦 Seeding database...');
      // For SQLite, use the local seed function
      if (!config.usePostgres) {
        await seed();
      }
    }
  } catch(e) {
    console.log('📦 Seeding needed...');
    if (!config.usePostgres) await seed();
  }
  
  app.listen(PORT, () => {
    console.log('');
    console.log('============================================');
    console.log(`  ⚔️  AVENGERS ARMORY SECURITY LAB ⚔️`);
    console.log(`  🌐 http://localhost:${PORT}`);
    console.log(`  🗄️  ${config.usePostgres ? 'Supabase PostgreSQL' : 'SQLite'}`);
    console.log('============================================');
    console.log('  🔐 admin / admin123 · tony / ironman');
    console.log('  📚 Lab Guide: http://localhost:' + PORT + '/lab');
    console.log('');
  });
}

startServer().catch(e => { console.error('❌', e); process.exit(1); });

module.exports = app;
