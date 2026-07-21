// ============================================================
// ⚔️  AVENGERS ARMORY - OWASP TOP 10 SECURITY LAB ⚔️
// Supports: SQLite (local) or Supabase PostgreSQL (Mgmt API)
// ============================================================

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
  cookie: { httpOnly: false, secure: false }
}));

// A06: Legacy XML API
app.get('/api/legacy/products', (req, res) => {
  res.json({ error: 'Legacy XML API deprecated.', hint: 'A06: Outdated components' });
});

// A06: XXE - Legacy XML Parser
app.post('/api/legacy/parse-xml', bodyParser.text({ type: 'text/xml' }), (req, res) => {
  const xml = req.body || req.query.xml || '';
  if (!xml) return res.send('<error>No XML provided</error>');
  try {
    // Simulate XXE by checking for DOCTYPE + ENTITY patterns
    const hasExternalEntity = /<!DOCTYPE[^>]*ENTITY[^>]*SYSTEM/i.test(xml);
    const hasFileRead = /file:\/\//i.test(xml);
    const hasHttp = /http[s]?:\/\//i.test(xml);
    if (hasExternalEntity && hasFileRead) {
      return res.type('text/xml').send(`<?xml version="1.0"?><result><data>${fs.readFileSync('/etc/passwd', 'utf8').substring(0, 500).replace(/</g, '&lt;')}</data><note>A06: XXE successful! You read a local file!</note></result>`);
    }
    if (hasExternalEntity && hasHttp) {
      return res.type('text/xml').send('<?xml version="1.0"?><result><data>SSRF triggered via XXE!</data><note>A06: XXE + SSRF chain!</note></result>');
    }
    res.type('text/xml').send(`<?xml version="1.0"?><result><processed>${xml.substring(0, 200).replace(/</g, '&lt;')}</processed></result>`);
  } catch (e) {
    res.type('text/xml').send(`<?xml version="1.0"?><error>${e.message}</error>`);
  }
});

// A06: Known CVE check - reports outdated packages
app.get('/api/check-versions', (req, res) => {
  res.json({
    express: '4.16.0 (CVE-2022-24999: qs vulnerable to prototype pollution)',
    note: 'A06: Outdated components with known CVEs - no patch management!',
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

// A05: Exposed server headers (leaks version info)
app.use((req, res, next) => {
  res.header('X-Powered-By', 'Avengers-Armory/1.0.0 (Express 4.16.0)');
  res.header('Server', 'Apache/2.4.1 (Ubuntu) - WARNING: Actually Express!');
  next();
});

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

// A04: Password change WITHOUT current password verification
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
      headers: { 'content-type': resp.headers['content-type'], server: resp.headers['server'] || 'unknown' },
      note: 'A10: SSRF confirmed - server made request to ' + url
    });
  } catch (e) {
    res.json({ url, error: e.message, note: 'SSRF attempt failed - but server tried!' });
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

// A08: Insecure Deserialization - unserializes user input
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
    res.json({ deserialized: result, note: 'A08: Raw data deserialized via eval() - code executed!' });
  } catch (e) {
    res.json({ error: `Deserialization failed: ${e.message}`, hint: 'Try: ?raw={toString:process.mainModule.require("child_process").execSync("id").toString()}' });
  }
});

// A08: Auto-update without integrity check
app.get('/api/check-update', (req, res) => {
  res.json({
    update_available: true, version: '2.0.0',
    download_url: 'http://malicious-update-server.com/payload.exe',
    signature: 'unsigned',
    note: 'A08: Auto-update downloads from untrusted source without signature verification!'
  });
});

// ---- A09: No Logging / Audit ----
app.post('/api/transfer', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  // A09: Zero logging on financial transactions - no timestamp, no user tracking, no IP
  res.json({ success: true, message: `Transferred $${req.body.amount} to ${req.body.to_username}`, note: 'A09: Not logged! No audit trail exists for this transaction.' });
});

// A09: No logging on admin actions
app.post('/admin/no-audit/action', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  res.json({
    message: `Admin action '${req.body.action}' performed on user ${req.body.target_user_id}`, note: 'A09: This admin action was NOT logged. No one will know!'
  });
});

// A09: Login failures not logged (this route just to demonstrate)
app.get('/api/audit-trail', (req, res) => {
  // A09 + A05: The audit trail SHOULD exist but doesn't
  res.json({ login_failures: 'NOT LOGGED', admin_actions: 'NOT LOGGED', transfers: 'NOT LOGGED', note: 'A09: Complete audit trail failure!' });
});

// ---- REFLECTED XSS ----
app.get('/xss/search', (req, res) => {
  const q = req.query.q || '';
  res.send(`<html><body style="background:#0a0a0f;color:#e8e8f0;font-family:sans-serif;padding:40px;text-align:center;"><h1>🔍 Results</h1><p>Search: ${q}</p><a href="/" style="color:#1e90ff;">← Back</a></body></html>`);
});

// A03: Command Injection - ping/network tool
app.get('/api/tools/ping', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const host = req.query.host || 'localhost';
  // A03: Command Injection - user input passed directly to exec()
  exec(`ping -c 3 ${host} 2>&1`, { timeout: 5000 }, (err, stdout, stderr) => {
    if (err) return res.json({ error: err.message, output: stderr });
    res.type('text/plain').send(stdout);
  });
});

// A03: Command Injection via curl/network tools
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

// A04: Business Logic - Coupon abuse (no validation, can reuse)
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

// A04: Negative quantity / price manipulation
app.post('/api/price-override', (req, res) => {
  if (!isAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
  const { product_id, price } = req.body;
  // A04: No validation - client sends the price, server trusts it
  res.json({ success: true, message: `Set product ${product_id} price to $${price}`, note: 'A04: Price override accepted without server-side validation!' });
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

// A01: Forced browsing - hidden admin console
app.get('/.env', (req, res) => {
  res.json({
    DB_HOST: 'localhost', DB_NAME: 'avengers_armory',
    DB_USER: 'root', DB_PASS: 'supersecret123',
    API_KEY: 'sk-avengers-secret-key-2024',
    JWT_SECRET: 'thanos-is-coming',
    note: 'A01: Sensitive .env file exposed via forced browsing!'
  });
});

// A01: CORS misconfiguration
app.get('/api/cors-test', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.json({ secret: 'A01: CORS misconfig - any origin can read this!', data: 'sensitive_api_data' });
});

// A05: Directory listing
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

// A07: Weak password reset
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
    note: 'A07: Reset token is predictable! Just MD5 of email! Also, no token expiry!'
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
  res.json({ token_valid: true, email, expected_token: expectedToken, note: 'A07: Predictable token! Append &new_password=NEWPASS to reset!' });
}));

// A07: Session fixation - session ID doesn't change on login
// (Already implemented - session is reused on login)

// A05: Config file exposed
app.get('/config.js', (req, res) => {
  // A05: Source code / config exposed!
  res.send(`// WARNING: This should NOT be accessible!
// But the static file serve exposes it.
// Check /debug for the actual config.
`);
});

// A05: Verbose error page for 500s (already in error handler below)

// A03: UNION-based SQLi endpoint for data extraction
app.get('/api/sqli/union', wrap(async (req, res) => {
  const col = req.query.col || 'username';
  // A03: UNION-based SQL Injection - cast to text for PostgreSQL compat
  const result = await db().prepare(`SELECT ${col}::text FROM users UNION SELECT password::text FROM users`).all();
  res.json({ data: result, note: 'A03: UNION SQLi - extracting passwords!' });
}));

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
    { id: 'A10', name: 'SSRF', endpoints: ['/avatar/fetch (Server-side URL fetch)', '/api/ssrf/probe (Blind SSRF detection)', 'Cloud metadata: 169.254.169.254', '/ssrf-guide (Exploitation guide)'] }
  ]});
});

// ---- 404 ----
app.use((req, res) => res.status(404).render('404', { message: 'This page was destroyed by Thanos! Snap!' }));

// ---- ERROR HANDLER ----
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send(`<html><body style="background:#0a0a0f;color:#e23636;font-family:sans-serif;padding:40px;"><h1>💥 ${err.message}</h1><pre style="color:#888;">${err.stack}</pre><a href="/" style="color:#1e90ff;">← Back</a></body></html>`);
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
