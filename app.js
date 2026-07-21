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
  cookie: { httpOnly: false, secure: false }
}));

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

app.get('/.env', (req, res) => {
  res.json({
    DB_HOST: 'localhost', DB_NAME: 'avengers_armory',
    DB_USER: 'root', DB_PASS: 'supersecret123',
    API_KEY: 'sk-avengers-secret-key-2024',
    JWT_SECRET: 'thanos-is-coming',
  });
});

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
