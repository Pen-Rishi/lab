// ============================================================
// AVENGERS SECURITY LAB - Seed Supabase via Management API
// Uses the auth session token to seed the database
// ============================================================

const PROJECT_REF = 'chsmudfembonqsyxhmuh';
const AUTH_TOKEN = process.env.SUPABASE_AUTH_TOKEN || '';

async function runSQL(sql, label) {
  if (!AUTH_TOKEN) {
    console.log('❌ ' + label + ': No SUPABASE_AUTH_TOKEN provided');
    return;
  }
  const res = await fetch('https://api.supabase.com/v1/projects/' + PROJECT_REF + '/database/query', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + AUTH_TOKEN
    },
    body: JSON.stringify({ query: sql })
  });
  const text = await res.text();
  if (res.status >= 200 && res.status < 300) {
    console.log('✅ ' + label);
  } else {
    console.log('❌ ' + label + ': ' + text.substring(0, 200));
  }
}

async function seedSupabase() {
  console.log('🗄️  Seeding Supabase database...\n');

  // 1. Create tables
  const tables = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT NOT NULL,
      full_name TEXT DEFAULT '',
      role TEXT DEFAULT 'user',
      is_admin INTEGER DEFAULT 0,
      avatar_url TEXT DEFAULT '/images/default-avatar.png',
      address TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      price REAL NOT NULL,
      category TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      stock INTEGER DEFAULT 10,
      featured INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS cart (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER DEFAULT 1,
      added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      total REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      shipping_address TEXT DEFAULT '',
      payment_method TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,
      order_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      product_name TEXT DEFAULT '',
      price REAL NOT NULL,
      quantity INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS feedback (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      username TEXT DEFAULT '',
      message TEXT DEFAULT '',
      rating INTEGER DEFAULT 5,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS reviews (
      id SERIAL PRIMARY KEY,
      product_id INTEGER NOT NULL,
      username TEXT DEFAULT '',
      comment TEXT DEFAULT '',
      rating INTEGER DEFAULT 5,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;
  await runSQL(tables, 'Tables created');

  // 2. Clear existing data
  await runSQL('DELETE FROM reviews', 'Cleared reviews');
  await runSQL('DELETE FROM feedback', 'Cleared feedback');
  await runSQL('DELETE FROM order_items', 'Cleared order_items');
  await runSQL('DELETE FROM orders', 'Cleared orders');
  await runSQL('DELETE FROM cart', 'Cleared cart');
  await runSQL('DELETE FROM products', 'Cleared products');
  await runSQL('DELETE FROM users', 'Cleared users');

  // 3. Seed users
  const users = [
    ['admin', 'admin123', 'admin@avengers.com', 'Nick Fury', 'admin', 1],
    ['tony', 'ironman', 'tony@stark.com', 'Tony Stark', 'user', 0],
    ['steve', 'america', 'steve@rogers.com', 'Steve Rogers', 'user', 0],
    ['thor', 'odin123', 'thor@asgard.com', 'Thor Odinson', 'user', 0],
    ['natasha', 'widow', 'natasha@shield.com', 'Natasha Romanoff', 'user', 0],
    ['bruce', 'hulk', 'bruce@banner.com', 'Bruce Banner', 'user', 0],
    ['peter', 'spidey', 'peter@parker.com', 'Peter Parker', 'user', 0],
    ['strange', 'magic123', 'strange@sanctum.com', 'Stephen Strange', 'user', 0],
    ['carol', 'captain', 'carol@danvers.com', 'Carol Danvers', 'user', 0],
    ['clint', 'arrow', 'clint@barton.com', 'Clint Barton', 'user', 0]
  ];
  for (const u of users) {
    await runSQL(
      `INSERT INTO users (username, password, email, full_name, role, is_admin) VALUES ('${u[0]}', '${u[1]}', '${u[2]}', '${u[3]}', '${u[4]}', ${u[5]})`,
      'User: ' + u[0]
    );
  }

  // 4. Seed products
  const products = [
    ['Mjolnir Replica', 'Authentic replica of Thor\'s hammer. Worth-worthy!', 2499.99, 'Weapons', 5, 1],
    ['Captain America\'s Shield', 'Vibranium-infused replica shield. Bulletproof!', 1899.99, 'Weapons', 3, 1],
    ['Iron Man Arc Reactor', 'Miniature arc reactor technology. Glows blue!', 999.99, 'Tech', 10, 1],
    ['Stormbreaker Axe', 'King Thor\'s axe forged in a dying star. Unleash the storm!', 3499.99, 'Weapons', 2, 1],
    ['Black Panther Vibranium Claws', 'Wakandan technology retractable claws.', 1499.99, 'Weapons', 7, 0],
    ['Hawkeye\'s Recurve Bow', 'Professional-grade compound bow with trick arrows.', 799.99, 'Weapons', 8, 0],
    ['Doctor Strange Sling Ring', 'Open portals to anywhere in the multiverse!', 2999.99, 'Mystic', 4, 1],
    ['Iron Man Mark LXXXV Suit', 'Nanotechnology suit with repulsors and flight.', 9999.99, 'Apparel', 1, 1],
    ['Captain America Stealth Suit', 'Tactical stealth suit for covert ops.', 1299.99, 'Apparel', 6, 0],
    ['Black Widow Tactical Suit', 'Espionage-grade tactical suit.', 1499.99, 'Apparel', 4, 0],
    ['Spider-Man Web-Shooters', 'Tony Stark edition web-shooters. Thwip!', 599.99, 'Tech', 15, 1],
    ['Ant-Man Suit (Pym Tech)', 'Pym Particle technology. Size-shifting!', 4499.99, 'Apparel', 2, 0],
    ['Infinity Gauntlet Replica', 'Gold-plated with realistic infinity stones!', 4999.99, 'Collectibles', 3, 1],
    ['Tesseract (Space Stone)', 'Cosmic cube containing the Space Stone.', 1999.99, 'Collectibles', 5, 1],
    ['Time Stone (Eye of Agamotto)', 'The Eye of Agamotto. Rewind time!', 2499.99, 'Collectibles', 4, 0],
    ['Soul Stone Prop', 'Replica of the Soul Stone.', 1499.99, 'Collectibles', 6, 0],
    ['J.A.R.V.I.S. AI Assistant', 'Your own AI-powered home assistant!', 2999.99, 'Tech', 8, 1],
    ['Quinjet Model Kit', '1:48 scale model of the Avengers Quinjet.', 249.99, 'Collectibles', 20, 0],
    ['HulkBuster Armor (Legacy)', 'Veronica satellite-deployed Hulkbuster.', 14999.99, 'Apparel', 1, 1],
    ['Nano Gauntlet (Endgame)', 'Tony and Bruce\'s Nano Gauntlet.', 7999.99, 'Collectibles', 2, 1],
    ['Captain Marvel Jacket', 'Starforce-issue jacket with Kree patches.', 899.99, 'Apparel', 10, 0],
    ['Loki\'s Scepter (Mind Stone)', 'The Chitauri scepter.', 3999.99, 'Weapons', 3, 0],
    ['Groot Baby Pot', 'I am Groot! Groot sapling in a pot.', 149.99, 'Collectibles', 50, 1],
    ['Vibranium Sample (Raw)', 'Raw Wakandan vibranium sample.', 4999.99, 'Mystic', 2, 0],
    ['Asgardian Mead (Premium)', 'Premium golden mead. Skal! (21+)', 199.99, 'Mystic', 30, 0]
  ];
  for (const p of products) {
    await runSQL(
      `INSERT INTO products (name, description, price, category, stock, featured) VALUES ('${p[0].replace(/'/g, "''")}', '${p[1].replace(/'/g, "''")}', ${p[2]}, '${p[3]}', ${p[4]}, ${p[5]})`,
      'Product: ' + p[0].substring(0, 30)
    );
  }

  // 5. Seed reviews
  const reviews = [
    [1, 'tony', 'Finally, a worthy replica!', 5],
    [2, 'steve', 'Doesn\'t match the suit but still cool!', 4],
    [3, 'peter', 'Mr. Stark would be proud!', 5],
    [4, 'thor', 'Almost as good as the real thing!', 5],
    [7, 'strange', 'DORMAMMU! Oh wait, wrong realm.', 5],
    [11, 'peter', 'Upgraded from my homemade ones!', 5],
    [12, 'tony', 'Pym tech is impressive.', 5],
    [13, 'thanos', 'Perfectly balanced, as all things should be.', 5],
    [23, 'rocket', 'I am not a pet! But fine, it\'s cute.', 5],
    [25, 'thor', 'Tastes like home! Skal!', 5]
  ];
  for (const r of reviews) {
    await runSQL(
      `INSERT INTO reviews (product_id, username, comment, rating) VALUES (${r[0]}, '${r[1]}', '${r[2].replace(/'/g, "''")}', ${r[3]})`,
      'Review by ' + r[1]
    );
  }

  // 6. Seed feedback
  const feedbacks = [
    [2, 'tony', 'Best armory in the galaxy! Jarvis loves it.', 5],
    [3, 'steve', 'Quality products. Fair prices.', 4],
    [4, 'thor', 'ANOTHER! This is a glorious establishment!', 5]
  ];
  for (const f of feedbacks) {
    await runSQL(
      `INSERT INTO feedback (user_id, username, message, rating) VALUES (${f[0]}, '${f[1]}', '${f[2].replace(/'/g, "''")}', ${f[3]})`,
      'Feedback from ' + f[1]
    );
  }

  console.log('\n============================================');
  console.log('  ✅ Supabase database seeded!');
  console.log('  👤 ' + users.length + ' users');
  console.log('  📦 ' + products.length + ' products');
  console.log('  💬 ' + (reviews.length + feedbacks.length) + ' reviews/feedback');
  console.log('============================================');
}

// Priority: 1) env var, 2) command line arg
const token = process.env.SUPABASE_AUTH_TOKEN || process.argv[2];

if (token) {
  process.env.SUPABASE_AUTH_TOKEN = token;
  seedSupabase().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1); });
} else {
  console.log('Usage: SUPABASE_AUTH_TOKEN=<token> node seed-supabase.js');
  console.log('Get your token from the Supabase dashboard (browser dev tools -> Application -> Cookies -> sb-api-token)');
  process.exit(1);
}
