// ============================================================
// AVENGERS SECURITY LAB - Seed Data
// Populates SQLite with Avengers-themed data
// ============================================================

const { initDb, saveDatabase } = require('./database');

async function seed() {
  const db = await initDb();
  
  // Clear existing data
  try { db.db.run('DELETE FROM reviews'); } catch(e) {}
  try { db.db.run('DELETE FROM feedback'); } catch(e) {}
  try { db.db.run('DELETE FROM order_items'); } catch(e) {}
  try { db.db.run('DELETE FROM orders'); } catch(e) {}
  try { db.db.run('DELETE FROM cart'); } catch(e) {}
  try { db.db.run('DELETE FROM products'); } catch(e) {}
  try { db.db.run('DELETE FROM users'); } catch(e) {}

  // ---- USERS ----
  const users = [
    { username: 'admin', password: 'admin123', email: 'admin@avengers.com', full_name: 'Nick Fury', role: 'admin', is_admin: 1 },
    { username: 'tony', password: 'ironman', email: 'tony@stark.com', full_name: 'Tony Stark', role: 'user', is_admin: 0 },
    { username: 'steve', password: 'america', email: 'steve@rogers.com', full_name: 'Steve Rogers', role: 'user', is_admin: 0 },
    { username: 'thor', password: 'odin123', email: 'thor@asgard.com', full_name: 'Thor Odinson', role: 'user', is_admin: 0 },
    { username: 'natasha', password: 'widow', email: 'natasha@shield.com', full_name: 'Natasha Romanoff', role: 'user', is_admin: 0 },
    { username: 'bruce', password: 'hulk', email: 'bruce@banner.com', full_name: 'Bruce Banner', role: 'user', is_admin: 0 },
    { username: 'peter', password: 'spidey', email: 'peter@parker.com', full_name: 'Peter Parker', role: 'user', is_admin: 0 },
    { username: 'strange', password: 'magic123', email: 'strange@sanctum.com', full_name: 'Stephen Strange', role: 'user', is_admin: 0 },
    { username: 'carol', password: 'captain', email: 'carol@danvers.com', full_name: 'Carol Danvers', role: 'user', is_admin: 0 },
    { username: 'clint', password: 'arrow', email: 'clint@barton.com', full_name: 'Clint Barton', role: 'user', is_admin: 0 }
  ];
  for (const u of users) {
    try { db.db.run('INSERT INTO users (username, password, email, full_name, role, is_admin) VALUES (?, ?, ?, ?, ?, ?)', [u.username, u.password, u.email, u.full_name, u.role, u.is_admin]); } catch(e) {}
  }

  // ---- PRODUCTS ----
  const products = [
    { name: 'Mjolnir Replica', description: 'Authentic replica of Thor\'s hammer. Worth-worthy!', price: 2499.99, category: 'Weapons', stock: 5, featured: 1 },
    { name: 'Captain America\'s Shield', description: 'Vibranium-infused replica shield. Bulletproof!', price: 1899.99, category: 'Weapons', stock: 3, featured: 1 },
    { name: 'Iron Man Arc Reactor', description: 'Miniature arc reactor technology. Glows blue!', price: 999.99, category: 'Tech', stock: 10, featured: 1 },
    { name: 'Stormbreaker Axe', description: 'King Thor\'s axe forged in a dying star. Unleash the storm!', price: 3499.99, category: 'Weapons', stock: 2, featured: 1 },
    { name: 'Black Panther Vibranium Claws', description: 'Wakandan technology retractable claws. Vibranium sharp!', price: 1499.99, category: 'Weapons', stock: 7, featured: 0 },
    { name: 'Hawkeye\'s Recurve Bow', description: 'Professional-grade compound bow with trick arrows. Never miss!', price: 799.99, category: 'Weapons', stock: 8, featured: 0 },
    { name: 'Doctor Strange Sling Ring', description: 'Open portals to anywhere in the multiverse!', price: 2999.99, category: 'Mystic', stock: 4, featured: 1 },
    { name: 'Iron Man Mark LXXXV Suit', description: 'Nanotechnology suit with repulsors, unibeam, and flight capabilities.', price: 9999.99, category: 'Apparel', stock: 1, featured: 1 },
    { name: 'Captain America Stealth Suit', description: 'Tactical stealth suit used in covert operations.', price: 1299.99, category: 'Apparel', stock: 6, featured: 0 },
    { name: 'Black Widow Tactical Suit', description: 'Espionage-grade tactical suit with stun disks and grappling hook.', price: 1499.99, category: 'Apparel', stock: 4, featured: 0 },
    { name: 'Spider-Man Web-Shooters', description: 'Tony Stark edition web-shooters with 576 web combinations. Thwip!', price: 599.99, category: 'Tech', stock: 15, featured: 1 },
    { name: 'Ant-Man Suit (Pym Tech)', description: 'Pym Particle technology suit. Size-shifting capabilities!', price: 4499.99, category: 'Apparel', stock: 2, featured: 0 },
    { name: 'Infinity Gauntlet Replica', description: 'Gold-plated Infinity Gauntlet with realistic infinity stones!', price: 4999.99, category: 'Collectibles', stock: 3, featured: 1 },
    { name: 'Tesseract (Space Stone)', description: 'Cosmic cube containing the Space Stone. Handle with care!', price: 1999.99, category: 'Collectibles', stock: 5, featured: 1 },
    { name: 'Time Stone (Eye of Agamotto)', description: 'The Eye of Agamotto containing the Time Stone. Rewind time!', price: 2499.99, category: 'Collectibles', stock: 4, featured: 0 },
    { name: 'Soul Stone Prop', description: 'Replica of the Soul Stone. Requires a sacrifice... just kidding!', price: 1499.99, category: 'Collectibles', stock: 6, featured: 0 },
    { name: 'J.A.R.V.I.S. AI Assistant', description: 'Your own AI-powered home assistant. Smarter than F.R.I.D.A.Y.!', price: 2999.99, category: 'Tech', stock: 8, featured: 1 },
    { name: 'Quinjet Model Kit', description: '1:48 scale model of the Avengers Quinjet. Assemble required!', price: 249.99, category: 'Collectibles', stock: 20, featured: 0 },
    { name: 'HulkBuster Armor (Legacy)', description: 'Veronica satellite-deployed Hulkbuster armor.', price: 14999.99, category: 'Apparel', stock: 1, featured: 1 },
    { name: 'Nano Gauntlet (Endgame)', description: 'Tony and Bruce\'s Nano Gauntlet. Thanos-level power!', price: 7999.99, category: 'Collectibles', stock: 2, featured: 1 },
    { name: 'Captain Marvel Jacket', description: 'Starforce-issue jacket with Kree technology patches.', price: 899.99, category: 'Apparel', stock: 10, featured: 0 },
    { name: 'Loki\'s Scepter (Mind Stone)', description: 'The Chitauri scepter containing the Mind Stone.', price: 3999.99, category: 'Weapons', stock: 3, featured: 0 },
    { name: 'Groot Baby Pot', description: 'I am Groot! Groot sapling in a terra cotta pot. We are Groot!', price: 149.99, category: 'Collectibles', stock: 50, featured: 1 },
    { name: 'Vibranium Sample (Raw)', description: 'Small sample of raw Wakandan vibranium.', price: 4999.99, category: 'Mystic', stock: 2, featured: 0 },
    { name: 'Asgardian Mead (Premium)', description: 'Premium golden mead from Asgardian royal cellars. Skål! (21+)', price: 199.99, category: 'Mystic', stock: 30, featured: 0 }
  ];
  for (const p of products) {
    try { db.db.run('INSERT INTO products (name, description, price, category, stock, featured) VALUES (?, ?, ?, ?, ?, ?)', [p.name, p.description, p.price, p.category, p.stock, p.featured]); } catch(e) {}
  }

  // ---- REVIEWS ----
  const reviews = [
    { product_id: 1, username: 'tony', comment: 'Finally, a worthy replica! ⚡', rating: 5 },
    { product_id: 1, username: 'steve', comment: 'Nice hammer. Can he lift it though?', rating: 4 },
    { product_id: 2, username: 'tony', comment: 'Doesn\'t match the suit but still cool!', rating: 4 },
    { product_id: 2, username: 'natasha', comment: 'Perfect for training sessions.', rating: 5 },
    { product_id: 3, username: 'pepper', comment: 'Tony made me one. This one is just as bright!', rating: 5 },
    { product_id: 3, username: 'peter', comment: 'Mr. Stark would be proud!', rating: 5 },
    { product_id: 4, username: 'thor', comment: 'Almost as good as the real thing! Almost.', rating: 5 },
    { product_id: 7, username: 'strange', comment: 'DORMAMMU! Oh wait, wrong realm. Nice ring.', rating: 5 },
    { product_id: 11, username: 'peter', comment: 'Upgraded from my homemade ones. These are amazing!', rating: 5 },
    { product_id: 13, username: 'thanos', comment: 'Perfectly balanced, as all things should be.', rating: 5 },
    { product_id: 14, username: 'loki', comment: 'I could have taken over Midgard with this.', rating: 4 },
    { product_id: 22, username: 'rocket', comment: 'I am not a pet! But fine, the Groot pot is cute.', rating: 5 },
    { product_id: 24, username: 'thor', comment: 'Tastes like home! Skål! 🍻', rating: 5 }
  ];
  for (const r of reviews) {
    try { db.db.run('INSERT INTO reviews (product_id, username, comment, rating) VALUES (?, ?, ?, ?)', [r.product_id, r.username, r.comment, r.rating]); } catch(e) {}
  }

  // ---- FEEDBACK ----
  const feedbacks = [
    { user_id: 2, username: 'tony', message: 'Best armory in the galaxy! Jarvis loves it.', rating: 5 },
    { user_id: 3, username: 'steve', message: 'Quality products. Fair prices.', rating: 4 },
    { user_id: 4, username: 'thor', message: 'ANOTHER! This is a glorious establishment!', rating: 5 }
  ];
  for (const f of feedbacks) {
    try { db.db.run('INSERT INTO feedback (user_id, username, message, rating) VALUES (?, ?, ?, ?)', [f.user_id, f.username, f.message, f.rating]); } catch(e) {}
  }

  saveDatabase();
  console.log('============================================');
  console.log('  ✅ Avengers Lab Database Seeded!');
  console.log(`  👤 ${users.length} users · 📦 ${products.length} products`);
  console.log('============================================');
}

module.exports = { seed };
