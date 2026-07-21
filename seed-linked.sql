-- Create tables
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

-- Clear existing data
DELETE FROM reviews;
DELETE FROM feedback;
DELETE FROM order_items;
DELETE FROM orders;
DELETE FROM cart;
DELETE FROM products;
DELETE FROM users;

-- Reset sequences
ALTER SEQUENCE users_id_seq RESTART WITH 1;
ALTER SEQUENCE products_id_seq RESTART WITH 1;
ALTER SEQUENCE reviews_id_seq RESTART WITH 1;
ALTER SEQUENCE feedback_id_seq RESTART WITH 1;

-- Seed users
INSERT INTO users (username, password, email, full_name, role, is_admin) VALUES
('admin', 'admin123', 'admin@avengers.com', 'Nick Fury', 'admin', 1),
('tony', 'ironman', 'tony@stark.com', 'Tony Stark', 'user', 0),
('steve', 'america', 'steve@rogers.com', 'Steve Rogers', 'user', 0),
('thor', 'odin123', 'thor@asgard.com', 'Thor Odinson', 'user', 0),
('natasha', 'widow', 'natasha@shield.com', 'Natasha Romanoff', 'user', 0),
('bruce', 'hulk', 'bruce@banner.com', 'Bruce Banner', 'user', 0),
('peter', 'spidey', 'peter@parker.com', 'Peter Parker', 'user', 0),
('strange', 'magic123', 'strange@sanctum.com', 'Stephen Strange', 'user', 0),
('carol', 'captain', 'carol@danvers.com', 'Carol Danvers', 'user', 0),
('clint', 'arrow', 'clint@barton.com', 'Clint Barton', 'user', 0);

-- Seed products
INSERT INTO products (name, description, price, category, stock, featured) VALUES
('Mjolnir Replica', 'Authentic replica of Thor''s hammer. Worth-worthy!', 2499.99, 'Weapons', 5, 1),
('Captain America''s Shield', 'Vibranium-infused replica shield. Bulletproof!', 1899.99, 'Weapons', 3, 1),
('Iron Man Arc Reactor', 'Miniature arc reactor technology. Glows blue!', 999.99, 'Tech', 10, 1),
('Stormbreaker Axe', 'King Thor''s axe forged in a dying star. Unleash the storm!', 3499.99, 'Weapons', 2, 1),
('Black Panther Vibranium Claws', 'Wakandan technology retractable claws.', 1499.99, 'Weapons', 7, 0),
('Hawkeye''s Recurve Bow', 'Professional-grade compound bow with trick arrows.', 799.99, 'Weapons', 8, 0),
('Doctor Strange Sling Ring', 'Open portals to anywhere in the multiverse!', 2999.99, 'Mystic', 4, 1),
('Iron Man Mark LXXXV Suit', 'Nanotechnology suit with repulsors and flight.', 9999.99, 'Apparel', 1, 1),
('Captain America Stealth Suit', 'Tactical stealth suit for covert ops.', 1299.99, 'Apparel', 6, 0),
('Black Widow Tactical Suit', 'Espionage-grade tactical suit.', 1499.99, 'Apparel', 4, 0),
('Spider-Man Web-Shooters', 'Tony Stark edition web-shooters. Thwip!', 599.99, 'Tech', 15, 1),
('Ant-Man Suit (Pym Tech)', 'Pym Particle technology. Size-shifting!', 4499.99, 'Apparel', 2, 0),
('Infinity Gauntlet Replica', 'Gold-plated with realistic infinity stones!', 4999.99, 'Collectibles', 3, 1),
('Tesseract (Space Stone)', 'Cosmic cube containing the Space Stone.', 1999.99, 'Collectibles', 5, 1),
('Time Stone (Eye of Agamotto)', 'The Eye of Agamotto. Rewind time!', 2499.99, 'Collectibles', 4, 0),
('Soul Stone Prop', 'Replica of the Soul Stone.', 1499.99, 'Collectibles', 6, 0),
('J.A.R.V.I.S. AI Assistant', 'Your own AI-powered home assistant!', 2999.99, 'Tech', 8, 1),
('Quinjet Model Kit', '1:48 scale model of the Avengers Quinjet.', 249.99, 'Collectibles', 20, 0),
('HulkBuster Armor (Legacy)', 'Veronica satellite-deployed Hulkbuster.', 14999.99, 'Apparel', 1, 1),
('Nano Gauntlet (Endgame)', 'Tony and Bruce''s Nano Gauntlet.', 7999.99, 'Collectibles', 2, 1),
('Captain Marvel Jacket', 'Starforce-issue jacket with Kree patches.', 899.99, 'Apparel', 10, 0),
('Loki''s Scepter (Mind Stone)', 'The Chitauri scepter.', 3999.99, 'Weapons', 3, 0),
('Groot Baby Pot', 'I am Groot! Groot sapling in a pot.', 149.99, 'Collectibles', 50, 1),
('Vibranium Sample (Raw)', 'Raw Wakandan vibranium sample.', 4999.99, 'Mystic', 2, 0),
('Asgardian Mead (Premium)', 'Premium golden mead. Skal! (21+)', 199.99, 'Mystic', 30, 0);

-- Seed reviews
INSERT INTO reviews (product_id, username, comment, rating) VALUES
(1, 'tony', 'Finally, a worthy replica!', 5),
(2, 'steve', 'Doesn''t match the suit but still cool!', 4),
(3, 'peter', 'Mr. Stark would be proud!', 5),
(4, 'thor', 'Almost as good as the real thing!', 5),
(7, 'strange', 'DORMAMMU! Oh wait, wrong realm.', 5),
(11, 'peter', 'Upgraded from my homemade ones!', 5),
(12, 'tony', 'Pym tech is impressive.', 5),
(13, 'thanos', 'Perfectly balanced, as all things should be.', 5),
(23, 'rocket', 'I am not a pet! But fine, it''s cute.', 5),
(25, 'thor', 'Tastes like home! Skal!', 5);

-- Seed feedback
INSERT INTO feedback (user_id, username, message, rating) VALUES
(2, 'tony', 'Best armory in the galaxy! Jarvis loves it.', 5),
(3, 'steve', 'Quality products. Fair prices.', 4),
(4, 'thor', 'ANOTHER! This is a glorious establishment!', 5);
