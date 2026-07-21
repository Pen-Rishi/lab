// ============================================================
// AVENGERS SECURITY LAB - PostgreSQL Database Wrapper
// Uses Supabase PostgreSQL (via pg) with SQL injection support
// ============================================================

const { Pool } = require('pg');
const config = require('./config');

let pool = null;

// ---- PostgreSQL Wrapper ----
// Provides a similar API to the sql.js wrapper but async
class PGDatabase {
  constructor(pool) {
    this.pool = pool;
    this.db = this; // For compatibility
  }

  async query(text, params) {
    // Raw query execution - supports SQL injection!
    try {
      const result = await this.pool.query(text, params);
      return result;
    } catch (e) {
      throw e;
    }
  }

  // Execute a raw SQL string (for SQL injection vulns)
  async rawQuery(sql) {
    try {
      const result = await this.pool.query(sql);
      return result;
    } catch (e) {
      throw e;
    }
  }

  // Returns all rows as array of objects
  async all(sql, ...params) {
    try {
      const actualParams = params.length === 1 && Array.isArray(params[0]) ? params[0] : params;
      const result = await this.pool.query(sql, actualParams.length > 0 ? actualParams : undefined);
      return result.rows || [];
    } catch (e) {
      throw e;
    }
  }

  // Returns first row or null
  async get(sql, ...params) {
    try {
      const actualParams = params.length === 1 && Array.isArray(params[0]) ? params[0] : params;
      const result = await this.pool.query(sql, actualParams.length > 0 ? actualParams : undefined);
      return result.rows && result.rows.length > 0 ? result.rows[0] : null;
    } catch (e) {
      throw e;
    }
  }

  // Execute INSERT/UPDATE/DELETE
  async run(sql, ...params) {
    try {
      const actualParams = params.length === 1 && Array.isArray(params[0]) ? params[0] : params;
      const result = await this.pool.query(sql, actualParams.length > 0 ? actualParams : undefined);
      return { 
        rowCount: result.rowCount,
        lastInsertRowid: result.rows && result.rows[0] ? result.rows[0].id : null
      };
    } catch (e) {
      throw e;
    }
  }

  // Prepare-style interface for compatibility
  prepare(sql) {
    const self = this;
    return {
      all: async (...params) => self.all(sql, ...params),
      get: async (...params) => self.get(sql, ...params),
      run: async (...params) => self.run(sql, ...params)
    };
  }

  async close() {
    await this.pool.end();
  }
}

// ---- Initialize connection pool ----
async function initDb() {
  if (!pool) {
    if (!config.postgresUrl) {
      throw new Error('PostgreSQL not configured. Set config.usePostgres=true and config.postgresUrl in config.js');
    }
    pool = new Pool({
      connectionString: config.postgresUrl,
      ssl: {
        rejectUnauthorized: false
      },
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    });

    // Test connection
    try {
      const client = await pool.connect();
      console.log('✅ Connected to Supabase PostgreSQL!');
      client.release();
    } catch (e) {
      console.error('❌ Failed to connect to Supabase:', e.message);
      throw e;
    }
  }

  const db = new PGDatabase(pool);

  // Create tables if they don't exist
  await initTables(db);

  return db;
}

// ---- Create tables ----
async function initTables(db) {
  const createSQL = `
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

  // Execute each statement separately
  const statements = createSQL.split(';').filter(s => s.trim());
  for (const stmt of statements) {
    try {
      if (stmt.trim()) {
        await db.rawQuery(stmt);
      }
    } catch (e) {
      // Ignore "already exists" errors
      if (!e.message.includes('already exists')) {
        console.warn('Table creation warning:', e.message.substring(0, 100));
      }
    }
  }
}

// ---- Save is a no-op for PostgreSQL (auto-persists) ----
function saveDatabase() {
  // PostgreSQL auto-persists - no-op
}

// ---- Get ready db (for compatibility) ----
let _db = null;

function getReadyDb() {
  return _db;
}

module.exports = { initDb, getReadyDb, saveDatabase, PGDatabase };
