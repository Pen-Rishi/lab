// ============================================================
// AVENGERS SECURITY LAB - Database
// SQLite database using sql.js (pure JS, no native deps)
// ============================================================

const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const config = require('./config');

let db = null;
let SQL = null;

// ---- Synchronous wrapper to match better-sqlite3 API ----
class StatementWrapper {
  constructor(db, sql) {
    this.db = db;
    this.sql = sql;
    this.stmt = null;
  }

  _prepare() {
    if (!this.stmt) {
      this.stmt = this.db.prepare(this.sql);
    }
    return this.stmt;
  }

  _bind(params) {
    const stmt = this._prepare();
    if (params) {
      const arr = Array.isArray(params) ? params : [params];
      stmt.bind(arr);
    }
    return stmt;
  }

  run(...params) {
    try {
      const stmt = this._bind(params);
      stmt.step();
      stmt.free();
      this.stmt = null;
      return { lastInsertRowid: this.db.exec("SELECT last_insert_rowid()")[0]?.values?.[0]?.[0] };
    } catch (e) {
      this.db.run(this.sql); // Fallback for raw SQL
      return {};
    }
  }

  get(...params) {
    try {
      const stmt = this._bind(params);
      if (stmt.step()) {
        const result = stmt.getAsObject();
        stmt.free();
        this.stmt = null;
        return result;
      }
      stmt.free();
      this.stmt = null;
      return undefined;
    } catch (e) {
      return undefined;
    }
  }

  all(...params) {
    const results = [];
    try {
      const stmt = this._bind(params);
      while (stmt.step()) {
        results.push(stmt.getAsObject());
      }
      stmt.free();
      this.stmt = null;
    } catch (e) {
      // Fallback: try executing and parsing result
      try {
        this.db.run(this.sql);
      } catch(e2) {}
    }
    return results;
  }
}

class DatabaseWrapper {
  constructor(sqlDb) {
    this.db = sqlDb;
  }

  prepare(sql) {
    return new StatementWrapper(this.db, sql);
  }

  run(sql, params) {
    try {
      if (params) {
        const stmt = this.db.prepare(sql);
        const arr = Array.isArray(params) ? params : [params];
        stmt.bind(arr);
        stmt.step();
        stmt.free();
      } else {
        this.db.run(sql);
      }
    } catch (e) {
      // Ignore errors for SQL injection lab
    }
    return { lastInsertRowid: () => this.db.exec("SELECT last_insert_rowid()")[0]?.values?.[0]?.[0] };
  }

  exec(sql) {
    try {
      return this.db.exec(sql);
    } catch (e) {
      return [];
    }
  }
}

function saveDatabase() {
  // Access the raw sql.js database from the wrapper
  const rawDb = db && db.db;
  if (rawDb && SQL) {
    const data = rawDb.export();
    const buffer = Buffer.from(data);
    const dbPath = path.resolve(config.dbPath);
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(dbPath, buffer);
  }
}

async function getDatabase() {
  if (!db) {
    SQL = await initSqlJs();
    
    const dbPath = path.resolve(config.dbPath);
    let sqlDb;
    
    if (fs.existsSync(dbPath)) {
      const fileBuffer = fs.readFileSync(dbPath);
      sqlDb = new SQL.Database(fileBuffer);
    } else {
      sqlDb = new SQL.Database();
    }
    
    db = new DatabaseWrapper(sqlDb);
    initTables();
    saveDatabase();
  }
  return db;
}

function initTables() {
  // Create tables safely
  const createSQL = `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT NOT NULL,
      full_name TEXT DEFAULT '',
      role TEXT DEFAULT 'user',
      is_admin INTEGER DEFAULT 0,
      avatar_url TEXT DEFAULT '/images/default-avatar.png',
      address TEXT DEFAULT '',
      phone TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      price REAL NOT NULL,
      category TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      stock INTEGER DEFAULT 10,
      featured INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS cart (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      quantity INTEGER DEFAULT 1,
      added_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      total REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      shipping_address TEXT DEFAULT '',
      payment_method TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS order_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL,
      product_id INTEGER NOT NULL,
      product_name TEXT DEFAULT '',
      price REAL NOT NULL,
      quantity INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT DEFAULT '',
      message TEXT DEFAULT '',
      rating INTEGER DEFAULT 5,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      username TEXT DEFAULT '',
      comment TEXT DEFAULT '',
      rating INTEGER DEFAULT 5,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `;
  
  // Execute each statement separately
  const statements = createSQL.split(';').filter(s => s.trim());
  for (const stmt of statements) {
    try {
      db.db.run(stmt + ';');
    } catch (e) {
      // Ignore errors
    }
  }
}

// For use in routes - will be initialized asynchronously
let readyDb = null;

async function initDb() {
  readyDb = await getDatabase();
  return readyDb;
}

function getReadyDb() {
  return readyDb || db;
}

module.exports = { getDatabase, initDb, getReadyDb, saveDatabase };
