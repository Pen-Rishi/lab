// ============================================================
// AVENGERS SECURITY LAB - Supabase Management API Database
// Uses api.supabase.com/v1/projects/{ref}/database/query
// ============================================================

const config = require('./config');

const MGMT_API = 'https://api.supabase.com/v1/projects';

class MgmtDatabase {
  constructor(projectRef, authToken) {
    this.projectRef = projectRef || config.supabaseProjectRef;
    // Priority: param > env var > config file
    this.authToken = authToken || process.env.SUPABASE_MGMT_TOKEN || config.supabaseMgmtToken;
    this.baseUrl = `${MGMT_API}/${this.projectRef}/database/query`;
    this.db = this; // For compatibility
  }

  async _query(sql) {
    const res = await fetch(this.baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.authToken}`
      },
      body: JSON.stringify({ query: sql })
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Supabase API ${res.status}: ${text.substring(0, 200)}`);
    }

    const text = await res.text();
    if (!text || text.trim() === '') return [];
    
    try {
      return JSON.parse(text);
    } catch {
      return [];
    }
  }

  // Execute SQL and return all rows
  async all(sql, ...params) {
    const finalSql = this._injectParams(sql, params);
    const result = await this._query(finalSql);
    return result || [];
  }

  // Execute SQL and return first row
  async get(sql, ...params) {
    const finalSql = this._injectParams(sql, params);
    const result = await this._query(finalSql);
    return (result && result.length > 0) ? result[0] : null;
  }

  // Execute INSERT/UPDATE/DELETE
  async run(sql, ...params) {
    const finalSql = this._injectParams(sql, params);
    const result = await this._query(finalSql);
    return { rowCount: result ? result.length : 0 };
  }

  // Prepare-style interface
  prepare(sql) {
    const self = this;
    return {
      all: async (...params) => self.all(sql, ...params),
      get: async (...params) => self.get(sql, ...params),
      run: async (...params) => self.run(sql, ...params)
    };
  }

  // Convert $1, $2 params to SQLite-style ? params for the API
  _injectParams(sql, params) {
    if (!params || params.length === 0) return sql;
    
    // Flatten nested arrays
    const flat = [];
    for (const p of params) {
      if (Array.isArray(p)) flat.push(...p);
      else flat.push(p);
    }
    
    if (flat.length === 0) return sql;
    
    // Replace positional params with escaped values
    let idx = 0;
    return sql.replace(/\$(\d+)/g, (match, num) => {
      const val = flat[parseInt(num) - 1];
      if (val === undefined || val === null) return 'NULL';
      if (typeof val === 'number') return val.toString();
      // Escape single quotes for strings
      return `'${String(val).replace(/'/g, "''")}'`;
    });
  }
}

// Lazy singleton
let _db = null;

function getReadyDb() {
  return _db;
}

function saveDatabase() {
  // No-op: Supabase auto-persists
}

async function initDb() {
  if (!config.supabaseMgmtToken) {
    throw new Error('Supabase Management API token not configured. Set supabaseMgmtToken in config.js');
  }
  _db = new MgmtDatabase(config.supabaseProjectRef, config.supabaseMgmtToken);
  
  // Test connection
  try {
    await _db._query('SELECT 1 as test');
    console.log('✅ Connected to Supabase via Management API');
  } catch (e) {
    console.error('❌ Supabase connection failed:', e.message);
    console.log('⚠️  Starting without database - static vuln endpoints still work');
  }
  
  return _db;
}

module.exports = { initDb, getReadyDb, saveDatabase, MgmtDatabase };
