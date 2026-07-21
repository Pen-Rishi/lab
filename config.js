// ============================================================
// AVENGERS SECURITY LAB - Configuration
// WARNING: This configuration contains intentional
// security vulnerabilities for educational purposes!
// ============================================================

module.exports = {
  // Server config
  port: process.env.PORT || 3000,
  
  // Database
  dbPath: './avengers_lab.db',
  
  // PostgreSQL (Supabase)
  usePostgres: true,
  postgresUrl: process.env.POSTGRES_URL || '',
  supabaseUrl: process.env.SUPABASE_URL || '',
  supabaseProjectRef: process.env.SUPABASE_PROJECT_REF || '',
  supabaseMgmtToken: process.env.SUPABASE_MGMT_TOKEN || '',

  // Session secret - A02: Cryptographic Failure (weak/guessable secret)
  sessionSecret: 'avengers123',
  
  // Admin credentials - A05: Security Misconfiguration (default creds)
  admin: {
    username: 'admin',
    password: 'admin123',
    email: 'admin@avengers.com'
  },
  
  // Flag for debug mode - A05: Security Misconfiguration
  debugMode: true,
  
  // Store configuration
  store: {
    name: 'Avengers Armory',
    tagline: 'Equip Like a Hero',
    currency: 'USD',
    taxRate: 0.08
  },
  
  // Vulnerability flags (all enabled by default)
  vulns: {
    sqlInjection: true,
    idor: true,
    xss: true,
    ssrf: true,
    massAssignment: true,
    weakCrypto: true,
    debugEndpoint: true,
    noRateLimit: true,
    noAuditLog: true,
    insecureDeserialization: true
  }
};
