/* ════════════════════════════════════════════════════════════
   db/database.js — ZEN ASSETS Database Module
   SQLite + Better-SQLite3

   Exports: db.init(), db.raw(), db.{users, sessions, otpCodes, wallets, transactions, audit}
════════════════════════════════════════════════════════════ */

const Database = require('better-sqlite3');
const path      = require('path');
const fs        = require('fs');

// ── Database Path ──────────────────────────────────────────
const DB_PATH = path.join(__dirname, '../data/zen_assets.db');

// ── Ensure Data Directory Exists ───────────────────────────
if (!fs.existsSync(path.dirname(DB_PATH))) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

// ── Database Connection ────────────────────────────────────
let db = null;

// ── Initialize Database ────────────────────────────────────
function init() {
  if (db) return; // Already initialized

  db = new Database(DB_PATH);

  // Enable WAL mode for better concurrency
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('cache_size = 1000000'); // 1GB cache
  db.pragma('foreign_keys = ON');

  // Create tables if they don't exist
  createTables();

  // Prepare statements
  prepareStatements();

  console.log(`[DB] Connected to SQLite database at ${DB_PATH}`);
}

// ── Create Tables ──────────────────────────────────────────
function createTables() {
  // Users table already exists, skip creation

  // Sessions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      token TEXT UNIQUE NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // OTP codes table
  db.exec(`
    CREATE TABLE IF NOT EXISTS otp_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      code TEXT NOT NULL,
      type TEXT NOT NULL,
      expires_at DATETIME NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Wallets table
  db.exec(`
    CREATE TABLE IF NOT EXISTS wallets (
      id TEXT PRIMARY KEY,
      user_id TEXT UNIQUE NOT NULL,
      balance REAL DEFAULT 0.0,
      currency TEXT DEFAULT 'USD',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Transactions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      balance_before REAL NOT NULL,
      balance_after REAL NOT NULL,
      description TEXT,
      reference_id TEXT,
      status TEXT DEFAULT 'completed',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Audit log table
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      action TEXT NOT NULL,
      details TEXT,
      level TEXT DEFAULT 'info',
      ip_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Admin broadcasts table
  db.exec(`
    CREATE TABLE IF NOT EXISTS broadcasts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_id TEXT NOT NULL,
      subject TEXT NOT NULL,
      message TEXT NOT NULL,
      recipient_emails TEXT NOT NULL,
      sent_count INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (admin_id) REFERENCES users(id)
    )
  `);
}

// ── Prepare Statements ────────────────────────────────────
function prepareStatements() {
  // User operations
  users.create = db.prepare(`
    INSERT INTO users (id, email, password_hash, full_name)
    VALUES (?, ?, ?, ?)
  `);

  users.findByEmail = db.prepare(`
    SELECT * FROM users WHERE email = ? LIMIT 1
  `);

  users.findById = db.prepare(`
    SELECT * FROM users WHERE id = ? LIMIT 1
  `);

  users.update = db.prepare(`
    UPDATE users SET full_name = ?, tier = ?, kyc_status = ?
    WHERE id = ?
  `);

  users.list = db.prepare(`
    SELECT id, email, full_name, tier, kyc_status, created_at
    FROM users ORDER BY created_at DESC
  `);

  // Session operations
  sessions.create = db.prepare(`
    INSERT INTO sessions (id, user_id, token_jti, ip_address, user_agent, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  sessions.findByToken = db.prepare(`
    SELECT s.*, u.email, u.full_name, u.tier
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.token_jti = ? AND s.expires_at > CURRENT_TIMESTAMP AND s.revoked = 0
    LIMIT 1
  `);

  sessions.delete = db.prepare(`
    UPDATE sessions SET revoked = 1 WHERE token_jti = ?
  `);

  sessions.revoke = db.prepare(`
    UPDATE sessions SET revoked = 1 WHERE token_jti = ?
  `);

  sessions.revokeAllForUser = db.prepare(`
    UPDATE sessions SET revoked = 1 WHERE user_id = ?
  `);

  sessions.cleanup = () => {
    const stmt = db.prepare(`DELETE FROM sessions WHERE expires_at <= CURRENT_TIMESTAMP OR revoked = 1`);
    const deleted = stmt.run();
    if (deleted.changes > 0) {
      console.log(`[DB] Cleaned up ${deleted.changes} expired/revoked sessions`);
    }
  };

  // OTP operations
  otpCodes.create = db.prepare(`
    INSERT INTO otp_codes (user_id, code, type, expires_at)
    VALUES (?, ?, ?, ?)
  `);

  otpCodes.findValid = db.prepare(`
    SELECT * FROM otp_codes
    WHERE user_id = ? AND code = ? AND type = ? AND expires_at > CURRENT_TIMESTAMP AND used = FALSE
    LIMIT 1
  `);

  otpCodes.markUsed = db.prepare(`
    UPDATE otp_codes SET used = TRUE WHERE id = ?
  `);

  otpCodes.cleanup = () => {
    const stmt = db.prepare(`DELETE FROM otp_codes WHERE expires_at <= CURRENT_TIMESTAMP OR used = TRUE`);
    const deleted = stmt.run();
    if (deleted.changes > 0) {
      console.log(`[DB] Cleaned up ${deleted.changes} expired/used OTP codes`);
    }
  };

  // Wallet operations
  wallets.findByUser = db.prepare(`
    SELECT * FROM wallets WHERE user_id = ? LIMIT 1
  `);

  wallets.create = db.prepare(`
    INSERT INTO wallets (id, user_id, balance, initial_deposit, total_deposited, total_withdrawn, total_earned, total_claimed, pending_earnings)
    VALUES (?, ?, ?, 0, 0, 0, 0, 0, 0)
  `);

  wallets.updateBalance = db.prepare(`
    UPDATE wallets SET balance = ?, updated_at = CURRENT_TIMESTAMP
    WHERE user_id = ?
  `);

  wallets.creditBalance = (userId, amount) => {
    const wallet = wallets.findByUser.get(userId);
    if (!wallet) {
      const walletId = require('crypto').randomUUID();
      wallets.create.run(walletId, userId, amount);
      return { before: 0, after: amount };
    }
    const newBalance = wallet.balance + amount;
    wallets.updateBalance.run(newBalance, userId);
    return { before: wallet.balance, after: newBalance };
  };

  wallets.debitBalance = (userId, amount) => {
    const wallet = wallets.findByUser.get(userId);
    if (!wallet || wallet.balance < amount) {
      throw new Error('Insufficient balance');
    }
    const newBalance = wallet.balance - amount;
    wallets.updateBalance.run(newBalance, userId);
    return { before: wallet.balance, after: newBalance };
  };

  // Transaction operations
  transactions.create = db.prepare(`
    INSERT INTO transactions (id, user_id, type, amount, balance_before, balance_after, status, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  transactions.listByUser = db.prepare(`
    SELECT * FROM transactions
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `);

  transactions.countByUser = db.prepare(`
    SELECT COUNT(*) as total FROM transactions WHERE user_id = ?
  `);

  // Audit operations
  audit.log = db.prepare(`
    INSERT INTO audit_log (id, user_id, action, severity, details, ip_address)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  audit.list = db.prepare(`
    SELECT a.*, u.email
    FROM audit_log a
    LEFT JOIN users u ON a.user_id = u.id
    ORDER BY a.created_at DESC
    LIMIT ? OFFSET ?
  `);

  // Broadcast operations
  broadcasts.create = db.prepare(`
    INSERT INTO broadcasts (admin_id, subject, message, recipient_emails)
    VALUES (?, ?, ?, ?)
  `);

  broadcasts.list = db.prepare(`
    SELECT b.*, u.email as admin_email
    FROM broadcasts b
    JOIN users u ON b.admin_id = u.id
    ORDER BY b.created_at DESC
    LIMIT ? OFFSET ?
  `);
}

// ── Raw Database Access ────────────────────────────────────
function raw() {
  if (!db) throw new Error('Database not initialized');
  return db;
}

// ── User Operations ────────────────────────────────────────
const users = {
  create: null,
  findByEmail: null,
  findById: null,
  update: null,
  list: null
};

// ── Session Operations ─────────────────────────────────────
const sessions = {
  create: null,
  findByToken: null,
  delete: null,
  cleanup: null
};

// ── OTP Operations ─────────────────────────────────────────
const otpCodes = {
  create: null,
  findValid: null,
  markUsed: null,
  cleanup: null
};

// ── Wallet Operations ──────────────────────────────────────
const wallets = {
  findByUser: null,
  create: null,
  updateBalance: null,
  creditBalance: null,
  debitBalance: null
};

// ── Transaction Operations ────────────────────────────────
const transactions = {
  create: null,
  listByUser: null,
  countByUser: null
};

// ── Audit Operations ──────────────────────────────────────
const audit = {
  log: null,
  list: null
};

// ── Broadcast Operations ───────────────────────────────────
const broadcasts = {
  create: null,
  list: null
};

// ── Export Module ──────────────────────────────────────────
module.exports = {
  init,
  raw,
  users,
  sessions,
  otpCodes,
  wallets,
  transactions,
  audit,
  broadcasts
};