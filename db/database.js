/* ════════════════════════════════════════════════════════════
   db/database.js — ZEN ASSETS Database Module
   SQLite + Better-SQLite3 — high-level facade API for routes
════════════════════════════════════════════════════════════ */

const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');
const path     = require('path');
const fs       = require('fs');

const DB_PATH = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.join(__dirname, '../data/zen_assets.db');

if (!fs.existsSync(path.dirname(DB_PATH))) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

let db = null;
const _stmts = {};

function init() {
  if (db) return;
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  createTables();
  migrateSchema();
  prepareStatements();
  seedAdmin();
  console.log(`[DB] Connected to SQLite database at ${DB_PATH}`);
}

/** Ensure admin exists on server (Render env: ADMIN_EMAIL / ADMIN_PASSWORD) */
function seedAdmin() {
  const email = (process.env.ADMIN_EMAIL || 'admin@zenassets.com').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  const fullName = process.env.ADMIN_NAME || 'ZEN Admin';
  if (!password) {
    console.warn('[DB] ADMIN_PASSWORD not set — admin seed skipped');
    return;
  }
  const hash = bcrypt.hashSync(password, 12);
  const existing = users.findByEmail(email);
  if (!existing) {
    const id = crypto.randomUUID();
    db.prepare(`
      INSERT INTO users (id, email, password_hash, full_name, role, tier, status, email_verified)
      VALUES (?, ?, ?, ?, 'admin', 'diamond', 'active', 1)
    `).run(id, email, hash, fullName);
    wallets.create(id, 0);
    console.log(`[DB] Admin account created: ${email}`);
    return;
  }
  if (process.env.SYNC_ADMIN_PASSWORD === 'true') {
    db.prepare(`
      UPDATE users SET password_hash = ?, full_name = ?, role = 'admin', status = 'active', email_verified = 1
      WHERE email = ?
    `).run(hash, fullName, email);
    console.log(`[DB] Admin password synced (SYNC_ADMIN_PASSWORD): ${email}`);
  } else {
    db.prepare(`
      UPDATE users SET full_name = ?, role = 'admin', status = 'active', email_verified = 1 WHERE email = ?
    `).run(fullName, email);
  }
  if (!wallets.findByUser(existing.id)) wallets.create(existing.id, 0);
}

function migrateSchema() {
  const cols = db.prepare('PRAGMA table_info(users)').all();
  if (!cols.some(c => c.name === 'settings_json')) {
    db.exec(`ALTER TABLE users ADD COLUMN settings_json TEXT NOT NULL DEFAULT '{}'`);
    console.log('[DB] Added users.settings_json column');
  }
}

function createTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      tier TEXT DEFAULT 'gold',
      status TEXT DEFAULT 'active',
      kyc_status TEXT DEFAULT 'none',
      email_verified INTEGER DEFAULT 0,
      pin_hash TEXT,
      last_login TEXT,
      settings_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      token_jti TEXT UNIQUE NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      expires_at DATETIME NOT NULL,
      revoked INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
      session_jti TEXT,
      ip_address TEXT,
      user_agent TEXT,
      expires_at DATETIME NOT NULL,
      revoked INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS otp_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      code TEXT NOT NULL,
      type TEXT NOT NULL,
      expires_at DATETIME NOT NULL,
      used INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS wallets (
      id TEXT PRIMARY KEY,
      user_id TEXT UNIQUE NOT NULL,
      balance REAL DEFAULT 0.0,
      initial_deposit REAL DEFAULT 0,
      total_deposited REAL DEFAULT 0,
      total_withdrawn REAL DEFAULT 0,
      total_earned REAL DEFAULT 0,
      total_claimed REAL DEFAULT 0,
      pending_earnings REAL DEFAULT 0,
      currency TEXT DEFAULT 'USD',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      balance_before REAL DEFAULT 0,
      balance_after REAL DEFAULT 0,
      method TEXT,
      reference_id TEXT,
      notes TEXT,
      status TEXT DEFAULT 'completed',
      admin_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS trades (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      symbol TEXT NOT NULL,
      side TEXT NOT NULL,
      order_type TEXT DEFAULT 'market',
      quantity REAL NOT NULL,
      entry_price REAL NOT NULL,
      exit_price REAL,
      pnl REAL DEFAULT 0,
      fee REAL DEFAULT 0,
      status TEXT DEFAULT 'open',
      strategy TEXT,
      notes TEXT,
      opened_at TEXT,
      closed_at TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      action TEXT NOT NULL,
      details TEXT,
      severity TEXT DEFAULT 'info',
      ip_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS broadcasts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_id TEXT NOT NULL,
      subject TEXT NOT NULL,
      message TEXT NOT NULL,
      recipient_emails TEXT NOT NULL,
      sent_count INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS kyc_documents (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      doc_type TEXT,
      doc_front TEXT,
      doc_back TEXT,
      selfie TEXT,
      full_name TEXT,
      date_of_birth TEXT,
      country TEXT,
      status TEXT DEFAULT 'pending',
      reviewed_by TEXT,
      review_notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      reviewed_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS platform_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  try {
    db.exec(`ALTER TABLE users ADD COLUMN country TEXT`);
  } catch (_) { /* column exists */ }
}

function prepareStatements() {
  _stmts.userInsert = db.prepare(`
    INSERT INTO users (id, email, password_hash, full_name, role, tier, status, email_verified)
    VALUES (?, ?, ?, ?, 'user', ?, 'active', 1)
  `);
  _stmts.userByEmail = db.prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
  _stmts.userById = db.prepare('SELECT * FROM users WHERE id = ? LIMIT 1');
  _stmts.sessionInsert = db.prepare(`
    INSERT INTO sessions (user_id, token_jti, ip_address, user_agent, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `);
  _stmts.sessionByJti = db.prepare(`
    SELECT * FROM sessions
    WHERE token_jti = ? AND revoked = 0 AND expires_at > datetime('now')
    LIMIT 1
  `);
  _stmts.sessionRevoke = db.prepare('UPDATE sessions SET revoked = 1 WHERE token_jti = ?');
  _stmts.sessionRevokeAll = db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ?');
  _stmts.sessionsByUser = db.prepare(`
    SELECT id, token_jti, ip_address, user_agent, expires_at, revoked, created_at
    FROM sessions WHERE user_id = ? AND revoked = 0 AND expires_at > datetime('now')
    ORDER BY created_at DESC
  `);
  _stmts.refreshInsert = db.prepare(`
    INSERT INTO refresh_tokens (user_id, token_hash, session_jti, ip_address, user_agent, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  _stmts.refreshByHash = db.prepare(`
    SELECT * FROM refresh_tokens
    WHERE token_hash = ? AND revoked = 0 AND expires_at > datetime('now')
    LIMIT 1
  `);
  _stmts.refreshRevoke = db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?');
  _stmts.refreshRevokeAll = db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?');
  _stmts.walletByUser = db.prepare('SELECT * FROM wallets WHERE user_id = ? LIMIT 1');
  _stmts.walletInsert = db.prepare(`
    INSERT INTO wallets (id, user_id, balance, initial_deposit, total_deposited)
    VALUES (?, ?, ?, ?, ?)
  `);
}

function raw() {
  if (!db) throw new Error('Database not initialized');
  return db;
}

function _parseExpiresIn(str) {
  const m = String(str || '30d').match(/^(\d+)([smhd])$/i);
  if (!m) return 30 * 24 * 60 * 60 * 1000;
  const n = parseInt(m[1], 10);
  const u = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
  return n * (u[m[2].toLowerCase()] || 86400000);
}

// ── Users ───────────────────────────────────────────────────
const users = {
  create({ email, passwordHash, fullName, tier = 'gold' }) {
    const id = crypto.randomUUID();
    _stmts.userInsert.run(id, email.toLowerCase().trim(), passwordHash, fullName, tier);
    return id;
  },
  findByEmail(email) {
    return _stmts.userByEmail.get((email || '').toLowerCase().trim()) || null;
  },
  findById(id) {
    return _stmts.userById.get(id) || null;
  },
  setPin(userId, pinHash) {
    db.prepare('UPDATE users SET pin_hash = ? WHERE id = ?').run(pinHash, userId);
  },
  updateLogin(userId) {
    db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(userId);
  },
  updateStatus(userId, status) {
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, userId);
  },
  updateTier(userId, tier) {
    db.prepare('UPDATE users SET tier = ? WHERE id = ?').run(tier, userId);
  },
  updateKYC(userId, kycStatus) {
    db.prepare('UPDATE users SET kyc_status = ? WHERE id = ?').run(kycStatus, userId);
  },
  updateFullName(userId, fullName) {
    const name = (fullName || '').trim();
    if (!name) return;
    db.prepare('UPDATE users SET full_name = ? WHERE id = ?').run(name, userId);
  },
  getSettings(userId) {
    const row = db.prepare('SELECT settings_json FROM users WHERE id = ?').get(userId);
    if (!row) return {};
    try {
      return JSON.parse(row.settings_json || '{}');
    } catch {
      return {};
    }
  },
  updateSettings(userId, settingsObj) {
    const json = JSON.stringify(settingsObj || {});
    db.prepare('UPDATE users SET settings_json = ? WHERE id = ?').run(json, userId);
  },
  delete(userId) {
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  },
  count() {
    return db.prepare("SELECT COUNT(*) as c FROM users WHERE role != 'admin'").get().c;
  },
  list({ page = 1, limit = 20, search = '', status = '', tier = '' } = {}) {
    let sql = `
      SELECT u.id, u.email, u.full_name, u.role, u.tier, u.status, u.kyc_status,
             u.email_verified, u.last_login, u.created_at, u.settings_json,
             COALESCE(w.balance, 0) AS balance,
             COALESCE(w.total_deposited, 0) AS total_deposited
      FROM users u
      LEFT JOIN wallets w ON w.user_id = u.id
      WHERE u.role != 'admin'`;
    const params = [];
    if (search) {
      sql += ' AND (u.email LIKE ? OR u.full_name LIKE ?)';
      const q = `%${search}%`;
      params.push(q, q);
    }
    if (status) { sql += ' AND u.status = ?'; params.push(status); }
    if (tier) { sql += ' AND u.tier = ?'; params.push(tier); }
    const countSql = sql.replace(/SELECT[\s\S]+?FROM users u/, 'SELECT COUNT(*) AS total FROM users u');
    const total = db.prepare(countSql).get(...params).total;
    sql += ' ORDER BY u.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, (page - 1) * limit);
    const usersList = db.prepare(sql).all(...params);
    return { users: usersList, total, page, limit, pages: Math.ceil(total / limit) || 1 };
  },
};

// ── Sessions ──────────────────────────────────────────────────
const sessions = {
  create({ userId, tokenJti, ipAddress = '', userAgent = '', expiresAt }) {
    _stmts.sessionInsert.run(userId, tokenJti, ipAddress, userAgent, expiresAt);
  },
  findByJti(jti) {
    return _stmts.sessionByJti.get(jti) || null;
  },
  findByToken(jti) {
    return sessions.findByJti(jti);
  },
  revoke(jti) {
    _stmts.sessionRevoke.run(jti);
  },
  revokeAllForUser(userId) {
    _stmts.sessionRevokeAll.run(userId);
  },
  revokeAllExcept(userId, exceptJti) {
    db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND token_jti != ?')
      .run(userId, exceptJti);
  },
  listByUser(userId) {
    return _stmts.sessionsByUser.all(userId);
  },
  cleanup() {
    const r = db.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now') OR revoked = 1").run();
    if (r.changes > 0) console.log(`[DB] Cleaned up ${r.changes} expired/revoked sessions`);
    db.prepare("DELETE FROM refresh_tokens WHERE expires_at <= datetime('now') OR revoked = 1").run();
  },
};

// ── Refresh tokens ────────────────────────────────────────────
const refreshTokens = {
  create({ userId, sessionJti, ipAddress = '', userAgent = '' }) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const ms = _parseExpiresIn(process.env.REFRESH_EXPIRES_IN || '30d');
    const expiresAt = new Date(Date.now() + ms).toISOString();
    _stmts.refreshInsert.run(userId, tokenHash, sessionJti || null, ipAddress, userAgent, expiresAt);
    return { refreshToken: rawToken, expiresAt };
  },
  findByRawToken(rawToken) {
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    return _stmts.refreshByHash.get(tokenHash) || null;
  },
  revoke(rawToken) {
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    _stmts.refreshRevoke.run(tokenHash);
  },
  revokeAllForUser(userId) {
    _stmts.refreshRevokeAll.run(userId);
  },
};

// ── OTP ─────────────────────────────────────────────────────
const otpCodes = {
  create(userId, code, type, ttlMinutes) {
    const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();
    db.prepare('INSERT INTO otp_codes (user_id, code, type, expires_at) VALUES (?, ?, ?, ?)')
      .run(userId, code, type, expiresAt);
  },
  verify(userId, code, type) {
    const row = db.prepare(`
      SELECT * FROM otp_codes
      WHERE user_id = ? AND code = ? AND type = ? AND expires_at > datetime('now') AND used = 0
      LIMIT 1
    `).get(userId, code, type);
    if (!row) return { ok: false, error: 'Invalid or expired code' };
    db.prepare('UPDATE otp_codes SET used = 1 WHERE id = ?').run(row.id);
    return { ok: true };
  },
  recentlySent(userId, type) {
    const row = db.prepare(`
      SELECT created_at FROM otp_codes
      WHERE user_id = ? AND type = ? AND created_at > datetime('now', '-60 seconds')
      ORDER BY created_at DESC LIMIT 1
    `).get(userId, type);
    return !!row;
  },
  cleanup() {
    const r = db.prepare("DELETE FROM otp_codes WHERE expires_at <= datetime('now') OR used = 1").run();
    if (r.changes > 0) console.log(`[DB] Cleaned up ${r.changes} OTP codes`);
  },
};

// ── Wallets ─────────────────────────────────────────────────
const wallets = {
  findByUser(userId) {
    return _stmts.walletByUser.get(userId) || null;
  },
  create(userId, initialDeposit = 0) {
    const walletId = crypto.randomUUID();
    const dep = parseFloat(initialDeposit) || 0;
    _stmts.walletInsert.run(walletId, userId, dep, dep, dep > 0 ? dep : 0);
  },
  setBalance(userId, amount) {
    const bal = parseFloat(amount) || 0;
    db.prepare(`
      UPDATE wallets SET balance = ?, initial_deposit = ?, total_deposited = ?,
        updated_at = datetime('now') WHERE user_id = ?
    `).run(bal, bal, bal, userId);
  },
  addDeposit(userId, amount) {
    const wallet = wallets.findByUser(userId);
    if (!wallet) {
      wallets.create(userId, amount);
      return { before: 0, after: amount };
    }
    const dep = parseFloat(amount) || 0;
    const after = wallet.balance + dep;
    db.prepare(`
      UPDATE wallets SET balance = ?, total_deposited = total_deposited + ?,
        updated_at = datetime('now') WHERE user_id = ?
    `).run(after, dep, userId);
    return { before: wallet.balance, after };
  },
  creditBalance(userId, amount) {
    const wallet = wallets.findByUser(userId);
    if (!wallet) {
      wallets.create(userId, amount);
      return { before: 0, after: amount };
    }
    const dep = parseFloat(amount) || 0;
    const after = wallet.balance + dep;
    db.prepare('UPDATE wallets SET balance = ?, updated_at = datetime(\'now\') WHERE user_id = ?').run(after, userId);
    return { before: wallet.balance, after };
  },
  debitBalance(userId, amount) {
    const wallet = wallets.findByUser(userId);
    if (!wallet || wallet.balance < amount) throw new Error('Insufficient balance');
    const after = wallet.balance - amount;
    db.prepare('UPDATE wallets SET balance = ?, updated_at = datetime(\'now\') WHERE user_id = ?').run(after, userId);
    return { before: wallet.balance, after };
  },
  processWithdrawal(userId, amount) {
    return wallets.debitBalance(userId, amount);
  },
  addPendingEarnings(userId, amount) {
    const wallet = wallets.findByUser(userId);
    const dep = parseFloat(amount) || 0;
    if (!wallet) {
      wallets.create(userId, 0);
    }
    db.prepare(`
      UPDATE wallets SET
        pending_earnings = pending_earnings + ?,
        total_earned = total_earned + ?,
        updated_at = datetime('now')
      WHERE user_id = ?
    `).run(dep, dep, userId);
    const w = wallets.findByUser(userId);
    return { pendingEarnings: w.pending_earnings };
  },
  recordWithdrawalCompleted(userId, amount) {
    const abs = Math.abs(parseFloat(amount) || 0);
    db.prepare(`
      UPDATE wallets SET
        total_withdrawn = total_withdrawn + ?,
        updated_at = datetime('now')
      WHERE user_id = ?
    `).run(abs, userId);
  },
};

// ── Transactions ──────────────────────────────────────────────
const transactions = {
  create(opts) {
    const id = crypto.randomUUID();
    const {
      userId, type, amount, status = 'completed', method = null, reference = null,
      balanceBefore = 0, balanceAfter = null, notes = null,
    } = opts;
    const after = balanceAfter != null ? balanceAfter : balanceBefore;
    db.prepare(`
      INSERT INTO transactions (id, user_id, type, amount, balance_before, balance_after, method, reference_id, notes, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, userId, type, amount, balanceBefore, after, method, reference, notes, status);
    return id;
  },
  findById(id) {
    return db.prepare('SELECT * FROM transactions WHERE id = ?').get(id) || null;
  },
  listByUser(userId, { page = 1, limit = 20, type = '' } = {}) {
    let sql = 'SELECT * FROM transactions WHERE user_id = ?';
    const params = [userId];
    if (type) { sql += ' AND type = ?'; params.push(type); }
    const total = db.prepare(sql.replace('SELECT *', 'SELECT COUNT(*) as total')).get(...params).total;
    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, (page - 1) * limit);
    return { transactions: db.prepare(sql).all(...params), total, page, limit };
  },
  listPending(txType) {
    return db.prepare(`
      SELECT t.*, u.email, u.full_name FROM transactions t
      JOIN users u ON t.user_id = u.id
      WHERE t.type = ? AND t.status = 'pending' ORDER BY t.created_at DESC
    `).all(txType);
  },
  updateStatus(id, status, adminId = null) {
    db.prepare('UPDATE transactions SET status = ?, admin_id = ? WHERE id = ?').run(status, adminId, id);
  },
  stats() {
    const row = db.prepare(`
      SELECT
        COUNT(*) as total_transactions,
        COALESCE(SUM(CASE WHEN type = 'deposit' AND status = 'completed' THEN amount ELSE 0 END), 0) as total_deposits,
        COALESCE(SUM(CASE WHEN type = 'withdrawal' AND status = 'completed' THEN ABS(amount) ELSE 0 END), 0) as total_withdrawals,
        COUNT(CASE WHEN type = 'withdrawal' AND status = 'pending' THEN 1 END) as pending_withdrawals
      FROM transactions
    `).get();
    return row;
  },
};

// ── Trades ────────────────────────────────────────────────────
const trades = {
  stats(userId) {
    const row = db.prepare(`
      SELECT
        COUNT(*) as total_trades,
        COALESCE(SUM(CASE WHEN pnl > 0 THEN 1 ELSE 0 END), 0) as wins,
        COALESCE(SUM(CASE WHEN pnl < 0 THEN 1 ELSE 0 END), 0) as losses,
        COALESCE(SUM(pnl), 0) as total_pnl
      FROM trades WHERE user_id = ? AND status = 'closed'
    `).get(userId);
    return {
      total_trades: row.total_trades || 0,
      wins: row.wins || 0,
      losses: row.losses || 0,
      total_pnl: row.total_pnl || 0,
    };
  },
  listByUser(userId, { page = 1, limit = 20, status = '' } = {}) {
    let sql = 'SELECT * FROM trades WHERE user_id = ?';
    const params = [userId];
    if (status) { sql += ' AND status = ?'; params.push(status); }
    const total = db.prepare(sql.replace('SELECT *', 'SELECT COUNT(*) as total')).get(...params).total;
    sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, (page - 1) * limit);
    return { trades: db.prepare(sql).all(...params), total, page, limit };
  },
  openPositions(userId) {
    return db.prepare("SELECT * FROM trades WHERE user_id = ? AND status = 'open' ORDER BY opened_at DESC").all(userId);
  },
  close(tradeId, exitPrice, pnl, fee) {
    db.prepare(`
      UPDATE trades SET exit_price = ?, pnl = ?, fee = ?, status = 'closed',
        closed_at = datetime('now') WHERE id = ?
    `).run(exitPrice, pnl, fee, tradeId);
  },
};

// ── Audit ─────────────────────────────────────────────────────
const audit = {
  log(userId, action, details, severity = 'info', ip = null) {
    const detailsStr = details == null ? null : (typeof details === 'string' ? details : JSON.stringify(details));
    db.prepare('INSERT INTO audit_log (user_id, action, details, severity, ip_address) VALUES (?, ?, ?, ?, ?)')
      .run(userId, action, detailsStr, severity, ip);
  },
  list({ page = 1, limit = 50, userId = '', severity = '' } = {}) {
    let sql = 'SELECT a.*, u.email FROM audit_log a LEFT JOIN users u ON a.user_id = u.id WHERE 1=1';
    const params = [];
    if (userId) { sql += ' AND a.user_id = ?'; params.push(userId); }
    if (severity) { sql += ' AND a.severity = ?'; params.push(severity); }
    const total = db.prepare(sql.replace(/SELECT .+ FROM/, 'SELECT COUNT(*) as total FROM')).get(...params).total;
    sql += ' ORDER BY a.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, (page - 1) * limit);
    return { entries: db.prepare(sql).all(...params), total, page, limit };
  },
};

const broadcasts = {
  create(adminId, subject, message, recipientEmails) {
    db.prepare('INSERT INTO broadcasts (admin_id, subject, message, recipient_emails) VALUES (?, ?, ?, ?)')
      .run(adminId, subject, message, JSON.stringify(recipientEmails));
  },
  list({ page = 1, limit = 20 } = {}) {
    const rows = db.prepare(`
      SELECT b.*, u.email as admin_email FROM broadcasts b
      JOIN users u ON b.admin_id = u.id ORDER BY b.created_at DESC LIMIT ? OFFSET ?
    `).all(limit, (page - 1) * limit);
    return { broadcasts: rows };
  },
  listForUser(email, limit = 30) {
    const rows = db.prepare(`
      SELECT id, subject, message, recipient_emails, created_at FROM broadcasts ORDER BY created_at DESC LIMIT 100
    `).all();
    const norm = (email || '').trim().toLowerCase();
    return rows.filter((b) => {
      try {
        const list = JSON.parse(b.recipient_emails || '[]');
        if (!Array.isArray(list) || list.length === 0) return true;
        return list.some((e) => String(e).toLowerCase() === norm);
      } catch {
        return true;
      }
    }).slice(0, limit);
  },
};

const DEFAULT_PLATFORM_CONFIG = {
  registration: true,
  trading: true,
  autoTrader: true,
  withdrawals: true,
  maintenance: false,
};

const platformSettings = {
  get() {
    const out = { ...DEFAULT_PLATFORM_CONFIG };
    try {
      const rows = db.prepare('SELECT key, value FROM platform_settings').all();
      rows.forEach((r) => {
        try { out[r.key] = JSON.parse(r.value); } catch { out[r.key] = r.value; }
      });
    } catch { /* table may not exist yet */ }
    return out;
  },
  set(patch) {
    Object.entries(patch).forEach(([key, val]) => {
      db.prepare(`
        INSERT INTO platform_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')
      `).run(key, JSON.stringify(val));
    });
    return platformSettings.get();
  },
};

module.exports = {
  init,
  raw,
  users,
  sessions,
  refreshTokens,
  otpCodes,
  wallets,
  transactions,
  trades,
  audit,
  broadcasts,
  platformSettings,
};
