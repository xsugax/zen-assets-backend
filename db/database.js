/* ════════════════════════════════════════════════════════════
   database.js — SQLite Database Layer
   ZEN ASSETS Backend

   Initialises schema, seeds admin, provides CRUD helpers.
════════════════════════════════════════════════════════════ */

const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const bcrypt   = require('bcryptjs');
const { v4: uuid } = require('uuid');

let db;

// ── Initialise ──────────────────────────────────────────────
function init() {
  const dbPath = process.env.DB_PATH || './data/zen_assets.db';
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  db = new Database(dbPath);

  // Performance pragmas
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');

  createTables();
  seedAdmin();

  console.log('✅ Database ready:', dbPath);
  return db;
}

// ── Schema ──────────────────────────────────────────────────
function createTables() {
  db.exec(`
    -- Users table
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      email         TEXT UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      full_name     TEXT NOT NULL,
      role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
      tier          TEXT NOT NULL DEFAULT 'gold' CHECK(tier IN ('bronze','silver','gold','platinum','diamond')),
      status        TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','banned')),
      kyc_status    TEXT NOT NULL DEFAULT 'pending' CHECK(kyc_status IN ('pending','submitted','verified','rejected')),
      phone         TEXT,
      country       TEXT,
      created_at    TEXT NOT NULL DEFAULT (datetime('now')),
      last_login    TEXT,
      login_count   INTEGER DEFAULT 0,
      two_factor    INTEGER DEFAULT 0
    );

    -- Wallet — one per user
    CREATE TABLE IF NOT EXISTS wallets (
      id              TEXT PRIMARY KEY,
      user_id         TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      balance         REAL NOT NULL DEFAULT 0 CHECK(balance >= 0),
      initial_deposit REAL NOT NULL DEFAULT 0,
      total_deposited REAL NOT NULL DEFAULT 0,
      total_withdrawn REAL NOT NULL DEFAULT 0,
      total_earned    REAL NOT NULL DEFAULT 0,
      total_claimed   REAL NOT NULL DEFAULT 0,
      pending_earnings REAL NOT NULL DEFAULT 0,
      created_at      TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Transactions ledger — every money movement
    CREATE TABLE IF NOT EXISTS transactions (
      id             TEXT PRIMARY KEY,
      user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type           TEXT NOT NULL CHECK(type IN (
        'deposit','withdrawal','trade_profit','trade_loss',
        'bonus_daily','bonus_weekly','interest','claim',
        'admin_credit','admin_debit','fee'
      )),
      amount         REAL NOT NULL,
      status         TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','completed','rejected','cancelled')),
      method         TEXT,
      reference      TEXT,
      balance_before REAL,
      balance_after  REAL,
      notes          TEXT,
      created_at     TEXT NOT NULL DEFAULT (datetime('now')),
      processed_at   TEXT,
      processed_by   TEXT REFERENCES users(id)
    );

    -- Sessions — JWT tracking for revocation
    CREATE TABLE IF NOT EXISTS sessions (
      id         TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_jti  TEXT UNIQUE NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      revoked    INTEGER DEFAULT 0
    );

    -- Audit log
    CREATE TABLE IF NOT EXISTS audit_log (
      id         TEXT PRIMARY KEY,
      user_id    TEXT REFERENCES users(id),
      action     TEXT NOT NULL,
      severity   TEXT DEFAULT 'info' CHECK(severity IN ('info','warn','error','critical')),
      details    TEXT,
      ip_address TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- Trade history
    CREATE TABLE IF NOT EXISTS trades (
      id          TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      symbol      TEXT NOT NULL,
      side        TEXT NOT NULL CHECK(side IN ('buy','sell')),
      order_type  TEXT DEFAULT 'market' CHECK(order_type IN ('market','limit','stop','stop_limit')),
      quantity    REAL NOT NULL,
      entry_price REAL NOT NULL,
      exit_price  REAL,
      pnl         REAL DEFAULT 0,
      fee         REAL DEFAULT 0,
      status      TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed','cancelled','liquidated')),
      strategy    TEXT,
      notes       TEXT,
      opened_at   TEXT NOT NULL DEFAULT (datetime('now')),
      closed_at   TEXT
    );

    -- KYC document submissions
    CREATE TABLE IF NOT EXISTS kyc_documents (
      id              TEXT PRIMARY KEY,
      user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      doc_type        TEXT NOT NULL CHECK(doc_type IN ('passport','national_id','drivers_license','residence_permit')),
      doc_front       TEXT NOT NULL,
      doc_back        TEXT,
      selfie          TEXT,
      full_name       TEXT,
      date_of_birth   TEXT,
      country         TEXT,
      status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','superseded')),
      reviewer_id     TEXT REFERENCES users(id),
      reviewer_notes  TEXT,
      submitted_at    TEXT NOT NULL DEFAULT (datetime('now')),
      reviewed_at     TEXT
    );

    -- Indexes for performance
    CREATE INDEX IF NOT EXISTS idx_users_email        ON users(email);
    CREATE INDEX IF NOT EXISTS idx_wallets_user       ON wallets(user_id);
    CREATE INDEX IF NOT EXISTS idx_transactions_user  ON transactions(user_id);
    CREATE INDEX IF NOT EXISTS idx_transactions_type  ON transactions(type, status);
    CREATE INDEX IF NOT EXISTS idx_sessions_user      ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_jti       ON sessions(token_jti);
    CREATE INDEX IF NOT EXISTS idx_trades_user        ON trades(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_user         ON audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_kyc_user           ON kyc_documents(user_id);
    CREATE INDEX IF NOT EXISTS idx_kyc_status         ON kyc_documents(status);
  `);
}

// ── Seed Admin User ─────────────────────────────────────────
function seedAdmin() {
  const email = process.env.ADMIN_EMAIL || 'admin@zenassets.com';
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) return;

  const password = process.env.ADMIN_PASSWORD || 'ZenAdmin2026!';
  const hash = bcrypt.hashSync(password, 12);
  const id = uuid();

  db.prepare(`
    INSERT INTO users (id, email, password_hash, full_name, role, tier, status, kyc_status)
    VALUES (?, ?, ?, ?, 'admin', 'diamond', 'active', 'verified')
  `).run(id, email, hash, process.env.ADMIN_NAME || 'ZEN Admin');

  db.prepare(`
    INSERT INTO wallets (id, user_id, balance, initial_deposit)
    VALUES (?, ?, 0, 0)
  `).run(uuid(), id);

  console.log(`🔐 Admin seeded: ${email}`);
}

// ═══════════════════════════════════════════════════════════
//  CRUD HELPERS
// ═══════════════════════════════════════════════════════════

// ── Users ───────────────────────────────────────────────────
const users = {
  findByEmail(email) {
    return db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE').get(email);
  },
  findById(id) {
    return db.prepare('SELECT id, email, full_name, role, tier, status, kyc_status, phone, country, created_at, last_login, login_count, two_factor FROM users WHERE id = ?').get(id);
  },
  create({ email, passwordHash, fullName, tier = 'gold', role = 'user' }) {
    const id = uuid();
    db.prepare(`
      INSERT INTO users (id, email, password_hash, full_name, tier, role)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, email.toLowerCase(), passwordHash, fullName, tier, role);
    return id;
  },
  updateLogin(id) {
    db.prepare(`
      UPDATE users SET last_login = datetime('now'), login_count = login_count + 1 WHERE id = ?
    `).run(id);
  },
  updateStatus(id, status) {
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, id);
  },
  updateTier(id, tier) {
    db.prepare('UPDATE users SET tier = ? WHERE id = ?').run(tier, id);
  },
  updateKYC(id, kycStatus) {
    db.prepare('UPDATE users SET kyc_status = ? WHERE id = ?').run(kycStatus, id);
  },
  list({ page = 1, limit = 20, search = '', status = '', tier = '' } = {}) {
    let where = 'WHERE role != \'admin\'';
    const params = [];
    if (search) { where += ' AND (email LIKE ? OR full_name LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
    if (status) { where += ' AND status = ?'; params.push(status); }
    if (tier)   { where += ' AND tier = ?'; params.push(tier); }

    const total = db.prepare(`SELECT COUNT(*) as count FROM users ${where}`).get(...params).count;
    const offset = (page - 1) * limit;
    const rows = db.prepare(`
      SELECT u.id, u.email, u.full_name, u.role, u.tier, u.status, u.kyc_status,
             u.created_at, u.last_login, u.login_count,
             w.balance, w.total_deposited, w.total_withdrawn, w.total_earned
      FROM users u LEFT JOIN wallets w ON w.user_id = u.id
      ${where}
      ORDER BY u.created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);

    return { users: rows, total, page, pages: Math.ceil(total / limit) };
  },
  count() {
    return db.prepare('SELECT COUNT(*) as count FROM users WHERE role != \'admin\'').get().count;
  },
  delete(id) {
    return db.prepare('DELETE FROM users WHERE id = ? AND role != \'admin\'').run(id);
  },
};

// ── Wallets ─────────────────────────────────────────────────
const wallets = {
  findByUser(userId) {
    return db.prepare('SELECT * FROM wallets WHERE user_id = ?').get(userId);
  },
  create(userId, initialDeposit = 0) {
    const id = uuid();
    db.prepare(`
      INSERT INTO wallets (id, user_id, balance, initial_deposit, total_deposited)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, userId, initialDeposit, initialDeposit, initialDeposit);
    return id;
  },
  creditBalance(userId, amount, reason = '') {
    const wallet = this.findByUser(userId);
    if (!wallet) throw new Error('Wallet not found');
    const newBalance = wallet.balance + amount;
    db.prepare(`
      UPDATE wallets SET balance = ?, total_earned = total_earned + ?, updated_at = datetime('now') WHERE user_id = ?
    `).run(newBalance, amount, userId);
    return { before: wallet.balance, after: newBalance };
  },
  debitBalance(userId, amount) {
    const wallet = this.findByUser(userId);
    if (!wallet) throw new Error('Wallet not found');
    if (wallet.balance < amount) throw new Error('Insufficient balance');
    const newBalance = wallet.balance - amount;
    db.prepare(`
      UPDATE wallets SET balance = ?, updated_at = datetime('now') WHERE user_id = ?
    `).run(newBalance, userId);
    return { before: wallet.balance, after: newBalance };
  },
  addDeposit(userId, amount) {
    const wallet = this.findByUser(userId);
    if (!wallet) throw new Error('Wallet not found');
    const newBalance = wallet.balance + amount;
    db.prepare(`
      UPDATE wallets SET balance = ?, total_deposited = total_deposited + ?, updated_at = datetime('now') WHERE user_id = ?
    `).run(newBalance, amount, userId);
    return { before: wallet.balance, after: newBalance };
  },
  processWithdrawal(userId, amount) {
    const wallet = this.findByUser(userId);
    if (!wallet) throw new Error('Wallet not found');
    if (wallet.balance < amount) throw new Error('Insufficient balance');
    const newBalance = wallet.balance - amount;
    db.prepare(`
      UPDATE wallets SET balance = ?, total_withdrawn = total_withdrawn + ?, updated_at = datetime('now') WHERE user_id = ?
    `).run(newBalance, amount, userId);
    return { before: wallet.balance, after: newBalance };
  },
  setBalance(userId, newBalance) {
    db.prepare(`
      UPDATE wallets SET balance = ?, updated_at = datetime('now') WHERE user_id = ?
    `).run(newBalance, userId);
  },
};

// ── Transactions ────────────────────────────────────────────
const transactions = {
  create({ userId, type, amount, status = 'pending', method, reference, balanceBefore, balanceAfter, notes }) {
    const id = uuid();
    db.prepare(`
      INSERT INTO transactions (id, user_id, type, amount, status, method, reference, balance_before, balance_after, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, userId, type, amount, status, method, reference, balanceBefore, balanceAfter, notes);
    return id;
  },
  findById(id) {
    return db.prepare('SELECT * FROM transactions WHERE id = ?').get(id);
  },
  updateStatus(id, status, processedBy = null) {
    db.prepare(`
      UPDATE transactions SET status = ?, processed_at = datetime('now'), processed_by = ? WHERE id = ?
    `).run(status, processedBy, id);
  },
  listByUser(userId, { page = 1, limit = 20, type = '' } = {}) {
    let where = 'WHERE user_id = ?';
    const params = [userId];
    if (type) { where += ' AND type = ?'; params.push(type); }
    const total = db.prepare(`SELECT COUNT(*) as count FROM transactions ${where}`).get(...params).count;
    const offset = (page - 1) * limit;
    const rows = db.prepare(`SELECT * FROM transactions ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
    return { transactions: rows, total, page, pages: Math.ceil(total / limit) };
  },
  listPending(type = '') {
    let q = 'SELECT t.*, u.email, u.full_name FROM transactions t JOIN users u ON u.id = t.user_id WHERE t.status = \'pending\'';
    if (type) q += ' AND t.type = ?';
    q += ' ORDER BY t.created_at ASC';
    return type ? db.prepare(q).all(type) : db.prepare(q).all();
  },
  stats() {
    return db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END) as total_volume,
        SUM(CASE WHEN type = 'deposit' AND status = 'completed' THEN amount ELSE 0 END) as total_deposits,
        SUM(CASE WHEN type = 'withdrawal' AND status = 'completed' THEN amount ELSE 0 END) as total_withdrawals,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count
      FROM transactions
    `).get();
  },
};

// ── Sessions ────────────────────────────────────────────────
const sessions = {
  create({ userId, tokenJti, ipAddress, userAgent, expiresAt }) {
    const id = uuid();
    db.prepare(`
      INSERT INTO sessions (id, user_id, token_jti, ip_address, user_agent, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, userId, tokenJti, ipAddress, userAgent, expiresAt);
    return id;
  },
  findByJti(jti) {
    return db.prepare('SELECT * FROM sessions WHERE token_jti = ? AND revoked = 0').get(jti);
  },
  revoke(jti) {
    db.prepare('UPDATE sessions SET revoked = 1 WHERE token_jti = ?').run(jti);
  },
  revokeAllForUser(userId) {
    db.prepare('UPDATE sessions SET revoked = 1 WHERE user_id = ?').run(userId);
  },
  cleanup() {
    db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now') OR revoked = 1").run();
  },
};

// ── Audit Log ───────────────────────────────────────────────
const audit = {
  log(userId, action, details = '', severity = 'info', ipAddress = '') {
    const id = uuid();
    db.prepare(`
      INSERT INTO audit_log (id, user_id, action, severity, details, ip_address)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, userId, action, severity, typeof details === 'object' ? JSON.stringify(details) : details, ipAddress);
  },
  list({ page = 1, limit = 50, userId = '', severity = '' } = {}) {
    let where = 'WHERE 1=1';
    const params = [];
    if (userId) { where += ' AND a.user_id = ?'; params.push(userId); }
    if (severity) { where += ' AND a.severity = ?'; params.push(severity); }
    const total = db.prepare(`SELECT COUNT(*) as count FROM audit_log a ${where}`).get(...params).count;
    const offset = (page - 1) * limit;
    const rows = db.prepare(`
      SELECT a.*, u.email, u.full_name
      FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
      ${where}
      ORDER BY a.created_at DESC LIMIT ? OFFSET ?
    `).all(...params, limit, offset);
    return { logs: rows, total, page, pages: Math.ceil(total / limit) };
  },
};

// ── Trades ──────────────────────────────────────────────────
const trades = {
  create({ userId, symbol, side, orderType = 'market', quantity, entryPrice, strategy }) {
    const id = uuid();
    db.prepare(`
      INSERT INTO trades (id, user_id, symbol, side, order_type, quantity, entry_price, strategy)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, userId, symbol, side, orderType, quantity, entryPrice, strategy);
    return id;
  },
  close(id, exitPrice, pnl, fee = 0) {
    db.prepare(`
      UPDATE trades SET exit_price = ?, pnl = ?, fee = ?, status = 'closed', closed_at = datetime('now') WHERE id = ?
    `).run(exitPrice, pnl, fee, id);
  },
  listByUser(userId, { page = 1, limit = 20, status = '' } = {}) {
    let where = 'WHERE user_id = ?';
    const params = [userId];
    if (status) { where += ' AND status = ?'; params.push(status); }
    const total = db.prepare(`SELECT COUNT(*) as count FROM trades ${where}`).get(...params).count;
    const offset = (page - 1) * limit;
    const rows = db.prepare(`SELECT * FROM trades ${where} ORDER BY opened_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
    return { trades: rows, total, page, pages: Math.ceil(total / limit) };
  },
  openPositions(userId) {
    return db.prepare('SELECT * FROM trades WHERE user_id = ? AND status = \'open\' ORDER BY opened_at DESC').all(userId);
  },
  stats(userId) {
    return db.prepare(`
      SELECT
        COUNT(*) as total_trades,
        SUM(CASE WHEN pnl > 0 THEN 1 ELSE 0 END) as wins,
        SUM(CASE WHEN pnl < 0 THEN 1 ELSE 0 END) as losses,
        SUM(pnl) as total_pnl,
        AVG(pnl) as avg_pnl,
        MAX(pnl) as best_trade,
        MIN(pnl) as worst_trade
      FROM trades WHERE user_id = ? AND status = 'closed'
    `).get(userId);
  },
};

// ── Raw DB access ───────────────────────────────────────────
function raw() { return db; }

module.exports = {
  init, raw,
  users, wallets, transactions, sessions, audit, trades,
};
