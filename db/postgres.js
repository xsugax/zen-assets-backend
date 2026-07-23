/* ════════════════════════════════════════════════════════════
   db/postgres.js — PostgreSQL Database Module
   ZEN ASSETS Backend
   
   Mirrors the exact API surface of db/database.js so routes
   work seamlessly with either SQLite or PostgreSQL.
   Auto-activated when DATABASE_URL environment variable is set.
════════════════════════════════════════════════════════════ */

const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');

let pool = null;
let connected = false;

// ── Connection ────────────────────────────────────────────
function getPool() {
  if (pool) return pool;
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL not set');
  pool = new Pool({
    connectionString: url,
    ssl: process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
  });
  return pool;
}

async function query(sql, params = []) {
  const client = await getPool().connect();
  try {
    const result = await client.query(sql, params);
    return result;
  } finally {
    client.release();
  }
}

function _uuid() { return crypto.randomUUID(); }
function _now() { return new Date().toISOString(); }
function _parseExpiresIn(str) {
  const m = String(str || '30d').match(/^(\d+)([smhd])$/i);
  if (!m) return 30 * 24 * 60 * 60 * 1000;
  const n = parseInt(m[1], 10);
  const u = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
  return n * (u[m[2].toLowerCase()] || 86400000);
}

// ── Schema Creation ───────────────────────────────────────
async function createSchema() {
  await query(`
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
      last_login TIMESTAMPTZ,
      settings_json TEXT NOT NULL DEFAULT '{}',
      country TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_jti TEXT UNIQUE NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      revoked INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT UNIQUE NOT NULL,
      session_jti TEXT,
      ip_address TEXT,
      user_agent TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      revoked INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS otp_codes (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      code TEXT NOT NULL,
      type TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS wallets (
      id TEXT PRIMARY KEY,
      user_id TEXT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      balance REAL DEFAULT 0.0,
      initial_deposit REAL DEFAULT 0,
      total_deposited REAL DEFAULT 0,
      total_withdrawn REAL DEFAULT 0,
      total_earned REAL DEFAULT 0,
      total_claimed REAL DEFAULT 0,
      pending_earnings REAL DEFAULT 0,
      currency TEXT DEFAULT 'USD',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      balance_before REAL DEFAULT 0,
      balance_after REAL DEFAULT 0,
      method TEXT,
      reference_id TEXT,
      notes TEXT,
      status TEXT DEFAULT 'completed',
      admin_id TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS trades (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
      opened_at TIMESTAMPTZ,
      closed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY,
      user_id TEXT,
      action TEXT NOT NULL,
      details TEXT,
      severity TEXT DEFAULT 'info',
      ip_address TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS broadcasts (
      id SERIAL PRIMARY KEY,
      admin_id TEXT NOT NULL,
      subject TEXT NOT NULL,
      message TEXT NOT NULL,
      recipient_emails TEXT NOT NULL,
      sent_count INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS kyc_documents (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
      created_at TIMESTAMPTZ DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS platform_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // ── Indexes for performance ──────────────────────────
  try {
    await query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
    await query('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)');
    await query('CREATE INDEX IF NOT EXISTS idx_sessions_jti ON sessions(token_jti)');
    await query('CREATE INDEX IF NOT EXISTS idx_refresh_hash ON refresh_tokens(token_hash)');
    await query('CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id)');
    await query('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)');
    await query('CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC)');
    await query('CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id, created_at DESC)');
    await query('CREATE INDEX IF NOT EXISTS idx_otp_user ON otp_codes(user_id, type)');
  } catch (_) { /* index may already exist */ }

  console.log('[PG] Schema verified/created');
}

// ── Seed Admin ─────────────────────────────────────────────
async function seedAdmin() {
  const email = (process.env.ADMIN_EMAIL || 'admin@zenassets.com').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  const fullName = process.env.ADMIN_NAME || 'ZEN Admin';
  if (!password) {
    console.warn('[PG] ADMIN_PASSWORD not set — admin seed skipped');
    return;
  }
  const hash = bcrypt.hashSync(password, 12);
  const existing = await query('SELECT id FROM users WHERE email = $1', [email]);

  if (existing.rows.length === 0) {
    const id = _uuid();
    await query(`
      INSERT INTO users (id, email, password_hash, full_name, role, tier, status, email_verified)
      VALUES ($1, $2, $3, $4, 'admin', 'diamond', 'active', 1)
    `, [id, email, hash, fullName]);
    await wallets.create(id, 0);
    console.log(`[PG] Admin account created: ${email}`);
  } else {
    const adminId = existing.rows[0].id;
    if (process.env.SYNC_ADMIN_PASSWORD === 'true') {
      await query(`
        UPDATE users SET password_hash = $1, full_name = $2, role = 'admin', status = 'active', email_verified = 1
        WHERE email = $3
      `, [hash, fullName, email]);
      console.log(`[PG] Admin password synced: ${email}`);
    } else {
      await query(`
        UPDATE users SET full_name = $1, role = 'admin', status = 'active', email_verified = 1 WHERE email = $2
      `, [fullName, email]);
    }
    const w = await query('SELECT id FROM wallets WHERE user_id = $1', [adminId]);
    if (w.rows.length === 0) await wallets.create(adminId, 0);
  }
}

// ── Init ──────────────────────────────────────────────────
async function init() {
  if (connected) return;
  try {
    await createSchema();
    await seedAdmin();
    connected = true;
    console.log('[PG] Connected to PostgreSQL');
  } catch (err) {
    console.error('[PG] Init error:', err.message);
    throw err;
  }
}

// ── Users ──────────────────────────────────────────────────
const users = {
  async create({ email, passwordHash, fullName, tier = 'gold' }) {
    const id = _uuid();
    await query(`
      INSERT INTO users (id, email, password_hash, full_name, role, tier, status, email_verified)
      VALUES ($1, $2, $3, $4, 'user', $5, 'active', 1)
    `, [id, email.toLowerCase().trim(), passwordHash, fullName, tier]);
    return id;
  },

  async findByEmail(email) {
    const r = await query('SELECT * FROM users WHERE email = $1', [(email || '').toLowerCase().trim()]);
    return r.rows[0] || null;
  },

  async findById(id) {
    const r = await query('SELECT * FROM users WHERE id = $1', [id]);
    return r.rows[0] || null;
  },

  async setPin(userId, pinHash) {
    await query('UPDATE users SET pin_hash = $1 WHERE id = $2', [pinHash, userId]);
  },

  async updateLogin(userId) {
    await query("UPDATE users SET last_login = NOW() WHERE id = $1", [userId]);
  },

  async updateStatus(userId, status) {
    await query('UPDATE users SET status = $1 WHERE id = $2', [status, userId]);
  },

  async updateTier(userId, tier) {
    await query('UPDATE users SET tier = $1 WHERE id = $2', [tier, userId]);
  },

  async updateKYC(userId, kycStatus) {
    await query('UPDATE users SET kyc_status = $1 WHERE id = $2', [kycStatus, userId]);
  },

  async updateFullName(userId, fullName) {
    const name = (fullName || '').trim();
    if (!name) return;
    await query('UPDATE users SET full_name = $1 WHERE id = $2', [name, userId]);
  },

  async getSettings(userId) {
    const r = await query('SELECT settings_json FROM users WHERE id = $1', [userId]);
    if (!r.rows[0]) return {};
    try { return JSON.parse(r.rows[0].settings_json || '{}'); }
    catch { return {}; }
  },

  async updateSettings(userId, settingsObj) {
    await query('UPDATE users SET settings_json = $1 WHERE id = $2', [JSON.stringify(settingsObj || {}), userId]);
  },

  async delete(userId) {
    await query('DELETE FROM users WHERE id = $1', [userId]);
  },

  async count() {
    const r = await query("SELECT COUNT(*)::int as c FROM users WHERE role != 'admin'");
    return r.rows[0].c;
  },

  async list({ page = 1, limit = 20, search = '', status = '', tier = '' } = {}) {
    let sql = `
      SELECT u.id, u.email, u.full_name, u.role, u.tier, u.status, u.kyc_status,
             u.email_verified, u.last_login, u.created_at, u.settings_json,
             COALESCE(w.balance, 0) AS balance,
             COALESCE(w.total_deposited, 0) AS total_deposited
      FROM users u
      LEFT JOIN wallets w ON w.user_id = u.id
      WHERE u.role != 'admin'`;
    const params = [];
    let paramIdx = 1;

    if (search) {
      sql += ` AND (u.email ILIKE $${paramIdx} OR u.full_name ILIKE $${paramIdx})`;
      params.push(`%${search}%`);
      paramIdx++;
    }
    if (status) {
      sql += ` AND u.status = $${paramIdx}`;
      params.push(status);
      paramIdx++;
    }
    if (tier) {
      sql += ` AND u.tier = $${paramIdx}`;
      params.push(tier);
      paramIdx++;
    }

    const countSql = sql.replace(/SELECT[\s\S]+?FROM users u/, 'SELECT COUNT(*)::int AS total FROM users u');
    const totalR = await query(countSql, params);
    const total = totalR.rows[0].total;

    sql += ' ORDER BY u.created_at DESC LIMIT $' + paramIdx + ' OFFSET $' + (paramIdx + 1);
    params.push(limit, (page - 1) * limit);
    const result = await query(sql, params);

    return { users: result.rows, total, page, limit, pages: Math.ceil(total / limit) || 1 };
  },
};

// ── Sessions ────────────────────────────────────────────────
const sessions = {
  async create({ userId, tokenJti, ipAddress = '', userAgent = '', expiresAt }) {
    await query(`
      INSERT INTO sessions (user_id, token_jti, ip_address, user_agent, expires_at)
      VALUES ($1, $2, $3, $4, $5)
    `, [userId, tokenJti, ipAddress, userAgent, expiresAt]);
  },

  async findByJti(jti) {
    const r = await query(`
      SELECT * FROM sessions
      WHERE token_jti = $1 AND revoked = 0 AND expires_at > NOW()
      LIMIT 1
    `, [jti]);
    return r.rows[0] || null;
  },

  async findByToken(jti) { return sessions.findByJti(jti); },

  async revoke(jti) {
    await query('UPDATE sessions SET revoked = 1 WHERE token_jti = $1', [jti]);
  },

  async revokeAllForUser(userId) {
    await query('UPDATE sessions SET revoked = 1 WHERE user_id = $1', [userId]);
  },

  async revokeAllExcept(userId, exceptJti) {
    await query('UPDATE sessions SET revoked = 1 WHERE user_id = $1 AND token_jti != $2', [userId, exceptJti]);
  },

  async listByUser(userId) {
    const r = await query(`
      SELECT id, token_jti, ip_address, user_agent, expires_at, revoked, created_at
      FROM sessions WHERE user_id = $1 AND revoked = 0 AND expires_at > NOW()
      ORDER BY created_at DESC
    `, [userId]);
    return r.rows;
  },

  async cleanup() {
    const r = await query("DELETE FROM sessions WHERE expires_at <= NOW() OR revoked = 1");
    if (r.rowCount > 0) console.log(`[PG] Cleaned up ${r.rowCount} expired/revoked sessions`);
    const r2 = await query("DELETE FROM refresh_tokens WHERE expires_at <= NOW() OR revoked = 1");
    if (r2.rowCount > 0) console.log(`[PG] Cleaned up ${r2.rowCount} expired refresh tokens`);
  },
};

// ── Refresh Tokens ──────────────────────────────────────────
const refreshTokens = {
  async create({ userId, sessionJti, ipAddress = '', userAgent = '' }) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const ms = _parseExpiresIn(process.env.REFRESH_EXPIRES_IN || '30d');
    const expiresAt = new Date(Date.now() + ms).toISOString();
    await query(`
      INSERT INTO refresh_tokens (user_id, token_hash, session_jti, ip_address, user_agent, expires_at)
      VALUES ($1, $2, $3, $4, $5, $6)
    `, [userId, tokenHash, sessionJti || null, ipAddress, userAgent, expiresAt]);
    return { refreshToken: rawToken, expiresAt };
  },

  async findByRawToken(rawToken) {
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const r = await query(`
      SELECT * FROM refresh_tokens
      WHERE token_hash = $1 AND revoked = 0 AND expires_at > NOW()
      LIMIT 1
    `, [tokenHash]);
    return r.rows[0] || null;
  },

  async revoke(rawToken) {
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    await query('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = $1', [tokenHash]);
  },

  async revokeAllForUser(userId) {
    await query('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = $1', [userId]);
  },
};

// ── OTP ────────────────────────────────────────────────────
const otpCodes = {
  async create(userId, code, type, ttlMinutes) {
    const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();
    await query(
      'INSERT INTO otp_codes (user_id, code, type, expires_at) VALUES ($1, $2, $3, $4)',
      [userId, code, type, expiresAt]
    );
  },

  async verify(userId, code, type) {
    const r = await query(`
      SELECT * FROM otp_codes
      WHERE user_id = $1 AND code = $2 AND type = $3 AND expires_at > NOW() AND used = 0
      LIMIT 1
    `, [userId, code, type]);
    if (r.rows.length === 0) return { ok: false, error: 'Invalid or expired code' };
    await query('UPDATE otp_codes SET used = 1 WHERE id = $1', [r.rows[0].id]);
    return { ok: true };
  },

  async recentlySent(userId, type) {
    const r = await query(`
      SELECT created_at FROM otp_codes
      WHERE user_id = $1 AND type = $2 AND created_at > NOW() - INTERVAL '60 seconds'
      ORDER BY created_at DESC LIMIT 1
    `, [userId, type]);
    return r.rows.length > 0;
  },

  async cleanup() {
    const r = await query("DELETE FROM otp_codes WHERE expires_at <= NOW() OR used = 1");
    if (r.rowCount > 0) console.log(`[PG] Cleaned up ${r.rowCount} OTP codes`);
  },
};

// ── Wallets ────────────────────────────────────────────────
const wallets = {
  async findByUser(userId) {
    const r = await query('SELECT * FROM wallets WHERE user_id = $1', [userId]);
    return r.rows[0] || null;
  },

  async create(userId, initialDeposit = 0) {
    const walletId = _uuid();
    const dep = parseFloat(initialDeposit) || 0;
    await query(`
      INSERT INTO wallets (id, user_id, balance, initial_deposit, total_deposited)
      VALUES ($1, $2, $3, $4, $5)
    `, [walletId, userId, dep, dep, dep > 0 ? dep : 0]);
  },

  async setBalance(userId, amount) {
    const bal = parseFloat(amount) || 0;
    await query(`
      UPDATE wallets SET balance = $1, initial_deposit = $2, total_deposited = $3, updated_at = NOW()
      WHERE user_id = $4
    `, [bal, bal, bal, userId]);
  },

  async addDeposit(userId, amount) {
    const wallet = await wallets.findByUser(userId);
    if (!wallet) {
      await wallets.create(userId, amount);
      return { before: 0, after: amount };
    }
    const dep = parseFloat(amount) || 0;
    const after = wallet.balance + dep;
    await query(`
      UPDATE wallets SET balance = $1, total_deposited = total_deposited + $2, updated_at = NOW()
      WHERE user_id = $3
    `, [after, dep, userId]);
    return { before: wallet.balance, after };
  },

  async creditBalance(userId, amount) {
    const wallet = await wallets.findByUser(userId);
    if (!wallet) {
      await wallets.create(userId, amount);
      return { before: 0, after: amount };
    }
    const dep = parseFloat(amount) || 0;
    const after = wallet.balance + dep;
    await query("UPDATE wallets SET balance = $1, updated_at = NOW() WHERE user_id = $2", [after, userId]);
    return { before: wallet.balance, after };
  },

  async debitBalance(userId, amount) {
    const wallet = await wallets.findByUser(userId);
    if (!wallet || wallet.balance < amount) throw new Error('Insufficient balance');
    const after = wallet.balance - amount;
    await query("UPDATE wallets SET balance = $1, updated_at = NOW() WHERE user_id = $2", [after, userId]);
    return { before: wallet.balance, after };
  },

  async processWithdrawal(userId, amount) { return wallets.debitBalance(userId, amount); },

  async addPendingEarnings(userId, amount) {
    const wallet = await wallets.findByUser(userId);
    const dep = parseFloat(amount) || 0;
    if (!wallet) await wallets.create(userId, 0);
    await query(`
      UPDATE wallets SET pending_earnings = pending_earnings + $1, total_earned = total_earned + $2, updated_at = NOW()
      WHERE user_id = $3
    `, [dep, dep, userId]);
    const w = await wallets.findByUser(userId);
    return { pendingEarnings: w.pending_earnings };
  },

  async recordWithdrawalCompleted(userId, amount) {
    const abs = Math.abs(parseFloat(amount) || 0);
    await query(`
      UPDATE wallets SET total_withdrawn = total_withdrawn + $1, updated_at = NOW()
      WHERE user_id = $2
    `, [abs, userId]);
  },
};

// ── Transactions ────────────────────────────────────────────
const transactions = {
  async create(opts) {
    const id = _uuid();
    const { userId, type, amount, status = 'completed', method = null, reference = null,
            balanceBefore = 0, balanceAfter = null, notes = null } = opts;
    const after = balanceAfter != null ? balanceAfter : balanceBefore;
    await query(`
      INSERT INTO transactions (id, user_id, type, amount, balance_before, balance_after, method, reference_id, notes, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [id, userId, type, amount, balanceBefore, after, method, reference, notes, status]);
    return id;
  },

  async findById(id) {
    const r = await query('SELECT * FROM transactions WHERE id = $1', [id]);
    return r.rows[0] || null;
  },

  async listByUser(userId, { page = 1, limit = 20, type = '' } = {}) {
    let sql = 'SELECT * FROM transactions WHERE user_id = $1';
    const params = [userId];
    let idx = 2;
    if (type) { sql += ` AND type = $${idx}`; params.push(type); idx++; }
    const totalR = await query(sql.replace('SELECT *', 'SELECT COUNT(*)::int as total'), params);
    const total = totalR.rows[0].total;
    sql += ` ORDER BY created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`;
    params.push(limit, (page - 1) * limit);
    const result = await query(sql, params);
    return { transactions: result.rows, total, page, limit };
  },

  async listPending(txType) {
    const r = await query(`
      SELECT t.*, u.email, u.full_name FROM transactions t
      JOIN users u ON t.user_id = u.id
      WHERE t.type = $1 AND t.status = 'pending' ORDER BY t.created_at DESC
    `, [txType]);
    return r.rows;
  },

  async updateStatus(id, status, adminId = null) {
    await query('UPDATE transactions SET status = $1, admin_id = $2 WHERE id = $3', [status, adminId, id]);
  },

  async stats() {
    const r = await query(`
      SELECT
        COUNT(*)::int as total_transactions,
        COALESCE(SUM(CASE WHEN type = 'deposit' AND status = 'completed' THEN amount ELSE 0 END), 0) as total_deposits,
        COALESCE(SUM(CASE WHEN type = 'withdrawal' AND status = 'completed' THEN ABS(amount) ELSE 0 END), 0) as total_withdrawals,
        COUNT(CASE WHEN type = 'withdrawal' AND status = 'pending' THEN 1 END)::int as pending_withdrawals
      FROM transactions
    `);
    return r.rows[0];
  },
};

// ── Trades ──────────────────────────────────────────────────
const trades = {
  async stats(userId) {
    const r = await query(`
      SELECT
        COUNT(*)::int as total_trades,
        COALESCE(SUM(CASE WHEN pnl > 0 THEN 1 ELSE 0 END), 0)::int as wins,
        COALESCE(SUM(CASE WHEN pnl < 0 THEN 1 ELSE 0 END), 0)::int as losses,
        COALESCE(SUM(pnl), 0) as total_pnl
      FROM trades WHERE user_id = $1 AND status = 'closed'
    `, [userId]);
    return r.rows[0] || { total_trades: 0, wins: 0, losses: 0, total_pnl: 0 };
  },

  async listByUser(userId, { page = 1, limit = 20, status = '' } = {}) {
    let sql = 'SELECT * FROM trades WHERE user_id = $1';
    const params = [userId];
    let idx = 2;
    if (status) { sql += ` AND status = $${idx}`; params.push(status); idx++; }
    const totalR = await query(sql.replace('SELECT *', 'SELECT COUNT(*)::int as total'), params);
    const total = totalR.rows[0].total;
    sql += ` ORDER BY created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`;
    params.push(limit, (page - 1) * limit);
    const result = await query(sql, params);
    return { trades: result.rows, total, page, limit };
  },

  async openPositions(userId) {
    const r = await query("SELECT * FROM trades WHERE user_id = $1 AND status = 'open' ORDER BY opened_at DESC", [userId]);
    return r.rows;
  },

  async close(tradeId, exitPrice, pnl, fee) {
    await query(`
      UPDATE trades SET exit_price = $1, pnl = $2, fee = $3, status = 'closed', closed_at = NOW()
      WHERE id = $4
    `, [exitPrice, pnl, fee, tradeId]);
  },
};

// ── Audit ───────────────────────────────────────────────────
const audit = {
  async log(userId, action, details, severity = 'info', ip = null) {
    const detailsStr = details == null ? null : (typeof details === 'string' ? details : JSON.stringify(details));
    await query(
      'INSERT INTO audit_log (user_id, action, details, severity, ip_address) VALUES ($1, $2, $3, $4, $5)',
      [userId, action, detailsStr, severity, ip]
    );
  },

  async list({ page = 1, limit = 50, userId = '', severity = '' } = {}) {
    let sql = 'SELECT a.*, u.email FROM audit_log a LEFT JOIN users u ON a.user_id = u.id WHERE 1=1';
    const params = [];
    let idx = 1;
    if (userId) { sql += ` AND a.user_id = $${idx}`; params.push(userId); idx++; }
    if (severity) { sql += ` AND a.severity = $${idx}`; params.push(severity); idx++; }
    const totalR = await query(sql.replace(/SELECT .+ FROM/, 'SELECT COUNT(*)::int as total FROM'), params);
    const total = totalR.rows[0].total;
    sql += ` ORDER BY a.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`;
    params.push(limit, (page - 1) * limit);
    const result = await query(sql, params);
    return { entries: result.rows, total, page, limit };
  },
};

// ── Broadcasts ──────────────────────────────────────────────
const broadcasts = {
  async create(adminId, subject, message, recipientEmails) {
    await query(
      'INSERT INTO broadcasts (admin_id, subject, message, recipient_emails) VALUES ($1, $2, $3, $4)',
      [adminId, subject, message, JSON.stringify(recipientEmails)]
    );
  },

  async list({ page = 1, limit = 20 } = {}) {
    const r = await query(`
      SELECT b.*, u.email as admin_email FROM broadcasts b
      JOIN users u ON b.admin_id = u.id ORDER BY b.created_at DESC LIMIT $1 OFFSET $2
    `, [limit, (page - 1) * limit]);
    return { broadcasts: r.rows };
  },

  async listForUser(email, limit = 30) {
    const r = await query('SELECT id, subject, message, recipient_emails, created_at FROM broadcasts ORDER BY created_at DESC LIMIT 100');
    const norm = (email || '').trim().toLowerCase();
    const filtered = r.rows.filter((b) => {
      try {
        const list = JSON.parse(b.recipient_emails || '[]');
        if (!Array.isArray(list) || list.length === 0) return true;
        return list.some((e) => String(e).toLowerCase() === norm);
      } catch { return true; }
    });
    return filtered.slice(0, limit);
  },
};

// ── Platform Settings ───────────────────────────────────────
const DEFAULT_PLATFORM_CONFIG = {
  registration: true, trading: true, autoTrader: true,
  withdrawals: true, maintenance: false,
};

const platformSettings = {
  async get() {
    const out = { ...DEFAULT_PLATFORM_CONFIG };
    try {
      const r = await query('SELECT key, value FROM platform_settings');
      r.rows.forEach((row) => {
        try { out[row.key] = JSON.parse(row.value); } catch { out[row.key] = row.value; }
      });
    } catch { /* table may not exist */ }
    return out;
  },

  async set(patch) {
    for (const [key, val] of Object.entries(patch)) {
      await query(`
        INSERT INTO platform_settings (key, value, updated_at) VALUES ($1, $2, NOW())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
      `, [key, JSON.stringify(val)]);
    }
    return platformSettings.get();
  },
};

// ── Raw query access (for legacy route compatibility) ──────
function raw() {
  return {
    prepare: () => ({
      run: (...args) => {
        // Fire-and-forget for simple updates
        const sql = args[0];
        const params = args.slice(1);
        query(sql, params).catch(e => console.error('[PG] Raw query error:', e.message));
      },
      get: (...args) => {
        // Synchronous get is not possible in PG — this is a best-effort stub
        console.warn('[PG] raw().prepare().get() called — use async equivalents');
        return null;
      },
    }),
  };
}

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
