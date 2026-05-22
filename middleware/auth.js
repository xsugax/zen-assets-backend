/* ════════════════════════════════════════════════════════════
   auth.js — JWT Authentication Middleware
   ZEN ASSETS Backend
════════════════════════════════════════════════════════════ */

const jwt  = require('jsonwebtoken');
const db   = require('../db/database');

const JWT_SECRET = process.env.JWT_SECRET || (
  process.env.NODE_ENV === 'production' ? null : 'dev_only_jwt_secret_change_me'
);

if (!JWT_SECRET) {
  console.error('[AUTH] FATAL: JWT_SECRET is required in production');
  if (process.env.NODE_ENV === 'production') process.exit(1);
}

// ── Verify JWT Token ────────────────────────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Check session is still valid (not revoked)
    const session = db.sessions.findByJti(decoded.jti);
    if (!session) {
      return res.status(401).json({ error: 'Session expired or revoked', code: 'SESSION_INVALID' });
    }

    // Check user still exists and is active
    const user = db.users.findById(decoded.sub);
    if (!user) {
      return res.status(401).json({ error: 'User not found', code: 'USER_NOT_FOUND' });
    }
    if (user.status !== 'active') {
      return res.status(403).json({ error: `Account ${user.status}`, code: 'ACCOUNT_DISABLED' });
    }

    // Attach user to request
    req.user = user;
    req.tokenJti = decoded.jti;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid token', code: 'TOKEN_INVALID' });
  }
}

// ── Require Admin Role ──────────────────────────────────────
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required', code: 'FORBIDDEN' });
  }
  next();
}

// ── Generate JWT ────────────────────────────────────────────
function generateToken(userId, role) {
  const { v4: uuid } = require('uuid');
  const jti = uuid();
  const expiresIn = process.env.JWT_EXPIRES_IN || '15m';

  const token = jwt.sign(
    { sub: userId, role, jti },
    JWT_SECRET,
    { expiresIn }
  );

  // Calculate expiry date for DB storage
  const decoded = jwt.decode(token);
  const expiresAt = new Date(decoded.exp * 1000).toISOString();

  return { token, jti, expiresAt };
}

/** Create access JWT + DB session + refresh token for a login event */
function issueAuthCredentials(userId, role, req) {
  const { token, jti, expiresAt } = generateToken(userId, role);
  db.sessions.create({
    userId,
    tokenJti: jti,
    ipAddress: req.ip || '',
    userAgent: req.headers['user-agent'] || '',
    expiresAt,
  });
  const { refreshToken, expiresAt: refreshExpiresAt } = db.refreshTokens.create({
    userId,
    sessionJti: jti,
    ipAddress: req.ip || '',
    userAgent: req.headers['user-agent'] || '',
  });
  const decoded = require('jsonwebtoken').decode(token);
  return {
    token,
    refreshToken,
    jti,
    expiresAt,
    refreshExpiresAt,
    expiresIn: decoded && decoded.exp ? decoded.exp - Math.floor(Date.now() / 1000) : 900,
  };
}

module.exports = { authenticate, requireAdmin, generateToken, issueAuthCredentials, JWT_SECRET };
