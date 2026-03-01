/* ════════════════════════════════════════════════════════════
   auth.js — JWT Authentication Middleware
   ZEN ASSETS Backend
════════════════════════════════════════════════════════════ */

const jwt  = require('jsonwebtoken');
const db   = require('../db/database');

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_change_me';

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
  const expiresIn = process.env.JWT_EXPIRES_IN || '7d';

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

module.exports = { authenticate, requireAdmin, generateToken };
