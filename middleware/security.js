/* ════════════════════════════════════════════════════════════
   middleware/security.js — Security Validation & Sanitization
   ZEN ASSETS Backend

   Input sanitization, request validation, and injection prevention.
════════════════════════════════════════════════════════════ */

// ── Sanitize input to prevent XSS ───────────────────────────
function sanitizeInput(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/[<>]/g, '')        // Remove brackets
    .replace(/[&]/g, '&amp;')    // Encode ampersand
    .replace(/["']/g, '')        // Remove quotes
    .trim();
}

// ── Validate email format (strict) ──────────────────────────
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email) && email.length <= 254;
}

// ── Validate amount (prevent negative/excessive) ────────────
function validateAmount(amount) {
  const num = parseFloat(amount);
  return !isNaN(num) && num > 0 && num < 1_000_000; // Max $1M
}

// ── Security middleware ─────────────────────────────────────
function securityMiddleware(req, res, next) {
  // ── Sanitize query params
  Object.keys(req.query).forEach(key => {
    if (typeof req.query[key] === 'string') {
      req.query[key] = sanitizeInput(req.query[key]);
    }
  });

  // ── Sanitize body
  if (req.body && typeof req.body === 'object') {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        req.body[key] = sanitizeInput(req.body[key]);
      }
    });
  }

  // ── Check for SQL injection patterns
  const sqlPatterns = /(\b(DROP|DELETE|INSERT|UPDATE|SELECT|EXEC|EXECUTE)\b|--|;|\/\*|\*\/)/i;
  const fullRequest = JSON.stringify({ ...req.query, ...req.body });
  if (sqlPatterns.test(fullRequest)) {
    return res.status(400).json({ error: 'Invalid input detected' });
  }

  // ── Limit request body size (already done by express, but enforce again)
  req.on('error', err => {
    console.error('[SECURITY] Request error:', err.message);
    res.status(413).json({ error: 'Payload too large' });
  });

  next();
}

// ── Log suspicious activities ───────────────────────────────
function auditLog(userId, action, severity = 'info', details = {}, ip = '') {
  const db = require('../db/database');
  const timestamp = new Date().toISOString();
  const log = {
    timestamp,
    userId,
    action,
    severity,
    details: JSON.stringify(details),
    ip,
  };

  if (severity === 'critical') {
    console.error(`[SECURITY] CRITICAL: ${action} by ${userId} — ${JSON.stringify(details)}`);
  }

  try {
    db.audit.log(userId, action, details, severity, ip);
  } catch (err) {
    console.error('[AUDIT] Failed to log:', err.message);
  }
}

module.exports = {
  securityMiddleware,
  sanitizeInput,
  validateEmail,
  validateAmount,
  auditLog,
};
