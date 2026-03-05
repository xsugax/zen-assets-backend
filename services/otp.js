/* ════════════════════════════════════════════════════════════
   services/otp.js — OTP Code Generator
   ZEN ASSETS Backend

   Generates cryptographically secure 6-digit codes using
   Node.js crypto.randomInt() (like Binance's email codes).

   Storage:  db.otpCodes (SQLite) — fully isolated per user/type
   TTLs:     15 min  email_verify
             10 min  login_otp
             30 min  password_reset
════════════════════════════════════════════════════════════ */

const crypto = require('crypto');

/**
 * Generate a cryptographically secure 6-digit OTP.
 * crypto.randomInt(100000, 1000000) ensures uniform distribution
 * across 100000–999999 inclusive, with no modulo bias.
 *
 * @returns {string} 6-digit numeric string e.g. "483920"
 */
function generate() {
  return String(crypto.randomInt(100000, 1000000));
}

module.exports = { generate };
