/* ════════════════════════════════════════════════════════════
   services/crypto.js — Encryption Service
   ZEN ASSETS Backend

   Encrypts/decrypts sensitive user data at rest.
   Uses AES-256-GCM for authenticated encryption.
════════════════════════════════════════════════════════════ */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const SALT_LENGTH = 16;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

// Get encryption key from env (must be 32 bytes for AES-256)
function getKey() {
  const key = process.env.DATA_ENCRYPTION_KEY;
  if (!key) {
    console.warn('[CRYPTO] DATA_ENCRYPTION_KEY not set — using development key');
    return crypto.scryptSync('zen_assets_dev_only_change_in_production_2026', 'salt', 32);
  }
  // If key is hex string, convert to buffer
  if (key.length === 64) return Buffer.from(key, 'hex');
  // Otherwise derive from passphrase
  return crypto.scryptSync(key, 'zen_salt', 32);
}

// Encrypt sensitive string
function encrypt(plaintext) {
  if (!plaintext) return null;
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
    let encrypted = cipher.update(String(plaintext), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    // Format: iv:authTag:ciphertext (all hex)
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  } catch (err) {
    console.error('[CRYPTO] Encrypt failed:', err.message);
    return null;
  }
}

// Decrypt sensitive string
function decrypt(encrypted) {
  if (!encrypted) return null;
  try {
    const parts = encrypted.split(':');
    if (parts.length !== 3) throw new Error('Invalid encrypted format');
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const ciphertext = parts[2];
    const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
    decipher.setAuthTag(authTag);
    let plaintext = decipher.update(ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');
    return plaintext;
  } catch (err) {
    console.error('[CRYPTO] Decrypt failed:', err.message);
    return null;
  }
}

// Hash for comparison (like passwords, but without salt/pepper)
function hash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Generate a random token (for 2FA, password reset, etc)
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

module.exports = { encrypt, decrypt, hash, generateToken };
