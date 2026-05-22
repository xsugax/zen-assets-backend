/* ════════════════════════════════════════════════════════════
   routes/auth.js — Authentication Routes
   ZEN ASSETS Backend

   POST /api/auth/register   — Create account
   POST /api/auth/login      — Login
   GET  /api/auth/me         — Current user + wallet
   POST /api/auth/logout     — Revoke session
   POST /api/auth/change-password — Change password
════════════════════════════════════════════════════════════ */

const express    = require('express');
const bcrypt     = require('bcryptjs');
const router     = express.Router();
const db         = require('../db/database');
const { authenticate, issueAuthCredentials } = require('../middleware/auth');
const emailService = require('../services/email');
const otpService = require('../services/otp');
const { attachSettingsToUser, mergeSettings } = require('../utils/user-settings');

function clientUser(row) {
  const u = attachSettingsToUser(row);
  return {
    id: u.id,
    email: u.email,
    fullName: u.full_name,
    role: u.role,
    tier: u.tier,
    status: u.status,
    kycStatus: u.kyc_status,
    copyTrade: u.copyTrade,
    tradingPaused: u.tradingPaused,
    profitPaused: u.profitPaused,
    experienceTier: u.experienceTier,
    settings: u.settings,
  };
}

// ── Email Format Validator (real-world domains only) ────────
function isValidEmail(addr) {
  if (!addr || typeof addr !== 'string') return false;
  const trimmed = addr.trim().toLowerCase();
  // Must have local@domain.tld, domain at least 2 parts, TLD at least 2 chars
  if (!/^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/.test(trimmed)) return false;
  // Block obviously fake domains
  const domain = trimmed.split('@')[1];
  if (['test.com','example.com','localhost','temp.com','fake.com'].includes(domain)) return false;
  return true;
}

// ── Password Strength Validator ─────────────────────────────
function validatePassword(pwd) {
  const minLength = parseInt(process.env.MIN_PASSWORD_LENGTH || 8, 10);
  const requireUpper = process.env.REQUIRE_UPPERCASE === 'true';
  const requireLower = process.env.REQUIRE_LOWERCASE === 'true';
  const requireNum = process.env.REQUIRE_NUMBERS === 'true';
  const requireSpecial = process.env.REQUIRE_SPECIAL_CHARS === 'true';

  if (pwd.length < minLength) {
    return { ok: false, error: `Password must be at least ${minLength} characters` };
  }
  if (requireUpper && !/[A-Z]/.test(pwd)) {
    return { ok: false, error: 'Password must contain uppercase letters (A-Z)' };
  }
  if (requireLower && !/[a-z]/.test(pwd)) {
    return { ok: false, error: 'Password must contain lowercase letters (a-z)' };
  }
  if (requireNum && !/[0-9]/.test(pwd)) {
    return { ok: false, error: 'Password must contain numbers (0-9)' };
  }
  if (requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd)) {
    return { ok: false, error: 'Password must contain special characters (!@#$%^&*)' };
  }
  return { ok: true };
}


const { assertRegistrationAllowed } = require('../utils/user-controls');

// ── Register ────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    assertRegistrationAllowed();
    const { email: rawEmail, password, fullName, tier = 'gold', pin } = req.body;
    const depositAmount = 0; // Public registration cannot self-fund — use deposits or admin
    const email = (rawEmail || '').trim().toLowerCase();

    // Validation
    if (!email || !password || !fullName) {
      return res.status(400).json({ error: 'Email, password, and full name are required' });
    }

    // PIN validation (required, exactly 4 digits)
    if (!pin || !/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'A 4-digit PIN is required for quick login' });
    }

    // Strict password validation
    const pwdCheck = validatePassword(password);
    if (!pwdCheck.ok) {
      return res.status(400).json({ error: pwdCheck.error });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid, real email address (e.g. name@gmail.com)' });
    }

    // Check duplicate
    const existing = db.users.findByEmail(email);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    // Hash password with bcrypt (cost factor 12)
    const passwordHash = await bcrypt.hash(password, 12);

    const { VALID_TIERS } = require('../utils/validators');
    const tierNorm = String(tier).toLowerCase();
    if (!VALID_TIERS.includes(tierNorm)) {
      return res.status(400).json({ error: `Invalid tier. Choose: ${VALID_TIERS.join(', ')}` });
    }

    // Create user
    const userId = db.users.create({ email, passwordHash, fullName, tier: tierNorm });

    // Set PIN (hashed)
    const pinHash = await bcrypt.hash(pin, 10);
    db.users.setPin(userId, pinHash);

    // Create wallet
    db.wallets.create(userId, depositAmount);

    // If there's an initial deposit, log the transaction
    if (depositAmount > 0) {
      db.transactions.create({
        userId,
        type: 'deposit',
        amount: depositAmount,
        status: 'completed',
        method: 'initial_deposit',
        balanceBefore: 0,
        balanceAfter: depositAmount,
        notes: 'Initial registration deposit',
      });
    }

    // Audit
    db.audit.log(userId, 'user.registered', { email, tier, depositAmount }, 'info', req.ip);

    const newUser = db.users.findById(userId);
    if (newUser) {
      emailService.sendWelcome(newUser).catch(err => console.error('[AUTH] Welcome email failed:', err.message));
    }

    // Activate account immediately (no OTP verification)
    db.raw().prepare("UPDATE users SET status = 'active', email_verified = 1 WHERE id = ?").run(userId);

    const creds = issueAuthCredentials(userId, 'user', req);
    const wallet = db.wallets.findByUser(userId);

    res.status(201).json({
      success: true,
      token: creds.token,
      refreshToken: creds.refreshToken,
      expiresIn: creds.expiresIn,
      user: { id: userId, email, fullName, role: 'user', tier, status: 'active', kycStatus: 'none' },
      wallet: wallet ? { balance: wallet.balance, initialDeposit: wallet.initial_deposit, totalDeposited: wallet.total_deposited, totalWithdrawn: wallet.total_withdrawn, totalEarned: wallet.total_earned } : null,
    });
  } catch (err) {
    if (err.status === 503) return res.status(503).json({ error: err.message, code: err.code });
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// ── Login ───────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email: rawEmail, password } = req.body;
    const email = (rawEmail || '').trim().toLowerCase();

    // Validate input
    if (!email || !password) {
      console.warn(`[AUTH/LOGIN] Missing credentials from IP: ${req.ip}`);
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Basic email format validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      console.warn(`[AUTH/LOGIN] Invalid email format: ${email} from IP: ${req.ip}`);
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Find user
    const user = db.users.findByEmail(email);
    if (!user) {
      console.warn(`[AUTH/LOGIN] User not found: ${email} from IP: ${req.ip}`);
      // Don't reveal if email exists - return same message
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check account status — must be active (admin-created users default to active)
    if (user.status !== 'active') {
      const msg = user.status === 'suspended'
        ? 'Account suspended. Contact support.'
        : user.status === 'banned'
          ? 'Account banned.'
          : `Account is ${user.status}. Contact support to activate.`;
      console.warn(`[AUTH/LOGIN] Non-active account (${user.status}): ${email}`);
      return res.status(403).json({ error: msg, code: 'ACCOUNT_DISABLED', status: user.status });
    }

    // Verify password with timing-safe comparison
    let valid = false;
    try {
      valid = await bcrypt.compare(password, user.password_hash);
    } catch (bcryptErr) {
      console.error(`[AUTH/LOGIN] Password verification error for ${email}:`, bcryptErr.message);
      return res.status(500).json({ error: 'Authentication service temporarily unavailable' });
    }

    if (!valid) {
      console.warn(`[AUTH/LOGIN] Invalid password for ${email} from IP: ${req.ip}`);
      db.audit.log(user.id, 'auth.login_failed', { email }, 'warn', req.ip);
      // Add small delay to prevent brute force (100-300ms)
      await new Promise(resolve => setTimeout(resolve, Math.random() * 200 + 100));
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const creds = issueAuthCredentials(user.id, user.role, req);
    db.users.updateLogin(user.id);

    const wallet = db.wallets.findByUser(user.id);
    db.audit.log(user.id, 'auth.login', { ip: req.ip }, 'info', req.ip);

    console.log(`[AUTH/LOGIN] ✓ Success: ${email} from IP: ${req.ip}`);

    res.json({
      success: true,
      token: creds.token,
      refreshToken: creds.refreshToken,
      expiresIn: creds.expiresIn,
      user: clientUser(user),
      wallet: wallet ? { balance: wallet.balance, initialDeposit: wallet.initial_deposit, totalDeposited: wallet.total_deposited, totalWithdrawn: wallet.total_withdrawn, totalEarned: wallet.total_earned } : null,
    });
  } catch (err) {
    console.error('[AUTH/LOGIN] Unexpected error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// ── Refresh access token ────────────────────────────────────
router.post('/refresh', (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ error: 'refreshToken is required', code: 'NO_REFRESH_TOKEN' });
    }

    const row = db.refreshTokens.findByRawToken(refreshToken);
    if (!row) {
      return res.status(401).json({ error: 'Invalid or expired refresh token', code: 'REFRESH_INVALID' });
    }

    const user = db.users.findById(row.user_id);
    if (!user || user.status !== 'active') {
      db.refreshTokens.revoke(refreshToken);
      return res.status(403).json({ error: 'Account not active', code: 'ACCOUNT_DISABLED' });
    }

    db.refreshTokens.revoke(refreshToken);
    const creds = issueAuthCredentials(user.id, user.role, req);

    res.json({
      success: true,
      token: creds.token,
      refreshToken: creds.refreshToken,
      expiresIn: creds.expiresIn,
    });
  } catch (err) {
    console.error('[AUTH/REFRESH] error:', err);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

// ── List active sessions ──────────────────────────────────────
router.get('/sessions', authenticate, (req, res) => {
  const list = db.sessions.listByUser(req.user.id).map(s => ({
    id: s.id,
    jti: s.token_jti,
    ipAddress: s.ip_address,
    userAgent: s.user_agent,
    createdAt: s.created_at,
    expiresAt: s.expires_at,
    current: s.token_jti === req.tokenJti,
  }));
  res.json({ sessions: list });
});

// ── Get Current User ────────────────────────────────────────
router.get('/me', authenticate, (req, res) => {
  const wallet = db.wallets.findByUser(req.user.id);
  let tradeStats = {};
  try {
    tradeStats = db.trades.stats(req.user.id) || {};
  } catch (_) { /* trades optional */ }

  const userWithSettings = attachSettingsToUser(req.user);
  res.json({
    user: {
      id: userWithSettings.id,
      email: userWithSettings.email,
      fullName: userWithSettings.full_name,
      role: userWithSettings.role,
      tier: userWithSettings.tier,
      status: userWithSettings.status,
      kycStatus: userWithSettings.kyc_status,
      createdAt: userWithSettings.created_at,
      lastLogin: userWithSettings.last_login,
      copyTrade: userWithSettings.copyTrade,
      tradingPaused: userWithSettings.tradingPaused,
      profitPaused: userWithSettings.profitPaused,
      experienceTier: userWithSettings.experienceTier,
    },
    wallet: wallet ? {
      balance: wallet.balance,
      initialDeposit: wallet.initial_deposit,
      totalDeposited: wallet.total_deposited,
      totalWithdrawn: wallet.total_withdrawn,
      totalEarned: wallet.total_earned,
      totalClaimed: wallet.total_claimed,
      pendingEarnings: wallet.pending_earnings,
    } : null,
    trading: tradeStats || {},
  });
});

// ── Logout ──────────────────────────────────────────────────
router.post('/logout', authenticate, (req, res) => {
  db.sessions.revoke(req.tokenJti);
  const { refreshToken } = req.body;
  if (refreshToken) db.refreshTokens.revoke(refreshToken);
  db.audit.log(req.user.id, 'auth.logout', null, 'info', req.ip);
  res.json({ success: true, message: 'Logged out successfully' });
});

// ── Logout all other devices (re-issues token for this device) ─
router.post('/logout-all', authenticate, (req, res) => {
  db.sessions.revokeAllForUser(req.user.id);
  db.refreshTokens.revokeAllForUser(req.user.id);
  const creds = issueAuthCredentials(req.user.id, req.user.role, req);
  db.audit.log(req.user.id, 'auth.logout_all', { keptCurrent: true }, 'info', req.ip);
  res.json({
    success: true,
    message: 'All other sessions revoked',
    token: creds.token,
    refreshToken: creds.refreshToken,
    expiresIn: creds.expiresIn,
  });
});

// ── User settings (experience density, etc.) ────────────────
router.patch('/settings', authenticate, (req, res) => {
  try {
    const user = db.users.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const merged = mergeSettings(user.settings_json, req.body || {});
    db.users.updateSettings(req.user.id, merged);
    const updated = attachSettingsToUser(db.users.findById(req.user.id));

    db.audit.log(req.user.id, 'auth.settings_updated', {
      experienceTier: updated.experienceTier,
    }, 'info', req.ip);

    res.json({
      success: true,
      settings: updated.settings,
      experienceTier: updated.experienceTier,
      copyTrade: updated.copyTrade,
      tradingPaused: updated.tradingPaused,
      profitPaused: updated.profitPaused,
    });
  } catch (err) {
    console.error('[AUTH/SETTINGS] error:', err);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// ── Change Password ─────────────────────────────────────────
router.post('/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' });
    }
    const pwdCheck = validatePassword(newPassword);
    if (!pwdCheck.ok) {
      return res.status(400).json({ error: pwdCheck.error });
    }

    // Get full user (with hash)
    const user = db.users.findByEmail(req.user.email);
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const newHash = await bcrypt.hash(newPassword, 12);
    db.raw().prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, req.user.id);

    db.sessions.revokeAllForUser(req.user.id);
    db.refreshTokens.revokeAllForUser(req.user.id);

    const creds = issueAuthCredentials(req.user.id, req.user.role, req);

    db.audit.log(req.user.id, 'auth.password_changed', null, 'info', req.ip);

  res.json({
    success: true,
    message: 'Password changed. All other sessions revoked.',
    token: creds.token,
    refreshToken: creds.refreshToken,
    expiresIn: creds.expiresIn,
  });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// ── Verify Email OTP (after registration) ───────────────────────────
router.post('/verify-email', async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !code) return res.status(400).json({ error: 'userId and code are required' });

    const check = db.otpCodes.verify(userId, String(code).trim(), 'email_verify');
    if (!check.ok) return res.status(400).json({ error: check.error });

    // Activate account
    db.raw().prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(userId);

    // Issue JWT and create session
    const user = db.raw().prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const creds = issueAuthCredentials(user.id, user.role, req);
    db.users.updateLogin(user.id);

    const wallet = db.wallets.findByUser(user.id);
    db.audit.log(user.id, 'auth.email_verified', null, 'info', req.ip);

    // TEMP: Email sending disabled for login troubleshooting
    // emailService.sendWelcome(user).catch(err => console.error('Welcome email failed:', err));
    const depositAmount = wallet ? wallet.initial_deposit : 0;
    // if (depositAmount > 0) {
    //   emailService.sendDepositConfirm(user, depositAmount, 'Initial Deposit').catch(err => console.error('Deposit email failed:', err));
    // }

    res.json({
      success: true,
      token: creds.token,
      refreshToken: creds.refreshToken,
      expiresIn: creds.expiresIn,
      user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role, tier: user.tier, status: user.status, kycStatus: user.kyc_status },
      wallet: wallet ? { balance: wallet.balance, initialDeposit: wallet.initial_deposit, totalDeposited: wallet.total_deposited, totalWithdrawn: wallet.total_withdrawn, totalEarned: wallet.total_earned } : null,
    });
  } catch (err) {
    console.error('Verify email error:', err);
    res.status(500).json({ error: 'Verification failed. Please try again.' });
  }
});

// ── Verify Login OTP (after password validated) ─────────────────────
router.post('/verify-login-otp', async (req, res) => {
  try {
    const { userId, code } = req.body;
    if (!userId || !code) return res.status(400).json({ error: 'userId and code are required' });

    const check = db.otpCodes.verify(userId, String(code).trim(), 'login_otp');
    if (!check.ok) return res.status(400).json({ error: check.error });

    const user = db.raw().prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.status === 'suspended') return res.status(403).json({ error: 'Account suspended. Contact support.' });

    const creds = issueAuthCredentials(user.id, user.role, req);
    db.users.updateLogin(user.id);

    const wallet = db.wallets.findByUser(user.id);
    db.audit.log(user.id, 'auth.login', { ip: req.ip }, 'info', req.ip);

    res.json({
      success: true,
      token: creds.token,
      refreshToken: creds.refreshToken,
      expiresIn: creds.expiresIn,
      user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role, tier: user.tier, status: user.status, kycStatus: user.kyc_status },
      wallet: wallet ? { balance: wallet.balance, initialDeposit: wallet.initial_deposit, totalDeposited: wallet.total_deposited, totalWithdrawn: wallet.total_withdrawn, totalEarned: wallet.total_earned } : null,
    });
  } catch (err) {
    console.error('Verify login OTP error:', err);
    res.status(500).json({ error: 'Verification failed. Please try again.' });
  }
});

// ── Resend OTP (rate-limited: one per 60 seconds) ────────────────────
router.post('/resend-otp', async (req, res) => {
  try {
    const { userId, type } = req.body;
    if (!userId || !type) return res.status(400).json({ error: 'userId and type are required' });
    if (!['email_verify', 'login_otp', 'password_reset'].includes(type)) {
      return res.status(400).json({ error: 'Invalid OTP type' });
    }

    // Rate limit: one resend per 60 seconds
    if (db.otpCodes.recentlySent(userId, type)) {
      return res.status(429).json({ error: 'Please wait 60 seconds before requesting a new code.' });
    }

    const user = db.raw().prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const newCode = otpService.generate();
    const ttl = type === 'email_verify' ? 15 : type === 'password_reset' ? 30 : 10;
    db.otpCodes.create(userId, newCode, type, ttl);

    // TEMP: Email sending disabled for login troubleshooting
    // if (type === 'email_verify') {
    //   emailService.sendEmailVerification(user, newCode).catch(err => console.error('Resend email failed:', err));
    // } else if (type === 'login_otp') {
    //   emailService.sendLoginOTP(user, newCode, req.ip).catch(err => console.error('Resend login OTP failed:', err));
    // }

    db.audit.log(userId, `auth.otp_resent.${type}`, null, 'info', req.ip);
    res.json({ success: true, message: 'A new verification code has been sent to your email.' });
  } catch (err) {
    console.error('Resend OTP error:', err);
    res.status(500).json({ error: 'Failed to resend code. Please try again.' });
  }
});

// ── Forgot Password (sends OTP code via email) ──────────────
router.post('/forgot-password', async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }

    const user = db.users.findByEmail(email);
    if (user && user.status !== 'banned') {
      if (db.otpCodes.recentlySent(user.id, 'password_reset')) {
        return res.status(429).json({ error: 'Please wait 60 seconds before requesting another code.' });
      }
      const code = otpService.generate();
      db.otpCodes.create(user.id, code, 'password_reset', 30);
      emailService.sendPasswordReset(user, code, req.ip).catch(err => {
        console.error('[AUTH] Password reset email failed:', err.message);
      });
      db.audit.log(user.id, 'auth.password_reset_requested', { ip: req.ip }, 'info', req.ip);
    }

    res.json({
      success: true,
      message: 'If that email is registered, a reset code has been sent. Check your inbox.',
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Could not process request. Try again later.' });
  }
});

// ── Reset Password (email + OTP code + new password) ────────
router.post('/reset-password', async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const { code, newPassword } = req.body;
    if (!email || !code || !newPassword) {
      return res.status(400).json({ error: 'Email, reset code, and new password are required' });
    }

    const pwdCheck = validatePassword(newPassword);
    if (!pwdCheck.ok) {
      return res.status(400).json({ error: pwdCheck.error });
    }

    const user = db.users.findByEmail(email);
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset code' });
    }

    const check = db.otpCodes.verify(user.id, String(code).trim(), 'password_reset');
    if (!check.ok) {
      return res.status(400).json({ error: check.error || 'Invalid or expired reset code' });
    }

    const newHash = await bcrypt.hash(newPassword, 12);
    db.raw().prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, user.id);
    db.sessions.revokeAllForUser(user.id);
    db.refreshTokens.revokeAllForUser(user.id);
    db.audit.log(user.id, 'auth.password_reset_completed', { ip: req.ip }, 'info', req.ip);

    res.json({ success: true, message: 'Password updated. You can sign in with your new password.' });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Failed to reset password. Please try again.' });
  }
});

// ── Login with PIN (quick auth — email + 4-digit PIN) ───────
router.post('/pin-login', async (req, res) => {
  try {
    const { email: rawEmail, pin } = req.body;
    const email = (rawEmail || '').trim().toLowerCase();
    if (!email || !pin) return res.status(400).json({ error: 'Email and PIN are required' });
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });

    const user = db.users.findByEmail(email);
    if (!user) return res.status(401).json({ error: 'Invalid email or PIN' });
    if (user.status !== 'active') {
      const msg = user.status === 'suspended'
        ? 'Account suspended. Contact support.'
        : user.status === 'banned'
          ? 'Account banned.'
          : `Account is ${user.status}. Contact support to activate.`;
      return res.status(403).json({ error: msg, code: 'ACCOUNT_DISABLED', status: user.status });
    }
    if (!user.pin_hash) return res.status(400).json({ error: 'No PIN set for this account. Use password login.' });

    const valid = await bcrypt.compare(pin, user.pin_hash);
    if (!valid) {
      db.audit.log(user.id, 'auth.pin_login_failed', { email }, 'warn', req.ip);
      return res.status(401).json({ error: 'Invalid email or PIN' });
    }

    // PIN login skips OTP for convenience
    const creds = issueAuthCredentials(user.id, user.role, req);
    db.users.updateLogin(user.id);

    const wallet = db.wallets.findByUser(user.id);
    db.audit.log(user.id, 'auth.pin_login', { ip: req.ip }, 'info', req.ip);

    res.json({
      success: true,
      token: creds.token,
      refreshToken: creds.refreshToken,
      expiresIn: creds.expiresIn,
      user: clientUser(user),
      wallet: wallet ? { balance: wallet.balance, initialDeposit: wallet.initial_deposit, totalDeposited: wallet.total_deposited, totalWithdrawn: wallet.total_withdrawn, totalEarned: wallet.total_earned } : null,
    });
  } catch (err) {
    console.error('PIN login error:', err);
    res.status(500).json({ error: 'PIN login failed. Please try again.' });
  }
});

// ── Set/Change PIN (authenticated) ──────────────────────────
router.post('/set-pin', authenticate, async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin || !/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });

    const pinHash = await bcrypt.hash(pin, 10);
    db.users.setPin(req.user.id, pinHash);
    db.audit.log(req.user.id, 'auth.pin_set', null, 'info', req.ip);

    res.json({ success: true, message: 'PIN updated successfully' });
  } catch (err) {
    console.error('Set PIN error:', err);
    res.status(500).json({ error: 'Failed to set PIN' });
  }
});

module.exports = router;
