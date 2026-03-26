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
const { authenticate, generateToken } = require('../middleware/auth');
const emailService = require('../services/email');
const otpService = require('../services/otp');

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
  const minLength = parseInt(process.env.MIN_PASSWORD_LENGTH || 12, 10);
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


// ── Register ────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { email: rawEmail, password, fullName, tier = 'gold', depositAmount = 0, pin } = req.body;
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

    // Create user
    const userId = db.users.create({ email, passwordHash, fullName, tier });

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

    // Activate account immediately (no OTP verification)
    db.raw().prepare("UPDATE users SET status = 'active', email_verified = 1 WHERE id = ?").run(userId);

    // Generate JWT so user is logged in right away
    const { token, jti, expiresAt } = generateToken(userId, 'user');
    db.sessions.create({ userId, tokenJti: jti, ipAddress: req.ip, userAgent: req.headers['user-agent'] || '', expiresAt });

    const wallet = db.wallets.findByUser(userId);

    res.status(201).json({
      success: true,
      token,
      user: { id: userId, email, fullName, role: 'user', tier, status: 'active', kycStatus: 'none' },
      wallet: wallet ? { balance: wallet.balance, initialDeposit: wallet.initial_deposit, totalDeposited: wallet.total_deposited, totalWithdrawn: wallet.total_withdrawn, totalEarned: wallet.total_earned } : null,
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// ── Login ───────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email: rawEmail, password } = req.body;
    const email = (rawEmail || '').trim().toLowerCase();

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = db.users.findByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check status
    if (user.status === 'suspended') {
      return res.status(403).json({ error: 'Account suspended. Contact support.' });
    }
    if (user.status === 'banned') {
      return res.status(403).json({ error: 'Account banned.' });
    }

    // Verify password
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      db.audit.log(user.id, 'auth.login_failed', { email }, 'warn', req.ip);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Direct login — generate JWT (no OTP)
    const { token, jti, expiresAt } = generateToken(user.id, user.role);
    db.sessions.create({ userId: user.id, tokenJti: jti, ipAddress: req.ip, userAgent: req.headers['user-agent'] || '', expiresAt });
    db.users.updateLogin(user.id);

    const wallet = db.wallets.findByUser(user.id);
    db.audit.log(user.id, 'auth.login', { ip: req.ip }, 'info', req.ip);

    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role, tier: user.tier, status: user.status, kycStatus: user.kyc_status },
      wallet: wallet ? { balance: wallet.balance, initialDeposit: wallet.initial_deposit, totalDeposited: wallet.total_deposited, totalWithdrawn: wallet.total_withdrawn, totalEarned: wallet.total_earned } : null,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// ── Get Current User ────────────────────────────────────────
router.get('/me', authenticate, (req, res) => {
  const wallet = db.wallets.findByUser(req.user.id);
  const tradeStats = db.trades.stats(req.user.id);

  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      fullName: req.user.full_name,
      role: req.user.role,
      tier: req.user.tier,
      status: req.user.status,
      kycStatus: req.user.kyc_status,
      createdAt: req.user.created_at,
      lastLogin: req.user.last_login,
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
  // Revoke current session
  db.sessions.revoke(req.tokenJti);
  db.audit.log(req.user.id, 'auth.logout', null, 'info', req.ip);
  res.json({ success: true, message: 'Logged out successfully' });
});

// ── Logout All Sessions ─────────────────────────────────────
router.post('/logout-all', authenticate, (req, res) => {
  db.sessions.revokeAllForUser(req.user.id);
  db.audit.log(req.user.id, 'auth.logout_all', null, 'info', req.ip);
  res.json({ success: true, message: 'All sessions revoked' });
});

// ── Change Password ─────────────────────────────────────────
router.post('/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters' });
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

    // Revoke all other sessions
    db.sessions.revokeAllForUser(req.user.id);

    // Re-issue token for current session
    const { token, jti, expiresAt } = generateToken(req.user.id, req.user.role);
    db.sessions.create({
      userId: req.user.id,
      tokenJti: jti,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || '',
      expiresAt,
    });

    db.audit.log(req.user.id, 'auth.password_changed', null, 'info', req.ip);

  res.json({ success: true, message: 'Password changed. All other sessions revoked.', token });
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

    const { token, jti, expiresAt } = generateToken(user.id, user.role);
    db.sessions.create({ userId: user.id, tokenJti: jti, ipAddress: req.ip, userAgent: req.headers['user-agent'] || '', expiresAt });
    db.users.updateLogin(user.id);

    const wallet = db.wallets.findByUser(user.id);
    db.audit.log(user.id, 'auth.email_verified', null, 'info', req.ip);

    // Send welcome email now that account is verified
    emailService.sendWelcome(user).catch(err => console.error('Welcome email failed:', err));
    const depositAmount = wallet ? wallet.initial_deposit : 0;
    if (depositAmount > 0) {
      emailService.sendDepositConfirm(user, depositAmount, 'Initial Deposit').catch(err => console.error('Deposit email failed:', err));
    }

    res.json({
      success: true,
      token,
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

    const { token, jti, expiresAt } = generateToken(user.id, user.role);
    db.sessions.create({ userId: user.id, tokenJti: jti, ipAddress: req.ip, userAgent: req.headers['user-agent'] || '', expiresAt });
    db.users.updateLogin(user.id);

    const wallet = db.wallets.findByUser(user.id);
    db.audit.log(user.id, 'auth.login', { ip: req.ip }, 'info', req.ip);

    res.json({
      success: true,
      token,
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

    if (type === 'email_verify') {
      emailService.sendEmailVerification(user, newCode).catch(err => console.error('Resend email failed:', err));
    } else if (type === 'login_otp') {
      emailService.sendLoginOTP(user, newCode, req.ip).catch(err => console.error('Resend login OTP failed:', err));
    }

    db.audit.log(userId, `auth.otp_resent.${type}`, null, 'info', req.ip);
    res.json({ success: true, message: 'A new verification code has been sent to your email.' });
  } catch (err) {
    console.error('Resend OTP error:', err);
    res.status(500).json({ error: 'Failed to resend code. Please try again.' });
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
    if (user.status === 'suspended') return res.status(403).json({ error: 'Account suspended. Contact support.' });
    if (user.status === 'banned') return res.status(403).json({ error: 'Account banned.' });
    if (!user.pin_hash) return res.status(400).json({ error: 'No PIN set for this account. Use password login.' });

    const valid = await bcrypt.compare(pin, user.pin_hash);
    if (!valid) {
      db.audit.log(user.id, 'auth.pin_login_failed', { email }, 'warn', req.ip);
      return res.status(401).json({ error: 'Invalid email or PIN' });
    }

    // PIN login skips OTP for convenience
    const { token, jti, expiresAt } = generateToken(user.id, user.role);
    db.sessions.create({ userId: user.id, tokenJti: jti, ipAddress: req.ip, userAgent: req.headers['user-agent'] || '', expiresAt });
    db.users.updateLogin(user.id);

    const wallet = db.wallets.findByUser(user.id);
    db.audit.log(user.id, 'auth.pin_login', { ip: req.ip }, 'info', req.ip);

    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role, tier: user.tier, status: user.status, kycStatus: user.kyc_status },
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
