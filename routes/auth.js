/* ════════════════════════════════════════════════════════════
   routes/auth.js — Authentication Routes
   ZEN ASSETS Backend

   POST /api/auth/register   — Create account
   POST /api/auth/login      — Login
   GET  /api/auth/me         — Current user + wallet
   POST /api/auth/logout     — Revoke session
   POST /api/auth/change-password — Change password
════════════════════════════════════════════════════════════ */

const express = require('express');
const bcrypt  = require('bcryptjs');
const router  = express.Router();
const db      = require('../db/database');
const { authenticate, generateToken } = require('../middleware/auth');
const email   = require('../services/email');

// ── Password Strength Validator ─────────────────────────────
function validatePassword(pwd) {
  // Simple, user-friendly validation
  if (!pwd || pwd.length < 8) {
    return { ok: false, error: 'Password must be at least 8 characters' };
  }
  if (pwd.length > 128) {
    return { ok: false, error: 'Password must be less than 128 characters' };
  }
  return { ok: true };
}


// ── Register ────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { email, password, fullName, tier = 'gold', depositAmount = 0 } = req.body;

    // Validation
    if (!email || !password || !fullName) {
      return res.status(400).json({ ok: false, error: 'Email, password, and full name are required' });
    }

    const emailLower = email.toLowerCase().trim();
    
    // Email validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLower)) {
      return res.status(400).json({ ok: false, error: 'Invalid email format' });
    }

    // Password validation
    const pwdCheck = validatePassword(password);
    if (!pwdCheck.ok) {
      return res.status(400).json({ ok: false, error: pwdCheck.error });
    }

    // Check duplicate
    const existing = db.users.findByEmail(emailLower);
    if (existing) {
      return res.status(409).json({ ok: false, error: 'An account with this email already exists. Please login instead.' });
    }

    // Verify tier is valid
    const validTiers = ['bronze', 'silver', 'gold', 'platinum', 'diamond'];
    if (!validTiers.includes(tier)) {
      return res.status(400).json({ ok: false, error: 'Invalid membership tier' });
    }

    // Verify deposit meets minimum for tier
    const deposit = parseFloat(depositAmount) || 0;
    const minDeposits = { bronze: 5000, silver: 25000, gold: 100000, platinum: 500000, diamond: 1000000 };
    if (deposit < minDeposits[tier]) {
      return res.status(400).json({ ok: false, error: `${tier.charAt(0).toUpperCase() + tier.slice(1)} tier requires minimum $${minDeposits[tier].toLocaleString()} deposit` });
    }

    // Hash password (cost factor 10 for speed)
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    let userId;
    try {
      userId = db.users.create({ email: emailLower, passwordHash, fullName, tier });
    } catch (dbErr) {
      console.error('DB Create User Error:', dbErr);
      return res.status(500).json({ ok: false, error: 'Failed to create account. Please try again.' });
    }

    // Create wallet
    try {
      db.wallets.create(userId, deposit);
    } catch (dbErr) {
      console.error('DB Create Wallet Error:', dbErr);
      // Don't fail - user is created, wallet might have issues
    }

    // Log transaction if deposit
    if (deposit > 0) {
      try {
        db.transactions.create({
          userId,
          type: 'deposit',
          amount: deposit,
          status: 'completed',
          method: 'initial_deposit',
          balanceBefore: 0,
          balanceAfter: deposit,
          notes: 'Initial registration deposit',
        });
      } catch (e) {
        console.error('Transaction Log Error:', e);
      }
    }

    // Audit log (don't fail on audit)
    try {
      if (db.audit && db.audit.log) {
        db.audit.log(userId, 'user.registered', { email: emailLower, tier, depositAmount: deposit }, 'info', req.ip);
      }
    } catch (e) {
      console.error('Audit Error:', e);
    }

    // Send welcome email (fire-and-forget, don't block)
    if (email && email.sendWelcome) {
      email.sendWelcome({ email: emailLower, full_name: fullName }).catch(err => {
        console.error('Email send error:', err.message);
      });
    }

    res.status(201).json({
      ok: true,
      success: true,
      message: 'Account created successfully! You can now login.',
      user: { id: userId, email: emailLower, fullName, tier },
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ ok: false, error: 'Registration failed. Please try again or contact support.' });
  }
});

// ── Login ───────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password are required' });
    }

    const emailLower = email.toLowerCase().trim();

    // Find user
    const user = db.users.findByEmail(emailLower);
    if (!user) {
      // Don't reveal if email exists - generic error for security
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }

    // Check account status
    if (user.status === 'suspended') {
      return res.status(403).json({ ok: false, error: 'Account suspended. Please contact support.' });
    }
    if (user.status === 'banned') {
      return res.status(403).json({ ok: false, error: 'Account is no longer active.' });
    }

    // Verify password
    let passwordValid = false;
    try {
      passwordValid = await bcrypt.compare(password, user.password_hash);
    } catch (bcryptErr) {
      console.error('Bcrypt compare error:', bcryptErr);
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }

    if (!passwordValid) {
      // Log failed attempt (don't block)
      if (db.audit && db.audit.log) {
        try {
          db.audit.log(user.id, 'auth.login_failed', { email: emailLower, ip: req.ip }, 'warn', req.ip);
        } catch (e) {
          console.error('Audit error:', e);
        }
      }
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }

    // Generate JWT
    let token, jti, expiresAt;
    try {
      const tokenData = generateToken(user.id, user.role);
      token = tokenData.token;
      jti = tokenData.jti;
      expiresAt = tokenData.expiresAt;
    } catch (jwtErr) {
      console.error('JWT generation error:', jwtErr);
      return res.status(500).json({ ok: false, error: 'Login failed. Please try again.' });
    }

    // Create session (don't fail if this fails)
    try {
      db.sessions.create({
        userId: user.id,
        tokenJti: jti,
        ipAddress: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        expiresAt,
      });
    } catch (sessErr) {
      console.error('Session creation error:', sessErr);
      // Continue anyway - token will still work
    }

    // Update login timestamp (don't fail if this fails)
    try {
      db.users.updateLogin(user.id);
    } catch (updateErr) {
      console.error('Update login error:', updateErr);
    }

    // Get wallet
    let wallet = null;
    try {
      wallet = db.wallets.findByUser(user.id);
    } catch (walletErr) {
      console.error('Wallet error:', walletErr);
    }

    // Audit log (don't block)
    if (db.audit && db.audit.log) {
      try {
        db.audit.log(user.id, 'auth.login', { ip: req.ip }, 'info', req.ip);
      } catch (e) {
        console.error('Audit error:', e);
      }
    }

    res.json({
      ok: true,
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        tier: user.tier,
        status: user.status,
        kycStatus: user.kyc_status,
      },
      wallet: wallet ? {
        balance: wallet.balance,
        initialDeposit: wallet.initial_deposit,
        totalDeposited: wallet.total_deposited,
        totalWithdrawn: wallet.total_withdrawn,
        totalEarned: wallet.total_earned,
      } : { balance: 0 },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ ok: false, error: 'Login failed. Please try again or contact support.' });
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

module.exports = router;
