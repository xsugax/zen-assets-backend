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

// ── Register ────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { email, password, fullName, tier = 'gold', depositAmount = 0 } = req.body;

    // Validation
    if (!email || !password || !fullName) {
      return res.status(400).json({ error: 'Email, password, and full name are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
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

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      user: { id: userId, email: email.toLowerCase(), fullName, tier },
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// ── Login ───────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

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

    // Generate JWT
    const { token, jti, expiresAt } = generateToken(user.id, user.role);

    // Store session
    db.sessions.create({
      userId: user.id,
      tokenJti: jti,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || '',
      expiresAt,
    });

    // Update login timestamp
    db.users.updateLogin(user.id);

    // Get wallet
    const wallet = db.wallets.findByUser(user.id);

    // Audit
    db.audit.log(user.id, 'auth.login', { ip: req.ip }, 'info', req.ip);

    res.json({
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
      } : null,
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

module.exports = router;
