/* ════════════════════════════════════════════════════════════
   routes/admin.js — Admin Management Routes
   ZEN ASSETS Backend

   All routes require admin role.

   GET    /api/admin/users          — List users (paginated, searchable)
   POST   /api/admin/users          — Create user (admin-created, skips OTP)
   GET    /api/admin/users/:id      — Get user details
   PATCH  /api/admin/users/:id      — Update user (status, tier, KYC, balance)
   DELETE /api/admin/users/:id      — Delete user
   POST   /api/admin/users/:id/credit   — Credit balance
   POST   /api/admin/users/:id/debit    — Debit balance
   GET    /api/admin/withdrawals    — Pending withdrawals
   POST   /api/admin/withdrawals/:id/approve  — Approve withdrawal
   POST   /api/admin/withdrawals/:id/reject   — Reject withdrawal
   GET    /api/admin/stats          — Platform statistics
   GET    /api/admin/audit          — Audit log
════════════════════════════════════════════════════════════ */

const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const db      = require('../db/database');
const { authenticate, requireAdmin } = require('../middleware/auth');
const email   = require('../services/email');

// All admin routes require authentication + admin role
router.use(authenticate, requireAdmin);

// ── List Users ──────────────────────────────────────────────
router.get('/users', (req, res) => {
  const { page = 1, limit = 20, search = '', status = '', tier = '' } = req.query;
  const result = db.users.list({
    page: parseInt(page), limit: parseInt(limit), search, status, tier,
  });
  res.json(result);
});

// ── Get User Details ────────────────────────────────────────
router.get('/users/:id', (req, res) => {
  const user = db.users.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const wallet = db.wallets.findByUser(req.params.id);
  const tradeStats = db.trades.stats(req.params.id);
  const recentTx = db.transactions.listByUser(req.params.id, { limit: 10 });
  const recentTrades = db.trades.listByUser(req.params.id, { limit: 10 });

  res.json({
    user,
    wallet: wallet || {},
    trading: tradeStats || {},
    recentTransactions: recentTx.transactions,
    recentTrades: recentTrades.trades,
  });
});

// ── Admin Create User ───────────────────────────────────────
router.post('/users', async (req, res) => {
  try {
    const { email: rawEmail, fullName, password, pin, tier = 'gold', depositAmount = 0 } = req.body;
    if (!rawEmail || !fullName || !password) {
      return res.status(400).json({ error: 'Email, full name, and password are required' });
    }
    const userEmail = rawEmail.toLowerCase().trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    const existing = db.users.findByEmail(userEmail);
    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const userId = db.users.create({ email: userEmail, passwordHash, fullName, tier });

    // Set PIN if provided
    if (pin && /^\d{4}$/.test(pin)) {
      const pinHash = await bcrypt.hash(pin, 10);
      db.users.setPin(userId, pinHash);
    }

    // Activate immediately (admin-created accounts skip email verification)
    db.users.updateStatus(userId, 'active');

    // Create wallet with initial deposit
    const dep = parseFloat(depositAmount) || 0;
    db.wallets.create(userId, dep);

    if (dep > 0) {
      db.transactions.create({
        userId, type: 'admin_credit', amount: dep, status: 'completed',
        method: 'admin', balanceBefore: 0, balanceAfter: dep,
        notes: `Admin-created account funded by ${req.user.email}`,
      });
    }

    db.audit.log(req.user.id, 'admin.user_created', {
      targetUser: userId, email: userEmail, tier, depositAmount: dep,
    }, 'info', req.ip);

    const created = db.users.findById(userId);
    const wallet = db.wallets.findByUser(userId);
    res.status(201).json({ success: true, user: created, wallet });
  } catch (err) {
    console.error('Admin create user error:', err);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// ── Update User (status, tier, KYC, balance) ────────────────
router.patch('/users/:id', (req, res) => {
  const user = db.users.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { status, tier, kycStatus, balance, depositAmount } = req.body;
  const changes = [];

  if (status && ['active', 'suspended', 'banned'].includes(status)) {
    db.users.updateStatus(req.params.id, status);
    changes.push(`status → ${status}`);
  }
  if (tier && ['bronze', 'silver', 'gold', 'platinum', 'diamond'].includes(tier)) {
    db.users.updateTier(req.params.id, tier);
    changes.push(`tier → ${tier}`);
  }
  if (kycStatus && ['pending', 'submitted', 'verified', 'rejected'].includes(kycStatus)) {
    db.users.updateKYC(req.params.id, kycStatus);
    changes.push(`KYC → ${kycStatus}`);
  }

  // Handle balance/deposit updates from admin funding
  const fundAmount = parseFloat(balance) || parseFloat(depositAmount) || 0;
  if (fundAmount > 0) {
    try {
      let wallet = db.wallets.findByUser(req.params.id);
      if (!wallet) {
        db.wallets.create(req.params.id, fundAmount);
        changes.push(`wallet created: $${fundAmount}`);
      } else if (wallet.balance !== fundAmount) {
        db.wallets.setBalance(req.params.id, fundAmount);
        changes.push(`balance → $${fundAmount}`);
      }
    } catch (e) {
      console.warn('Wallet update:', e.message);
    }
  }

  if (changes.length > 0) {
    db.audit.log(req.user.id, 'admin.user_updated', {
      targetUser: req.params.id,
      changes: changes.join(', '),
    }, 'info', req.ip);
  }

  const updated = db.users.findById(req.params.id);
  const wallet = db.wallets.findByUser(req.params.id);
  res.json({ success: true, user: updated, wallet, changes });
});

// ── Delete User ─────────────────────────────────────────────
router.delete('/users/:id', (req, res) => {
  const user = db.users.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  db.audit.log(req.user.id, 'admin.user_deleted', {
    targetUser: req.params.id,
    email: user.email,
  }, 'critical', req.ip);

  db.users.delete(req.params.id);
  res.json({ success: true, message: `User ${user.email} deleted` });
});

// ── Credit Balance ──────────────────────────────────────────
router.post('/users/:id/credit', (req, res) => {
  try {
    const { amount, notes = '' } = req.body;
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Amount must be greater than 0' });
    }

    const user = db.users.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { before, after } = db.wallets.addDeposit(req.params.id, amount);

    db.transactions.create({
      userId: req.params.id,
      type: 'admin_credit',
      amount,
      status: 'completed',
      method: 'admin',
      balanceBefore: before,
      balanceAfter: after,
      notes: notes || `Admin credit by ${req.user.email}`,
    });

    db.audit.log(req.user.id, 'admin.balance_credit', {
      targetUser: req.params.id,
      amount,
      before,
      after,
      notes,
    }, 'warn', req.ip);

    res.json({ success: true, balance: after, credited: amount });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── Debit Balance ───────────────────────────────────────────
router.post('/users/:id/debit', (req, res) => {
  try {
    const { amount, notes = '' } = req.body;
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Amount must be greater than 0' });
    }

    const user = db.users.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { before, after } = db.wallets.debitBalance(req.params.id, amount);

    db.transactions.create({
      userId: req.params.id,
      type: 'admin_debit',
      amount: -amount,
      status: 'completed',
      method: 'admin',
      balanceBefore: before,
      balanceAfter: after,
      notes: notes || `Admin debit by ${req.user.email}`,
    });

    db.audit.log(req.user.id, 'admin.balance_debit', {
      targetUser: req.params.id,
      amount,
      before,
      after,
      notes,
    }, 'warn', req.ip);

    res.json({ success: true, balance: after, debited: amount });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── Pending Withdrawals ─────────────────────────────────────
router.get('/withdrawals', (req, res) => {
  const pending = db.transactions.listPending('withdrawal');
  res.json({ withdrawals: pending });
});

// ── Approve Withdrawal ──────────────────────────────────────
router.post('/withdrawals/:id/approve', (req, res) => {
  try {
    const tx = db.transactions.findById(req.params.id);
    if (!tx) return res.status(404).json({ error: 'Transaction not found' });
    if (tx.type !== 'withdrawal') return res.status(400).json({ error: 'Not a withdrawal' });
    if (tx.status !== 'pending') return res.status(400).json({ error: `Cannot approve: status is ${tx.status}` });

    // Process the withdrawal (debit funds)
    const { before, after } = db.wallets.processWithdrawal(tx.user_id, Math.abs(tx.amount));

    // Update transaction
    db.transactions.updateStatus(req.params.id, 'completed', req.user.id);

    // Update balance snapshots
    db.raw().prepare('UPDATE transactions SET balance_before = ?, balance_after = ? WHERE id = ?')
      .run(before, after, req.params.id);

    db.audit.log(req.user.id, 'admin.withdrawal_approved', {
      txId: req.params.id,
      userId: tx.user_id,
      amount: tx.amount,
    }, 'warn', req.ip);

    // Notify user
    const user = db.users.findById(tx.user_id);
    if (user) email.sendWithdrawalUpdate(user, Math.abs(tx.amount), 'completed').catch(() => {});

    res.json({ success: true, message: 'Withdrawal approved and processed' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── Reject Withdrawal ───────────────────────────────────────
router.post('/withdrawals/:id/reject', (req, res) => {
  const { reason = '' } = req.body;
  const tx = db.transactions.findById(req.params.id);
  if (!tx) return res.status(404).json({ error: 'Transaction not found' });
  if (tx.type !== 'withdrawal') return res.status(400).json({ error: 'Not a withdrawal' });
  if (tx.status !== 'pending') return res.status(400).json({ error: `Cannot reject: status is ${tx.status}` });

  db.transactions.updateStatus(req.params.id, 'rejected', req.user.id);

  db.audit.log(req.user.id, 'admin.withdrawal_rejected', {
    txId: req.params.id,
    userId: tx.user_id,
    amount: tx.amount,
    reason,
  }, 'warn', req.ip);

  // Notify user
  const rejUser = db.users.findById(tx.user_id);
  if (rejUser) email.sendWithdrawalUpdate(rejUser, Math.abs(tx.amount), 'rejected', reason).catch(() => {});

  res.json({ success: true, message: 'Withdrawal rejected' });
});

// ── Platform Statistics ─────────────────────────────────────
router.get('/stats', (req, res) => {
  const userCount = db.users.count();
  const txStats = db.transactions.stats();

  // Total platform balance
  const totalBalance = db.raw().prepare(
    'SELECT SUM(balance) as total FROM wallets'
  ).get();

  // Users by tier
  const tierBreakdown = db.raw().prepare(`
    SELECT tier, COUNT(*) as count FROM users WHERE role != 'admin' GROUP BY tier
  `).all();

  // Users by status
  const statusBreakdown = db.raw().prepare(`
    SELECT status, COUNT(*) as count FROM users WHERE role != 'admin' GROUP BY status
  `).all();

  // Recent signups (last 7 days)
  const recentSignups = db.raw().prepare(`
    SELECT COUNT(*) as count FROM users
    WHERE created_at >= datetime('now', '-7 days') AND role != 'admin'
  `).get();

  res.json({
    users: {
      total: userCount,
      recentSignups: recentSignups.count,
      byTier: tierBreakdown,
      byStatus: statusBreakdown,
    },
    financial: {
      totalPlatformBalance: totalBalance.total || 0,
      ...txStats,
    },
  });
});

// ── Admin Set/Reset User PIN ────────────────────────────────
router.post('/users/:id/set-pin', async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin || !/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });

    const user = db.users.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const pinHash = await bcrypt.hash(pin, 10);
    db.users.setPin(req.params.id, pinHash);

    db.audit.log(req.user.id, 'admin.user_pin_set', {
      targetUser: req.params.id,
      email: user.email,
    }, 'info', req.ip);

    res.json({ success: true, message: `PIN set for ${user.email}` });
  } catch (err) {
    console.error('Admin set PIN error:', err);
    res.status(500).json({ error: 'Failed to set PIN' });
  }
});

// ── Admin Reset Password ────────────────────────────────────
router.post('/users/:id/reset-password', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const user = db.users.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const passwordHash = await bcrypt.hash(password, 12);
    db.raw().prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, req.params.id);

    db.audit.log(req.user.id, 'admin.user_password_reset', {
      targetUser: req.params.id,
      email: user.email,
    }, 'warn', req.ip);

    res.json({ success: true, message: `Password reset for ${user.email}` });
  } catch (err) {
    console.error('Admin password reset error:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ── Audit Log ───────────────────────────────────────────────
router.get('/audit', (req, res) => {
  const { page = 1, limit = 50, userId = '', severity = '' } = req.query;
  const result = db.audit.list({
    page: parseInt(page), limit: parseInt(limit), userId, severity,
  });
  res.json(result);
});

module.exports = router;
