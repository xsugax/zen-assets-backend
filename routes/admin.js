/* ════════════════════════════════════════════════════════════
   routes/admin.js — Admin Management Routes
   ZEN ASSETS Backend

   All routes require admin role.

   GET    /api/admin/users          — List users (paginated, searchable)
   GET    /api/admin/users/:id      — Get user details
   PATCH  /api/admin/users/:id      — Update user (status, tier, KYC)
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
const db      = require('../db/database');
const { authenticate, requireAdmin } = require('../middleware/auth');

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

// ── Update User (status, tier, KYC) ─────────────────────────
router.patch('/users/:id', (req, res) => {
  const user = db.users.findById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { status, tier, kycStatus } = req.body;
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

  if (changes.length > 0) {
    db.audit.log(req.user.id, 'admin.user_updated', {
      targetUser: req.params.id,
      changes: changes.join(', '),
    }, 'info', req.ip);
  }

  const updated = db.users.findById(req.params.id);
  res.json({ success: true, user: updated, changes });
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

// ── Audit Log ───────────────────────────────────────────────
router.get('/audit', (req, res) => {
  const { page = 1, limit = 50, userId = '', severity = '' } = req.query;
  const result = db.audit.list({
    page: parseInt(page), limit: parseInt(limit), userId, severity,
  });
  res.json(result);
});

module.exports = router;
