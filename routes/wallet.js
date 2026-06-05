/* ════════════════════════════════════════════════════════════
   routes/wallet.js — Wallet & Transaction Routes
   ZEN ASSETS Backend

   GET  /api/wallet              — Get wallet balance
   GET  /api/wallet/transactions — Transaction history
   POST /api/wallet/deposit      — Request deposit (pending)
   POST /api/wallet/withdraw     — Request withdrawal (pending)
   POST /api/wallet/claim        — Claim pending earnings
════════════════════════════════════════════════════════════ */

const express = require('express');
const router  = express.Router();
const db      = require('../db/database');
const { authenticate } = require('../middleware/auth');
const email   = require('../services/email');
const {
  assertTradingAllowed,
  assertProfitsAllowed,
  assertWithdrawalsAllowed,
} = require('../utils/user-controls');
const {
  parseSettingsJson,
  mergeSettings,
  normalizeCopyTrade,
  resolveActivationFee,
  isCopyEngineActive,
  attachSettingsToUser,
} = require('../utils/user-settings');

// All wallet routes require authentication
router.use(authenticate);

// ── Get Wallet ──────────────────────────────────────────────
router.get('/', (req, res) => {
  const wallet = db.wallets.findByUser(req.user.id);
  if (!wallet) return res.status(404).json({ error: 'Wallet not found' });

  res.json({
    ok: true,
    balance: wallet.balance,
    initialDeposit: wallet.initial_deposit,
    totalDeposited: wallet.total_deposited,
    totalWithdrawn: wallet.total_withdrawn,
    totalEarned: wallet.total_earned,
    totalClaimed: wallet.total_claimed,
    pendingEarnings: wallet.pending_earnings,
    updatedAt: wallet.updated_at,
  });
});

// ── Transaction History ─────────────────────────────────────
router.get('/transactions', (req, res) => {
  const { page = 1, limit = 20, type = '' } = req.query;
  const result = db.transactions.listByUser(req.user.id, {
    page: parseInt(page), limit: parseInt(limit), type,
  });
  res.json(result);
});

// ── Request Deposit ─────────────────────────────────────────
router.post('/deposit', (req, res) => {
  try {
    const { amount, method, reference = '' } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Amount must be greater than 0' });
    }
    if (!method) {
      return res.status(400).json({ error: 'Payment method is required' });
    }

    const validMethods = [
      'crypto_btc', 'crypto_eth', 'crypto_usdt', 'crypto_usdc', 'crypto_sol',
      'paypal', 'skrill', 'neteller', 'bank_transfer',
    ];
    if (!validMethods.includes(method)) {
      return res.status(400).json({ error: 'Invalid payment method' });
    }

    const wallet = db.wallets.findByUser(req.user.id);

    const txId = db.transactions.create({
      userId: req.user.id,
      type: 'deposit',
      amount,
      status: 'pending',
      method,
      reference,
      balanceBefore: wallet ? wallet.balance : 0,
      notes: `Deposit via ${method}`,
    });

    db.audit.log(req.user.id, 'wallet.deposit_requested', {
      amount, method, reference, txId,
    }, 'info', req.ip);

    res.json({
      success: true,
      message: 'Deposit request submitted. Awaiting confirmation.',
      transactionId: txId,
      // Return deposit instructions based on method
      instructions: getDepositInstructions(method),
    });
  } catch (err) {
    console.error('Deposit error:', err);
    res.status(500).json({ error: 'Failed to process deposit request' });
  }
});

// ── Request Withdrawal ──────────────────────────────────────
router.post('/withdraw', (req, res) => {
  try {
    assertWithdrawalsAllowed();
    const { amount, method, address = '', notes = '' } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Amount must be greater than 0' });
    }
    if (amount < 10) {
      return res.status(400).json({ error: 'Minimum withdrawal is $10' });
    }
    if (!method) {
      return res.status(400).json({ error: 'Withdrawal method is required' });
    }

    const wallet = db.wallets.findByUser(req.user.id);
    if (!wallet) return res.status(404).json({ error: 'Wallet not found' });

    if (wallet.balance < amount) {
      return res.status(400).json({
        error: 'Insufficient balance',
        available: wallet.balance,
        requested: amount,
      });
    }

    // For crypto withdrawals, address is required
    if (method.startsWith('crypto_') && !address) {
      return res.status(400).json({ error: 'Wallet address is required for crypto withdrawals' });
    }

    // KYC check for large withdrawals
    if (amount > 1000 && req.user.kyc_status !== 'verified') {
      return res.status(403).json({
        error: 'KYC verification required for withdrawals over $1,000',
        kycStatus: req.user.kyc_status,
      });
    }

    const withdrawAmount = Math.abs(parseFloat(amount));
    const { before, after } = db.wallets.debitBalance(req.user.id, withdrawAmount);

    const txId = db.transactions.create({
      userId: req.user.id,
      type: 'withdrawal',
      amount: -withdrawAmount,
      status: 'pending',
      method,
      reference: address,
      balanceBefore: before,
      balanceAfter: after,
      notes: notes || `Withdrawal to ${method}: ${address || 'N/A'}`,
    });

    db.audit.log(req.user.id, 'wallet.withdrawal_requested', {
      amount, method, address, txId,
    }, 'warn', req.ip);

    const user = db.users.findById(req.user.id);
    if (user) {
      email.sendWithdrawalUpdate(user, amount, 'pending', method).catch(() => {});
    }

    res.json({
      success: true,
      message: 'Withdrawal request submitted. Pending admin approval.',
      transactionId: txId,
      estimatedTime: getProcessingTime(method),
    });
  } catch (err) {
    if (err.status === 403 || err.status === 503) {
      return res.status(err.status).json({ error: err.message, code: err.code });
    }
    console.error('Withdrawal error:', err);
    res.status(500).json({ error: 'Failed to process withdrawal request' });
  }
});

// ── Copy engine activation fee (institutional clearance) ───
router.get('/copy-engine', (req, res) => {
  const settings = parseSettingsJson(req.user.settings_json);
  const copyTrade = normalizeCopyTrade(settings.copyTrade);
  const fee = resolveActivationFee(copyTrade, req.user.tier);
  res.json({
    ok: true,
    copyTrade,
    activationFee: fee,
    status: isCopyEngineActive(copyTrade) ? 'active'
      : (copyTrade.feePaid && !copyTrade.activated) ? 'pending_clearance'
      : (copyTrade.mode !== 'disabled' && copyTrade.enabled) ? 'awaiting_payment'
      : 'locked',
  });
});

router.post('/copy-activation', (req, res) => {
  try {
    const settings = parseSettingsJson(req.user.settings_json);
    const copyTrade = normalizeCopyTrade(settings.copyTrade);

    if (isCopyEngineActive(copyTrade)) {
      return res.status(400).json({ error: 'Copy engine is already active.', code: 'ALREADY_ACTIVE' });
    }
    if (copyTrade.feePaid) {
      return res.status(400).json({ error: 'Activation fee already authorized. Awaiting account manager clearance.', code: 'PENDING_CLEARANCE' });
    }
    if (copyTrade.mode === 'disabled' || !copyTrade.enabled) {
      return res.status(403).json({ error: 'No institutional strategy assigned yet. Contact your account manager.', code: 'NOT_ASSIGNED' });
    }

    const fee = resolveActivationFee(copyTrade, req.user.tier);
    const wallet = db.wallets.findByUser(req.user.id);
    if (!wallet) return res.status(404).json({ error: 'Wallet not found' });
    if (wallet.balance < fee) {
      return res.status(400).json({
        error: `Insufficient balance. Engine activation requires $${fee.toLocaleString()}.`,
        code: 'INSUFFICIENT_BALANCE',
        activationFee: fee,
        balance: wallet.balance,
      });
    }

    const { before, after } = db.wallets.debitBalance(req.user.id, fee);
    const now = new Date().toISOString();
    const nextCopy = normalizeCopyTrade({
      ...copyTrade,
      feePaid: true,
      feePaidAt: now,
      activationRequestedAt: now,
      activated: false,
    });
    const merged = mergeSettings(req.user.settings_json, { copyTrade: nextCopy });
    db.users.updateSettings(req.user.id, merged);

    db.transactions.create({
      userId: req.user.id,
      type: 'copy_activation_fee',
      amount: fee,
      status: 'completed',
      method: 'wallet',
      balanceBefore: before,
      balanceAfter: after,
      notes: `Institutional copy engine activation fee — pending clearance`,
    });

    db.audit.log(req.user.id, 'copy_activation_fee_paid', { fee, tier: req.user.tier }, 'info');

    const updatedUser = attachSettingsToUser(db.users.findById(req.user.id));
    res.json({
      ok: true,
      fee,
      balance: after,
      copyTrade: updatedUser.copyTrade,
      status: 'pending_clearance',
      message: 'Activation fee authorized. Your account manager will enable live execution.',
    });
  } catch (err) {
    console.error('Copy activation error:', err);
    res.status(500).json({ error: 'Failed to process activation fee' });
  }
});

// ── Claim Pending Earnings ──────────────────────────────────
router.post('/claim', (req, res) => {
  try {
    assertProfitsAllowed(req.user);
    const { amount, pool = 'all' } = req.body;
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Nothing to claim' });
    }

    const wallet = db.wallets.findByUser(req.user.id);
    if (!wallet) return res.status(404).json({ error: 'Wallet not found' });

    const claimAmount = parseFloat(amount);
    const pending = parseFloat(wallet.pending_earnings) || 0;
    if (claimAmount > pending + 0.001) {
      return res.status(400).json({
        error: `Cannot claim more than pending earnings ($${pending.toFixed(2)})`,
        pendingEarnings: pending,
      });
    }

    // Transfer from pending -> balance
    const newBalance = wallet.balance + claimAmount;
    db.raw().prepare(`
      UPDATE wallets SET
        balance = ?,
        total_claimed = total_claimed + ?,
        pending_earnings = MAX(0, pending_earnings - ?),
        updated_at = datetime('now')
      WHERE user_id = ?
    `).run(newBalance, claimAmount, claimAmount, req.user.id);

    db.transactions.create({
      userId: req.user.id,
      type: 'claim',
      amount: claimAmount,
      status: 'completed',
      method: pool,
      balanceBefore: wallet.balance,
      balanceAfter: newBalance,
      notes: `Claimed from ${pool} pool`,
    });

    res.json({
      success: true,
      claimed: claimAmount,
      balanceBefore: wallet.balance,
      balanceAfter: newBalance,
      pendingEarnings: Math.max(0, pending - claimAmount),
    });
  } catch (err) {
    if (err.status === 403) return res.status(403).json({ error: err.message, code: err.code });
    console.error('Claim error:', err);
    res.status(500).json({ error: 'Failed to process claim' });
  }
});

// ── Helpers ─────────────────────────────────────────────────
function getDepositInstructions(method) {
  const instructions = {
    crypto_btc:  { network: 'Bitcoin', confirmations: 3, minAmount: 0.0001 },
    crypto_eth:  { network: 'Ethereum (ERC-20)', confirmations: 12, minAmount: 0.01 },
    crypto_usdt: { network: 'Solana SPL', confirmations: 1, minAmount: 10 },
    crypto_usdc: { network: 'Ethereum (ERC-20)', confirmations: 12, minAmount: 10 },
    crypto_sol:  { network: 'Solana', confirmations: 1, minAmount: 0.1 },
    paypal:      { minAmount: 10, fee: '3.49% + $0.49' },
    bank_transfer: { minAmount: 100, processingDays: '1-3 business days' },
  };
  return instructions[method] || { note: 'Contact support for instructions' };
}

function getProcessingTime(method) {
  const times = {
    crypto_btc: '10-60 minutes',
    crypto_eth: '5-15 minutes',
    crypto_usdt: '5-15 minutes',
    crypto_usdc: '5-15 minutes',
    crypto_sol: '1-5 minutes',
    paypal: '1-2 business days',
    bank_transfer: '3-5 business days',
  };
  return times[method] || '1-5 business days';
}

module.exports = router;
