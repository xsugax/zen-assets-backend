/* ════════════════════════════════════════════════════════════
   routes/trades.js — Trade History API
   ZEN ASSETS Backend

   POST   /api/trades           — save a completed trade
   GET    /api/trades           — list user's trades (paginated)
   GET    /api/trades/stats     — win rate, total PnL, etc.
   GET    /api/trades/open      — open positions for user
   PATCH  /api/trades/:id/close — close an open trade
════════════════════════════════════════════════════════════ */

const express = require('express');
const router  = express.Router();
const { authenticate } = require('../middleware/auth');
const db      = require('../db/database');

// ── POST /api/trades — save a trade ────────────────────────
router.post('/', authenticate, (req, res) => {
  try {
    const {
      symbol, side, order_type, quantity,
      entry_price, exit_price, pnl, fee,
      status, strategy, notes,
      opened_at, closed_at,
    } = req.body;

    if (!symbol || !side || !quantity || !entry_price) {
      return res.status(400).json({ error: 'symbol, side, quantity, entry_price are required' });
    }

    if (!['buy', 'sell'].includes(side)) {
      return res.status(400).json({ error: 'side must be buy or sell' });
    }

    const userId = req.user.id;
    const rawDb  = db.raw();

    // If trade is already closed (frontend records a complete trade), upsert it
    const tradeStatus = status || (exit_price ? 'closed' : 'open');

    const id = require('uuid').v4();
    rawDb.prepare(`
      INSERT INTO trades (
        id, user_id, symbol, side, order_type,
        quantity, entry_price, exit_price, pnl, fee,
        status, strategy, notes, opened_at, closed_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id, userId, symbol.toUpperCase(), side,
      order_type || 'market',
      quantity, entry_price,
      exit_price || null,
      pnl || 0, fee || 0,
      tradeStatus, strategy || null, notes || null,
      opened_at || new Date().toISOString(),
      closed_at || (tradeStatus === 'closed' ? new Date().toISOString() : null),
    );

    // If profitable closed trade, record balance movement as transaction
    if (tradeStatus === 'closed' && pnl && pnl !== 0) {
      const wallet = db.wallets.findByUser(userId);
      if (wallet) {
        const txType = pnl > 0 ? 'trade_profit' : 'trade_loss';
        const absAmount = Math.abs(Number(pnl));

        if (pnl > 0) {
          db.wallets.creditBalance(userId, absAmount);
        } else {
          try { db.wallets.debitBalance(userId, absAmount); } catch (_) { /* already deducted in frontend */ }
        }

        const updatedWallet = db.wallets.findByUser(userId);
        db.transactions.create({
          userId,
          type:          txType,
          amount:        absAmount,
          status:        'completed',
          method:        'auto_trader',
          reference:     id,
          balanceBefore: wallet.balance,
          balanceAfter:  updatedWallet ? updatedWallet.balance : wallet.balance,
          notes:         `${symbol} ${side} — PnL: ${pnl >= 0 ? '+' : ''}${Number(pnl).toFixed(2)}`,
        });
      }
    }

    db.audit.log(userId, 'trade_saved', { id, symbol, side, pnl }, 'info');

    res.status(201).json({ id, message: 'Trade saved' });
  } catch (err) {
    console.error('POST /api/trades error:', err);
    res.status(500).json({ error: 'Failed to save trade' });
  }
});

// ── GET /api/trades/stats — aggregated PnL stats ───────────
router.get('/stats', authenticate, (req, res) => {
  try {
    const stats = db.trades.stats(req.user.id);
    const winRate = stats.total_trades > 0
      ? parseFloat(((stats.wins / stats.total_trades) * 100).toFixed(1))
      : 0;
    res.json({ ...stats, win_rate: winRate });
  } catch (err) {
    console.error('GET /api/trades/stats error:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ── GET /api/trades/open — open positions ──────────────────
router.get('/open', authenticate, (req, res) => {
  try {
    const positions = db.trades.openPositions(req.user.id);
    res.json({ positions });
  } catch (err) {
    console.error('GET /api/trades/open error:', err);
    res.status(500).json({ error: 'Failed to fetch open positions' });
  }
});

// ── GET /api/trades — paginated trade list ─────────────────
router.get('/', authenticate, (req, res) => {
  try {
    const page   = parseInt(req.query.page, 10)  || 1;
    const limit  = parseInt(req.query.limit, 10) || 20;
    const status = req.query.status || '';
    const result = db.trades.listByUser(req.user.id, { page, limit, status });
    res.json(result);
  } catch (err) {
    console.error('GET /api/trades error:', err);
    res.status(500).json({ error: 'Failed to fetch trades' });
  }
});

// ── PATCH /api/trades/:id/close — close open trade ─────────
router.patch('/:id/close', authenticate, (req, res) => {
  try {
    const trade = db.raw().prepare(
      'SELECT * FROM trades WHERE id = ? AND user_id = ?'
    ).get(req.params.id, req.user.id);

    if (!trade) return res.status(404).json({ error: 'Trade not found' });
    if (trade.status !== 'open') return res.status(400).json({ error: 'Trade is not open' });

    const { exit_price, pnl, fee } = req.body;
    if (!exit_price) return res.status(400).json({ error: 'exit_price required' });

    db.trades.close(trade.id, exit_price, pnl || 0, fee || 0);
    res.json({ message: 'Trade closed', id: trade.id });
  } catch (err) {
    console.error('PATCH /api/trades/:id/close error:', err);
    res.status(500).json({ error: 'Failed to close trade' });
  }
});

module.exports = router;
