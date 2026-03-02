/* ════════════════════════════════════════════════════════════
   services/cron.js — Automated Earnings Scheduler
   ZEN ASSETS Backend

   Daily  cron: credits APY-based earnings to every active user
   Weekly cron: creates bonus_weekly transaction summary
════════════════════════════════════════════════════════════ */

const cron  = require('node-cron');
const db    = require('../db/database');
const email = require('./email');

// ── Tier APY rates (annual) ─────────────────────────────────
const TIER_APY = {
  bronze:   0.18,   // 18% APY
  silver:   0.27,   // 27% APY
  gold:     0.38,   // 38% APY
  platinum: 0.55,   // 55% APY
  diamond:  0.75,   // 75% APY
};

const DAILY_RATE = Object.fromEntries(
  Object.entries(TIER_APY).map(([tier, apy]) => [tier, apy / 365])
);

// ── Process daily earnings for all active users ─────────────
async function runDailyEarnings() {
  if (process.env.EARNINGS_CRON_ENABLED !== 'true') {
    console.log('[CRON] Daily earnings disabled via EARNINGS_CRON_ENABLED');
    return;
  }

  console.log('[CRON] Running daily earnings job...');
  const rawDb = db.raw();

  // Fetch all active users (non-admin) with a wallet balance > 0
  const activeUsers = rawDb.prepare(`
    SELECT u.id, u.email, u.full_name, u.tier,
           w.balance, w.pending_earnings
    FROM users u
    JOIN wallets w ON w.user_id = u.id
    WHERE u.role = 'user'
      AND u.status = 'active'
      AND w.balance > 0
  `).all();

  let credited = 0;
  let skipped  = 0;

  for (const user of activeUsers) {
    try {
      const rate = DAILY_RATE[user.tier] || DAILY_RATE.gold;
      const earning = parseFloat((user.balance * rate).toFixed(2));

      if (earning < 0.01) { skipped++; continue; }

      // Credit wallet
      const { after: newBalance } = db.wallets.creditBalance(user.id, earning);

      // Record transaction
      db.transactions.create({
        userId:        user.id,
        type:          'bonus_daily',
        amount:        earning,
        status:        'completed',
        method:        'auto',
        reference:     `daily-${new Date().toISOString().slice(0, 10)}`,
        balanceBefore: user.balance,
        balanceAfter:  newBalance,
        notes:         `Daily earnings (${user.tier} tier, ${(rate * 100).toFixed(4)}% daily)`,
      });

      // Log audit
      db.audit.log(user.id, 'daily_earnings_credited', { earning, tier: user.tier }, 'info');

      // Send email notification (non-blocking)
      email.sendEarningsCredit(user, earning, 'daily', newBalance).catch(() => {});

      credited++;
    } catch (err) {
      console.error(`[CRON] Failed to credit earnings for user ${user.id}:`, err.message);
    }
  }

  console.log(`[CRON] Daily earnings: ${credited} credited, ${skipped} skipped (balance too low)`);
}

// ── Process weekly bonus summary ────────────────────────────
async function runWeeklyBonus() {
  if (process.env.EARNINGS_CRON_ENABLED !== 'true') return;

  console.log('[CRON] Running weekly bonus summary job...');
  const rawDb = db.raw();

  // Get users with completed daily earnings this week
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

  const weeklyTotals = rawDb.prepare(`
    SELECT t.user_id, u.email, u.full_name, u.tier,
           SUM(t.amount) as week_total,
           w.balance
    FROM transactions t
    JOIN users u ON u.id = t.user_id
    JOIN wallets w ON w.user_id = t.user_id
    WHERE t.type = 'bonus_daily'
      AND t.status = 'completed'
      AND t.created_at >= ?
    GROUP BY t.user_id
  `).all(weekAgo);

  for (const row of weeklyTotals) {
    try {
      // Calculate 2% weekly bonus on top of daily earnings
      const bonus = parseFloat((row.week_total * 0.02).toFixed(2));
      if (bonus < 0.01) continue;

      const { after: newBalance } = db.wallets.creditBalance(row.user_id, bonus);

      db.transactions.create({
        userId:        row.user_id,
        type:          'bonus_weekly',
        amount:        bonus,
        status:        'completed',
        method:        'auto',
        reference:     `weekly-${new Date().toISOString().slice(0, 10)}`,
        balanceBefore: row.balance,
        balanceAfter:  newBalance,
        notes:         `Weekly bonus (2% of $${row.week_total.toFixed(2)} in daily earnings)`,
      });

      db.audit.log(row.user_id, 'weekly_bonus_credited', { bonus, weekEarnings: row.week_total }, 'info');
      email.sendEarningsCredit({ email: row.email, full_name: row.full_name }, bonus, 'weekly', newBalance).catch(() => {});
    } catch (err) {
      console.error(`[CRON] Weekly bonus failed for ${row.user_id}:`, err.message);
    }
  }

  console.log('[CRON] Weekly bonus job complete');
}

// ── Init — registers cron jobs ──────────────────────────────
function init() {
  if (process.env.EARNINGS_CRON_ENABLED !== 'true') {
    console.log('[CRON] Earnings scheduler disabled. Set EARNINGS_CRON_ENABLED=true to enable.');
    return;
  }

  // Daily earnings: runs every day at 00:05 UTC
  cron.schedule('5 0 * * *', runDailyEarnings, { timezone: 'UTC' });
  console.log('[CRON] Daily earnings scheduled: 00:05 UTC every day');

  // Weekly bonus: runs every Sunday at 01:00 UTC
  cron.schedule('0 1 * * 0', runWeeklyBonus, { timezone: 'UTC' });
  console.log('[CRON] Weekly bonus scheduled: 01:00 UTC every Sunday');
}

module.exports = { init, runDailyEarnings, runWeeklyBonus };
