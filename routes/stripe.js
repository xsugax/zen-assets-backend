/* ════════════════════════════════════════════════════════════
   routes/stripe.js — Stripe Payment Integration
   ZEN ASSETS Backend

   GET  /api/stripe/publishable-key    — return pk_ key to frontend
   POST /api/stripe/create-session     — create Checkout session
   POST /api/stripe/webhook            — handle payment.succeeded
════════════════════════════════════════════════════════════ */

const express = require('express');
const router  = express.Router();
const { authenticate } = require('../middleware/auth');
const db      = require('../db/database');
const email   = require('../services/email');

// Lazy-load Stripe only when keys are present
function getStripe() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key || key.startsWith('sk_test_placeholder') || key.startsWith('sk_live_placeholder')) {
    return null;
  }
  return require('stripe')(key);
}

// ── GET /api/stripe/publishable-key ────────────────────────
router.get('/publishable-key', (req, res) => {
  const key = process.env.STRIPE_PUBLISHABLE_KEY || '';
  if (!key || key.startsWith('pk_test_placeholder')) {
    return res.json({ key: null, enabled: false });
  }
  res.json({ key, enabled: true });
});

// ── POST /api/stripe/create-session ────────────────────────
router.post('/create-session', authenticate, async (req, res) => {
  const stripe = getStripe();
  if (!stripe) {
    return res.status(503).json({ error: 'Stripe payments not configured. Please add API keys.' });
  }

  try {
    const { amount } = req.body; // amount in USD
    if (!amount || isNaN(amount) || Number(amount) < 10) {
      return res.status(400).json({ error: 'Minimum deposit is $10' });
    }

    const amountCents = Math.round(Number(amount) * 100);
    const user = db.users.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      customer_email: user.email,
      line_items: [{
        price_data: {
          currency: 'usd',
          unit_amount: amountCents,
          product_data: {
            name: 'ZEN ASSETS Deposit',
            description: `Deposit $${Number(amount).toFixed(2)} to your trading wallet`,
          },
        },
        quantity: 1,
      }],
      metadata: {
        user_id:    req.user.id,
        user_email: user.email,
        amount_usd: amount.toString(),
      },
      success_url: `${process.env.FRONTEND_URL || 'https://zen-assets.surge.sh'}/?deposit=success&amount=${amount}`,
      cancel_url:  `${process.env.FRONTEND_URL || 'https://zen-assets.surge.sh'}/?deposit=cancelled`,
    });

    // Log pending deposit
    db.transactions.create({
      userId:    req.user.id,
      type:      'deposit',
      amount:    Number(amount),
      status:    'pending',
      method:    'stripe',
      reference: session.id,
      notes:     `Stripe Checkout session created`,
    });

    db.audit.log(req.user.id, 'stripe_session_created', { sessionId: session.id, amount }, 'info');

    res.json({ url: session.url, sessionId: session.id });
  } catch (err) {
    console.error('POST /api/stripe/create-session error:', err);
    res.status(500).json({ error: 'Failed to create payment session' });
  }
});

// ── POST /api/stripe/webhook ────────────────────────────────
// Stripe calls this endpoint on payment events
// Must be registered BEFORE express.json() middleware applies to raw body
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  const sig    = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!secret || secret.startsWith('whsec_placeholder')) {
    // Dev mode: process without signature verification
    console.warn('[STRIPE WEBHOOK] No webhook secret — skipping verification');
  }

  let event;
  try {
    if (secret && !secret.startsWith('whsec_placeholder')) {
      event = stripe.webhooks.constructEvent(req.body, sig, secret);
    } else {
      event = JSON.parse(req.body.toString());
    }
  } catch (err) {
    console.error('[STRIPE WEBHOOK] Signature verification failed:', err.message);
    return res.status(400).json({ error: `Webhook Error: ${err.message}` });
  }

  // ── Handle checkout.session.completed ──────────────────
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;

    if (session.payment_status === 'paid') {
      const userId    = session.metadata?.user_id;
      const amountUSD = parseFloat(session.metadata?.amount_usd || 0);

      if (!userId || !amountUSD) {
        console.error('[STRIPE WEBHOOK] Missing metadata:', session.metadata);
        return res.json({ received: true });
      }

      try {
        const user = db.users.findById(userId);
        if (!user) throw new Error(`User ${userId} not found`);

        // Credit wallet
        db.wallets.addDeposit(userId, amountUSD);

        // Update pending transaction to completed
        const rawDb = db.raw();
        rawDb.prepare(`
          UPDATE transactions SET status = 'completed', processed_at = datetime('now')
          WHERE reference = ? AND user_id = ? AND type = 'deposit'
        `).run(session.id, userId);

        db.audit.log(userId, 'stripe_payment_completed', { sessionId: session.id, amount: amountUSD }, 'info');

        // Send confirmation email
        email.sendDepositConfirm(user, amountUSD, 'Stripe / Card').catch(() => {});

        console.log(`[STRIPE WEBHOOK] Deposit confirmed: $${amountUSD} for user ${userId}`);
      } catch (err) {
        console.error('[STRIPE WEBHOOK] Processing error:', err.message);
      }
    }
  }

  res.json({ received: true });
});

module.exports = router;
