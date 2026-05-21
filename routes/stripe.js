/* ════════════════════════════════════════════════════════════
   routes/stripe.js — Stripe Payment Integration
   ZEN ASSETS Backend
════════════════════════════════════════════════════════════ */

const express = require('express');
const router  = express.Router();
const webhookRouter = express.Router();
const { authenticate } = require('../middleware/auth');
const db      = require('../db/database');
const email   = require('../services/email');

function getStripe() {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key || key.startsWith('sk_test_placeholder') || key.startsWith('sk_live_placeholder')) {
    return null;
  }
  return require('stripe')(key);
}

const FRONTEND = process.env.FRONTEND_URL || 'https://zenassets.tech';

router.get('/publishable-key', (req, res) => {
  const key = process.env.STRIPE_PUBLISHABLE_KEY || '';
  if (!key || key.startsWith('pk_test_placeholder')) {
    return res.json({ key: null, enabled: false });
  }
  res.json({ key, enabled: true });
});

router.post('/create-session', authenticate, async (req, res) => {
  const stripe = getStripe();
  if (!stripe) {
    return res.status(503).json({ error: 'Stripe payments not configured. Please add API keys.' });
  }

  try {
    const { amount } = req.body;
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
        user_id: user.id,
        user_email: user.email,
        amount_usd: amount.toString(),
      },
      success_url: `${FRONTEND}/?deposit=success&amount=${amount}`,
      cancel_url: `${FRONTEND}/?deposit=cancelled`,
    });

    db.transactions.create({
      userId: req.user.id,
      type: 'deposit',
      amount: Number(amount),
      status: 'pending',
      method: 'stripe',
      reference: session.id,
      notes: 'Stripe Checkout session created',
    });

    db.audit.log(req.user.id, 'stripe_session_created', { sessionId: session.id, amount }, 'info');

    res.json({ url: session.url, sessionId: session.id });
  } catch (err) {
    console.error('POST /api/stripe/create-session error:', err);
    res.status(500).json({ error: 'Failed to create payment session' });
  }
});

async function handleWebhook(req, res) {
  const stripe = getStripe();
  if (!stripe) return res.status(503).json({ error: 'Stripe not configured' });

  const sig = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || '');
    if (secret && !secret.startsWith('whsec_placeholder')) {
      event = stripe.webhooks.constructEvent(rawBody, sig, secret);
    } else if (process.env.NODE_ENV === 'production') {
      return res.status(400).json({ error: 'Webhook secret not configured' });
    } else {
      console.warn('[STRIPE WEBHOOK] Dev mode — parsing without signature');
      event = JSON.parse(rawBody.toString());
    }
  } catch (err) {
    console.error('[STRIPE WEBHOOK] Signature verification failed:', err.message);
    return res.status(400).json({ error: `Webhook Error: ${err.message}` });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;

    if (session.payment_status === 'paid') {
      const userId = session.metadata?.user_id;
      const amountUSD = parseFloat(session.metadata?.amount_usd || 0);

      if (!userId || !amountUSD) {
        console.error('[STRIPE WEBHOOK] Missing metadata:', session.metadata);
        return res.json({ received: true });
      }

      try {
        const rawDb = db.raw();
        const alreadyDone = rawDb.prepare(`
          SELECT id FROM transactions
          WHERE reference_id = ? AND user_id = ? AND type = 'deposit' AND status = 'completed'
          LIMIT 1
        `).get(session.id, userId);

        if (alreadyDone) {
          console.log('[STRIPE WEBHOOK] Already processed:', session.id);
          return res.json({ received: true });
        }

        const user = db.users.findById(userId);
        if (!user) throw new Error(`User ${userId} not found`);

        db.wallets.addDeposit(userId, amountUSD);

        rawDb.prepare(`
          UPDATE transactions SET status = 'completed'
          WHERE reference_id = ? AND user_id = ? AND type = 'deposit'
        `).run(session.id, userId);

        db.audit.log(userId, 'stripe_payment_completed', { sessionId: session.id, amount: amountUSD }, 'info');
        email.sendDepositConfirm(user, amountUSD, 'Stripe / Card').catch(() => {});

        console.log(`[STRIPE WEBHOOK] Deposit confirmed: $${amountUSD} for user ${userId}`);
      } catch (err) {
        console.error('[STRIPE WEBHOOK] Processing error:', err.message);
      }
    }
  }

  res.json({ received: true });
}

webhookRouter.post('/', handleWebhook);

module.exports = router;
module.exports.webhookRouter = webhookRouter;
