/* ════════════════════════════════════════════════════════════
   server.js — ZEN ASSETS Backend Server
   Express + SQLite + JWT Authentication

   Start:  npm start        (production)
           npm run dev      (watch mode)
════════════════════════════════════════════════════════════ */

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const db         = require('./db/database');

const app  = express();
const PORT = parseInt(process.env.PORT, 10) || 4000;

// ── Initialise Database ─────────────────────────────────────
db.init();

// Clean up expired sessions every hour
setInterval(() => db.sessions.cleanup(), 60 * 60 * 1000);

// ── Initialise Cron Jobs ────────────────────────────────────
require('./services/cron').init();

// ── Security Headers ────────────────────────────────────────
app.use(helmet());

// ── CORS ────────────────────────────────────────────────────
const allowedOrigins = [
  process.env.FRONTEND_URL || 'https://zen-assets.surge.sh',
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:8080',
];

app.use(cors({
  origin(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('CORS: Origin not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── Body Parsing ────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Trust Proxy (for Render / Railway behind reverse proxy) ─
app.set('trust proxy', 1);

// ── Global Rate Limiter ─────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 300,                    // 300 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' },
});
app.use('/api', globalLimiter);

// ── Auth Rate Limiter (stricter for login/register) ─────────
const authLimiter = rateLimit({
  windowMs: (parseInt(process.env.LOGIN_RATE_WINDOW, 10) || 15) * 60 * 1000,
  max: parseInt(process.env.LOGIN_RATE_LIMIT, 10) || 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again later.' },
});

// ── Request Logging ─────────────────────────────────────────
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    if (process.env.NODE_ENV !== 'test') {
      console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${ms}ms`);
    }
  });
  next();
});

// ── Health Check ────────────────────────────────────────────
// ── Root ────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ name: 'ZEN ASSETS API', status: 'running', docs: '/api/health' });
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// ── Routes ──────────────────────────────────────────────────
const authRoutes   = require('./routes/auth');
const adminRoutes  = require('./routes/admin');
const walletRoutes = require('./routes/wallet');
const tradesRoutes = require('./routes/trades');
const stripeRoutes = require('./routes/stripe');
const kycRoutes    = require('./routes/kyc');

// Stripe webhook must receive raw body — register BEFORE express.json parses it
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));

// Apply stricter rate limit to auth endpoints
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

app.use('/api/auth',   authRoutes);
app.use('/api/admin',  adminRoutes);
app.use('/api/wallet', walletRoutes);
app.use('/api/trades', tradesRoutes);
app.use('/api/stripe', stripeRoutes);
app.use('/api/kyc',    kycRoutes);

// ── 404 Handler ─────────────────────────────────────────────
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
});

// ── Global Error Handler ────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Server error:', err);

  // CORS error
  if (err.message && err.message.startsWith('CORS')) {
    return res.status(403).json({ error: err.message });
  }

  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message,
  });
});

// ── Start ───────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║  ZEN ASSETS Backend Server                           ║
║  Port: ${PORT}                                         ║
║  Env:  ${process.env.NODE_ENV || 'development'}                                ║
║  DB:   ${process.env.DB_PATH || './data/zen_assets.db'}                    ║
╚══════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
