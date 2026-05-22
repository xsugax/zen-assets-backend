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
const { securityMiddleware } = require('./middleware/security');

const app  = express();
const PORT = parseInt(process.env.PORT, 10) || 4000;

// ── Initialise Database ─────────────────────────────────────
db.init();

// Clean up expired sessions and OTP codes every hour
setInterval(() => { db.sessions.cleanup(); db.otpCodes.cleanup(); }, 60 * 60 * 1000);

// ── Initialise Cron Jobs ────────────────────────────────────
require('./services/cron').init();

// ── Security Headers — Strict Mode ────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'", 'https:', 'wss:'],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: {
    maxAge: parseInt(process.env.HSTS_MAX_AGE || 31536000, 10),
    includeSubDomains: true,
    preload: process.env.HSTS_PRELOAD === 'true',
  },
  frameguard: { action: 'deny' },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// ── HTTPS Enforcement ───────────────────────────────────────
if (process.env.ENFORCE_HTTPS === 'true' && process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https' && !req.secure) {
      return res.status(403).json({ error: 'HTTPS required' });
    }
    next();
  });
}

// ── Add additional security headers ─────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});


// ── CORS ────────────────────────────────────────────────────
const allowedOrigins = [
  'https://zenassets.tech',
  'https://www.zenassets.tech',
  'http://zenassets.tech',
  'http://www.zenassets.tech',
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:8080',
];
if (process.env.FRONTEND_URL && !allowedOrigins.includes(process.env.FRONTEND_URL)) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

app.use(cors({
  origin(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    // Exact match
    if (allowedOrigins.includes(origin)) return callback(null, true);
    // Allow any *.zenassets.tech subdomain
    if (/^https?:\/\/([a-z0-9-]+\.)*zenassets\.tech$/i.test(origin)) return callback(null, true);
    // Allow Vercel preview deployments for zen-assets
    if (/^https:\/\/zen-assets[a-z0-9-]*\.vercel\.app$/i.test(origin)) return callback(null, true);
    // Allow GitHub Pages
    if (/^https:\/\/[a-z0-9-]+\.github\.io$/i.test(origin)) return callback(null, true);
    console.warn('CORS blocked origin:', origin);
    callback(new Error('CORS: Origin not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── Body Parsing ────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Request Sanitization & Input Validation ────────────────
app.use(securityMiddleware);

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

app.get('/api/platform/config', (req, res) => {
  try {
    res.json({ config: db.platformSettings.get() });
  } catch (e) {
    res.json({ config: { registration: true, trading: true, withdrawals: true, maintenance: false } });
  }
});

app.get('/api/health', (req, res) => {
  let dbOk = false;
  try {
    db.raw().prepare('SELECT 1 as ok').get();
    dbOk = true;
  } catch (e) {
    console.error('[HEALTH] DB check failed:', e.message);
  }
  const emailEnabled = !!(process.env.RESEND_API_KEY || process.env.SMTP_HOST);
  const cronEnabled = process.env.EARNINGS_CRON_ENABLED === 'true';
  const status = dbOk ? 'ok' : 'degraded';
  res.status(dbOk ? 200 : 503).json({
    status,
    db: dbOk ? 'connected' : 'error',
    email: emailEnabled ? 'configured' : 'disabled',
    earningsCron: cronEnabled ? 'enabled' : 'disabled',
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
const kycRoutes    = require('./routes/kyc');
const notifRoutes  = require('./routes/notifications');
const marketRoutes = require('./routes/market');

// Apply stricter rate limit to auth endpoints
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/pin-login', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);
app.use('/api/auth/reset-password', authLimiter);

app.use('/api/auth',   authRoutes);
app.use('/api/admin',  adminRoutes);
app.use('/api/wallet', walletRoutes);
app.use('/api/trades', tradesRoutes);
app.use('/api/kyc',    kycRoutes);
app.use('/api/notifications', notifRoutes);
app.use('/api/market', marketRoutes);

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
const server = app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║  ZEN ASSETS Backend Server                           ║
║  Port: ${PORT}                                         ║
║  Env:  ${process.env.NODE_ENV || 'development'}                                ║
║  DB:   ${process.env.DB_PATH || './data/zen_assets.db'}                    ║
╚══════════════════════════════════════════════════════╝
  `);
});

function shutdown(signal) {
  console.log(`[SERVER] ${signal} received — shutting down`);
  server.close(() => {
    try {
      const raw = db.raw();
      if (raw) raw.pragma('wal_checkpoint(TRUNCATE)');
    } catch (e) {
      console.warn('[SERVER] WAL checkpoint failed:', e.message);
    }
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = app;
