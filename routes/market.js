/* ════════════════════════════════════════════════════════════
   market.js — Public market data proxy (Binance klines)
   Stable server-side fetch; 45s in-memory cache per key.
════════════════════════════════════════════════════════════ */

const express = require('express');
const router = express.Router();

const BINANCE_KLINES = 'https://data-api.binance.vision/api/v3/klines';
const BINANCE_HOSTS = [
  'https://data-api.binance.vision',
  'https://api1.binance.com',
  'https://api2.binance.com',
  'https://api.binance.com',
];

const ALLOWED_SYMBOLS = new Set([
  'BTC', 'ETH', 'SOL', 'BNB', 'XRP', 'ADA', 'AVAX', 'LINK', 'MATIC', 'UNI', 'AAVE',
]);

const VALID_INTERVALS = new Set([
  '1m', '3m', '5m', '15m', '30m', '1h', '2h', '4h', '6h', '8h', '12h', '1d', '3d', '1w', '1M',
]);

const CACHE_TTL_MS = 45000;
const cache = new Map();

function cacheKey(symbol, interval, limit) {
  return `${symbol}:${interval}:${limit}`;
}

async function fetchBinanceKlines(symbol, interval, limit) {
  const pair = `${symbol}USDT`;
  const path = `/api/v3/klines?symbol=${pair}&interval=${interval}&limit=${limit}`;
  const errors = [];

  for (const host of BINANCE_HOSTS) {
    try {
      const ctrl = new AbortController();
      const tid = setTimeout(() => ctrl.abort(), 8000);
      const r = await fetch(`${host}${path}`, { signal: ctrl.signal });
      clearTimeout(tid);
      if (!r.ok) {
        errors.push(`${host}: HTTP ${r.status}`);
        continue;
      }
      const data = await r.json();
      if (!Array.isArray(data) || data.length < 5) {
        errors.push(`${host}: empty`);
        continue;
      }
      return data.map(k => ({
        t: k[0],
        o: +k[1],
        h: +k[2],
        l: +k[3],
        c: +k[4],
        v: +k[5],
      }));
    } catch (e) {
      errors.push(`${host}: ${e.message}`);
    }
  }

  // Final attempt on vision URL (legacy path)
  try {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), 8000);
    const r = await fetch(
      `${BINANCE_KLINES}?symbol=${symbol}USDT&interval=${interval}&limit=${limit}`,
      { signal: ctrl.signal }
    );
    clearTimeout(tid);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const data = await r.json();
    if (!Array.isArray(data) || data.length < 5) throw new Error('Empty');
    return data.map(k => ({
      t: k[0], o: +k[1], h: +k[2], l: +k[3], c: +k[4], v: +k[5],
    }));
  } catch (e) {
    errors.push(e.message);
  }

  throw new Error(errors.join('; ') || 'Binance klines unavailable');
}

// GET /api/market/klines?symbol=BTC&interval=1h&limit=200
router.get('/klines', async (req, res) => {
  try {
    const symbol = String(req.query.symbol || '').toUpperCase().replace(/[^A-Z]/g, '');
    let interval = String(req.query.interval || '1h');
    let limit = parseInt(req.query.limit, 10) || 120;

    if (!symbol || !ALLOWED_SYMBOLS.has(symbol)) {
      return res.status(400).json({ error: 'Invalid or unsupported symbol' });
    }
    if (!VALID_INTERVALS.has(interval)) interval = '1h';
    limit = Math.min(Math.max(limit, 5), 1000);

    const key = cacheKey(symbol, interval, limit);
    const hit = cache.get(key);
    if (hit && Date.now() - hit.ts < CACHE_TTL_MS) {
      return res.json({ ok: true, symbol, interval, limit, candles: hit.candles, cached: true });
    }

    const candles = await fetchBinanceKlines(symbol, interval, limit);
    cache.set(key, { ts: Date.now(), candles });

    if (cache.size > 200) {
      const oldest = [...cache.entries()].sort((a, b) => a[1].ts - b[1].ts)[0];
      if (oldest) cache.delete(oldest[0]);
    }

    res.json({ ok: true, symbol, interval, limit, candles, cached: false });
  } catch (err) {
    console.warn('[market/klines]', err.message);
    res.status(502).json({ error: err.message || 'Market data unavailable' });
  }
});

module.exports = router;
