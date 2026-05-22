#!/usr/bin/env node
/**
 * Wallet + platform config smoke test
 * Usage: node scripts/test-wallet-platform.js [baseUrl]
 */

const BASE = (process.argv[2] || 'http://localhost:4000').replace(/\/$/, '');
const email = `wtest${Date.now()}@gmail.com`;
const password = 'TestPass123!';

async function req(path, opts = {}) {
  const res = await fetch(`${BASE}/api${path}`, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

async function main() {
  console.log('Base URL:', BASE);

  const health = await req('/health');
  if (health.status !== 200 && health.status !== 503) {
    console.error('FAIL health', health.status);
    process.exit(1);
  }
  console.log('OK health', health.data.status, 'db:', health.data.db);

  const cfg = await req('/platform/config');
  if (!cfg.data.config) {
    console.error('FAIL platform config');
    process.exit(1);
  }
  console.log('OK platform config');

  const reg = await req('/auth/register', {
    method: 'POST',
    body: { email, password, fullName: 'Wallet Test', tier: 'gold', pin: '1234', depositAmount: 99999 },
  });
  if (reg.status !== 201 || !reg.data.token) {
    console.error('FAIL register', reg.status, reg.data);
    process.exit(1);
  }
  const token = reg.data.token;
  const walletAfterReg = reg.data.wallet?.balance ?? 0;
  if (walletAfterReg !== 0) {
    console.error('FAIL register self-deposit blocked, balance=', walletAfterReg);
    process.exit(1);
  }
  console.log('OK register with zero balance');

  const dep = await req('/wallet/deposit', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: { amount: 50, method: 'crypto_usdt', reference: 'test-tx' },
  });
  if (dep.status !== 200 || !dep.data.success) {
    console.error('FAIL deposit request', dep.status, dep.data);
    process.exit(1);
  }
  console.log('OK deposit request pending');

  const w = await req('/wallet', { headers: { Authorization: `Bearer ${token}` } });
  if (w.status !== 200) {
    console.error('FAIL wallet', w.status);
    process.exit(1);
  }
  console.log('OK wallet balance', w.data.balance);

  console.log('All wallet/platform checks passed');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
