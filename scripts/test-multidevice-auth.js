#!/usr/bin/env node
/**
 * Multi-device auth smoke test (register → login A → login B → both /me)
 * Usage: node scripts/test-multidevice-auth.js [baseUrl]
 * Example: node scripts/test-multidevice-auth.js http://localhost:4000
 */

const BASE = (process.argv[2] || 'http://localhost:4000').replace(/\/$/, '');
const email = `mdtest${Date.now()}@gmail.com`;
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

  const reg = await req('/auth/register', {
    method: 'POST',
    body: { email, password, fullName: 'MD Test', tier: 'gold', pin: '1234', depositAmount: 0 },
  });
  if (reg.status !== 201 || !reg.data.token) {
    console.error('FAIL register', reg.status, reg.data);
    process.exit(1);
  }
  console.log('OK register');

  const loginA = await req('/auth/login', {
    method: 'POST',
    body: { email, password },
  });
  if (loginA.status !== 200 || !loginA.data.refreshToken) {
    console.error('FAIL login A', loginA.status, loginA.data);
    process.exit(1);
  }
  console.log('OK login device A');

  const loginB = await req('/auth/login', {
    method: 'POST',
    body: { email, password },
  });
  if (loginB.status !== 200 || !loginB.data.token) {
    console.error('FAIL login B', loginB.status, loginB.data);
    process.exit(1);
  }
  console.log('OK login device B');

  const meA = await req('/auth/me', {
    headers: { Authorization: `Bearer ${loginA.data.token}` },
  });
  const meB = await req('/auth/me', {
    headers: { Authorization: `Bearer ${loginB.data.token}` },
  });
  if (meA.status !== 200 || meB.status !== 200) {
    console.error('FAIL /me', { meA: meA.status, meB: meB.status });
    process.exit(1);
  }
  console.log('OK both devices /auth/me');

  const refresh = await req('/auth/refresh', {
    method: 'POST',
    body: { refreshToken: loginA.data.refreshToken },
  });
  if (refresh.status !== 200 || !refresh.data.token) {
    console.error('FAIL refresh', refresh.status, refresh.data);
    process.exit(1);
  }
  console.log('OK refresh token rotation');

  const sessions = await req('/auth/sessions', {
    headers: { Authorization: `Bearer ${loginB.data.token}` },
  });
  if (sessions.status !== 200 || !Array.isArray(sessions.data.sessions)) {
    console.error('FAIL sessions list', sessions.status, sessions.data);
    process.exit(1);
  }
  console.log('OK sessions list:', sessions.data.sessions.length, 'active');

  console.log('\nAll multi-device auth checks passed.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
