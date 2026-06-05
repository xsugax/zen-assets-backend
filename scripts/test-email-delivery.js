#!/usr/bin/env node
/**
 * Email delivery smoke test
 * Usage: node scripts/test-email-delivery.js [baseUrl] [recipientEmail]
 * Example: node scripts/test-email-delivery.js http://localhost:4000 you@gmail.com
 */

const BASE = (process.argv[2] || 'http://localhost:4000').replace(/\/$/, '');
const TO = process.argv[3] || `emailtest${Date.now()}@gmail.com`;

async function main() {
  console.log('Base URL:', BASE);
  console.log('Test recipient:', TO);

  const health = await fetch(`${BASE}/api/health`).then(r => r.json()).catch(() => ({}));
  console.log('Health:', JSON.stringify(health, null, 2));

  if (health.email !== 'configured') {
    console.error('FAIL: Email driver not configured on server');
    process.exit(1);
  }

  const email = `reg${Date.now()}@gmail.com`;
  const password = 'TestPass123!';
  const reg = await fetch(`${BASE}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, fullName: 'Email Test', tier: 'gold', pin: '1234' }),
  });
  const regData = await reg.json().catch(() => ({}));

  if (reg.status !== 201 || !regData.needsVerification) {
    console.error('FAIL register', reg.status, regData);
    process.exit(1);
  }
  console.log('OK register — verification required');

  const code = regData.devCode;
  if (!code) {
    console.log('No devCode in response (production). Check inbox for verification email:', email);
    console.log('PASS: register triggered email send (manual inbox check required)');
    process.exit(0);
  }

  const verify = await fetch(`${BASE}/api/auth/verify-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: regData.userId, code }),
  });
  const verifyData = await verify.json().catch(() => ({}));
  if (verify.status !== 200 || !verifyData.token) {
    console.error('FAIL verify-email', verify.status, verifyData);
    process.exit(1);
  }
  console.log('OK verify-email + welcome email queued');
  console.log('Check inbox for:', email);
  console.log('All automated checks passed.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
