/* ════════════════════════════════════════════════════════════
   services/email.js — Transactional Email via Resend
   ZEN ASSETS Backend
════════════════════════════════════════════════════════════ */

const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);
const FROM   = 'ZEN ASSETS <noreply@zenassets.com>';
const BRAND  = '#00d4ff';

// ── Shared HTML wrapper ─────────────────────────────────────
function wrap(title, body) {
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{margin:0;padding:0;background:#0a0f1e;font-family:'Segoe UI',Arial,sans-serif;color:#e0e0e0}
  .container{max-width:600px;margin:40px auto;background:#111827;border-radius:12px;overflow:hidden;border:1px solid #1f2937}
  .header{background:linear-gradient(135deg,#0f1729,#1a2a4a);padding:32px;text-align:center;border-bottom:1px solid #1f2937}
  .header h1{margin:0;font-size:22px;color:#ffffff;letter-spacing:1px}
  .header .logo{font-size:28px;font-weight:800;color:${BRAND};letter-spacing:2px;margin-bottom:8px}
  .body{padding:32px}
  .alert{background:#1f2937;border-left:4px solid ${BRAND};padding:16px 20px;border-radius:0 8px 8px 0;margin:20px 0}
  .amount{font-size:36px;font-weight:800;color:${BRAND};text-align:center;padding:24px 0}
  .stat{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #1f2937;font-size:14px}
  .stat:last-child{border-bottom:none}
  .stat .label{color:#9ca3af}
  .stat .value{color:#ffffff;font-weight:600}
  .btn{display:inline-block;background:linear-gradient(135deg,${BRAND},#0099bb);color:#000;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;margin:20px 0}
  .footer{background:#0d1117;padding:20px;text-align:center;font-size:12px;color:#4b5563;border-top:1px solid #1f2937}
  .status-approved{color:#10b981;font-weight:700}
  .status-rejected{color:#ef4444;font-weight:700}
  .status-pending{color:#f59e0b;font-weight:700}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo">ZEN ASSETS</div>
    <h1>${title}</h1>
  </div>
  <div class="body">${body}</div>
  <div class="footer">
    &copy; ${new Date().getFullYear()} ZEN ASSETS &mdash; This is an automated message, please do not reply.<br>
    <a href="https://zen-assets.surge.sh" style="color:${BRAND};text-decoration:none">zen-assets.surge.sh</a>
  </div>
</div>
</body>
</html>`;
}

// ── Safe send wrapper ───────────────────────────────────────
async function send({ to, subject, html }) {
  if (!process.env.RESEND_API_KEY || process.env.RESEND_API_KEY.startsWith('re_placeholder')) {
    console.log(`[EMAIL SKIP] No API key — would send "${subject}" to ${to}`);
    return { skipped: true };
  }
  try {
    const result = await resend.emails.send({ from: FROM, to, subject, html });
    console.log(`[EMAIL OK] "${subject}" → ${to}`);
    return result;
  } catch (err) {
    console.error(`[EMAIL ERR] "${subject}" → ${to}:`, err.message);
    return { error: err.message };
  }
}

// ═══════════════════════════════════════════════════════════
//  EMAIL TEMPLATES
// ═══════════════════════════════════════════════════════════

// Welcome email after registration
async function sendWelcome(user) {
  return send({
    to: user.email,
    subject: 'Welcome to ZEN ASSETS — Your AI Trading Journey Begins',
    html: wrap('Welcome to ZEN ASSETS', `
      <p>Hi <strong>${user.full_name || user.email}</strong>,</p>
      <div class="alert">
        Your ZEN ASSETS account has been created successfully. You now have access to AI-powered trading,
        real-time market data, and intelligent portfolio management.
      </div>
      <p>Here's what you can do next:</p>
      <ul style="line-height:1.8;color:#9ca3af">
        <li>💰 <strong style="color:#fff">Fund your account</strong> — Make your first deposit to start trading</li>
        <li>🤖 <strong style="color:#fff">AI Auto-Trader</strong> — Let our AI manage trades on your behalf</li>
        <li>📊 <strong style="color:#fff">Live Charts</strong> — Real-time crypto & stock market data</li>
        <li>🛡️ <strong style="color:#fff">Complete KYC</strong> — Verify your identity to unlock full features</li>
      </ul>
      <div style="text-align:center">
        <a href="https://zen-assets.surge.sh" class="btn">Open Dashboard →</a>
      </div>
    `),
  });
}

// Deposit confirmed (after Stripe webhook / admin credit)
async function sendDepositConfirm(user, amount, method = 'Card') {
  return send({
    to: user.email,
    subject: `Deposit Confirmed — $${amount.toLocaleString('en-US', { minimumFractionDigits: 2 })}`,
    html: wrap('Deposit Confirmed', `
      <p>Hi <strong>${user.full_name || user.email}</strong>,</p>
      <p>Your deposit has been processed and added to your trading wallet.</p>
      <div class="amount">+$${Number(amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}</div>
      <div class="alert">
        <div class="stat"><span class="label">Method</span><span class="value">${method}</span></div>
        <div class="stat"><span class="label">Status</span><span class="value status-approved">Completed</span></div>
        <div class="stat"><span class="label">Date</span><span class="value">${new Date().toUTCString()}</span></div>
      </div>
      <div style="text-align:center">
        <a href="https://zen-assets.surge.sh" class="btn">View Wallet →</a>
      </div>
    `),
  });
}

// Withdrawal status update
async function sendWithdrawalUpdate(user, amount, status, notes = '') {
  const statusMap = {
    completed: { label: 'Approved', cls: 'status-approved', msg: 'Your withdrawal has been approved and will arrive within 1-3 business days.' },
    rejected:  { label: 'Rejected', cls: 'status-rejected', msg: 'Your withdrawal request has been declined. Please contact support if you have questions.' },
    processing:{ label: 'Processing', cls: 'status-pending', msg: 'Your withdrawal is currently being processed.' },
  };
  const info = statusMap[status] || statusMap.processing;
  return send({
    to: user.email,
    subject: `Withdrawal ${info.label} — $${Number(amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}`,
    html: wrap(`Withdrawal ${info.label}`, `
      <p>Hi <strong>${user.full_name || user.email}</strong>,</p>
      <p>${info.msg}</p>
      <div class="amount" style="color:${status === 'completed' ? '#10b981' : status === 'rejected' ? '#ef4444' : '#f59e0b'}">
        $${Number(amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}
      </div>
      <div class="alert">
        <div class="stat"><span class="label">Status</span><span class="value ${info.cls}">${info.label}</span></div>
        <div class="stat"><span class="label">Date</span><span class="value">${new Date().toUTCString()}</span></div>
        ${notes ? `<div class="stat"><span class="label">Note</span><span class="value">${notes}</span></div>` : ''}
      </div>
      <div style="text-align:center">
        <a href="https://zen-assets.surge.sh" class="btn">View Account →</a>
      </div>
    `),
  });
}

// KYC status update
async function sendKYCUpdate(user, status) {
  const statusMap = {
    verified: { label: 'Verified ✓', color: '#10b981', msg: 'Congratulations! Your identity has been verified. You now have full access to all platform features including higher withdrawal limits.' },
    rejected: { label: 'Rejected', color: '#ef4444', msg: 'Unfortunately your KYC documents could not be verified. Please resubmit with clear, valid government-issued ID documents.' },
    submitted:{ label: 'Under Review', color: '#f59e0b', msg: 'Your KYC documents have been received and are currently under review. This typically takes 1-2 business days.' },
  };
  const info = statusMap[status] || statusMap.submitted;
  return send({
    to: user.email,
    subject: `KYC Status: ${info.label}`,
    html: wrap('Identity Verification Update', `
      <p>Hi <strong>${user.full_name || user.email}</strong>,</p>
      <div class="alert" style="border-left-color:${info.color}">
        <p style="margin:0;color:${info.color};font-weight:700;font-size:16px">${info.label}</p>
        <p style="margin:8px 0 0">${info.msg}</p>
      </div>
      <div style="text-align:center">
        <a href="https://zen-assets.surge.sh" class="btn">View Account →</a>
      </div>
    `),
  });
}

// Daily/weekly earnings credited
async function sendEarningsCredit(user, amount, type = 'daily', newBalance = null) {
  const label = type === 'weekly' ? 'Weekly Bonus' : 'Daily Earnings';
  return send({
    to: user.email,
    subject: `${label} Credited — $${Number(amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}`,
    html: wrap(`${label} Credited`, `
      <p>Hi <strong>${user.full_name || user.email}</strong>,</p>
      <p>Your ${type} earnings have been automatically applied to your trading wallet.</p>
      <div class="amount">+$${Number(amount).toLocaleString('en-US', { minimumFractionDigits: 2 })}</div>
      <div class="alert">
        <div class="stat"><span class="label">Type</span><span class="value">${label}</span></div>
        <div class="stat"><span class="label">Credited</span><span class="value status-approved">Completed</span></div>
        ${newBalance !== null ? `<div class="stat"><span class="label">New Balance</span><span class="value">$${Number(newBalance).toLocaleString('en-US', { minimumFractionDigits: 2 })}</span></div>` : ''}
        <div class="stat"><span class="label">Date</span><span class="value">${new Date().toUTCString()}</span></div>
      </div>
      <p style="color:#9ca3af;font-size:13px">Earnings are calculated based on your account tier and current balance. Log in to view your full earnings history.</p>
      <div style="text-align:center">
        <a href="https://zen-assets.surge.sh" class="btn">View Wallet →</a>
      </div>
    `),
  });
}

module.exports = {
  sendWelcome,
  sendDepositConfirm,
  sendWithdrawalUpdate,
  sendKYCUpdate,
  sendEarningsCredit,
};
