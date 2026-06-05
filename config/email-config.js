/* ════════════════════════════════════════════════════════════
   config/email-config.js — Email Service Configuration
   ZEN ASSETS Backend

   Controls email sending across the platform.
   Set DISABLE_EMAILS=true to disable all email sending.
════════════════════════════════════════════════════════════ */

const DISABLE_EMAILS = process.env.DISABLE_EMAILS === 'true';

/**
 * Check if email should be sent
 * @returns {boolean} true if emails are disabled
 */
function emailsDisabled() {
  if (DISABLE_EMAILS) {
    console.log('[EMAIL-CONFIG] ℹ Email sending is currently disabled');
    return true;
  }
  return false;
}

/**
 * Log email that would have been sent
 * @param {string} type - Email type (welcome, deposit, etc)
 * @param {string} to - Recipient email
 * @param {string} subject - Email subject
 */
function logEmailToConsole(type, to, subject) {
  console.log(`[EMAIL-LOG] ${type.toUpperCase()} would be sent to ${to}`);
  console.log(`  Subject: ${subject}`);
}

module.exports = {
  DISABLE_EMAILS,
  emailsDisabled,
  logEmailToConsole,
};
