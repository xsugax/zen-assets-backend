/* Shared validation helpers for auth + admin user creation */

const VALID_TIERS = ['bronze', 'silver', 'gold', 'platinum', 'diamond'];
const VALID_STATUSES = ['active', 'suspended', 'banned'];
const VALID_KYC = ['none', 'pending', 'submitted', 'verified', 'rejected'];

function isValidEmail(addr) {
  if (!addr || typeof addr !== 'string') return false;
  const trimmed = addr.trim().toLowerCase();
  if (!/^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/.test(trimmed)) return false;
  const domain = trimmed.split('@')[1];
  if (['test.com', 'example.com', 'localhost', 'temp.com', 'fake.com'].includes(domain)) return false;
  return true;
}

function validatePassword(pwd) {
  const minLength = parseInt(process.env.MIN_PASSWORD_LENGTH || 8, 10);
  const requireUpper = process.env.REQUIRE_UPPERCASE === 'true';
  const requireLower = process.env.REQUIRE_LOWERCASE === 'true';
  const requireNum = process.env.REQUIRE_NUMBERS === 'true';
  const requireSpecial = process.env.REQUIRE_SPECIAL_CHARS === 'true';

  if (!pwd || pwd.length < minLength) {
    return { ok: false, error: `Password must be at least ${minLength} characters` };
  }
  if (requireUpper && !/[A-Z]/.test(pwd)) {
    return { ok: false, error: 'Password must contain uppercase letters (A-Z)' };
  }
  if (requireLower && !/[a-z]/.test(pwd)) {
    return { ok: false, error: 'Password must contain lowercase letters (a-z)' };
  }
  if (requireNum && !/[0-9]/.test(pwd)) {
    return { ok: false, error: 'Password must contain numbers (0-9)' };
  }
  if (requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd)) {
    return { ok: false, error: 'Password must contain special characters (!@#$%^&*)' };
  }
  return { ok: true };
}

module.exports = {
  VALID_TIERS,
  VALID_STATUSES,
  VALID_KYC,
  isValidEmail,
  validatePassword,
};
