/* Per-user admin controls from users.settings_json */

const db = require('../db/database');
const { parseSettingsJson, isCopyEngineActive } = require('./user-settings');

function getControlsForUser(userOrId) {
  const user = typeof userOrId === 'string' ? db.users.findById(userOrId) : userOrId;
  if (!user) {
    return { tradingPaused: false, profitPaused: false, copyTrade: null };
  }
  const settings = parseSettingsJson(user.settings_json);
  return {
    tradingPaused: !!settings.tradingPaused,
    profitPaused: !!settings.profitPaused,
    copyTrade: settings.copyTrade || null,
  };
}

function getPlatformConfig() {
  return db.platformSettings.get();
}

function assertPlatformTrading() {
  const cfg = getPlatformConfig();
  if (cfg.maintenance) {
    const err = new Error('Platform is in maintenance mode. Try again later.');
    err.code = 'MAINTENANCE';
    err.status = 503;
    throw err;
  }
  if (cfg.trading === false) {
    const err = new Error('Trading is temporarily disabled platform-wide.');
    err.code = 'TRADING_DISABLED';
    err.status = 503;
    throw err;
  }
}

function assertTradingAllowed(user) {
  assertPlatformTrading();
  const c = getControlsForUser(user);
  if (c.tradingPaused) {
    const err = new Error('Trading is paused for your account. Contact support.');
    err.code = 'TRADING_PAUSED';
    err.status = 403;
    throw err;
  }
  if (!isCopyEngineActive(c.copyTrade)) {
    const err = new Error('Institutional copy engine is not activated for your account.');
    err.code = 'COPY_ENGINE_LOCKED';
    err.status = 403;
    throw err;
  }
}

function assertProfitsAllowed(user) {
  const c = getControlsForUser(user);
  if (c.profitPaused) {
    const err = new Error('Earnings and claims are paused for your account. Contact support.');
    err.code = 'PROFIT_PAUSED';
    err.status = 403;
    throw err;
  }
}

function assertWithdrawalsAllowed() {
  const raw = process.env.WITHDRAWALS_ENABLED;
  if (raw === 'false') {
    const err = new Error('Withdrawals are temporarily disabled.');
    err.code = 'WITHDRAWALS_DISABLED';
    err.status = 503;
    throw err;
  }
  const cfg = getPlatformConfig();
  if (cfg.withdrawals === false) {
    const err = new Error('Withdrawals are temporarily disabled.');
    err.code = 'WITHDRAWALS_DISABLED';
    err.status = 503;
    throw err;
  }
}

function assertRegistrationAllowed() {
  const cfg = getPlatformConfig();
  if (cfg.maintenance) {
    const err = new Error('Registration is unavailable during maintenance.');
    err.code = 'MAINTENANCE';
    err.status = 503;
    throw err;
  }
  if (cfg.registration === false) {
    const err = new Error('New registrations are temporarily closed.');
    err.code = 'REGISTRATION_CLOSED';
    err.status = 503;
    throw err;
  }
}

module.exports = {
  getControlsForUser,
  getPlatformConfig,
  assertPlatformTrading,
  assertTradingAllowed,
  assertProfitsAllowed,
  assertWithdrawalsAllowed,
  assertRegistrationAllowed,
};
