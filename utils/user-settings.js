/* Per-user settings (copy trading, admin controls) stored in users.settings_json */

const VALID_COPY_MODES = [
  'disabled',
  'scalping',
  'mean_reversion',
  'momentum',
  'breakout',
  'multi',
  'aggressive',
];

/** Tier-based institutional engine activation fees (USD) */
const ACTIVATION_FEES_BY_TIER = {
  bronze:   9500,
  silver:   24500,
  gold:     49500,
  platinum: 99500,
  diamond:  249500,
};

const DEFAULT_COPY_TRADE = {
  enabled: false,
  mode: 'disabled',
  percent: 15,
  activated: false,
  activationFee: null,
  feePaid: false,
  feePaidAt: null,
  activationRequestedAt: null,
};

function parseSettingsJson(raw) {
  if (!raw) return {};
  try {
    return typeof raw === 'string' ? JSON.parse(raw) : { ...raw };
  } catch {
    return {};
  }
}

function normalizeCopyTrade(input, existing = {}) {
  const out = {
    ...DEFAULT_COPY_TRADE,
    ...existing,
    ...(input && typeof input === 'object' ? input : {}),
  };

  if (!VALID_COPY_MODES.includes(out.mode)) {
    out.mode = 'disabled';
  }

  out.percent = Math.max(0, Math.min(100, parseFloat(out.percent) || 0));

  if (out.mode === 'disabled') {
    out.enabled = false;
  } else if (typeof input?.enabled === 'boolean') {
    out.enabled = input.enabled;
  } else if (input?.mode && input.mode !== 'disabled') {
    out.enabled = true;
  }

  if (out.enabled && out.percent < 1) {
    out.percent = DEFAULT_COPY_TRADE.percent;
  }

  out.activated = !!out.activated;
  out.feePaid = !!out.feePaid;
  const fee = parseFloat(out.activationFee);
  out.activationFee = Number.isFinite(fee) && fee > 0 ? fee : null;

  return out;
}

function resolveActivationFee(copyTrade, tier = 'gold') {
  const ct = normalizeCopyTrade(copyTrade);
  if (ct.activationFee) return ct.activationFee;
  return ACTIVATION_FEES_BY_TIER[tier] || ACTIVATION_FEES_BY_TIER.gold;
}

function isCopyEngineActive(copyTrade) {
  const ct = normalizeCopyTrade(copyTrade);
  return ct.activated === true
    && ct.feePaid === true
    && ct.mode !== 'disabled'
    && ct.percent > 0;
}

function mergeSettings(existingRaw, patch = {}) {
  const base = parseSettingsJson(existingRaw);
  const next = { ...base };

  if (patch.copyTrade != null) {
    next.copyTrade = normalizeCopyTrade(patch.copyTrade, base.copyTrade);
  }

  if (typeof patch.tradingPaused === 'boolean') {
    next.tradingPaused = patch.tradingPaused;
  }
  if (typeof patch.profitPaused === 'boolean') {
    next.profitPaused = patch.profitPaused;
  }

  return next;
}

function attachSettingsToUser(row) {
  if (!row) return row;
  const settings = parseSettingsJson(row.settings_json);
  return {
    ...row,
    settings,
    copyTrade: normalizeCopyTrade(null, settings.copyTrade),
    tradingPaused: !!settings.tradingPaused,
    profitPaused: !!settings.profitPaused,
  };
}

module.exports = {
  VALID_COPY_MODES,
  ACTIVATION_FEES_BY_TIER,
  DEFAULT_COPY_TRADE,
  parseSettingsJson,
  normalizeCopyTrade,
  mergeSettings,
  attachSettingsToUser,
  resolveActivationFee,
  isCopyEngineActive,
};
