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

const DEFAULT_COPY_TRADE = {
  enabled: false,
  mode: 'disabled',
  percent: 15,
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

  return out;
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
  DEFAULT_COPY_TRADE,
  parseSettingsJson,
  normalizeCopyTrade,
  mergeSettings,
  attachSettingsToUser,
};
