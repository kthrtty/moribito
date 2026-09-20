/** 設定の読み書き（chrome.storage.sync）。UIとservice workerで共有する。 */
import { DEFAULT_THRESHOLDS } from './score.js';
import { PROVIDER_TEMPLATES, DEFAULT_DOH_ENDPOINT, isSafeEndpoint } from './reputation.js';

export const DEFAULT_SETTINGS = {
  enabled: true,
  blockThreshold: DEFAULT_THRESHOLDS.blockThreshold,
  warnThreshold: DEFAULT_THRESHOLDS.warnThreshold,
  useModel: false,        // 学習済みモデルを同梱した場合のみ true にする
  inspectPages: true,     // URLで決着しないページの表示内容も見る
  allowlist: [],          // ユーザーが「許可して続行」したドメイン
  useBlocklist: true,     // 配布済みフィッシング報告リストと照合する
  blocklistUrl: '',       // 更新の取得元（空なら同梱分のみ。ここ以外へは通信しない）
  // 外部リピュテーション照会は既定で全て無効。有効化は設定画面の機能フラグから。
  providerConfig: {},     // { [id]: { enabled, endpoint, apiKey } }
  detectorConfig: {},     // { [id]: { enabled } } 検出器ごとの差し替え
  dohEndpoint: DEFAULT_DOH_ENDPOINT,
  // Jev（外部API）の設定。APIキーはここに置かない（sync はGoogleへ同期されるため）
  jevConfig: { endpoint: '', model: 'jev-latest', sendFullUrl: false },
  stats: { checked: 0, warned: 0, blocked: 0 },
};

export async function loadSettings() {
  const stored = await chrome.storage.sync.get(DEFAULT_SETTINGS);
  return {
    ...DEFAULT_SETTINGS,
    ...stored,
    stats: { ...DEFAULT_SETTINGS.stats, ...(stored.stats ?? {}) },
    allowlist: Array.isArray(stored.allowlist) ? stored.allowlist : [],
  };
}

export async function saveSettings(patch) {
  await chrome.storage.sync.set(sanitizeSettingsPatch(patch));
}

const HOSTNAME_RE = /^[a-z0-9.-]{1,253}$/i;
const clamp = (value, min, max, fallback) => {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
};

/**
 * UIから渡された設定値を、保存する前に検証する。
 * UI側のバグや想定外の呼び出しで、判定を無効化する値（しきい値0など）や
 * 平文の取得元が保存されないようにする。既知のキー以外は捨てる。
 */
export function sanitizeSettingsPatch(patch = {}) {
  const out = {};
  if ('enabled' in patch) out.enabled = Boolean(patch.enabled);
  if ('useModel' in patch) out.useModel = Boolean(patch.useModel);
  if ('inspectPages' in patch) out.inspectPages = Boolean(patch.inspectPages);
  if ('useBlocklist' in patch) out.useBlocklist = Boolean(patch.useBlocklist);

  if ('blockThreshold' in patch) {
    out.blockThreshold = clamp(patch.blockThreshold, 0.5, 0.99, DEFAULT_SETTINGS.blockThreshold);
  }
  if ('warnThreshold' in patch) {
    const upper = (out.blockThreshold ?? DEFAULT_SETTINGS.blockThreshold) - 0.01;
    out.warnThreshold = clamp(patch.warnThreshold, 0.2, upper, DEFAULT_SETTINGS.warnThreshold);
  }

  if ('allowlist' in patch) {
    out.allowlist = [...new Set((Array.isArray(patch.allowlist) ? patch.allowlist : [])
      .map((entry) => String(entry ?? '').trim().toLowerCase())
      .filter((entry) => entry && HOSTNAME_RE.test(entry)))].slice(0, 500);
  }

  // 取得元は https のみ。平文や内部アドレスは受け付けない。
  for (const key of ['blocklistUrl', 'dohEndpoint']) {
    if (!(key in patch)) continue;
    const value = String(patch[key] ?? '').trim();
    out[key] = value === '' || isSafeEndpoint(value) ? value : '';
  }

  if ('providerConfig' in patch && patch.providerConfig && typeof patch.providerConfig === 'object') {
    const known = new Set(PROVIDER_TEMPLATES.map((p) => p.id));
    const config = {};
    for (const [id, entry] of Object.entries(patch.providerConfig)) {
      if (!known.has(id) || !entry || typeof entry !== 'object') continue;
      const endpoint = String(entry.endpoint ?? '').trim();
      config[id] = {
        enabled: Boolean(entry.enabled),
        endpoint: endpoint === '' || isSafeEndpoint(endpoint) ? endpoint : '',
      };
    }
    out.providerConfig = config;
  }

  if ('detectorConfig' in patch && patch.detectorConfig && typeof patch.detectorConfig === 'object') {
    const config = {};
    for (const [id, entry] of Object.entries(patch.detectorConfig)) {
      if (!/^[a-z0-9-]{1,40}$/.test(id) || !entry || typeof entry !== 'object') continue;
      config[id] = { enabled: Boolean(entry.enabled) };
    }
    out.detectorConfig = config;
  }

  if ('jevConfig' in patch && patch.jevConfig && typeof patch.jevConfig === 'object') {
    const endpoint = String(patch.jevConfig.endpoint ?? '').trim();
    const model = String(patch.jevConfig.model ?? '').trim();
    out.jevConfig = {
      endpoint: endpoint === '' || isSafeEndpoint(endpoint) ? endpoint : '',
      model: /^[a-z0-9._-]{1,40}$/i.test(model) ? model : DEFAULT_SETTINGS.jevConfig.model,
      sendFullUrl: Boolean(patch.jevConfig.sendFullUrl),
    };
  }
  // APIキーは sync に保存しない。storage.local 側で扱う。
  if ('apiKey' in patch || 'secrets' in patch) {
    // 明示的に捨てる
  }

  if ('stats' in patch && patch.stats && typeof patch.stats === 'object') {
    out.stats = {
      checked: clamp(patch.stats.checked, 0, Number.MAX_SAFE_INTEGER, 0),
      warned: clamp(patch.stats.warned, 0, Number.MAX_SAFE_INTEGER, 0),
      blocked: clamp(patch.stats.blocked, 0, Number.MAX_SAFE_INTEGER, 0),
    };
  }
  return out;
}

/** 雛形とユーザー設定を合成して、実行可能なプロバイダ一覧にする。 */
export function resolveProviders(settings) {
  const config = settings?.providerConfig ?? {};
  return PROVIDER_TEMPLATES.map((template) => ({
    ...template,
    ...(config[template.id] ?? {}),
  }));
}

/**
 * 検出器の設定を組み立てる。
 * 個別トグル（従来の設定項目）は detectorConfig へ写して互換を保つ。
 */
export function detectorConfigOf(settings) {
  const config = { ...(settings?.detectorConfig ?? {}) };
  const legacy = {
    blocklist: settings?.useBlocklist,
    'page-evidence': settings?.inspectPages,
    'local-model': settings?.useModel,
  };
  for (const [id, enabled] of Object.entries(legacy)) {
    if (typeof enabled === 'boolean' && config[id]?.enabled === undefined) {
      config[id] = { ...(config[id] ?? {}), enabled };
    }
  }
  // 外部照会はプロバイダが1つでも有効なときだけ動かす
  const providers = resolveProviders(settings).filter((p) => p.enabled && p.endpoint);
  if (config.reputation?.enabled === undefined) {
    config.reputation = { enabled: providers.length > 0 };
  }
  return config;
}

export function thresholdsOf(settings) {
  return {
    ...DEFAULT_THRESHOLDS,
    blockThreshold: settings.blockThreshold,
    warnThreshold: settings.warnThreshold,
  };
}
