/**
 * MV3 service worker。
 *  1. ルール判定は同期でここで実行し、危険なら即リダイレクト
 *  2. グレーゾーンのみ offscreen document 上のワーカー（＋任意のローカルモデル）に相談
 * 外部への問い合わせは一切行わない。
 */
import { analyzeUrl, analyzeWithPage, withExtraSignals } from '../core/analyze.js';
import { extractFeatures } from '../core/features.js';
import { evaluatePageEvidence } from '../core/page-evidence.js';
import { loadModel as loadUrlModel, predictHost } from '../core/url-classifier.js';
import { runDetection, resolveDetectors, describeDetectors } from '../core/pipeline.js';
import { DETECTOR_CATALOG } from '../core/detectors/index.js';
import { loadSettings, saveSettings, thresholdsOf, resolveProviders, detectorConfigOf, DEFAULT_SETTINGS } from '../core/settings.js';
import { createBlocklist, isStale, hashKey } from '../core/blocklist.js';
import { assertSafeEndpoint } from '../core/reputation.js';

const OFFSCREEN_PATH = 'src/offscreen/offscreen.html';
const PROBE_PATH = 'src/content/page-probe.js';
const WARNING_PATH = 'src/ui/warning.html';
const CACHE_LIMIT = 500;

const SECRET_IDS = new Set(['jev']);
const MAX_SECRET_LENGTH = 500;

const BLOCKLIST_PATH = 'data/blocklist.json';
const URL_MODEL_PATH = 'model/url-classifier.json';
const BLOCKLIST_ALARM = 'blocklist-update';

const verdictCache = new Map();   // url -> result
// 外部照会の結果を使い回すTTLキャッシュ（検出器へ services.cache として渡す）
const TTL_MS = 6 * 60 * 60 * 1000;
const ttlCache = new Map();
const cacheService = {
  get(key) {
    const entry = ttlCache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.at > TTL_MS) { ttlCache.delete(key); return null; }
    return entry.value;
  },
  set(key, value) {
    ttlCache.set(key, { at: Date.now(), value });
    if (ttlCache.size > 300) ttlCache.delete(ttlCache.keys().next().value);
  },
};
const tabVerdicts = new Map();    // tabId -> result
let settingsCache = null;
let offscreenReady = null;
let blocklistPromise = null;
let urlModelPromise = null;

// ---------------------------------------------------------------- settings
async function settings() {
  if (!settingsCache) settingsCache = await loadSettings();
  return settingsCache;
}
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'sync') settingsCache = null;
});

// ---------------------------------------------------------------- offscreen
async function ensureOffscreen() {
  if (offscreenReady) return offscreenReady;
  offscreenReady = (async () => {
    const existing = await chrome.runtime.getContexts?.({
      contextTypes: ['OFFSCREEN_DOCUMENT'],
    });
    if (existing?.length) return true;
    try {
      await chrome.offscreen.createDocument({
        url: OFFSCREEN_PATH,
        reasons: ['WORKERS'],
        justification: 'URL判定をメインスレッド外のワーカーで実行するため',
      });
      return true;
    } catch (err) {
      if (String(err?.message ?? err).includes('Only a single offscreen')) return true;
      console.warn('[moribito] offscreen document を作れませんでした:', err);
      return false;
    }
  })();
  return offscreenReady;
}

async function askWorker(payload, timeoutMs = 2500) {
  const ok = await ensureOffscreen();
  if (!ok) return null;
  try {
    const response = await Promise.race([
      chrome.runtime.sendMessage({ target: 'offscreen', payload }),
      new Promise((resolve) => setTimeout(() => resolve(null), timeoutMs)),
    ]);
    return response?.ok ? response.result : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------- 既知フィッシングリスト
/**
 * 配布済みのハッシュ表を読み込む。
 * 更新分（storage.local）があればそれを、なければ同梱分を使う。
 * 読み込みは service worker が起きるたびに一度だけ。
 */
function loadBlocklist() {
  if (blocklistPromise) return blocklistPromise;
  blocklistPromise = (async () => {
    try {
      const stored = await chrome.storage.local.get('blocklist');
      let artifact = stored.blocklist ?? null;
      if (!artifact || isStale(artifact)) {
        const res = await fetch(chrome.runtime.getURL(BLOCKLIST_PATH));
        const bundled = res.ok ? await res.json() : null;
        // 更新分が期限切れでも、同梱分より新しければそちらを使う
        if (!artifact || (bundled && !isStale(bundled))) artifact = bundled ?? artifact;
      }
      return artifact ? createBlocklist(artifact) : null;
    } catch (err) {
      console.warn('[moribito] リストを読み込めませんでした:', err?.message ?? err);
      return null;
    }
  })();
  return blocklistPromise;
}

/**
 * URL分類器を読み込む。同梱していなければ null のまま（ルールだけで動く）。
 * ONNXランタイムは使わない。内積とsigmoidだけなので素のJSで完結する。
 */
function loadUrlClassifier() {
  if (urlModelPromise) return urlModelPromise;
  urlModelPromise = (async () => {
    try {
      const res = await fetch(chrome.runtime.getURL(URL_MODEL_PATH));
      if (!res.ok) return null;
      return loadUrlModel(await res.json());
    } catch {
      return null; // 未配置。ルールのみで判定する。
    }
  })();
  return urlModelPromise;
}

async function blocklistStatus() {
  const list = await loadBlocklist();
  if (!list) return { available: false };
  return {
    available: true,
    size: list.size,
    generatedAt: list.generatedAt,
    expiresAt: list.expiresAt,
    stale: isStale({ expiresAt: list.expiresAt }),
    sources: list.sources,
  };
}

/** 設定された取得元からリストを更新する。ここ以外へは通信しない。 */
const MAX_BLOCKLIST_BYTES = 8 * 1024 * 1024; // storage.local の既定枠に収める
const BLOCKLIST_FETCH_TIMEOUT_MS = 20_000;

async function updateBlocklist() {
  const s = await settings();
  if (!s.blocklistUrl) return { ok: false, error: 'no-url' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), BLOCKLIST_FETCH_TIMEOUT_MS);
  try {
    // https 以外・内部アドレスは受け付けない（保存時にも検証しているが二重に確認する）
    const target = assertSafeEndpoint(s.blocklistUrl);
    const res = await fetch(target, { cache: 'no-cache', signal: controller.signal, redirect: 'follow' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const declared = Number(res.headers.get('content-length') ?? 0);
    if (declared > MAX_BLOCKLIST_BYTES) throw new Error('リストが大きすぎます');
    const text = await res.text();
    if (text.length > MAX_BLOCKLIST_BYTES) throw new Error('リストが大きすぎます');

    const artifact = JSON.parse(text);
    if (!artifact?.tables || artifact.algo !== 'sha256-64') throw new Error('形式が違います');
    for (const table of Object.values(artifact.tables)) {
      if (table && typeof table !== 'string') throw new Error('形式が違います');
    }
    await chrome.storage.local.set({ blocklist: artifact });
    blocklistPromise = null;
    verdictCache.clear();
    const status = await blocklistStatus();
    return { ok: true, status };
  } catch (err) {
    return { ok: false, error: String(err?.message ?? err) };
  } finally {
    clearTimeout(timer);
  }
}

chrome.alarms?.onAlarm.addListener(async (alarm) => {
  if (alarm.name === BLOCKLIST_ALARM) await updateBlocklist();
});

// ---------------------------------------------------------------- 判定
function cacheKey(url) {
  return url.slice(0, 500);
}

function rememberVerdict(url, result) {
  const key = cacheKey(url);
  verdictCache.set(key, result);
  if (verdictCache.size > CACHE_LIMIT) {
    verdictCache.delete(verdictCache.keys().next().value);
  }
}

/**
 * 判定に必要なものを1か所で組み立てる。
 * 検出器は chrome.* を知らないので、外部とのやり取りは services で注入する。
 */
/**
 * APIキーは storage.local に置く。
 * storage.sync に置くとGoogleアカウント経由で同期されてしまうため。
 * UIへは値を返さず、設定済みかどうかだけを返す。
 */
async function readSecret(id) {
  if (!SECRET_IDS.has(id)) return '';
  const stored = await chrome.storage.local.get('secrets');
  return String(stored.secrets?.[id] ?? '');
}

async function writeSecret(id, value) {
  if (!SECRET_IDS.has(id)) return false;
  const text = String(value ?? '').trim().slice(0, MAX_SECRET_LENGTH);
  const stored = await chrome.storage.local.get('secrets');
  const secrets = { ...(stored.secrets ?? {}) };
  if (text) secrets[id] = text;
  else delete secrets[id];
  await chrome.storage.local.set({ secrets });
  verdictCache.clear();
  ttlCache.clear();
  return true;
}

async function secretStatus() {
  const stored = await chrome.storage.local.get('secrets');
  const secrets = stored.secrets ?? {};
  return Object.fromEntries([...SECRET_IDS].map((id) => [id, Boolean(secrets[id])]));
}

async function buildContext(url, s, extra = {}) {
  const features = extractFeatures(url);
  const providers = resolveProviders(s);

  // k-匿名の照会で使うハッシュ接頭辞（必要なプロバイダが有効なときだけ計算する）
  let prefix = '';
  if (providers.some((p) => p.enabled && p.endpoint && p.kind === 'prefix') && features.ok) {
    try {
      const { hi } = await hashKey(`${features.host.replace(/^www\./, '')}${new URL(url).pathname}`);
      prefix = hi.toString(16).padStart(8, '0');
    } catch { prefix = ''; }
  }

  return {
    url,
    features,
    prefix,
    phase: extra.evidence ? 'content' : 'navigation',
    allowlist: new Set(s.allowlist),
    providers,
    dohEndpoint: s.dohEndpoint,
    jev: { ...(s.jevConfig ?? {}), apiKey: await readSecret('jev') },
    services: {
      blocklist: await loadBlocklist(),
      cache: cacheService,
      fetchImpl: (...args) => fetch(...args),
      classifyUrl: async (target) => {
        const model = await loadUrlClassifier();
        if (!model) return null;
        try {
          return predictHost(new URL(target).hostname, model);
        } catch {
          return null;
        }
      },
      // ローカルLLM/小型テキスト分類器の差し込み口。未配置なら null を返す。
      classifyText: async (text) => {
        const out = await askWorker({ type: 'classify-text', text });
        return out?.probability != null ? out : null;
      },
      // Chrome内蔵AI（Prompt API）。offscreen document 側で扱う。
      // 利用者が入力欄に触れた瞬間だけ呼ばれるので、数百msの推論を許容できる。
      identifyService: async (evidence, host) => {
        const out = await askWorker({ type: 'local-llm-identify', evidence, host }, 10_000);
        return out?.result ?? null;
      },
    },
    ...extra,
  };
}

export async function evaluate(url, { useCache = true, evidence = null } = {}) {
  // chrome:// や拡張ページなどは判定対象外
  if (!/^https?:\/\//i.test(url)) {
    return { ok: true, url, host: '', registrable: '', score: 0, verdict: 'allow',
             grey: false, signals: [], reason: 'non-web-scheme', source: 'rules' };
  }
  const key = cacheKey(url);
  if (useCache && !evidence && verdictCache.has(key)) return verdictCache.get(key);

  const s = await settings();
  const detectors = resolveDetectors(DETECTOR_CATALOG, detectorConfigOf(s));
  const ctx = await buildContext(url, s, evidence ? { evidence } : {});
  const result = await runDetection(ctx, detectors, {
    thresholds: thresholdsOf(s),
    onError: (detector, err) => console.warn(`[moribito] ${detector.id} が失敗:`, err?.message ?? err),
  });

  if (!evidence) rememberVerdict(url, result);
  return result;
}

// ---------------------------------------------------------------- バッジ
const BADGE = {
  block: { text: '!', color: '#c81e1e' },
  warn: { text: '?', color: '#d97706' },
  allow: { text: '', color: '#16a34a' },
};

async function paintBadge(tabId, result) {
  const style = BADGE[result?.verdict ?? 'allow'] ?? BADGE.allow;
  try {
    await chrome.action.setBadgeText({ tabId, text: style.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: style.color });
  } catch {
    // タブが既に閉じている
  }
}

async function bumpStat(kind) {
  const s = await settings();
  const stats = { ...s.stats, [kind]: (s.stats[kind] ?? 0) + 1 };
  settingsCache = { ...s, stats };
  await saveSettings({ stats });
}

// ---------------------------------------------------------------- ブロック
const WARN_RECORD_TTL_MS = 60 * 60 * 1000;

/** 古い警告レコードを片付ける（セッション記憶に溜め続けない）。 */
async function pruneWarnRecords() {
  const all = await chrome.storage.session.get(null);
  const stale = Object.entries(all)
    .filter(([key, value]) => key.startsWith('warn:')
      && Date.now() - (value?.blockedAt ?? 0) > WARN_RECORD_TTL_MS)
    .map(([key]) => key);
  if (stale.length) await chrome.storage.session.remove(stale);
}

async function blockNavigation(tabId, url, result) {
  const token = crypto.randomUUID();
  await pruneWarnRecords();
  await chrome.storage.session.set({ [`warn:${token}`]: { ...result, blockedAt: Date.now() } });
  const target = chrome.runtime.getURL(`${WARNING_PATH}?token=${token}`);
  await chrome.tabs.update(tabId, { url: target });
}

chrome.webNavigation.onBeforeNavigate.addListener(
  async (details) => {
    if (details.frameId !== 0) return;
    const s = await settings();
    if (!s.enabled) return;

    const result = await evaluate(details.url);
    tabVerdicts.set(details.tabId, result);
    await bumpStat('checked');
    await paintBadge(details.tabId, result);

    if (result.verdict === 'block') {
      const bypass = await chrome.storage.session.get(`bypass:${result.registrable || result.host}`);
      if (bypass[`bypass:${result.registrable || result.host}`]) return;
      await bumpStat('blocked');
      await blockNavigation(details.tabId, details.url, result);
    } else if (result.verdict === 'warn') {
      await bumpStat('warned');
    }
  },
  { url: [{ schemes: ['http', 'https'] }] },
);

// ------------------------------------------------- 表示コンテンツの検査
/**
 * どの深さで内容を見るか。
 *   'full'  … URLだけで決着しなかったページ。入力欄もブランド名も見る
 *   'watch' … 公式・著名ドメイン。走査はせず、全画面化などのイベントが
 *             起きたときだけ収集する（広告経由で差し込まれる詐欺への備え）
 *   null    … 見ない
 */
function probeModeFor(result) {
  if (!result?.ok) return null;
  if (result.verdict === 'block') return null;
  if (result.reason === 'non-web-scheme' || result.reason === 'private-network') return null;
  return result.reason ? 'watch' : 'full';
}

async function probePage(tabId, url, result) {
  const s = await settings();
  const mode = probeModeFor(result);
  if (!s.inspectPages || !mode) return;
  try {
    // files 指定では引数を渡せないので、先に印を置いてから本体を注入する
    await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      func: (value) => { globalThis.__moribitoMode = value; },
      args: [mode],
    });
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      files: [PROBE_PATH],
    });
    // URLだけで「注意」と出ている時点で、入力欄への介入を有効にしておく。
    // 表示内容を見る前に利用者が入力を始めることがあるため。
    if (result.verdict === 'warn') await sendRisk(tabId, 'warn', result.signals);

    if (mode === 'full' && injection?.result?.forms) {
      await applyPageEvidence(tabId, url, injection.result);
    }
  } catch {
    // chrome:// や権限のないページ、遷移済みなど。URL判定の結果をそのまま使う。
  }
}

/**
 * ページ側へ危険度を伝える。
 * これを受け取ったページは、認証情報の入力欄に触れた時点で注記を出し、
 * 送信の直前に一度だけ確認を挟む。
 */
async function sendRisk(tabId, level, signals) {
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: 'set-risk',
      level,
      reasons: (signals ?? []).slice(0, 3).map((signal) => signal.title),
    });
  } catch {
    // プローブが入っていないタブ
  }
}

/** 警告バーを出す（ページを差し替えない）。 */
async function showOverlay(tabId, signals) {
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: 'show-overlay',
      reasons: signals.map((signal) => signal.title),
    });
  } catch {
    // プローブが入っていないタブ
  }
}

/** ページ証拠を足して判定し直し、必要なら止める／注意を出す。 */
async function applyPageEvidence(tabId, url, evidence) {
  const s = await settings();
  if (!s.enabled || !s.inspectPages) return;

  const base = await evaluate(url);
  const mode = probeModeFor(base);
  if (!mode) return;

  // 公式・著名ドメイン: 正規サイトのログインページを疑わないよう、
  // 構造的な詐欺（電話誘導＋離脱妨害）だけを見る。
  // ドメイン自体は正規なので、ページの差し替えまではしない。
  if (mode === 'watch') {
    const signals = evaluatePageEvidence(extractFeatures(url), evidence, { mode: 'structure-only' });
    if (!signals.length) return;
    await bumpStat('warned');
    await sendRisk(tabId, 'warn', signals);
    await showOverlay(tabId, signals);
    return;
  }

  const combined = await evaluate(url, { useCache: false, evidence });
  const pageSignals = (combined.signals ?? []).filter((signal) => signal.from === 'page' || signal.from === 'model');
  combined.pageSignals = pageSignals;
  if (!pageSignals.length) return;

  rememberVerdict(url, combined);
  tabVerdicts.set(tabId, combined);
  await paintBadge(tabId, combined);

  const key = `bypass:${combined.registrable || combined.host}`;
  const bypass = await chrome.storage.session.get(key);
  if (bypass[key]) return;

  if (combined.verdict === 'block') {
    await bumpStat('blocked');
    await blockNavigation(tabId, url, combined);
  } else if (combined.verdict === 'warn') {
    await bumpStat('warned');
    await sendRisk(tabId, 'warn', combined.signals);
    await showOverlay(tabId, pageSignals);
  }
}

/**
 * サーバーリダイレクトの最終URLは onBeforeNavigate に来ない。
 * 正規サイトから転送された先の危険なページを取りこぼさないよう、
 * 確定した時点でもう一度判定する。
 */
chrome.webNavigation.onCommitted.addListener(
  async (details) => {
    if (details.frameId !== 0) return;
    if (!details.transitionQualifiers?.some((q) => q.includes('redirect'))) return;

    const s = await settings();
    if (!s.enabled) return;
    const result = await evaluate(details.url);
    if (result.verdict !== 'block') return;

    const key = `bypass:${result.registrable || result.host}`;
    const bypass = await chrome.storage.session.get(key);
    if (bypass[key]) return;

    await bumpStat('blocked');
    await blockNavigation(details.tabId, details.url, result);
  },
  { url: [{ schemes: ['http', 'https'] }] },
);

// onCommitted の時点ではDOMがまだ空なので、解析が済む onDOMContentLoaded で見る。
// 後から差し込まれるフォームは、content script の focusin が拾う。
chrome.webNavigation.onDOMContentLoaded.addListener(
  async (details) => {
    if (details.frameId !== 0) return;
    const s = await settings();
    if (!s.enabled) return;
    // タブに残っている古い判定（リダイレクト前のURLのもの）は使わない。
    // 使うと、正規ドメインから転送された先の詐欺ページを見逃す。
    const result = await evaluate(details.url);
    await probePage(details.tabId, details.url, result);
  },
  { url: [{ schemes: ['http', 'https'] }] },
);

chrome.tabs.onRemoved.addListener((tabId) => tabVerdicts.delete(tabId));

// ---------------------------------------------------------------- メッセージ
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.target === 'offscreen') return false; // offscreen宛は素通し

  (async () => {
    switch (message?.type) {
      case 'get-verdict': {
        const tabId = message.tabId ?? sender.tab?.id;
        let result = tabVerdicts.get(tabId) ?? null;
        if (!result && message.url) result = await evaluate(message.url);
        sendResponse({ ok: true, result, settings: await settings() });
        break;
      }
      case 'analyze-url': {
        sendResponse({ ok: true, result: await evaluate(message.url, { useCache: false }) });
        break;
      }
      case 'get-details': {
        const stored = await chrome.storage.session.get(`warn:${message.token}`);
        sendResponse({ ok: true, result: stored[`warn:${message.token}`] ?? null });
        break;
      }
      case 'proceed': {
        // 送信側から渡されたホスト名やURLは信用しない。
        // ブロック時に自分で保存したレコードだけを根拠にする
        // （警告画面に不具合があっても、任意のドメインを許可させられないため）。
        const token = String(message.token ?? '');
        const stored = await chrome.storage.session.get(`warn:${token}`);
        const record = stored[`warn:${token}`];
        if (!record?.url) {
          sendResponse({ ok: false, error: 'unknown-token' });
          break;
        }
        const host = record.registrable || record.host;
        const url = record.url;
        const permanent = Boolean(message.permanent);
        if (!host || !/^https?:\/\//i.test(url)) {
          sendResponse({ ok: false, error: 'invalid-record' });
          break;
        }
        if (permanent) {
          const s = await settings();
          const allowlist = [...new Set([...s.allowlist, host])];
          settingsCache = { ...s, allowlist };
          await saveSettings({ allowlist });
        } else {
          await chrome.storage.session.set({ [`bypass:${host}`]: true });
        }
        verdictCache.clear();
        const tabId = sender.tab?.id;
        if (tabId != null) await chrome.tabs.update(tabId, { url });
        sendResponse({ ok: true });
        break;
      }
      case 'page-evidence': {
        // URLはブラウザが教えてくれる送信元タブのものだけを使う。
        // メッセージに入っていたURLは信用しない。
        const tabId = sender.tab?.id;
        const url = sender.tab?.url;
        if (tabId != null && url && /^https?:\/\//i.test(url)) {
          await applyPageEvidence(tabId, url, message.evidence);
        }
        sendResponse({ ok: true });
        break;
      }
      case 'set-secret': {
        const ok = await writeSecret(message.id, message.value);
        sendResponse({ ok, status: await secretStatus() });
        break;
      }
      case 'secret-status': {
        // 値そのものは決して返さない
        sendResponse({ ok: true, status: await secretStatus() });
        break;
      }
      case 'get-detectors': {
        const s = await settings();
        sendResponse({ ok: true, detectors: describeDetectors(DETECTOR_CATALOG, detectorConfigOf(s)) });
        break;
      }
      case 'set-detector': {
        const s = await settings();
        const detectorConfig = {
          ...s.detectorConfig,
          [message.id]: { ...(s.detectorConfig?.[message.id] ?? {}), ...message.patch },
        };
        settingsCache = { ...s, detectorConfig };
        await saveSettings({ detectorConfig });
        verdictCache.clear();
        sendResponse({ ok: true, detectors: describeDetectors(DETECTOR_CATALOG, detectorConfigOf(await settings())) });
        break;
      }
      case 'get-providers': {
        sendResponse({ ok: true, providers: resolveProviders(await settings()) });
        break;
      }
      case 'set-provider': {
        const s = await settings();
        const providerConfig = {
          ...s.providerConfig,
          [message.id]: { ...(s.providerConfig?.[message.id] ?? {}), ...message.patch },
        };
        settingsCache = { ...s, providerConfig };
        await saveSettings({ providerConfig });
        ttlCache.clear();
        verdictCache.clear();
        sendResponse({ ok: true, providers: resolveProviders(await settings()) });
        break;
      }
      case 'blocklist-status': {
        sendResponse({ ok: true, status: await blocklistStatus() });
        break;
      }
      case 'blocklist-update': {
        sendResponse(await updateBlocklist());
        break;
      }
      case 'get-settings': {
        sendResponse({ ok: true, settings: await settings() });
        break;
      }
      case 'set-settings': {
        settingsCache = null;
        await saveSettings(message.patch ?? {});
        verdictCache.clear();
        sendResponse({ ok: true, settings: await settings() });
        break;
      }
      case 'reset-settings': {
        await chrome.storage.sync.clear();
        settingsCache = null;
        await saveSettings(DEFAULT_SETTINGS);
        verdictCache.clear();
        sendResponse({ ok: true, settings: await settings() });
        break;
      }
      case 'local-llm-status': {
        // availability() の呼び出し自体がダウンロードを誘発しうるため、
        // 機能が有効なときだけ問い合わせる。
        const s = await settings();
        const enabled = detectorConfigOf(s)['local-brand-check']?.enabled;
        if (!enabled) {
          sendResponse({ ok: true, state: 'disabled' });
          break;
        }
        const out = await askWorker({ type: 'local-llm-status' }, 8000);
        sendResponse({ ok: true, state: out?.state ?? 'unavailable' });
        break;
      }
      case 'model-state': {
        const state = await askWorker({ type: 'warmup', useModel: (await settings()).useModel });
        sendResponse({ ok: true, state: state?.modelState ?? 'unavailable' });
        break;
      }
      default:
        sendResponse({ ok: false, error: 'unknown-message' });
    }
  })();
  return true; // 非同期応答
});

chrome.runtime.onInstalled.addListener(() => {
  ensureOffscreen();
  chrome.alarms?.create(BLOCKLIST_ALARM, { periodInMinutes: 60 * 12, delayInMinutes: 5 });
});
chrome.runtime.onStartup?.addListener(() => {
  ensureOffscreen();
});

// テスト/デバッグから service worker 内の判定を直接叩けるようにする
globalThis.moribito = {
  evaluate, analyzeUrl, analyzeWithPage, askWorker, ensureOffscreen, applyPageEvidence,
  loadBlocklist, blocklistStatus, updateBlocklist, runDetection, buildContext, loadUrlClassifier,
  detectors: () => resolveDetectors(DETECTOR_CATALOG, {}),
  resetBlocklistCache: () => { blocklistPromise = null; verdictCache.clear(); },
};
