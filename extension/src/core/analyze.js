/**
 * 判定のエントリポイント。chrome.* に依存しないので
 * service worker / worker / Node のテストのどこからでも呼べる。
 */
import { extractFeatures } from './features.js';
import { evaluateRules } from './rules.js';
import { combine, verdictOf, isGrey, blendWithModel, DEFAULT_THRESHOLDS } from './score.js';
import { BRANDS, POPULAR_DOMAINS, brandOwning, isUserGeneratedArea } from './brands.js';
import { evaluatePageEvidence } from './page-evidence.js';

export { DEFAULT_THRESHOLDS };

/**
 * @param {string} rawUrl
 * @param {{thresholds?:object, allowlist?:Iterable<string>, brands?:Array}} options
 */
export function analyzeUrl(rawUrl, options = {}) {
  const thresholds = { ...DEFAULT_THRESHOLDS, ...(options.thresholds ?? {}) };
  const allowlist = options.allowlist instanceof Set
    ? options.allowlist
    : new Set(options.allowlist ?? []);
  const brands = options.brands ?? BRANDS;

  const f = extractFeatures(rawUrl);

  const base = {
    url: rawUrl,
    host: f.ok ? f.host : '',
    hostUnicode: f.ok ? f.hostUnicode : '',
    registrable: f.ok ? f.registrable : '',
    scheme: f.ok ? f.scheme : '',
    source: 'rules',
  };

  if (!f.ok) {
    return { ...base, ok: false, score: 0, verdict: 'allow', grey: false, signals: [], reason: f.error };
  }

  // 1. ユーザー許可リスト
  if (allowlist.has(f.registrable) || allowlist.has(f.host)) {
    return { ...base, ok: true, score: 0, verdict: 'allow', grey: false, signals: [], reason: 'allowlisted' };
  }

  // 2. 社内/自宅LAN・localhost は判定対象外（ルーター管理画面などの誤検知防止）
  if (f.isPrivateNetwork) {
    return { ...base, ok: true, score: 0, verdict: 'allow', grey: false, signals: [], reason: 'private-network' };
  }

  // 3. 正規ブランド本体 / 著名ドメインはここで打ち切る（誤検知の抑制）。
  //    ただしURL/ホスト単位で報告済みの場合は打ち切らない。
  //    正規ドメインが乗っ取られてフィッシングページを置かれる事例があるため。
  const hit = options.blocklistHit ?? null;
  const reportedPrecisely = hit && (hit.kind === 'url' || hit.kind === 'host');
  // 公式ドメインでも、第三者が中身を作れる領域は打ち切らない
  const userGenerated = isUserGeneratedArea(f.host, f.path);
  if (!reportedPrecisely && !userGenerated) {
    const owner = brandOwning(f.registrable);
    if (owner) {
      return { ...base, ok: true, score: 0, verdict: 'allow', grey: false, signals: [], reason: `official:${owner.id}` };
    }
    if (POPULAR_DOMAINS.has(f.registrable)) {
      return { ...base, ok: true, score: 0, verdict: 'allow', grey: false, signals: [], reason: 'popular-domain' };
    }
  }

  const signals = evaluateRules(f, { brands, blocklistHit: hit });
  const score = combine(signals);

  return {
    ...base,
    ok: true,
    score,
    verdict: verdictOf(score, thresholds),
    grey: isGrey(score, thresholds),
    signals: signals.sort((a, b) => b.weight - a.weight),
    features: summarize(f),
  };
}

/**
 * 表示コンテンツの証拠を足して判定し直す。
 * URL判定で打ち切られたもの（公式・著名・許可済み・LAN）はそのまま返す。
 */
export function analyzeWithPage(rawUrl, evidence, options = {}) {
  const thresholds = { ...DEFAULT_THRESHOLDS, ...(options.thresholds ?? {}) };
  const brands = options.brands ?? BRANDS;
  const base = analyzeUrl(rawUrl, options);
  if (!base.ok || base.reason) return base;

  const f = extractFeatures(rawUrl);
  const pageSignals = evaluatePageEvidence(f, evidence, { brands });
  if (!pageSignals.length) return { ...base, pageSignals: [] };

  const signals = [...base.signals, ...pageSignals].sort((a, b) => b.weight - a.weight);
  const score = combine(signals);
  return {
    ...base,
    score,
    signals,
    pageSignals,
    verdict: verdictOf(score, thresholds),
    grey: false,
    source: `${base.source}+page`,
  };
}

/** 外部照会などで得た信号を足して判定し直す。 */
export function withExtraSignals(result, extraSignals, options = {}) {
  const thresholds = { ...DEFAULT_THRESHOLDS, ...(options.thresholds ?? {}) };
  if (!result?.ok || !extraSignals?.length) return result;
  const signals = [...(result.signals ?? []), ...extraSignals].sort((a, b) => b.weight - a.weight);
  const score = combine(signals);
  return {
    ...result,
    score,
    signals,
    verdict: verdictOf(score, thresholds),
    grey: false,
    source: `${result.source}+${options.label ?? 'external'}`,
  };
}

/** モデル確率を受け取って判定を更新する（グレーゾーン専用）。 */
export function withModel(result, modelProb, options = {}) {
  const thresholds = { ...DEFAULT_THRESHOLDS, ...(options.thresholds ?? {}) };
  if (!result.ok || typeof modelProb !== 'number') return result;
  const score = blendWithModel(result.score, modelProb, options.modelWeight ?? 0.4);
  return {
    ...result,
    score,
    modelProb,
    source: 'rules+model',
    verdict: verdictOf(score, thresholds),
    grey: false,
  };
}

function summarize(f) {
  return {
    registrable: f.registrable,
    suffix: f.suffix,
    sub: f.sub,
    subUnicode: f.subUnicode,
    hostUnicode: f.hostUnicode,
    isIp: f.isIp,
    hasPunycode: f.hasPunycode,
    scriptKind: f.scriptKind,
    scripts: f.scripts,
    labelCount: f.labelCount,
    urlLength: f.urlLength,
  };
}
