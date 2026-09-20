/**
 * 検出器カタログ。
 *
 * 追加したいときはここに1つ足すだけでよい。パイプラインが段階順に呼び、
 * 設定画面は cost / description をそのまま表示する。
 * 各検出器は chrome.* を知らず、外部とのやり取りは ctx.services 経由で受け取る。
 */
import { BRANDS, POPULAR_DOMAINS, brandOwning } from '../brands.js';
import { evaluateRules, knownPhishingSignal } from '../rules.js';
import { evaluatePageEvidence } from '../page-evidence.js';
import { queryProviders, reputationSignals } from '../reputation.js';
import { queryJev, jevWeight, jevStateFor } from '../jev.js';

/** 利用者が明示的に許可したドメイン。何よりも優先する。 */
export const allowlistDetector = {
  id: 'allowlist',
  label: '利用者の許可リスト',
  description: '「危険を承知で続行」したドメインや、設定画面で許可したドメインを素通しします。',
  stage: 'allow',
  cost: { network: 'none', latency: 'low' },
  defaultEnabled: true,
  run(ctx) {
    const f = ctx.features;
    if (!f?.ok) return { decision: { verdict: 'allow', reason: f?.error ?? 'invalid-url' } };
    const allowlist = ctx.allowlist instanceof Set ? ctx.allowlist : new Set(ctx.allowlist ?? []);
    if (allowlist.has(f.registrable) || allowlist.has(f.host)) {
      return { decision: { verdict: 'allow', reason: 'allowlisted' } };
    }
    return null;
  },
};

/** 配布済みリストとのローカル照合。services.blocklist を注入して使う。 */
export const blocklistDetector = {
  id: 'blocklist',
  label: '既知フィッシングリスト（ローカル照合）',
  description: 'ハッシュ化して配布されたリストと端末内で突き合わせます。通信は発生しません。',
  stage: 'list',
  cost: { network: 'none', latency: 'low' },
  defaultEnabled: true,
  configurable: true,
  async run(ctx) {
    const list = ctx.services?.blocklist;
    if (!list || !ctx.features?.ok) return null;
    const hit = await list.lookup(ctx.url, ctx.features);
    return hit ? { signals: [knownPhishingSignal(hit)] } : null;
  },
};

/** 公式ブランド・著名ドメイン・社内LANはここで打ち切る（誤検知の抑制）。 */
export const knownGoodDetector = {
  id: 'known-good',
  label: '公式ドメイン・著名ドメインの打ち切り',
  description: '正規ブランドの公式ドメイン、広く使われているドメイン、社内LANは判定しません。',
  stage: 'safe',
  cost: { network: 'none', latency: 'low' },
  defaultEnabled: true,
  // URL/ホスト単位で報告済みなら打ち切らない（乗っ取られた正規サイト対策）
  runWhen: (state) => !state.signals.some(
    (s) => s.id === 'known-phishing' && (s.kind === 'url' || s.kind === 'host')),
  run(ctx) {
    const f = ctx.features;
    if (!f?.ok) return null;
    if (f.isPrivateNetwork) return { decision: { verdict: 'allow', reason: 'private-network' } };
    const owner = brandOwning(f.registrable);
    if (owner) return { decision: { verdict: 'allow', reason: `official:${owner.id}` } };
    if (POPULAR_DOMAINS.has(f.registrable)) {
      return { decision: { verdict: 'allow', reason: 'popular-domain' } };
    }
    return null;
  },
};

/** URL構造ルール（この拡張の中核）。 */
export const urlRulesDetector = {
  id: 'url-rules',
  label: 'URL構造ルール',
  description: 'ホモグリフ・混在スクリプト・ブランド詐称サブドメインなど22種の信号を見ます。',
  stage: 'url',
  cost: { network: 'none', latency: 'low' },
  defaultEnabled: true,
  run(ctx) {
    if (!ctx.features?.ok) return null;
    return { signals: evaluateRules(ctx.features, { brands: ctx.brands ?? BRANDS }) };
  },
};

/** 外部リピュテーション照会。既定で無効。グレーのときだけ動く。 */
export const reputationDetector = {
  id: 'reputation',
  label: '外部リピュテーション照会',
  description: 'URLだけで決着しない場合に、設定した外部サービスへ問い合わせます。閲覧先が相手に伝わります。',
  stage: 'reputation',
  cost: { network: 'domain', latency: 'high' },
  defaultEnabled: false,
  configurable: true,
  runWhen: (state) => state.grey,
  async run(ctx) {
    const providers = (ctx.providers ?? []).filter((p) => p.enabled && p.endpoint);
    if (!providers.length) return null;

    // 問い合わせ回数を抑えるため、ドメイン単位でTTL付きに使い回す
    const domainKey = `reputation:${ctx.features.registrable || ctx.features.host}`;
    const cached = ctx.services?.cache?.get(domainKey);
    if (cached) return { signals: reputationSignals(cached) };

    const results = await queryProviders(providers, {
      domain: ctx.features.registrable || ctx.features.host,
      url: ctx.url,
      prefix: ctx.prefix ?? '',
    }, { fetchImpl: ctx.services?.fetchImpl, dohEndpoint: ctx.dohEndpoint });
    ctx.services?.cache?.set(domainKey, results);
    return { signals: reputationSignals(results) };
  },
};

/**
 * Jev（TypeSafe AI）への問い合わせ。
 * 実行時に閲覧先を外部へ送る唯一の層なので、既定で無効・グレーのときだけ呼ぶ。
 */
export const jevDetector = {
  id: 'jev-remote',
  label: 'Jev による確率判定（外部API）',
  description: 'URLだけで決着しない場合に TypeSafe AI の Jev へ問い合わせます。'
    + '有効にすると閲覧先が外部に伝わります。既定ではホスト名のみを送ります。',
  stage: 'reputation',
  cost: { network: 'domain', latency: 'medium' },
  defaultEnabled: false,
  configurable: true,
  runWhen: (state) => state.grey,
  async run(ctx) {
    const config = ctx.jev;
    if (!config?.apiKey) return null;

    const cacheKey = `jev:${config.sendFullUrl ? ctx.url : ctx.features.host}`;
    const cached = ctx.services?.cache?.get(cacheKey);
    const answer = cached ?? await queryJev(ctx.url, config, {
      fetchImpl: ctx.services?.fetchImpl,
      timeoutMs: config.timeoutMs ?? 3000,
    });
    if (!answer) return null;
    if (!cached) ctx.services?.cache?.set(cacheKey, answer);

    if (answer.error) {
      // 外部の不調で判定を止めない。理由だけ残す。
      return { signals: [], note: `jev: ${answer.error}` };
    }

    const weight = jevWeight(answer);
    if (weight <= 0) return null;
    return {
      signals: [{
        id: 'jev-phishing',
        weight,
        title: '外部の確率判定モデルが危険と推定',
        detail: `Jev はフィッシングである確率を ${Math.round(answer.probability * 100)}%`
          + `（確信度 ${Math.round(answer.confidence * 100)}%）と推定しました。`
          + `送信したのは ${config.sendFullUrl ? 'URL全体' : 'ホスト名のみ'} です。`,
        from: 'jev',
      }],
    };
  },
};

/** 表示コンテンツの検査。ctx.evidence があるときだけ動く。 */
export const pageEvidenceDetector = {
  id: 'page-evidence',
  label: '表示コンテンツの検査',
  description: '入力欄が何を要求しているか、どのブランドを名乗っているかを端末内で調べます。',
  stage: 'content',
  cost: { network: 'none', latency: 'medium' },
  defaultEnabled: true,
  configurable: true,
  runWhen: (state, ctx) => true,
  run(ctx) {
    if (!ctx.evidence?.ok || !ctx.features?.ok) return null;
    return { signals: evaluatePageEvidence(ctx.features, ctx.evidence, { brands: ctx.brands ?? BRANDS }) };
  },
};

/**
 * ローカル軽量分類器。services.classifyUrl を注入する。
 * 確率は noisy-OR に載せるため、0.5を基準に0〜0.8へ写像する。
 */
export const localModelDetector = {
  id: 'local-model',
  label: 'ローカル分類器（URL）',
  description: 'グレーゾーンだけ、端末内の小型モデルで確率を出します。モデル未配置なら何もしません。',
  stage: 'model',
  cost: { network: 'none', latency: 'medium' },
  defaultEnabled: false,
  configurable: true,
  runWhen: (state) => state.grey,
  async run(ctx) {
    const classify = ctx.services?.classifyUrl;
    if (typeof classify !== 'function') return null;
    const probability = await classify(ctx.url);
    if (typeof probability !== 'number' || probability <= 0.5) return null;
    return {
      signals: [{
        id: 'local-model',
        weight: Math.min(0.8, (probability - 0.5) * 1.6),
        title: 'ローカル分類器が危険と判定',
        detail: `端末内のモデルがフィッシング確率 ${Math.round(probability * 100)}% と推定しました。`,
        from: 'model',
      }],
    };
  },
};

/**
 * ローカルLLM / 小型テキスト分類器による文面判定。
 * services.classifyText を注入すると動く。未注入なら何もしない。
 * 語句一致（page-evidence 側）より言い換えに強いが、重いので既定は無効。
 */
export const localTextModelDetector = {
  id: 'local-text-model',
  label: 'ローカル文面判定（煽り・不安の検出）',
  description: '「急がせる」「不安に訴える」といった文面を、端末内のモデルで判定します。'
    + '語句一致より言い換えに強い一方、処理が重くなります。',
  stage: 'model',
  cost: { network: 'none', latency: 'high' },
  defaultEnabled: false,
  configurable: true,
  runWhen: (state) => state.score >= 0.2,
  async run(ctx) {
    const classify = ctx.services?.classifyText;
    const text = ctx.evidence?.bodyText;
    if (typeof classify !== 'function' || !text) return null;
    const result = await classify(text);
    if (!result || (result.probability ?? 0) <= 0.6) return null;
    return {
      signals: [{
        id: 'manipulative-copy',
        weight: Math.min(0.6, (result.probability - 0.6) * 1.5),
        title: '不安を煽って操作しようとする文面',
        detail: result.label
          ? `文面が「${result.label}」と判定されました。`
          : '緊急性や不安を強調して入力を促す文面と判定されました。',
        from: 'model',
      }],
    };
  },
};

/** 既定のカタログ。順序はパイプラインが stage で決めるので並びは自由。 */
export const DETECTOR_CATALOG = [
  allowlistDetector,
  blocklistDetector,
  knownGoodDetector,
  urlRulesDetector,
  reputationDetector,
  jevDetector,
  pageEvidenceDetector,
  localModelDetector,
  localTextModelDetector,
];
