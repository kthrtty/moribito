/**
 * 判定パイプライン。
 *
 * 検出器（detector）を差し替え可能な部品として扱い、段階（stage）順に実行する。
 * 「どう判定するか」は各検出器が持ち、ここは「いつ誰を動かし、どう合成し、
 * どこで打ち切るか」だけを持つ。
 *
 * 検出器の契約:
 *   {
 *     id, label, stage, cost, defaultEnabled,
 *     runWhen?(state) => boolean,        // 省略時は常に実行
 *     run(ctx, state) => Promise<{ signals?, decision? }> | { signals?, decision? }
 *   }
 *   decision を返すとそこで確定して打ち切る（許可リストや公式ドメインなど）。
 *   signals は score.js の noisy-OR で合成される。
 *
 * ctx に chrome.* は入れない。外部とのやり取りは ctx.services 経由で注入する。
 */
import { combine, verdictOf, isGrey, DEFAULT_THRESHOLDS } from './score.js';

/**
 * 実行順。手前ほど安く確定的。
 *   allow    利用者が明示的に許可したもの（最優先）
 *   list     配布済みリストとの照合（乗っ取られた正規サイトを拾うため safe より前）
 *   safe     公式ブランド・著名ドメイン・社内LAN（ここで打ち切る）
 *   url      URL構造ルール
 *   reputation 外部照会（既定で無効）
 *   content  表示コンテンツ
 *   model    ローカル分類器 / ローカルLLM
 */
export const STAGES = ['allow', 'list', 'safe', 'url', 'reputation', 'content', 'model'];

export const COST = {
  none: { label: '通信なし', order: 0 },
  prefix: { label: 'ハッシュ接頭辞のみ送信', order: 1 },
  domain: { label: 'ドメイン名を送信', order: 2 },
  url: { label: 'URLを送信', order: 3 },
};

function stageOrder(detector) {
  const index = STAGES.indexOf(detector.stage);
  return index < 0 ? STAGES.length : index;
}

/** 有効な検出器を段階順に並べる。 */
export function orderDetectors(detectors) {
  return [...(detectors ?? [])]
    .filter((d) => d && typeof d.run === 'function')
    .sort((a, b) => stageOrder(a) - stageOrder(b) || String(a.id).localeCompare(String(b.id)));
}

/**
 * パイプラインを実行する。
 * @param {object} ctx  { url, features, settings, evidence?, services?, phase }
 * @param {Array} detectors
 * @param {object} options { thresholds, onError }
 */
export async function runDetection(ctx, detectors, options = {}) {
  const thresholds = { ...DEFAULT_THRESHOLDS, ...(options.thresholds ?? {}) };
  const ordered = orderDetectors(detectors);

  const signals = [];
  const ran = [];
  let decision = null;

  for (const detector of ordered) {
    const state = snapshot(signals, thresholds, ctx, ran);
    if (detector.runWhen && !detector.runWhen(state)) continue;

    let output;
    try {
      output = await detector.run(ctx, state);
    } catch (err) {
      // 1つの検出器の失敗で判定全体を止めない
      options.onError?.(detector, err);
      continue;
    }
    ran.push(detector.id);
    if (!output) continue;

    if (output.decision) {
      decision = { ...output.decision, by: detector.id };
      break;
    }
    for (const signal of output.signals ?? []) {
      signals.push({ ...signal, by: signal.by ?? detector.id });
    }
  }

  if (decision) {
    return {
      ...baseOf(ctx),
      ok: true,
      score: 0,
      verdict: decision.verdict ?? 'allow',
      grey: false,
      signals: [],
      reason: decision.reason,
      ran,
      source: decision.by,
    };
  }

  const score = combine(signals);
  return {
    ...baseOf(ctx),
    ok: true,
    score,
    verdict: verdictOf(score, thresholds),
    grey: isGrey(score, thresholds),
    signals: [...signals].sort((a, b) => b.weight - a.weight),
    ran,
    source: ran.join('+') || 'none',
  };
}

function snapshot(signals, thresholds, ctx, ran) {
  const score = combine(signals);
  return {
    score,
    verdict: verdictOf(score, thresholds),
    grey: isGrey(score, thresholds),
    signals,
    ran,
    phase: ctx.phase ?? 'navigation',
    thresholds,
  };
}

function baseOf(ctx) {
  const f = ctx.features;
  return {
    url: ctx.url,
    host: f?.ok ? f.host : '',
    hostUnicode: f?.ok ? f.hostUnicode : '',
    registrable: f?.ok ? f.registrable : '',
    scheme: f?.ok ? f.scheme : '',
  };
}

/** 設定の有効/無効を反映した検出器一覧を作る。 */
export function resolveDetectors(catalog, config = {}) {
  return (catalog ?? []).map((detector) => {
    const override = config[detector.id] ?? {};
    const enabled = override.enabled ?? detector.defaultEnabled ?? true;
    return { ...detector, ...override, enabled };
  }).filter((detector) => detector.enabled);
}

/** 設定画面に出すための一覧（無効なものも含む）。 */
export function describeDetectors(catalog, config = {}) {
  return (catalog ?? []).map((detector) => {
    const override = config[detector.id] ?? {};
    return {
      id: detector.id,
      label: detector.label,
      stage: detector.stage,
      description: detector.description ?? '',
      cost: detector.cost ?? { network: 'none', latency: 'low' },
      configurable: Boolean(detector.configurable),
      enabled: override.enabled ?? detector.defaultEnabled ?? true,
      defaultEnabled: detector.defaultEnabled ?? true,
    };
  });
}
