/** 危険信号の合成としきい値判定。 */

export const DEFAULT_THRESHOLDS = {
  blockThreshold: 0.85,  // これ以上で警告画面にリダイレクト
  warnThreshold: 0.55,   // これ以上でバッジ警告
  greyLow: 0.35,         // このレンジだけローカルモデルに相談する
  greyHigh: 0.9,
};

/**
 * noisy-OR で合成する。
 * 「独立した弱い証拠が積み重なると強くなるが、決して1を超えない」性質が
 * フィッシング判定の直感に合う。
 */
export function combine(signals) {
  let p = 0;
  for (const s of signals) {
    const w = Math.max(0, Math.min(1, Number(s.weight) || 0));
    p = p + w * (1 - p);
  }
  return p;
}

export function verdictOf(score, thresholds = DEFAULT_THRESHOLDS) {
  if (score >= thresholds.blockThreshold) return 'block';
  if (score >= thresholds.warnThreshold) return 'warn';
  return 'allow';
}

export function isGrey(score, thresholds = DEFAULT_THRESHOLDS) {
  return score >= thresholds.greyLow && score < thresholds.greyHigh;
}

/**
 * ルールスコアとモデル確率を統合する。
 * ルールを主、モデルを従とし、ルールが強く出ている場合はモデルで下げない。
 */
export function blendWithModel(ruleScore, modelProb, weight = 0.4) {
  if (typeof modelProb !== 'number' || Number.isNaN(modelProb)) return ruleScore;
  const blended = ruleScore * (1 - weight) + modelProb * weight;
  return Math.max(ruleScore >= 0.85 ? ruleScore : 0, Math.min(1, blended));
}
