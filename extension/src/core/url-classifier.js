/**
 * ホスト名の文字パターンから、フィッシングらしさを推定する線形分類器。
 *
 * 狙い:
 *   ルールが見ているのは「ブランド詐称」で、それ以外の型
 *   （無名ドメインの使い捨てフィッシング）は原理的に取れない。
 *   そこを文字パターンの学習で埋める。
 *
 * 設計上の判断:
 *   - **ホスト名だけを見る**。パスを入れると、学習データの偏り
 *     （正規側が素のトップページ中心）を学んでしまい、現実では無意味な
 *     「パスがあれば怪しい」という相関が乗る。
 *   - **ハッシュトリック**で語彙表を持たない。重みは固定長配列1本だけ。
 *   - **ONNXランタイムもWASMも使わない**。内積とsigmoidだけなので
 *     素のJavaScriptで数十マイクロ秒に収まる。
 *
 * 学習側（tools/train/train-url-classifier.mjs）とこのファイルで
 * 特徴量の作り方を共有しているので、ずれようがない。
 */

import { splitHost } from './psl.js';

export const CLASSIFIER_VERSION = 1;
export const DEFAULT_BUCKETS = 1 << 18; // 262,144。int8量子化で約256KB
export const NGRAM_MIN = 2;
export const NGRAM_MAX = 5;

/** FNV-1a（32bit）。軽くて分布が素直なので十分。 */
function fnv1a(text) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash;
}

/**
 * 正規化したホスト名。
 *
 * 先頭の `www.` は必ず落とす。安全性の情報を何も持たないのに、
 * 学習データでは「正規サイトの目印」として強く相関してしまうため
 * （正規側がトップページ中心のデータセットでは、この癖を学んだモデルが
 * mail.google.com や github.com をフィッシング扱いする）。
 */
export function normalizeHost(hostname) {
  const host = String(hostname ?? '').toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
  if (!host) return '';
  return `^${host}$`;
}

/**
 * 文字n-gramを、重み配列の添字と値の組へ落とす。
 * @returns {Map<number, number>} 添字 -> 出現回数（L2正規化前）
 */
export function featurize(hostname, buckets = DEFAULT_BUCKETS) {
  const text = normalizeHost(hostname);
  const counts = new Map();
  if (!text) return counts;

  for (let n = NGRAM_MIN; n <= NGRAM_MAX; n++) {
    for (let i = 0; i + n <= text.length; i++) {
      const index = fnv1a(text.slice(i, i + n)) % buckets;
      counts.set(index, (counts.get(index) ?? 0) + 1);
    }
  }
  return counts;
}

/** 長さの影響を消すためL2正規化する。短いドメインと長いドメインを同じ土俵に載せる。 */
export function normalizeFeatures(counts) {
  let norm = 0;
  for (const value of counts.values()) norm += value * value;
  norm = Math.sqrt(norm) || 1;
  const out = new Map();
  for (const [index, value] of counts) out.set(index, value / norm);
  return out;
}

/** 登録ドメイン（eTLD+1）だけを取り出す。 */
export function registrableOf(hostname) {
  const info = splitHost(String(hostname ?? '').toLowerCase());
  return info.registrable || info.host || '';
}

export function sigmoid(x) {
  if (x >= 0) return 1 / (1 + Math.exp(-x));
  const e = Math.exp(x);
  return e / (1 + e);
}

/**
 * 学習済みモデルからフィッシング確率を返す。
 * @param {string} hostname
 * @param {{weights: Float32Array|Int8Array, scale?:number, bias:number, buckets:number}} model
 */
export function predictHost(hostname, model) {
  if (!model?.weights) return null;
  // 学習時と同じ範囲を見る（ホスト名全体か、登録ドメインだけか）
  const target = model.scope === 'registrable' ? registrableOf(hostname) : hostname;
  if (!target) return null;
  const features = normalizeFeatures(featurize(target, model.buckets));
  const scale = model.scale ?? 1;
  let sum = model.bias;
  for (const [index, value] of features) sum += model.weights[index] * scale * value;
  return sigmoid(sum);
}

/**
 * 配布形式（int8量子化 + base64）を展開する。
 * artifact: { version, buckets, bias, scale, weights: base64 }
 */
export function loadModel(artifact) {
  if (!artifact || artifact.version !== CLASSIFIER_VERSION) return null;
  const binary = atob(artifact.weights);
  const weights = new Int8Array(binary.length);
  for (let i = 0; i < binary.length; i++) weights[i] = (binary.charCodeAt(i) << 24) >> 24;
  if (weights.length !== artifact.buckets) return null;
  return {
    weights,
    scale: Number(artifact.scale) || 1,
    bias: Number(artifact.bias) || 0,
    buckets: Number(artifact.buckets),
    scope: artifact.scope === 'registrable' ? 'registrable' : 'host',
    trainedAt: artifact.trainedAt ?? null,
    metrics: artifact.metrics ?? null,
  };
}

/** 学習側が使う書き出し。重みをint8へ量子化する。 */
export function quantize(weights) {
  let max = 0;
  for (const w of weights) max = Math.max(max, Math.abs(w));
  const scale = max === 0 ? 1 : max / 127;
  const quantized = new Int8Array(weights.length);
  for (let i = 0; i < weights.length; i++) {
    quantized[i] = Math.max(-127, Math.min(127, Math.round(weights[i] / scale)));
  }
  return { quantized, scale };
}
