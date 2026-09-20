/**
 * ドメイン名が「人が付けた名前らしいか」を測る。
 *
 * 自動生成されたドメイン名（DGA）は、文字のつながり方が実在ドメインの統計と違う。
 * `kjwhrgtlsdkfj` のような並びは、人が使うドメイン名ではまず現れない。
 * その現れにくさを、文字n-gramの対数尤度で測る。
 *
 * 子音の連続や数字の比率を数える従来の方法より素直で、
 * しきい値を「正常な名前の分布の何パーセンタイルか」で決められるのが利点。
 *
 * モデルは tools/build-ngram-model.mjs がトップサイトリストから作る。
 * **正常な名前だけの一クラスモデル**なので、フィッシング側のデータは要らない。
 */

import { NGRAM_SCALE, NGRAM_SIZE, NGRAM_CALIBRATION, NGRAM_BI_BASE64, NGRAM_TRI_BASE64 } from './ngram-data.js';

// 境界記号(0) + 英数字 + ハイフン
export const ALPHABET = '^abcdefghijklmnopqrstuvwxyz0123456789-';
export const NGRAM_ORDER = 3;

// trigram だけでは学習データに無い並びを過剰に罰するので、bigram と線形補間する
export const TRIGRAM_WEIGHT = 0.7;

const INDEX = new Map([...ALPHABET].map((ch, i) => [ch, i]));

export function indexOfChar(ch) {
  return INDEX.has(ch) ? INDEX.get(ch) : -1;
}

function decode(base64, scale) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  const quantized = new Int16Array(bytes.buffer);
  const out = new Float32Array(quantized.length);
  for (let i = 0; i < quantized.length; i++) out[i] = quantized[i] / scale;
  return out;
}

// 生成済みのテーブルを読み込む。psl-data.js などと同じく、生成物を同梱している。
const triTable = decode(NGRAM_TRI_BASE64, NGRAM_SCALE);
const biTable = decode(NGRAM_BI_BASE64, NGRAM_SCALE);
const calibration = NGRAM_CALIBRATION;
const size = NGRAM_SIZE;

export function namingModelReady() {
  return triTable.length > 0;
}

/** 名前1文字あたりの平均対数尤度。高いほど「普通の名前」。 */
export function nameLogLikelihood(name) {
  const text = String(name ?? '').toLowerCase();
  const seq = [0, 0];               // 先頭は境界記号を2つ置いて trigram を成立させる
  for (const ch of text) {
    const index = indexOfChar(ch);
    if (index >= 0) seq.push(index);
  }
  seq.push(0);
  if (seq.length < 4) return null;  // 1文字以下は判定しない

  let sum = 0;
  let count = 0;
  for (let i = 2; i < seq.length; i++) {
    const tri = triTable[(seq[i - 2] * size + seq[i - 1]) * size + seq[i]];
    const bi = biTable[seq[i - 1] * size + seq[i]];
    // 確率空間で補間してから対数に戻す
    sum += Math.log(TRIGRAM_WEIGHT * Math.exp(tri) + (1 - TRIGRAM_WEIGHT) * Math.exp(bi));
    count++;
  }
  return count ? sum / count : null;
}

/**
 * 0〜1 の「自動生成らしさ」。
 * 正常な名前の分布の下位分位点を基準にする。
 *   p05 以上 → 0（普通の名前）
 *   p001 以下 → 1（まず現れない並び）
 */
export function randomnessScore(name) {
  const score = nameLogLikelihood(name);
  if (score === null || !calibration) return null;
  const { p001, p05 } = calibration;
  if (score >= p05) return 0;
  if (score <= p001) return 1;
  return (p05 - score) / (p05 - p001);
}
