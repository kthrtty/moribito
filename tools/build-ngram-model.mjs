/**
 * 「普通のドメイン名らしさ」を測るための文字n-gramモデルを作る。
 *
 *   node tools/build-ngram-model.mjs data/top-1m.csv --take=200000
 *
 * 狙い:
 *   自動生成されたドメイン名（DGA）は、人が付けた名前と文字のつながり方が違う。
 *   `kjwhrgtlsdkfj` のような並びは、実在ドメインの統計ではまず現れない。
 *   その「現れにくさ」を対数尤度で測る。
 *
 * 前回のURL分類器との決定的な違い:
 *   あれは「正規 vs フィッシング」の二値分類で、正規側データの代表性が崩れて失敗した。
 *   こちらは**正常な名前だけを学習する一クラスモデル**なので、
 *   フィッシング側のデータを一切必要とせず、ラベルの偏りという問題が起きない。
 *   必要なのは「人がよく使うドメイン名の集合」だけで、それはトップサイトリストそのもの。
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { splitHost } from '../extension/src/core/psl.js';
import { ALPHABET, indexOfChar, TRIGRAM_WEIGHT } from '../extension/src/core/naming.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--')) ?? 'data/top-1m.csv';
const opt = (name, fallback) => {
  const hit = args.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};
const take = Number(opt('take', 200000));
const out = resolve(ROOT, opt('out', 'extension/src/core/ngram-data.js'));

const SIZE = ALPHABET.length; // 境界記号を含む

// --- 学習データ: トップサイトの登録ドメイン名（eTLD+1 のラベル部分） ---
const names = [];
const seen = new Set();
for (const line of readFileSync(resolve(ROOT, file), 'utf8').split(/\r?\n/)) {
  if (names.length >= take) break;
  const domain = (line.split(',')[1] ?? line.split(',')[0] ?? '').trim().toLowerCase();
  if (!domain || !domain.includes('.')) continue;
  const name = splitHost(domain).name;
  if (!name || name.length < 2 || seen.has(name)) continue;
  seen.add(name);
  names.push(name);
}
console.log(`学習に使う名前: ${names.length} 件 (${file})`);

// --- カウント（加算スムージング） ---
const biCounts = new Float64Array(SIZE * SIZE).fill(1);
const triCounts = new Float64Array(SIZE * SIZE * SIZE).fill(0.1); // 疎なので弱めに

function sequence(name) {
  const seq = [0, 0];
  for (const ch of name) {
    const index = indexOfChar(ch);
    if (index >= 0) seq.push(index);
  }
  seq.push(0);
  return seq;
}

for (const name of names) {
  const seq = sequence(name);
  for (let i = 2; i < seq.length; i++) {
    biCounts[seq[i - 1] * SIZE + seq[i]] += 1;
    triCounts[(seq[i - 2] * SIZE + seq[i - 1]) * SIZE + seq[i]] += 1;
  }
}

// --- 対数確率へ ---
const biLog = new Float64Array(SIZE * SIZE);
for (let a = 0; a < SIZE; a++) {
  let total = 0;
  for (let b = 0; b < SIZE; b++) total += biCounts[a * SIZE + b];
  for (let b = 0; b < SIZE; b++) biLog[a * SIZE + b] = Math.log(biCounts[a * SIZE + b] / total);
}

const triLog = new Float64Array(SIZE * SIZE * SIZE);
for (let ab = 0; ab < SIZE * SIZE; ab++) {
  let total = 0;
  for (let c = 0; c < SIZE; c++) total += triCounts[ab * SIZE + c];
  for (let c = 0; c < SIZE; c++) triLog[ab * SIZE + c] = Math.log(triCounts[ab * SIZE + c] / total);
}

/** 名前1件あたりの平均対数尤度（trigram と bigram の補間）。 */
function score(name) {
  const seq = sequence(name);
  if (seq.length < 4) return 0;
  let sum = 0;
  let count = 0;
  for (let i = 2; i < seq.length; i++) {
    const tri = triLog[(seq[i - 2] * SIZE + seq[i - 1]) * SIZE + seq[i]];
    const bi = biLog[seq[i - 1] * SIZE + seq[i]];
    sum += Math.log(TRIGRAM_WEIGHT * Math.exp(tri) + (1 - TRIGRAM_WEIGHT) * Math.exp(bi));
    count++;
  }
  return count ? sum / count : 0;
}

// --- 較正: 正常な名前のスコア分布から分位点を取る ---
const scores = names.map(score).sort((a, b) => a - b);
const pct = (p) => scores[Math.min(scores.length - 1, Math.floor(scores.length * p))];
const calibration = { p001: pct(0.001), p01: pct(0.01), p05: pct(0.05), p50: pct(0.5) };
console.log('正常な名前のスコア分布:');
for (const [k, v] of Object.entries(calibration)) console.log(`  ${k}: ${v.toFixed(4)}`);

// --- 書き出し（int16に量子化してbase64） ---
const scale = 1000;
function encode(values) {
  const quantized = new Int16Array(values.length);
  for (let i = 0; i < values.length; i++) {
    quantized[i] = Math.max(-32768, Math.min(32767, Math.round(values[i] * scale)));
  }
  let binary = '';
  const bytes = new Uint8Array(quantized.buffer);
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return Buffer.from(binary, 'binary').toString('base64');
}

const source = `/**
 * 「普通のドメイン名らしさ」の文字n-gramモデル（自動生成 — 手で編集しない）
 *   生成元: ${file}（上位 ${names.length} 件の登録ドメイン名）
 *   生成日: ${new Date().toISOString().slice(0, 10)}
 *   再生成: node tools/build-ngram-model.mjs
 *
 * 正常な名前だけから作った一クラスモデル。フィッシング側のデータは使っていない。
 * trigram と bigram を線形補間し、log を ${scale} 倍して int16 に量子化したもの。
 */

export const NGRAM_SCALE = ${scale};
export const NGRAM_SIZE = ${SIZE};

/** 正常な名前のスコア分布（下位分位点）。これを基準に異常さを測る。 */
export const NGRAM_CALIBRATION = {
  p001: ${calibration.p001.toFixed(4)},
  p01: ${calibration.p01.toFixed(4)},
  p05: ${calibration.p05.toFixed(4)},
  p50: ${calibration.p50.toFixed(4)},
};

export const NGRAM_BI_BASE64 = '${encode(biLog)}';
export const NGRAM_TRI_BASE64 = '${encode(triLog)}';
`;
writeFileSync(out, source);
console.log(`\n${out} を書き出しました (${(source.length / 1024).toFixed(1)} KB)`);

// --- 動作確認 ---
console.log('\n--- 参考スコア（低いほど「普通でない」） ---');
for (const name of [
  'google', 'amazon', 'mufg', 'rakuten', 'nikkei', 'wikipedia', 'my-project',
  'kjwhrgtlsdkfj', 'a8f3k29dj4mfs0x9alqp2mdk', 'x7f3k9qz2m', 'bugxic02',
  'zxcvbnmqwerty1234', 'qwrtplkjhgfdsazx', 'undergrdf', 'xw7-mks7h',
]) {
  console.log(`  ${name.padEnd(26)} ${score(name).toFixed(3)}`);
}
