/**
 * ホスト名の文字n-gramからフィッシングらしさを学習する（Nodeだけで完結）。
 *
 *   node tools/train/train-url-classifier.mjs data/PhiUSIIL_Phishing_URL_Dataset.csv \
 *     --url-col=URL --label-col=label --phishing-label=0 \
 *     --out=extension/model/url-classifier.json
 *
 * 外部モデルもPyTorchも要らない。教師ラベルがデータセットに付いているので蒸留でもない。
 *
 * 汎化を正しく測るための約束:
 *   - 分割は**登録ドメイン単位**。ランダム分割だと同じドメインの別URLが
 *     訓練とテストの両方に出て、「覚えただけ」でも高スコアになる。
 *   - 学習に使っていない別コーパス（tests/fixtures/urls.mjs）でも確認する。
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  featurize, normalizeFeatures, sigmoid, quantize, registrableOf,
  CLASSIFIER_VERSION, DEFAULT_BUCKETS,
} from '../../extension/src/core/url-classifier.js';
import { splitHost } from '../../extension/src/core/psl.js';
import { FREE_HOSTING } from '../../extension/src/core/brands.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
const opt = (name, fallback) => {
  const hit = args.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};

if (!file) {
  console.error('使い方: node tools/train/train-url-classifier.mjs <csv> [--url-col=URL] [--label-col=label] [--phishing-label=0]');
  process.exit(1);
}

const urlCol = opt('url-col', 'url');
const labelCol = opt('label-col', 'label');
const phishingLabel = opt('phishing-label', null);
const buckets = Number(opt('buckets', DEFAULT_BUCKETS));
const epochs = Number(opt('epochs', 8));
const learningRate = Number(opt('lr', 0.5));
const l2 = Number(opt('l2', 1e-6));
const testFraction = Number(opt('test-fraction', 0.2));
// host: ホスト名全体 / registrable: 登録ドメインだけ
const scope = opt('scope', 'host') === 'registrable' ? 'registrable' : 'host';
const outPath = resolve(ROOT, opt('out', 'extension/model/url-classifier.json'));
// 正規側を補うトップサイトリスト（rank,domain 形式）。
// PhiUSIIL の正規側は無名サイト中心で、人がよく使う有名サイトが入っていない。
// 補わないと「短くて有名なドメイン＝異常」と学習してしまう。
const benignList = opt('benign-list', null);
const benignTake = Number(opt('benign-take', 150000));

// ---------------------------------------------------------------- 読み込み
function splitCsvLine(line) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

const PHISH_LABELS = new Set(['1', 'phishing', 'phish', 'true', 'yes', 'malicious', 'bad']);
const isPhishing = (raw) => {
  const value = String(raw ?? '').trim().toLowerCase();
  return phishingLabel !== null ? value === String(phishingLabel).toLowerCase() : PHISH_LABELS.has(value);
};

console.log(`読み込み: ${file}`);
const lines = readFileSync(resolve(ROOT, file), 'utf8').replace(/^﻿/, '').split(/\r?\n/).filter(Boolean);
const header = splitCsvLine(lines[0]).map((h) => h.trim());
const iUrl = header.findIndex((h) => h.toLowerCase() === urlCol.toLowerCase());
const iLabel = header.findIndex((h) => h.toLowerCase() === labelCol.toLowerCase());
if (iUrl < 0 || iLabel < 0) throw new Error(`列が見つかりません: ${header.join(',')}`);

/** 登録ドメイン単位でハッシュして分割する（同じドメインは必ず同じ側へ）。 */
function bucketOfDomain(domain) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < domain.length; i++) {
    hash ^= domain.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash / 0xffffffff;
}

const seenHost = new Set();
const train = [];
const test = [];
let skipped = 0;

for (const line of lines.slice(1)) {
  const cols = splitCsvLine(line);
  let raw = (cols[iUrl] ?? '').trim();
  if (!raw) continue;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `http://${raw}`;

  let host;
  try {
    host = new URL(raw).hostname.toLowerCase();
  } catch {
    skipped++;
    continue;
  }
  if (!host || seenHost.has(host)) continue; // ホスト重複は1件に絞る
  seenHost.add(host);

  const info = splitHost(host);
  const domain = info.registrable || host;
  const sample = {
    host,
    target: scope === 'registrable' ? (info.registrable || host) : host,
    y: isPhishing(cols[iLabel]) ? 1 : 0,
  };
  (bucketOfDomain(domain) < testFraction ? test : train).push(sample);
}

// 共有ホスティング配下のフィッシングは、登録ドメイン単位で見ると
// ホスティング事業者そのものを悪性と教えることになるので除外する。
if (scope === 'registrable') {
  const before = train.length + test.length;
  const drop = (rows) => {
    for (let i = rows.length - 1; i >= 0; i--) {
      if (rows[i].y === 1 && (FREE_HOSTING.has(rows[i].target)
        || FREE_HOSTING.has(splitHost(rows[i].host).suffix))) rows.splice(i, 1);
    }
  };
  drop(train);
  drop(test);
  console.log(`共有ホスティング配下のフィッシングを除外: ${before - train.length - test.length}件`);
}

if (benignList) {
  const phishingDomains = new Set([...train, ...test].filter((r) => r.y === 1).map((r) => r.target));
  const known = new Set([...train, ...test].map((r) => r.target));
  let added = 0;
  const listLines = readFileSync(resolve(ROOT, benignList), 'utf8').split(/\r?\n/);
  for (const line of listLines) {
    if (added >= benignTake) break;
    const domain = (line.split(',')[1] ?? line.split(',')[0] ?? '').trim().toLowerCase();
    if (!domain || !domain.includes('.')) continue;
    const registrable = splitHost(domain).registrable || domain;
    // フィッシング側に出てくるドメインは、侵害されている可能性があるので使わない
    if (phishingDomains.has(registrable) || known.has(registrable)) continue;
    known.add(registrable);
    const sample = { host: domain, target: scope === 'registrable' ? registrable : domain, y: 0 };
    (bucketOfDomain(registrable) < testFraction ? test : train).push(sample);
    added++;
  }
  console.log(`トップサイトリストから正規サンプルを追加: ${added}件 (${benignList})`);
}

const count = (rows, y) => rows.filter((r) => r.y === y).length;
console.log(`訓練 ${train.length}件 (フィッシング ${count(train, 1)}) / `
  + `検証 ${test.length}件 (フィッシング ${count(test, 1)})`
  + (skipped ? ` / 解析不能 ${skipped}件` : ''));
console.log(`分割は登録ドメイン単位。検証側のドメインは訓練に一度も出てこない。`);
console.log(`特徴量の範囲: ${scope === 'registrable' ? '登録ドメインのみ' : 'ホスト名全体'}（先頭の www. は常に除去）\n`);

// ---------------------------------------------------------------- 特徴量
function vectorize(rows) {
  return rows.map((row) => ({ x: normalizeFeatures(featurize(row.target, buckets)), y: row.y }));
}
console.log('特徴量を作成中...');
const trainX = vectorize(train);
const testX = vectorize(test);

// ---------------------------------------------------------------- 学習
const weights = new Float64Array(buckets);
let bias = 0;

// クラス不均衡の補正（少ない側の勾配を強める）
const positives = count(train, 1);
const negatives = train.length - positives;
const posWeight = negatives / Math.max(1, positives);

function shuffle(array, seed) {
  let state = seed >>> 0;
  for (let i = array.length - 1; i > 0; i--) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const j = state % (i + 1);
    [array[i], array[j]] = [array[j], array[i]];
  }
}

const order = trainX.map((_, i) => i);
for (let epoch = 0; epoch < epochs; epoch++) {
  shuffle(order, 42 + epoch);
  const lr = learningRate / (1 + epoch * 0.6);
  let loss = 0;

  for (const index of order) {
    const { x, y } = trainX[index];
    let sum = bias;
    for (const [i, v] of x) sum += weights[i] * v;
    const p = sigmoid(sum);
    const sampleWeight = y === 1 ? posWeight : 1;
    const grad = (p - y) * sampleWeight;

    loss -= sampleWeight * (y ? Math.log(p + 1e-12) : Math.log(1 - p + 1e-12));
    bias -= lr * grad;
    for (const [i, v] of x) {
      weights[i] -= lr * (grad * v + l2 * weights[i]);
    }
  }
  console.log(`epoch ${epoch + 1}/${epochs}  loss=${(loss / trainX.length).toFixed(4)}  lr=${lr.toFixed(3)}`);
}

// ---------------------------------------------------------------- 評価
function score(sample) {
  let sum = bias;
  for (const [i, v] of sample.x) sum += weights[i] * v;
  return sigmoid(sum);
}

function metricsAt(rows, threshold) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const row of rows) {
    const flagged = row.p >= threshold;
    if (row.y === 1 && flagged) tp++;
    else if (row.y === 1) fn++;
    else if (flagged) fp++;
    else tn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  return {
    threshold, tp, fp, tn, fn, precision, recall,
    f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0,
    fpr: fp + tn ? fp / (fp + tn) : 0,
  };
}

function auc(rows) {
  const sorted = [...rows].sort((a, b) => a.p - b.p);
  let rankSum = 0;
  let positives = 0;
  sorted.forEach((row, i) => {
    if (row.y === 1) { rankSum += i + 1; positives++; }
  });
  const negatives = sorted.length - positives;
  if (!positives || !negatives) return NaN;
  return (rankSum - (positives * (positives + 1)) / 2) / (positives * negatives);
}

const scoredTrain = trainX.map((s) => ({ ...s, p: score(s) }));
const scoredTest = testX.map((s) => ({ ...s, p: score(s) }));

const pct = (v) => `${(v * 100).toFixed(2)}%`;
const show = (m) => `th=${m.threshold.toFixed(2)}  precision=${pct(m.precision)}  recall=${pct(m.recall)}  `
  + `F1=${pct(m.f1)}  誤検知率=${pct(m.fpr)}  (TP=${m.tp} FP=${m.fp} FN=${m.fn} TN=${m.tn})`;

console.log(`\n=== 検証（未知ドメイン ${scoredTest.length}件） ===`);
console.log(`AUC: 訓練 ${auc(scoredTrain).toFixed(4)} / 検証 ${auc(scoredTest).toFixed(4)}`);
const table = [];
for (let t = 0.5; t <= 0.96; t += 0.05) {
  const m = metricsAt(scoredTest, t);
  table.push(m);
  console.log(show(m));
}

// ---------------------------------------------------------------- 書き出し
const { quantized, scale } = quantize(weights);
let quantErr = 0;
for (const s of scoredTest.slice(0, 2000)) {
  let sum = bias;
  for (const [i, v] of s.x) sum += quantized[i] * scale * v;
  quantErr = Math.max(quantErr, Math.abs(sigmoid(sum) - s.p));
}
console.log(`\nint8量子化による確率の最大ずれ: ${quantErr.toFixed(5)}`);

let binary = '';
for (let i = 0; i < quantized.length; i += 0x8000) {
  binary += String.fromCharCode(...new Uint8Array(quantized.buffer, i, Math.min(0x8000, quantized.length - i)));
}

const artifact = {
  version: CLASSIFIER_VERSION,
  trainedAt: new Date().toISOString(),
  buckets,
  scope,
  bias,
  scale,
  source: file.split('/').pop(),
  training: {
    train: train.length, test: test.length, epochs, learningRate, l2,
    split: 'registrable-domain', benignList: benignList ?? null, benignTake: benignList ? benignTake : 0,
  },
  metrics: {
    aucTest: auc(scoredTest),
    aucTrain: auc(scoredTrain),
    byThreshold: table.map((m) => ({
      threshold: Number(m.threshold.toFixed(2)),
      precision: m.precision, recall: m.recall, fpr: m.fpr,
    })),
  },
  weights: btoa(binary),
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(artifact));
console.log(`\n${outPath} を書き出しました (${(JSON.stringify(artifact).length / 1024).toFixed(0)} KB)`);
