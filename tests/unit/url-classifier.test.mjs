/**
 * URL分類器の推論部分のテスト。
 * 学習済みモデルは同梱していないので、小さな重みを手で組んで検証する。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  normalizeHost, featurize, normalizeFeatures, registrableOf, sigmoid,
  predictHost, loadModel, quantize, CLASSIFIER_VERSION, DEFAULT_BUCKETS,
} from '../../extension/src/core/url-classifier.js';

test('先頭の www. は必ず落とす', () => {
  // 安全性の情報を持たないのに、学習データでは正規サイトの目印として
  // 強く相関してしまうため（これを残すと mail.google.com を危険と判定する）
  assert.equal(normalizeHost('www.google.com'), '^google.com$');
  assert.equal(normalizeHost('google.com'), '^google.com$');
  assert.equal(normalizeHost('mail.google.com'), '^mail.google.com$');
  assert.equal(normalizeHost('WWW.Example.COM.'), '^example.com$');
  assert.equal(normalizeHost(''), '');
});

test('n-gramは境界記号を含めて作る', () => {
  const counts = featurize('ab', 1 << 16);
  // '^ab$' から 2..4文字のn-gram: ^a, ab, b$, ^ab, ab$, ^ab$ の6個
  const total = [...counts.values()].reduce((a, b) => a + b, 0);
  assert.equal(total, 6);
  assert.ok(counts.size <= 6);
});

test('特徴量はL2正規化される（長さの影響を消す）', () => {
  const normalized = normalizeFeatures(featurize('example.com'));
  let norm = 0;
  for (const v of normalized.values()) norm += v * v;
  assert.ok(Math.abs(Math.sqrt(norm) - 1) < 1e-9);
});

test('登録ドメインだけを取り出せる', () => {
  assert.equal(registrableOf('mail.google.com'), 'google.com');
  assert.equal(registrableOf('a.b.example.co.jp'), 'example.co.jp');
  assert.equal(registrableOf('WWW.Example.COM'), 'example.com');
});

test('sigmoid は両端で破綻しない', () => {
  assert.ok(Math.abs(sigmoid(0) - 0.5) < 1e-12);
  assert.ok(sigmoid(1000) <= 1 && sigmoid(1000) > 0.99);
  assert.ok(sigmoid(-1000) >= 0 && sigmoid(-1000) < 0.01);
  assert.ok(Number.isFinite(sigmoid(-1e6)));
});

test('int8量子化は往復しても大きくずれない', () => {
  const weights = new Float64Array([0.5, -0.25, 1.0, -1.0, 0]);
  const { quantized, scale } = quantize(weights);
  for (let i = 0; i < weights.length; i++) {
    assert.ok(Math.abs(quantized[i] * scale - weights[i]) < 0.01);
  }
  // すべてゼロでも壊れない
  assert.equal(quantize(new Float64Array(4)).scale, 1);
});

/** 小さなモデルを手で組む（'evil' を含むと高スコアになる重み）。 */
function tinyModel(scope = 'host') {
  const buckets = 1 << 12;
  const weights = new Float64Array(buckets);
  for (const [index] of featurize('evil.test', buckets)) weights[index] = 4;
  const { quantized, scale } = quantize(weights);
  let binary = '';
  for (const byte of new Uint8Array(quantized.buffer)) binary += String.fromCharCode(byte);
  return {
    version: CLASSIFIER_VERSION, buckets, scope, bias: -1, scale,
    weights: Buffer.from(binary, 'binary').toString('base64'),
  };
}

test('配布形式を読み込んで推論できる', () => {
  const model = loadModel(tinyModel());
  assert.equal(model.buckets, 1 << 12);
  assert.equal(model.scope, 'host');

  const hit = predictHost('evil.test', model);
  const miss = predictHost('totally-different-name.example', model);
  assert.ok(hit > 0.5, `学習させたホストが低い: ${hit}`);
  assert.ok(miss < hit);
});

test('scope=registrable では登録ドメインだけを見る', () => {
  const model = loadModel(tinyModel('registrable'));
  // サブドメインが違っても同じ登録ドメインなら同じ結果になる
  assert.equal(predictHost('evil.test', model), predictHost('login.evil.test', model));
});

test('壊れた成果物は読み込まない', () => {
  assert.equal(loadModel(null), null);
  assert.equal(loadModel({ version: 999, weights: '', buckets: 4 }), null);
  // 宣言した長さと実際の重みが合わないものは弾く
  const broken = { ...tinyModel(), buckets: 99 };
  assert.equal(loadModel(broken), null);
});

test('モデルが無ければ推論しない', () => {
  assert.equal(predictHost('evil.test', null), null);
  assert.equal(predictHost('evil.test', {}), null);
});

test('既定のバケット数は配布サイズに収まる', () => {
  // int8量子化で 262,144 バイト = 256KB
  assert.equal(DEFAULT_BUCKETS, 1 << 18);
});
