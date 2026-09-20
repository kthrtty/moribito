/**
 * Jev（外部API）連携のテスト。
 * 実APIは叩かず、fetch を差し替えて検証する。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  jevStateFor, buildJevRequest, readJevAnswer, jevWeight, queryJev,
  JEV_DEFAULT_ENDPOINT, JEV_DEFAULT_MODEL, JEV_QUESTION_KEY,
} from '../../extension/src/core/jev.js';
import { DETECTOR_CATALOG } from '../../extension/src/core/detectors/index.js';
import { runDetection, resolveDetectors } from '../../extension/src/core/pipeline.js';
import { extractFeatures } from '../../extension/src/core/features.js';

const ok = (body) => async () => ({ ok: true, json: async () => body });
const ctxOf = (url, extra = {}) => ({ url, features: extractFeatures(url), ...extra });

const ANSWER = (probabilities, confidence = 0.8) => ({
  model: 'jev-latest',
  answers: {
    [JEV_QUESTION_KEY]: { type: 'choice', choice: 'phishing', probabilities, confidence },
  },
  usage: { input_tokens: 12, output_tokens: 0 },
});

// --- 送信内容 -------------------------------------------------------------
test('既定ではホスト名しか送らない', () => {
  assert.equal(jevStateFor('https://user:pw@evil.test/login?token=secret#frag'), 'evil.test');
});

test('URL全体を送る設定では、認証情報とフラグメントを落とす', () => {
  assert.equal(
    jevStateFor('https://user:pw@evil.test/login?token=abc#frag', { sendFullUrl: true }),
    'https://evil.test/login?token=abc');
});

test('http(s) 以外は送らない', () => {
  assert.equal(jevStateFor('chrome-extension://abc/page.html'), null);
  assert.equal(jevStateFor('not a url'), null);
});

// --- リクエスト組み立て ----------------------------------------------------
test('ドキュメントどおりの形でリクエストを組み立てる', () => {
  const body = buildJevRequest('evil.test');
  assert.equal(body.state, 'evil.test');
  assert.equal(body.model, JEV_DEFAULT_MODEL);
  const question = body.questions[JEV_QUESTION_KEY];
  assert.equal(question.type, 'choice');
  assert.ok(question.instructions.length > 10);
  assert.deepEqual(Object.keys(question.criteria).sort(), ['benign', 'phishing', 'suspicious']);
  // choice は criteria が必須
  for (const description of Object.values(question.criteria)) {
    assert.ok(description.length > 5);
  }
  assert.equal(buildJevRequest('x', { model: 'jev-1.13.0' }).model, 'jev-1.13.0');
});

// --- 応答の読み取り --------------------------------------------------------
test('確率と確信度を取り出す', () => {
  const answer = readJevAnswer(ANSWER({ phishing: 0.7, suspicious: 0.2, benign: 0.1 }, 0.9));
  // suspicious は半分の重みで足す: 0.7 + 0.2*0.5 = 0.8
  assert.ok(Math.abs(answer.probability - 0.8) < 1e-9);
  assert.equal(answer.confidence, 0.9);
  assert.equal(answer.choice, 'phishing');
});

test('想定外の応答では null を返す', () => {
  assert.equal(readJevAnswer(null), null);
  assert.equal(readJevAnswer({}), null);
  assert.equal(readJevAnswer({ answers: {} }), null);
  assert.equal(readJevAnswer({ answers: { [JEV_QUESTION_KEY]: {} } }), null);
});

test('範囲外の値を丸める', () => {
  const answer = readJevAnswer(ANSWER({ phishing: 5, suspicious: -1 }, 99));
  assert.equal(answer.probability, 1);
  assert.equal(answer.confidence, 1);
});

// --- 重みへの写像 ----------------------------------------------------------
test('確率0.5以下は信号にしない', () => {
  assert.equal(jevWeight({ probability: 0.5, confidence: 1 }), 0);
  assert.equal(jevWeight({ probability: 0.2, confidence: 1 }), 0);
});

test('単独ではブロックしきい値に届かない（上限0.8）', () => {
  assert.ok(jevWeight({ probability: 1, confidence: 1 }) <= 0.8);
  assert.ok(jevWeight({ probability: 1, confidence: 1 }) < 0.85);
});

test('確信度が低いと効きを弱める', () => {
  const high = jevWeight({ probability: 0.9, confidence: 1 });
  const low = jevWeight({ probability: 0.9, confidence: 0 });
  assert.ok(high > low);
});

// --- 通信 ------------------------------------------------------------------
test('POSTでBearer認証を付けて送る', async () => {
  let seen = null;
  const fetchImpl = async (url, init) => {
    seen = { url, init };
    return { ok: true, json: async () => ANSWER({ phishing: 0.9, suspicious: 0, benign: 0.1 }) };
  };
  const answer = await queryJev('https://evil.test/login', { apiKey: 'test-key' }, { fetchImpl });

  assert.equal(seen.url, JEV_DEFAULT_ENDPOINT);
  assert.equal(seen.init.method, 'POST');
  assert.equal(seen.init.headers.authorization, 'Bearer test-key');
  assert.equal(seen.init.headers['content-type'], 'application/json');
  assert.equal(JSON.parse(seen.init.body).state, 'evil.test');
  assert.ok(answer.probability > 0.5);
});

test('APIキーが無ければ通信しない', async () => {
  let called = 0;
  const fetchImpl = async () => { called++; return { ok: true, json: async () => ({}) }; };
  assert.equal(await queryJev('https://evil.test/', {}, { fetchImpl }), null);
  assert.equal(await queryJev('https://evil.test/', { apiKey: '' }, { fetchImpl }), null);
  assert.equal(called, 0);
});

test('https 以外のエンドポイントは拒否する', async () => {
  let called = 0;
  const fetchImpl = async () => { called++; return { ok: true, json: async () => ({}) }; };
  const result = await queryJev('https://evil.test/', { apiKey: 'k', endpoint: 'http://plain.test/v1' }, { fetchImpl });
  assert.ok(result.error);
  assert.equal(called, 0);
});

test('エラー応答でも例外を投げず、判定を止めない', async () => {
  for (const status of [401, 422, 429, 529]) {
    const res = await queryJev('https://evil.test/', { apiKey: 'k' }, {
      fetchImpl: async () => ({ ok: false, status, json: async () => ({}) }),
    });
    assert.equal(res.error, `HTTP ${status}`);
  }
  const boom = await queryJev('https://evil.test/', { apiKey: 'k' }, {
    fetchImpl: async () => { throw new Error('network down'); },
  });
  assert.ok(boom.error.includes('network down'));
});

// --- パイプラインへの組み込み ----------------------------------------------
test('既定では無効で、一度も通信しない', async () => {
  let called = 0;
  const fetchImpl = async () => { called++; return { ok: true, json: async () => ANSWER({ phishing: 1 }) }; };
  const url = 'https://aeon-card.info/update';
  const result = await runDetection(
    ctxOf(url, { jev: { apiKey: 'k' }, services: { fetchImpl } }),
    resolveDetectors(DETECTOR_CATALOG, {}));
  assert.equal(called, 0);
  assert.ok(!result.signals.some((s) => s.id === 'jev-phishing'));
});

test('有効化するとグレーのURLだけ問い合わせる', async () => {
  const asked = [];
  const fetchImpl = async (_url, init) => {
    asked.push(JSON.parse(init.body).state);
    return { ok: true, json: async () => ANSWER({ phishing: 0.95, suspicious: 0.05, benign: 0 }, 0.9) };
  };
  const detectors = resolveDetectors(DETECTOR_CATALOG, { 'jev-remote': { enabled: true } });
  const services = { fetchImpl };

  // グレー → 問い合わせる
  const grey = await runDetection(
    ctxOf('https://aeon-card.info/update', { jev: { apiKey: 'k' }, services }), detectors);
  assert.deepEqual(asked, ['aeon-card.info']);
  assert.ok(grey.signals.some((s) => s.id === 'jev-phishing'));
  assert.equal(grey.verdict, 'block', 'グレー + Jev でブロックに到達する');

  // 公式ドメイン → 打ち切られるので問い合わせない
  await runDetection(ctxOf('https://www.google.com/', { jev: { apiKey: 'k' }, services }), detectors);
  assert.deepEqual(asked, ['aeon-card.info']);

  // 明らかに危険なURLは既に確定しているので問い合わせない
  await runDetection(
    ctxOf('http://amazon.co.jp.verify.x7fk2p.top/signin', { jev: { apiKey: 'k' }, services }), detectors);
  assert.deepEqual(asked, ['aeon-card.info']);
});

test('結果はキャッシュして問い合わせ回数を抑える', async () => {
  let called = 0;
  const fetchImpl = async () => {
    called++;
    return { ok: true, json: async () => ANSWER({ phishing: 0.9, suspicious: 0, benign: 0.1 }) };
  };
  const store = new Map();
  const services = { fetchImpl, cache: { get: (k) => store.get(k) ?? null, set: (k, v) => store.set(k, v) } };
  const detectors = resolveDetectors(DETECTOR_CATALOG, { 'jev-remote': { enabled: true } });

  for (let i = 0; i < 3; i++) {
    await runDetection(ctxOf('https://aeon-card.info/update', { jev: { apiKey: 'k' }, services }), detectors);
  }
  assert.equal(called, 1);
});

test('外部が落ちていてもルールの判定はそのまま返る', async () => {
  const fetchImpl = async () => { throw new Error('down'); };
  const detectors = resolveDetectors(DETECTOR_CATALOG, { 'jev-remote': { enabled: true } });
  const url = 'https://aeon-card.info/update';
  const withJev = await runDetection(ctxOf(url, { jev: { apiKey: 'k' }, services: { fetchImpl } }), detectors);
  const without = await runDetection(ctxOf(url), resolveDetectors(DETECTOR_CATALOG, {}));
  assert.equal(withJev.verdict, without.verdict);
  assert.ok(Math.abs(withJev.score - without.score) < 1e-9);
});
