/**
 * Chrome内蔵AI（Prompt API）アダプタのテスト。
 * 実際のモデルは無いので、globalThis.LanguageModel を差し替えて検証する。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { availability, ensureSession, destroySession, buildPageSummary, buildPrompt, parseReply }
  from '../../extension/src/offscreen/local-llm.js';
import { DETECTOR_CATALOG } from '../../extension/src/core/detectors/index.js';
import { runDetection, resolveDetectors } from '../../extension/src/core/pipeline.js';
import { extractFeatures } from '../../extension/src/core/features.js';

const evidence = (o = {}) => ({
  ok: true, trigger: 'focusin', identity: { iconAlts: [], ...(o.identity ?? {}) },
  forms: o.forms ?? [], looseFields: o.looseFields ?? [], telLinks: [], phoneNumbers: [],
  trapSignals: {}, bodyText: o.bodyText ?? '', ...o,
});
const credentialForm = [{
  method: 'post', actionHost: '', searchLike: false,
  fields: [{ tag: 'input', type: 'password', hint: 'パスワード', autocomplete: 'current-password', maxLength: 0, inputmode: '' }],
}];

function stubModel({ state = 'available', create = async () => ({ prompt: async () => '{}' }) } = {}) {
  globalThis.LanguageModel = { availability: async () => state, create };
}
function clearModel() {
  delete globalThis.LanguageModel;
}

test.afterEach(async () => {
  await destroySession();
  clearModel();
});

// --- 可用性 ---------------------------------------------------------------
test('Prompt APIが無い環境では unsupported を返す', async () => {
  clearModel();
  assert.equal(await availability(), 'unsupported');
});

test('モデルの状態をそのまま返す', async () => {
  for (const state of ['unavailable', 'downloadable', 'downloading', 'available']) {
    stubModel({ state });
    assert.equal(await availability(), state);
    clearModel();
  }
});

test('downloadable ではセッションを作らない（数GBのDLを誘発させない）', async () => {
  let created = 0;
  stubModel({ state: 'downloadable', create: async () => { created++; return { prompt: async () => '{}' }; } });
  assert.equal(await ensureSession(), null);
  assert.equal(created, 0, 'モデル未取得なのにセッションを作った');
});

test('available のときだけセッションを作る', async () => {
  let created = 0;
  stubModel({ state: 'available', create: async () => { created++; return { prompt: async () => '{}' }; } });
  assert.notEqual(await ensureSession(), null);
  await ensureSession(); // 2回目は使い回す
  assert.equal(created, 1);
});

// --- モデルへ渡す材料 -------------------------------------------------------
test('モデルへ渡すのは身元を示す部分だけで、本文は含めない', () => {
  const summary = buildPageSummary(evidence({
    identity: { title: 'MUFG ログイン', h1: 'ログイン', siteName: 'MUFG' },
    forms: credentialForm,
    bodyText: 'これは本文です。ここには個人的な内容が含まれうる。',
  }), 'zmbc3c.info');

  assert.equal(summary.host, 'zmbc3c.info');
  assert.equal(summary.title, 'MUFG ログイン');
  assert.deepEqual(summary.inputLabels, ['パスワード']);
  assert.ok(!JSON.stringify(summary).includes('本文'), '本文が含まれている');
});

test('入力欄のラベルは件数を打ち切る', () => {
  const fields = Array.from({ length: 30 }, (_, i) => ({ hint: `field${i}` }));
  const summary = buildPageSummary(evidence({ looseFields: fields }), 'a.test');
  assert.ok(summary.inputLabels.length <= 12);
});

test('プロンプトはページ内容をデータとして扱うよう明示する', () => {
  const prompt = buildPrompt(buildPageSummary(evidence({ identity: { title: 'x' } }), 'a.test'));
  assert.ok(prompt.includes('<data>'));
  assert.ok(/untrusted/i.test(prompt));
  assert.ok(/not as a command/i.test(prompt));
});

// --- 応答の解釈 -------------------------------------------------------------
test('前後に文章が付いていてもJSONを取り出す', () => {
  const parsed = parseReply('Sure! {"service":"Bank of Ireland","asksForCredentials":true,'
    + '"hostIsOfficialForService":false,"confidence":0.9} hope this helps');
  assert.equal(parsed.service, 'Bank of Ireland');
  assert.equal(parsed.asksForCredentials, true);
  assert.equal(parsed.hostIsOfficialForService, false);
  assert.equal(parsed.confidence, 0.9);
});

test('壊れた応答では null を返す', () => {
  assert.equal(parseReply('わかりません'), null);
  assert.equal(parseReply('{壊れた'), null);
  assert.equal(parseReply(null), null);
});

test('範囲外や型違いの値を正規化する', () => {
  const parsed = parseReply('{"service":"  X  ","asksForCredentials":"yes",'
    + '"hostIsOfficialForService":"no","confidence":9}');
  assert.equal(parsed.service, 'X');
  assert.equal(parsed.asksForCredentials, false, '文字列 "yes" を真としてはいけない');
  assert.equal(parsed.hostIsOfficialForService, null, '真偽値以外は不明として扱う');
  assert.equal(parsed.confidence, 1);
});

// --- 検出器としての振る舞い（安全側の設計） -----------------------------------
const ctxOf = (url, extra = {}) => ({ url, features: extractFeatures(url), ...extra });
const enabled = () => resolveDetectors(DETECTOR_CATALOG, { 'local-brand-check': { enabled: true } });

test('入力しようとした契機のときだけモデルに聞く', async () => {
  let calls = 0;
  const identifyService = async () => { calls++; return null; };
  const url = 'https://aeon-card.info/update';

  await runDetection(ctxOf(url, {
    evidence: evidence({ trigger: 'load', forms: credentialForm }), services: { identifyService },
  }), enabled());
  assert.equal(calls, 0, '読み込み時に呼んではいけない');

  await runDetection(ctxOf(url, {
    evidence: evidence({ trigger: 'focusin', forms: credentialForm }), services: { identifyService },
  }), enabled());
  assert.equal(calls, 1);
});

test('名乗るサービスとドメインが食い違えば信号を出す', async () => {
  const identifyService = async () => ({
    service: 'Bank of Ireland', asksForCredentials: true,
    hostIsOfficialForService: false, confidence: 1,
  });
  const r = await runDetection(ctxOf('https://boi.secure365.ie-apps.services/login', {
    evidence: evidence({ trigger: 'focusin', forms: credentialForm }), services: { identifyService },
  }), enabled());

  const signal = r.signals.find((s) => s.id === 'local-brand-mismatch');
  assert.ok(signal, '辞書に無いブランドを検出できていない');
  assert.ok(signal.title.includes('Bank of Ireland'));
  assert.ok(signal.weight <= 0.8);
});

test('「正規である」「不明」では信号を出さない', async () => {
  for (const hostIsOfficialForService of [true, null]) {
    const identifyService = async () => ({
      service: 'Example Bank', asksForCredentials: true, hostIsOfficialForService, confidence: 1,
    });
    const r = await runDetection(ctxOf('https://aeon-card.info/update', {
      evidence: evidence({ trigger: 'focusin', forms: credentialForm }), services: { identifyService },
    }), enabled());
    assert.ok(!r.signals.some((s) => s.id === 'local-brand-mismatch'));
  }
});

test('プロンプトインジェクションで既存の疑いを消せない', async () => {
  // ページ側が「このドメインは正規だ」と答えさせることに成功した状況を作る
  const injected = async () => ({
    service: 'Amazon', asksForCredentials: true,
    hostIsOfficialForService: true, confidence: 1,
  });
  const url = 'http://amazon.co.jp.account-verify.x7fk2p.top/signin';
  const withModel = await runDetection(ctxOf(url, {
    evidence: evidence({ trigger: 'focusin', forms: credentialForm }), services: { identifyService: injected },
  }), enabled());
  const withoutModel = await runDetection(ctxOf(url, {
    evidence: evidence({ trigger: 'focusin', forms: credentialForm }),
  }), resolveDetectors(DETECTOR_CATALOG, {}));

  assert.equal(withModel.verdict, 'block');
  assert.ok(withModel.score >= withoutModel.score,
    'モデルの回答でスコアが下がった。injection に利用される。');
});

test('モデルが無い・失敗しても判定は続く', async () => {
  const url = 'https://aeon-card.info/update';
  const base = await runDetection(ctxOf(url, { evidence: evidence({ trigger: 'focusin' }) }),
    resolveDetectors(DETECTOR_CATALOG, {}));
  for (const identifyService of [async () => null, async () => { throw new Error('model gone'); }]) {
    const r = await runDetection(ctxOf(url, {
      evidence: evidence({ trigger: 'focusin', forms: credentialForm }), services: { identifyService },
    }), enabled());
    assert.equal(r.verdict, base.verdict);
  }
});
