import test from 'node:test';
import assert from 'node:assert/strict';

import { runDetection, orderDetectors, resolveDetectors, describeDetectors, STAGES } from '../../extension/src/core/pipeline.js';
import { DETECTOR_CATALOG } from '../../extension/src/core/detectors/index.js';
import { extractFeatures } from '../../extension/src/core/features.js';
import { analyzeUrl } from '../../extension/src/core/analyze.js';
import { hashKey, encodeTable, bytesToBase64, createBlocklist } from '../../extension/src/core/blocklist.js';

const ctxOf = (url, extra = {}) => ({ url, features: extractFeatures(url), ...extra });
const enabled = (config = {}) => resolveDetectors(DETECTOR_CATALOG, config);
const signal = (id, weight) => ({ id, weight, title: id, detail: id });

test('検出器は段階順に並ぶ', () => {
  const ordered = orderDetectors([
    { id: 'm', stage: 'model', run() {} },
    { id: 'u', stage: 'url', run() {} },
    { id: 'a', stage: 'allow', run() {} },
  ]);
  assert.deepEqual(ordered.map((d) => d.id), ['a', 'u', 'm']);
  assert.deepEqual(STAGES[0], 'allow');
});

test('decision を返した検出器でパイプラインが止まる', async () => {
  const ran = [];
  const detectors = [
    { id: 'first', stage: 'allow', run: () => { ran.push('first'); return { decision: { verdict: 'allow', reason: 'stop' } }; } },
    { id: 'second', stage: 'url', run: () => { ran.push('second'); return { signals: [signal('x', 0.9)] }; } },
  ];
  const r = await runDetection(ctxOf('https://a.test/'), detectors);
  assert.equal(r.reason, 'stop');
  assert.equal(r.verdict, 'allow');
  assert.deepEqual(ran, ['first']);
});

test('runWhen で実行条件を宣言できる', async () => {
  const detectors = [
    { id: 'base', stage: 'url', run: () => ({ signals: [signal('a', 0.5)] }) },
    { id: 'only-grey', stage: 'model', runWhen: (st) => st.grey, run: () => ({ signals: [signal('b', 0.5)] }) },
    { id: 'never', stage: 'model', runWhen: () => false, run: () => ({ signals: [signal('c', 0.9)] }) },
  ];
  const r = await runDetection(ctxOf('https://a.test/'), detectors);
  assert.deepEqual(r.ran, ['base', 'only-grey']);
  assert.ok(r.signals.some((s) => s.id === 'b'));
  assert.ok(!r.signals.some((s) => s.id === 'c'));
});

test('1つの検出器が落ちても判定は続く', async () => {
  const errors = [];
  const detectors = [
    { id: 'broken', stage: 'url', run: () => { throw new Error('boom'); } },
    { id: 'fine', stage: 'url', run: () => ({ signals: [signal('ok', 0.9)] }) },
  ];
  const r = await runDetection(ctxOf('https://a.test/'), detectors, { onError: (d, e) => errors.push([d.id, e.message]) });
  assert.equal(r.verdict, 'block');
  assert.deepEqual(errors, [['broken', 'boom']]);
  assert.deepEqual(r.ran, ['fine']);
});

test('信号にはどの検出器が出したかが残る', async () => {
  const detectors = [{ id: 'tagger', stage: 'url', run: () => ({ signals: [signal('x', 0.6)] }) }];
  const r = await runDetection(ctxOf('https://a.test/'), detectors);
  assert.equal(r.signals[0].by, 'tagger');
  assert.equal(r.source, 'tagger');
});

test('既定カタログは同期版 analyzeUrl と同じ判定を出す', async () => {
  const urls = [
    'https://www.google.com/',
    'http://amazon.co.jp.account-verify.x7fk2p.top/signin',
    'https://xn--80ak6aa92e.com/',
    'https://paypal-secure-login.com/',
    'http://192.168.1.1/login',
    'https://en.wikipedia.org/wiki/Phishing',
  ];
  for (const url of urls) {
    const viaPipeline = await runDetection(ctxOf(url), enabled());
    const viaAnalyze = analyzeUrl(url);
    assert.equal(viaPipeline.verdict, viaAnalyze.verdict, url);
    assert.ok(Math.abs(viaPipeline.score - viaAnalyze.score) < 1e-9, url);
    assert.equal(viaPipeline.reason ?? null, viaAnalyze.reason ?? null, url);
  }
});

test('外部照会とモデルは既定で無効', () => {
  const ids = enabled().map((d) => d.id);
  assert.ok(!ids.includes('reputation'));
  assert.ok(!ids.includes('local-model'));
  assert.ok(!ids.includes('local-text-model'));
  assert.ok(ids.includes('url-rules'));
  // 設定で個別に有効化できる
  assert.ok(enabled({ reputation: { enabled: true } }).map((d) => d.id).includes('reputation'));
  // 中核の検出器も無効化できる
  assert.ok(!enabled({ 'url-rules': { enabled: false } }).map((d) => d.id).includes('url-rules'));
});

test('設定画面向けの一覧に通信コストが載る', () => {
  const described = describeDetectors(DETECTOR_CATALOG, {});
  const reputation = described.find((d) => d.id === 'reputation');
  assert.equal(reputation.enabled, false);
  assert.equal(reputation.cost.network, 'domain');
  assert.equal(reputation.cost.latency, 'high');
  const rules = described.find((d) => d.id === 'url-rules');
  assert.equal(rules.cost.network, 'none');
  for (const d of described) assert.ok(d.label && d.description, `${d.id} に説明がない`);
});

test('既知リスト検出器は services 経由で差し替えられる', async () => {
  const table = bytesToBase64(encodeTable([await hashKey('evil.test/login')]));
  const blocklist = createBlocklist({ version: 1, algo: 'sha256-64', tables: { url: table } });

  const hit = await runDetection(
    ctxOf('https://evil.test/login', { services: { blocklist } }), enabled());
  assert.equal(hit.verdict, 'block');
  assert.ok(hit.signals.some((s) => s.id === 'known-phishing'));

  // 差し込まなければ何も起きない
  const miss = await runDetection(ctxOf('https://evil.test/login'), enabled());
  assert.ok(!miss.signals.some((s) => s.id === 'known-phishing'));
});

test('URL単位でリスト一致した著名ドメインは打ち切らない', async () => {
  const table = bytesToBase64(encodeTable([await hashKey('google.com/evil')]));
  const blocklist = createBlocklist({ version: 1, algo: 'sha256-64', tables: { url: table } });
  const r = await runDetection(ctxOf('https://www.google.com/evil', { services: { blocklist } }), enabled());
  assert.equal(r.verdict, 'block');
  assert.ok(!r.ran.includes('known-good') || r.reason === undefined);
});

test('ローカル分類器は services.classifyUrl を差し替えて試せる', async () => {
  const url = 'https://aeon-card.info/update';
  const base = await runDetection(ctxOf(url), enabled());
  assert.equal(base.grey, true);

  const withModel = await runDetection(
    ctxOf(url, { services: { classifyUrl: async () => 0.95 } }),
    enabled({ 'local-model': { enabled: true } }));
  assert.ok(withModel.score > base.score);
  assert.ok(withModel.signals.some((s) => s.id === 'local-model'));

  // モデルが確信を持てないときは何も足さない
  const unsure = await runDetection(
    ctxOf(url, { services: { classifyUrl: async () => 0.4 } }),
    enabled({ 'local-model': { enabled: true } }));
  assert.equal(unsure.score, base.score);
});

test('ローカルLLM（文面判定）も差し替え口として動く', async () => {
  const url = 'https://mail-check-center.cyou/';
  const evidence = { ok: true, identity: { iconAlts: [] }, forms: [], looseFields: [],
    bodyText: 'このままではアカウントが削除されます。すぐに手続きしてください。' };

  const detectors = enabled({ 'local-text-model': { enabled: true } });
  const r = await runDetection(
    ctxOf(url, { evidence, services: { classifyText: async () => ({ probability: 0.95, label: '不安を煽る' }) } }),
    detectors);
  assert.ok(r.signals.some((s) => s.id === 'manipulative-copy'));

  // 未注入（モデル未配置）なら何も起きない
  const none = await runDetection(ctxOf(url, { evidence }), detectors);
  assert.ok(!none.signals.some((s) => s.id === 'manipulative-copy'));
});

test('外部照会はプロバイダを注入したときだけ通信する', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return { ok: true, json: async () => ({ verdict: 'phishing' }) }; };
  const url = 'https://aeon-card.info/update';
  const providers = [{
    id: 'domain-reputation', kind: 'domain', enabled: true, weight: 0.8,
    endpoint: 'https://api.test/{domain}', label: 'テスト', hitWhen: { path: 'verdict', equalsAny: ['phishing'] },
  }];

  const off = await runDetection(ctxOf(url, { services: { fetchImpl } }), enabled());
  assert.equal(calls, 0, '無効なのに通信した');
  assert.ok(!off.signals.some((s) => s.id.startsWith('reputation-')));

  const on = await runDetection(
    ctxOf(url, { providers, services: { fetchImpl } }),
    enabled({ reputation: { enabled: true } }));
  assert.equal(calls, 1);
  assert.ok(on.signals.some((s) => s.id === 'reputation-domain-reputation'));
});
