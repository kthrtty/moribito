import test from 'node:test';
import assert from 'node:assert/strict';

import { readHit, fillTemplate, queryProvider, queryProviders, reputationSignals, resolveIps, PROVIDER_TEMPLATES } from '../../extension/src/core/reputation.js';
import { resolveProviders, DEFAULT_SETTINGS } from '../../extension/src/core/settings.js';
import { analyzeUrl, withExtraSignals } from '../../extension/src/core/analyze.js';

const ok = (body) => async () => ({ ok: true, json: async () => body });

test('外部連携は既定ですべて無効', () => {
  assert.ok(PROVIDER_TEMPLATES.length >= 3);
  assert.deepEqual(PROVIDER_TEMPLATES.filter((p) => p.enabled), []);
  assert.deepEqual(DEFAULT_SETTINGS.providerConfig, {});
  assert.deepEqual(resolveProviders(DEFAULT_SETTINGS).filter((p) => p.enabled), []);
  // 外部通信の負荷が大きいものには注記がある
  for (const p of PROVIDER_TEMPLATES) assert.ok(p.note.length > 10, `${p.id} に注記がない`);
});

test('無効・未設定のプロバイダは通信しない', async () => {
  let called = 0;
  const fetchImpl = async () => { called++; return { ok: true, json: async () => ({}) }; };
  await queryProvider({ id: 'x', enabled: false, endpoint: 'https://x/' }, { domain: 'a.test' }, { fetchImpl });
  await queryProvider({ id: 'x', enabled: true, endpoint: '' }, { domain: 'a.test' }, { fetchImpl });
  assert.equal(called, 0);
});

test('応答の読み方を設定で差し替えられる', () => {
  assert.equal(readHit({ matches: [{ threatType: 'SOCIAL_ENGINEERING' }] }, { path: 'matches', nonEmpty: true }), true);
  assert.equal(readHit({ matches: [] }, { path: 'matches', nonEmpty: true }), false);
  assert.equal(readHit({ verdict: 'PHISHING' }, { path: 'verdict', equalsAny: ['phishing'] }), true);
  assert.equal(readHit({ data: { score: 80 } }, { path: 'data.score', atLeast: 70 }), true);
  assert.equal(readHit({ data: { score: 20 } }, { path: 'data.score', atLeast: 70 }), false);
  assert.equal(readHit({ malicious: true }, { path: 'malicious', truthy: true }), true);
});

test('エンドポイントのプレースホルダを安全に展開する', () => {
  assert.equal(fillTemplate('https://api/v1?d={domain}&k={key}', { domain: 'evil.top', key: 'abc' }),
    'https://api/v1?d=evil.top&k=abc');
  // 値はURLエンコードされる
  assert.equal(fillTemplate('https://api/{domain}', { domain: 'a b/c' }), 'https://api/a%20b%2Fc');
  assert.equal(fillTemplate('https://api/{missing}', {}), 'https://api/');
});

test('ドメイン評価の一致を信号に変換する', async () => {
  const provider = {
    id: 'domain-reputation', kind: 'domain', enabled: true, weight: 0.8,
    endpoint: 'https://api/{domain}', label: 'テスト評価API',
    hitWhen: { path: 'verdict', equalsAny: ['phishing'] },
  };
  const hit = await queryProvider(provider, { domain: 'evil.top' }, { fetchImpl: ok({ verdict: 'phishing' }) });
  assert.equal(hit.weight, 0.8);
  const signals = reputationSignals([hit]);
  assert.equal(signals[0].id, 'reputation-domain-reputation');
  assert.equal(signals[0].from, 'reputation');

  const miss = await queryProvider(provider, { domain: 'good.example' }, { fetchImpl: ok({ verdict: 'clean' }) });
  assert.equal(miss, null);
});

test('IP評価は先にDoHで名前解決する', async () => {
  const requested = [];
  const fetchImpl = async (url) => {
    requested.push(url);
    if (url.includes('dns')) return { ok: true, json: async () => ({ Answer: [{ type: 1, data: '203.0.113.9' }] }) };
    return { ok: true, json: async () => ({ malicious: true }) };
  };
  const provider = {
    id: 'ip-reputation', kind: 'ip', enabled: true, weight: 0.6,
    endpoint: 'https://ipapi/{ip}', label: 'IP評価', hitWhen: { path: 'malicious', truthy: true },
  };
  const hit = await queryProvider(provider, { domain: 'evil.top' }, {
    fetchImpl, dohEndpoint: 'https://dns.test/dns-query?name={domain}&type=A',
  });
  assert.equal(hit.id, 'ip-reputation');
  assert.equal(requested.length, 2);
  assert.ok(requested[0].includes('evil.top'));
  assert.ok(requested[1].includes('203.0.113.9'));
});

test('外部が落ちていても判定を止めない', async () => {
  const boom = async () => { throw new Error('network down'); };
  const provider = { id: 'x', kind: 'domain', enabled: true, endpoint: 'https://api/{domain}', hitWhen: { path: 'v', truthy: true } };
  assert.equal(await queryProvider(provider, { domain: 'a.test' }, { fetchImpl: boom }), null);
  assert.deepEqual(await queryProviders([provider], { domain: 'a.test' }, { fetchImpl: boom }), []);
});

test('DoHの応答からAレコードだけ取り出す', async () => {
  const fetchImpl = ok({ Answer: [{ type: 5, data: 'cname.example' }, { type: 1, data: '198.51.100.7' }] });
  assert.deepEqual(await resolveIps('evil.top', 'https://dns.test/q?name={domain}', { fetchImpl }), ['198.51.100.7']);
});

test('外部信号を足すとスコアが上がる', () => {
  const base = analyzeUrl('https://paypal-secure-login.com/');
  assert.equal(base.verdict, 'warn');
  const raised = withExtraSignals(base, reputationSignals([{ id: 'x', weight: 0.9, detail: 'テスト' }]));
  assert.equal(raised.verdict, 'block');
  assert.ok(raised.source.includes('external'));
  // 信号が無ければ元のまま
  assert.equal(withExtraSignals(base, []), base);
});
