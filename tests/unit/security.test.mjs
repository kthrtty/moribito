/**
 * セキュリティ修正の回帰テスト。
 * 観点は OWASP ASVS v4.0.3 の該当章に対応させてある。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { sanitizeSettingsPatch, DEFAULT_SETTINGS } from '../../extension/src/core/settings.js';
import { assertSafeEndpoint, isSafeEndpoint, readHit, fillTemplate, queryProvider } from '../../extension/src/core/reputation.js';
import { sanitizeForDisplay, hasBidiControl } from '../../extension/src/core/unicode.js';
import { evaluatePageEvidence } from '../../extension/src/core/page-evidence.js';
import { extractFeatures } from '../../extension/src/core/features.js';

// 制御文字はエスケープではなくコードポイントから作る（ソースに直接置かない）
const RLO = String.fromCharCode(0x202e);   // 右から左へ上書き
const PDF = String.fromCharCode(0x202c);   // 方向の打ち消し
const ZWSP = String.fromCharCode(0x200b);  // ゼロ幅スペース
const BEL = String.fromCharCode(7);

// --- V5.3 出力の中立化 -----------------------------------------------------
test('V5.3: ページ由来の文字列からBiDi制御文字を除去する', () => {
  const attack = `evil${RLO}gnp.exe${PDF}.test`;
  assert.equal(hasBidiControl(attack), true);
  assert.equal(hasBidiControl(sanitizeForDisplay(attack)), false);
  assert.equal(sanitizeForDisplay(attack), 'evilgnp.exe.test');
  // ゼロ幅文字・制御文字も落ちる
  assert.equal(sanitizeForDisplay(`a${ZWSP}b${BEL}c`), 'abc');
  // 長さは必ず打ち切る
  assert.equal(sanitizeForDisplay('x'.repeat(500), 80).length, 80);
});

test('V5.3: 警告文に載せるフォーム送信先が無害化されている', () => {
  const f = extractFeatures('https://shop-example.sbs/checkout');
  const evidence = {
    ok: true, identity: { iconAlts: [] }, looseFields: [], bodyText: '',
    forms: [{
      method: 'post', searchLike: false,
      actionHost: `collector${RLO}evil${PDF}.test`,
      fields: [{ tag: 'input', type: 'password', hint: 'パスワード', autocomplete: '', inputmode: '', maxLength: 0 }],
    }],
  };
  const signal = evaluatePageEvidence(f, evidence).find((s) => s.id === 'form-cross-origin-post');
  assert.ok(signal);
  assert.equal(hasBidiControl(signal.detail), false, '警告文にBiDi制御文字が残っている');
});

// --- V5.1 入力検証 / V1.4 信頼境界 ------------------------------------------
test('V5.1: しきい値は保存前に妥当な範囲へ丸められる', () => {
  assert.equal(sanitizeSettingsPatch({ blockThreshold: 0 }).blockThreshold, 0.5);
  assert.equal(sanitizeSettingsPatch({ blockThreshold: 99 }).blockThreshold, 0.99);
  assert.equal(sanitizeSettingsPatch({ blockThreshold: 'x' }).blockThreshold, DEFAULT_SETTINGS.blockThreshold);
  // 注意しきい値がブロックしきい値を超えない
  const both = sanitizeSettingsPatch({ blockThreshold: 0.6, warnThreshold: 0.95 });
  assert.ok(both.warnThreshold < both.blockThreshold);
});

test('V5.1: 許可リストはホスト名の形だけを受け付ける', () => {
  const out = sanitizeSettingsPatch({
    allowlist: ['GOOD.example', '<script>alert(1)</script>', 'a'.repeat(300), '  ok.test  ', 'good.example'],
  });
  assert.deepEqual(out.allowlist, ['good.example', 'ok.test']);
});

test('V5.1: 未知のキーは保存しない', () => {
  const out = sanitizeSettingsPatch({ enabled: true, evilKey: 'x' });
  assert.deepEqual(Object.keys(out), ['enabled']);
});

test('V5.1: 検出器とプロバイダのIDを検証する', () => {
  const out = sanitizeSettingsPatch({
    providerConfig: {
      'domain-reputation': { enabled: true, endpoint: 'https://api.test/{domain}' },
      'unknown-id': { enabled: true },
    },
    detectorConfig: { 'url-rules': { enabled: false }, '../../evil': { enabled: true } },
  });
  assert.deepEqual(Object.keys(out.providerConfig), ['domain-reputation']);
  assert.deepEqual(Object.keys(out.detectorConfig), ['url-rules']);
});

// --- V9.1 通信の保護 / V5.5 SSRF --------------------------------------------
test('V9.1: 外部エンドポイントは https のみ受け付ける', () => {
  assert.ok(isSafeEndpoint('https://api.example.com/v1'));
  assert.throws(() => assertSafeEndpoint('http://api.example.com/v1'), /https/);
  assert.throws(() => assertSafeEndpoint('ftp://api.example.com/'), /https/);
  assert.throws(() => assertSafeEndpoint('not a url'), /URL/);
});

test('V5.5: 内部ネットワークへの問い合わせを拒否する', () => {
  for (const url of [
    'https://127.0.0.1/x', 'https://10.1.2.3/x', 'https://192.168.0.1/x',
    'https://172.16.0.1/x', 'https://172.31.255.255/x', 'https://169.254.169.254/x',
    'https://localhost/x', 'https://router.local/x', 'https://[::1]/x',
  ]) {
    assert.throws(() => assertSafeEndpoint(url), undefined, `${url} が通ってしまった`);
  }
  // 172.32 はプライベートではないので通る
  assert.ok(isSafeEndpoint('https://172.32.0.1/x'));
});

test('V9.1: URLに認証情報を埋め込ませない', () => {
  assert.throws(() => assertSafeEndpoint('https://user:secret@api.example.com/'), /認証情報/);
});

test('V5.1: 平文の取得元は設定として保存されない', () => {
  assert.equal(sanitizeSettingsPatch({ blocklistUrl: 'http://evil.test/list.json' }).blocklistUrl, '');
  assert.equal(sanitizeSettingsPatch({ blocklistUrl: 'https://ok.test/list.json' }).blocklistUrl, 'https://ok.test/list.json');
  assert.equal(sanitizeSettingsPatch({ dohEndpoint: 'https://127.0.0.1/q' }).dohEndpoint, '');
});

test('V5.5: 無効なエンドポイントでは通信自体を行わない', async () => {
  let called = 0;
  const fetchImpl = async () => { called++; return { ok: true, json: async () => ({ v: true }) }; };
  const provider = {
    id: 'x', kind: 'domain', enabled: true, endpoint: 'http://plain.test/{domain}',
    hitWhen: { path: 'v', truthy: true },
  };
  assert.equal(await queryProvider(provider, { domain: 'a.test' }, { fetchImpl }), null);
  assert.equal(called, 0, 'https以外へ通信した');
});

// --- V5.3 インジェクション ---------------------------------------------------
test('V5.3: エンドポイントに埋め込む値はURLエンコードされる', () => {
  const filled = fillTemplate('https://api.test/{domain}', { domain: '../../admin?x=1' });
  assert.ok(!filled.includes('../../'));
  assert.ok(filled.includes('%2F'));
});

test('V5.3: 応答の読み取りでプロトタイプを辿らせない', () => {
  assert.equal(readHit({}, { path: '__proto__', truthy: true }), false);
  assert.equal(readHit({}, { path: 'constructor.name', truthy: true }), false);
  assert.equal(readHit({}, { path: '__proto__.constructor', truthy: true }), false);
});
