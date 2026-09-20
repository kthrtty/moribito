import test from 'node:test';
import assert from 'node:assert/strict';

import { extractFeatures } from '../../extension/src/core/features.js';
import { credentialDemand, brandClaim, evaluatePageEvidence } from '../../extension/src/core/page-evidence.js';
import { analyzeWithPage, analyzeUrl } from '../../extension/src/core/analyze.js';

const field = (over = {}) => ({ tag: 'input', type: 'text', autocomplete: '', inputmode: '', maxLength: 0, hint: '', ...over });
const evidence = (over = {}) => ({ ok: true, trigger: 'load', identity: { iconAlts: [] }, forms: [], looseFields: [], bodyText: '', ...over });

test('検索ボックスだけのページは「要求」とみなさない', () => {
  const ev = evidence({
    forms: [{ method: 'get', actionHost: '', searchLike: true, fields: [field({ type: 'search', hint: 'サイト内検索' })] }],
  });
  const demand = credentialDemand(ev);
  assert.equal(demand.value, 0);
  assert.deepEqual(evaluatePageEvidence(extractFeatures('https://example-blog.click/'), ev), []);
});

test('password欄がなくてもカード情報の要求を拾う', () => {
  const ev = evidence({
    forms: [{ method: 'post', actionHost: '', searchLike: false, fields: [
      field({ type: 'tel', hint: 'カード番号' }),
      field({ type: 'text', autocomplete: 'cc-csc', hint: 'セキュリティコード' }),
    ] }],
  });
  const demand = credentialDemand(ev);
  assert.equal(demand.level, 'high');
  assert.ok(demand.kinds.includes('card'));
});

test('autocomplete属性だけでも認証情報だと分かる', () => {
  const ev = evidence({
    forms: [{ method: 'post', actionHost: '', searchLike: false, fields: [
      field({ type: 'text', autocomplete: 'current-password', hint: 'aaa' }),
    ] }],
  });
  assert.equal(credentialDemand(ev).level, 'high');
});

test('1桁入力欄が並ぶOTPの形を拾う', () => {
  const fields = Array.from({ length: 6 }, () => field({ inputmode: 'numeric', maxLength: 1, hint: '' }));
  const ev = evidence({ forms: [{ method: 'post', actionHost: '', searchLike: false, fields }] });
  const demand = credentialDemand(ev);
  assert.equal(demand.otpGroup, true);
  assert.equal(demand.level, 'medium');
});

test('form外の入力欄（JS送信）も見る', () => {
  const ev = evidence({ looseFields: [field({ type: 'password', hint: 'パスワード' })] });
  assert.equal(credentialDemand(ev).level, 'high');
});

test('ページが名乗るブランドを身元の面からだけ拾う', () => {
  assert.equal(brandClaim({ title: 'MUFG Bank | ログイン' }).brand.id, 'mufg');
  assert.equal(brandClaim({ title: 'ゆうちょダイレクト' }).brand.id, 'japanpost');
  assert.equal(brandClaim({ siteName: 'Apple' }).brand.id, 'apple');
  assert.equal(brandClaim({ title: '今日の献立' }), null);
  // 'line' が 'online' に当たらないこと
  assert.equal(brandClaim({ title: 'Online Shop' }), null);
});

test('文面だけでは判定しない（文字列一致で自然言語は判定できないため）', () => {
  const f = extractFeatures('https://notice-example.sbs/info');
  const ev = evidence({
    identity: { title: 'お知らせ', iconAlts: [] },
    bodyText: 'アカウントが一時停止されました。24時間以内にご確認ください。',
  });
  assert.deepEqual(evaluatePageEvidence(f, ev), [],
    '煽り文面だけで信号を出してはいけない（正規サイトの注意喚起と区別できない）');
});

test('サポート詐欺は文面ではなく構造で判定する', () => {
  const f = extractFeatures('http://win-alert-scan.top/');
  const structural = evidence({
    identity: { title: 'セキュリティ警告 - Microsoft', iconAlts: [] },
    telLinks: ['tel:0120000000'],
    trapSignals: { beforeUnload: true, autoplayAudio: true, modalOverlayCount: 1 },
  });
  const ids = evaluatePageEvidence(f, structural).map((s) => s.id);
  assert.ok(ids.includes('support-scam-structure'));

  // 電話への誘導も離脱妨害も無ければ、同じ文面でも信号は出ない
  const copyOnly = evidence({
    identity: { title: 'セキュリティ警告 - Microsoft', iconAlts: [] },
    bodyText: 'ウイルスに感染しています。今すぐお電話ください。',
  });
  const copyIds = evaluatePageEvidence(f, copyOnly).map((s) => s.id);
  assert.ok(!copyIds.includes('support-scam-structure'));
  assert.ok(!copyIds.includes('exit-trap'));
});

test('ブランド詐称＋認証情報要求で強い信号になる', () => {
  const f = extractFeatures('http://mufg-bk-support.cyou/login');
  const ev = evidence({
    identity: { title: 'MUFG Bank｜ログイン', iconAlts: [] },
    forms: [{ method: 'post', actionHost: '', searchLike: false, fields: [
      field({ type: 'password', autocomplete: 'current-password', hint: 'パスワード' }),
    ] }],
    bodyText: '第三者による不正なアクセスを検知しました。',
  });
  const ids = evaluatePageEvidence(f, ev).map((s) => s.id);
  assert.ok(ids.includes('page-brand-mismatch'));
  assert.ok(ids.includes('credential-form-insecure'));
});

test('入力内容が別ドメインへ送られるフォームを検出する', () => {
  const f = extractFeatures('https://shop-example.sbs/checkout');
  const ev = evidence({
    forms: [{ method: 'post', actionHost: 'collector.evil-host.top', searchLike: false, fields: [
      field({ type: 'password', hint: 'パスワード' }),
    ] }],
  });
  assert.ok(evaluatePageEvidence(f, ev).some((s) => s.id === 'form-cross-origin-post'));
});

test('復元フレーズの要求は単独で強い', () => {
  const f = extractFeatures('https://wallet-restore.xyz/');
  const ev = evidence({
    looseFields: [field({ tag: 'textarea', type: 'textarea', hint: 'リカバリーフレーズを入力' })],
  });
  assert.ok(evaluatePageEvidence(f, ev).some((s) => s.id === 'seed-phrase-form'));
});

test('公式ドメインでは表示内容を見ても信号を出さない', () => {
  const f = extractFeatures('https://www.amazon.co.jp/ap/signin');
  const ev = evidence({
    identity: { title: 'Amazon サインイン', iconAlts: [] },
    forms: [{ method: 'post', actionHost: '', searchLike: false, fields: [field({ type: 'password', hint: 'パスワード' })] }],
  });
  assert.deepEqual(evaluatePageEvidence(f, ev), []);
});

test('analyzeWithPage: グレーなURLがページ証拠でブロックに上がる', () => {
  const url = 'http://mufg-bk-support.cyou/login';
  assert.notEqual(analyzeUrl(url).verdict, 'block');

  const ev = evidence({
    identity: { title: 'MUFG Bank｜ログイン', iconAlts: [] },
    forms: [{ method: 'post', actionHost: '', searchLike: false, fields: [
      field({ type: 'password', autocomplete: 'current-password', hint: 'パスワード' }),
    ] }],
  });
  const combined = analyzeWithPage(url, ev);
  assert.equal(combined.verdict, 'block');
  assert.equal(combined.source, 'rules+page');
  assert.ok(combined.pageSignals.length >= 1);
});

test('analyzeWithPage: 打ち切られたURLは内容を見ても変えない', () => {
  const ev = evidence({
    identity: { title: 'Apple ID' },
    forms: [{ method: 'post', actionHost: '', searchLike: false, fields: [field({ type: 'password', hint: 'パスワード' })] }],
  });
  const r = analyzeWithPage('https://www.google.com/', ev);
  assert.equal(r.verdict, 'allow');
  assert.equal(r.reason, 'official:google');
});

test('正規サイトらしいページは内容を見ても上がらない', () => {
  const f = extractFeatures('https://shop.example-store.com/login');
  const ev = evidence({
    identity: { title: 'Example Store — ログイン', iconAlts: ['Example Store'] },
    forms: [{ method: 'post', actionHost: '', searchLike: false, fields: [
      field({ type: 'email', autocomplete: 'username', hint: 'メールアドレス' }),
      field({ type: 'password', autocomplete: 'current-password', hint: 'パスワード' }),
    ] }],
  });
  const ids = evaluatePageEvidence(f, ev).map((s) => s.id);
  assert.deepEqual(ids.filter((id) => id !== 'credential-form'), []);
});
