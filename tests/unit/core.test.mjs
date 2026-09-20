import test from 'node:test';
import assert from 'node:assert/strict';

import { toUnicode, decodeLabel } from '../../extension/src/core/punycode.js';
import { skeleton, collapse, hasConfusable } from '../../extension/src/core/confusables.js';
import { splitHost, publicSuffixOf, isIpHost, isPrivateHost } from '../../extension/src/core/psl.js';
import { scriptProfile, mixedScriptLabels, hasInvisible, hasBidiControl } from '../../extension/src/core/unicode.js';
import { levenshtein, shannonEntropy, tokenize } from '../../extension/src/core/text.js';
import { extractFeatures } from '../../extension/src/core/features.js';
import { combine, verdictOf, blendWithModel } from '../../extension/src/core/score.js';
import { analyzeUrl, withModel } from '../../extension/src/core/analyze.js';
import { BENIGN, PHISHING, SUSPICIOUS } from '../fixtures/urls.mjs';

test('punycode: xn-- ラベルをUnicodeへ戻す', () => {
  assert.equal(toUnicode('xn--pypal-4ve.com'), 'pаypal.com');
  assert.equal(toUnicode('xn--80ak6aa92e.com'), 'аррӏе.com');
  assert.equal(toUnicode('example.com'), 'example.com');
  assert.equal(toUnicode('www.xn--eckwd4c7c.jp').startsWith('www.'), true);
  // 壊れたラベルは落とさずそのまま返す
  assert.equal(toUnicode('xn--!!!.com'), 'xn--!!!.com');
  assert.throws(() => decodeLabel('é'), RangeError);
});

test('confusables: 見た目の骨格をASCIIへ畳み込む', () => {
  assert.equal(skeleton('pаypal.com'), 'paypal.com');       // キリル文字а
  assert.equal(skeleton('аррӏе.com'), 'apple.com');
  assert.equal(skeleton('ＧＯＯＧＬＥ.com'), 'google.com'); // 全角
  assert.equal(skeleton('gοogle'), 'google');                // ギリシャ文字ο
  assert.equal(collapse('rnicrosoft-login'), 'microsoftlogin');   // rn -> m
  assert.equal(collapse('g00gle'), 'google');                     // 0 -> o
  assert.equal(collapse('pay-pal'), 'paypal');
  assert.equal(hasConfusable('pаypal'), true);
  assert.equal(hasConfusable('paypal'), false);
});

test('psl: 登録ドメインを正しく切り出す', () => {
  assert.equal(publicSuffixOf('www.example.co.jp'), 'co.jp');
  assert.equal(publicSuffixOf('example.unknown-tld'), 'unknown-tld'); // 既定ルール
  assert.equal(splitHost('a.b.example.co.jp').registrable, 'example.co.jp');
  assert.equal(splitHost('a.b.example.co.jp').sub, 'a.b');
  assert.equal(splitHost('shop.pages.dev').registrable, 'shop.pages.dev');
  assert.equal(splitHost('login.amazon.co.jp.verify.top').registrable, 'verify.top');
  assert.equal(splitHost('login.amazon.co.jp.verify.top').sub, 'login.amazon.co.jp');
  assert.equal(splitHost('foo.city.kawasaki.jp').registrable, 'city.kawasaki.jp'); // 例外ルール
  assert.equal(isIpHost('192.0.2.1'), true);
  assert.equal(isIpHost('999.0.0.1'), false);
  assert.equal(isPrivateHost('192.168.0.1'), true);
  assert.equal(isPrivateHost('203.0.113.1'), false);
  assert.equal(isPrivateHost('nas.local'), true);
});

test('unicode: 混在スクリプトと不可視文字', () => {
  assert.equal(scriptProfile('pаypal').kind, 'mixed');
  assert.equal(scriptProfile('paypal').kind, 'ascii');
  assert.equal(scriptProfile('日本語テストabc').kind, 'allowed-cjk');
  assert.deepEqual(mixedScriptLabels('pаypal.com'), ['pаypal']);
  assert.deepEqual(mixedScriptLabels('example.co.jp'), []);
  assert.equal(hasInvisible('goo​gle.com'), true);
  assert.equal(hasBidiControl('example‮moc.evil'), true);
});

test('text: 距離とエントロピー', () => {
  assert.equal(levenshtein('amazon', 'arnazon'), 2);
  assert.equal(levenshtein('mercari', 'mercarl'), 1);
  assert.equal(levenshtein('abc', 'xyz', 1), 2); // 打ち切り
  assert.ok(shannonEntropy('a8f3k29dj4mfs0x9alqp2mdk') > 3.5);
  assert.ok(shannonEntropy('wwwwwwwwww') < 0.1);
  assert.deepEqual(tokenize('amazon-co-jp.login'), ['amazon', 'co', 'jp', 'login']);
});

test('features: URLを構造化できる', () => {
  const f = extractFeatures('http://user@amazon.co.jp.verify.x7fk2p.top:8080/signin?cmd=update');
  assert.equal(f.ok, true);
  assert.equal(f.registrable, 'x7fk2p.top');
  assert.equal(f.sub, 'amazon.co.jp.verify');
  assert.equal(f.tld, 'top');
  assert.equal(f.userinfo, true);
  assert.equal(f.hasNonStandardPort, true);
  assert.equal(f.isHttps, false);
  assert.ok(f.subTokens.includes('amazon'));
  assert.ok(f.pathTokens.includes('signin'));

  assert.equal(extractFeatures('not a url').ok, false);
});

test('score: noisy-OR は単調で1を超えない', () => {
  assert.equal(combine([]), 0);
  assert.equal(combine([{ weight: 0.5 }]), 0.5);
  assert.equal(combine([{ weight: 0.5 }, { weight: 0.5 }]), 0.75);
  assert.ok(combine(Array(20).fill({ weight: 0.9 })) <= 1);
  assert.equal(verdictOf(0.9), 'block');
  assert.equal(verdictOf(0.6), 'warn');
  assert.equal(verdictOf(0.1), 'allow');
  // ルールが強いときはモデルで引き下げない
  assert.ok(blendWithModel(0.9, 0.0) >= 0.9);
  assert.ok(blendWithModel(0.5, 1.0) > 0.5);
  assert.equal(blendWithModel(0.5, null), 0.5);
});

test('analyze: 正規サイトを誤検知しない', () => {
  const failures = [];
  for (const url of BENIGN) {
    const r = analyzeUrl(url);
    if (r.verdict !== 'allow') failures.push(`${r.verdict} ${r.score.toFixed(2)} ${url}`);
  }
  assert.deepEqual(failures, [], `誤検知:\n${failures.join('\n')}`);
});

test('analyze: フィッシングURLをブロックする', () => {
  const failures = [];
  for (const url of PHISHING) {
    const r = analyzeUrl(url);
    if (r.verdict !== 'block') failures.push(`${r.verdict} ${r.score.toFixed(2)} ${url}`);
  }
  assert.deepEqual(failures, [], `見逃し:\n${failures.join('\n')}`);
});

test('analyze: 灰色URLは少なくとも警告になる', () => {
  for (const url of SUSPICIOUS) {
    const r = analyzeUrl(url);
    assert.notEqual(r.verdict, 'allow', `${url} が allow になっています`);
  }
});

test('analyze: 検出理由が人間に読める形で返る', () => {
  const r = analyzeUrl('http://amazon.co.jp.account-verify.x7fk2p.top/signin');
  assert.ok(r.signals.length >= 3);
  assert.ok(r.signals.every((s) => typeof s.title === 'string' && s.title.length > 0));
  assert.ok(r.signals.every((s) => typeof s.detail === 'string' && s.detail.length > 0));
  assert.ok(r.signals[0].weight >= r.signals[r.signals.length - 1].weight); // 強い順
  assert.ok(r.signals.some((s) => s.id === 'brand-in-subdomain'));
});

test('analyze: 許可リストとプライベートネットワークは判定を打ち切る', () => {
  const url = 'http://amazon.co.jp.account-verify.x7fk2p.top/signin';
  assert.equal(analyzeUrl(url).verdict, 'block');
  assert.equal(analyzeUrl(url, { allowlist: ['x7fk2p.top'] }).verdict, 'allow');
  assert.equal(analyzeUrl('http://10.0.0.1/login').reason, 'private-network');
});

test('analyze: しきい値を変えると判定が変わる', () => {
  const url = 'https://paypal-secure-login.com/';
  assert.equal(analyzeUrl(url).verdict, 'warn');
  assert.equal(analyzeUrl(url, { thresholds: { blockThreshold: 0.7 } }).verdict, 'block');
});

test('withModel: グレーゾーンでモデル確率を統合する', () => {
  const base = analyzeUrl('https://aeon-card.info/update');
  assert.equal(base.grey, true);
  const high = withModel(base, 0.98);
  assert.ok(high.score > base.score);
  assert.equal(high.source, 'rules+model');
  assert.equal(withModel(base, null).score, base.score);
});

test('analyze: 不可視文字・BiDiを見逃さない', () => {
  const zeroWidth = analyzeUrl('https://goo​gle-support.com/login');
  assert.ok(zeroWidth.signals.some((s) => s.id === 'invisible-char'));
  const bidi = analyzeUrl('https://example.com/‮gnp.exe');
  assert.ok(bidi.signals.some((s) => s.id === 'bidi-control'));
});
