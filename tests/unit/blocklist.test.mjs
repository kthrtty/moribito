import test from 'node:test';
import assert from 'node:assert/strict';

import { urlKeys, hashKey, encodeTable, decodeTable, bytesToBase64, base64ToBytes, createBlocklist, isStale } from '../../extension/src/core/blocklist.js';
import { splitHost } from '../../extension/src/core/psl.js';
import { analyzeUrl } from '../../extension/src/core/analyze.js';

const info = (url) => splitHost(new URL(url).hostname);

async function buildList(urlEntries = [], hostEntries = [], domainEntries = []) {
  const table = async (keys) => bytesToBase64(encodeTable(await Promise.all(keys.map(hashKey))));
  return createBlocklist({
    version: 1,
    algo: 'sha256-64',
    generatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    tables: { url: await table(urlEntries), host: await table(hostEntries), domain: await table(domainEntries) },
  });
}

test('照合キーは広い順から狭い順に並ぶ', () => {
  const url = 'https://www.evil.top/a/b/c?x=1';
  const keys = urlKeys(url, info(url)).map((k) => `${k.kind}:${k.key}`);
  assert.deepEqual(keys, [
    'url:evil.top/a/b/c?x=1',
    'url:evil.top/a/b/c',
    'url:evil.top/a/b',
    'url:evil.top/a',
    'host:evil.top',
    'domain:evil.top',
  ]);
  assert.deepEqual(urlKeys('ftp://example.com/x', null), []);
  assert.deepEqual(urlKeys('壊れたURL', null), []);
});

test('エンコード/デコードで往復できる', async () => {
  const entries = await Promise.all(['a', 'b', 'c'].map(hashKey));
  const decoded = decodeTable(base64ToBytes(bytesToBase64(encodeTable(entries))));
  assert.equal(decoded.count, 3);
  // 昇順に並んでいる（二分探索の前提）
  for (let i = 1; i < decoded.count; i++) {
    const asc = decoded.hi[i - 1] < decoded.hi[i]
      || (decoded.hi[i - 1] === decoded.hi[i] && decoded.lo[i - 1] <= decoded.lo[i]);
    assert.ok(asc);
  }
});

test('URL単位の一致だけでは同じホストの別ページに波及しない', async () => {
  const list = await buildList(['shop.example.com/wp/login.php']);
  assert.equal((await list.lookup('https://shop.example.com/wp/login.php', info('https://shop.example.com/x')))?.kind, 'url');
  assert.equal(await list.lookup('https://shop.example.com/', info('https://shop.example.com/')), null);
});

test('ホスト単位・ドメイン単位の一致も引ける', async () => {
  const list = await buildList([], ['evil.top'], ['bad-domain.xyz']);
  assert.equal((await list.lookup('https://evil.top/anything', info('https://evil.top/')))?.kind, 'host');
  assert.equal((await list.lookup('https://a.b.bad-domain.xyz/x', info('https://a.b.bad-domain.xyz/')))?.kind, 'domain');
  assert.equal(await list.lookup('https://good.example/', info('https://good.example/')), null);
});

test('www の有無とクエリ違いを吸収する', async () => {
  const list = await buildList(['evil.top/verify']);
  assert.ok(await list.lookup('https://www.evil.top/verify', info('https://www.evil.top/')));
  assert.ok(await list.lookup('https://evil.top/verify?id=123', info('https://evil.top/')));
  assert.ok(await list.lookup('https://evil.top/verify/', info('https://evil.top/')));
});

test('期限切れを判定できる', () => {
  assert.equal(isStale({ expiresAt: new Date(Date.now() - 1000).toISOString() }), true);
  assert.equal(isStale({ expiresAt: new Date(Date.now() + 1000).toISOString() }), false);
  assert.equal(isStale({}), false);
});

test('リスト一致はブロック、URL/ホスト一致は著名ドメインの打ち切りより優先する', () => {
  const opt = (kind) => ({ blocklistHit: { kind } });
  assert.equal(analyzeUrl('https://plain-example.com/x', opt('url')).verdict, 'block');
  // 乗っ取られた正規サイトを想定
  const hijacked = analyzeUrl('https://www.google.com/evil', opt('url'));
  assert.equal(hijacked.verdict, 'block');
  assert.ok(hijacked.signals.some((s) => s.id === 'known-phishing'));
  // ドメイン単位の一致は巻き添えが大きいので打ち切りを優先する
  assert.equal(analyzeUrl('https://www.google.com/evil', opt('domain')).verdict, 'allow');
  // 一致がなければ従来どおり
  assert.equal(analyzeUrl('https://plain-example.com/x').verdict, 'allow');
});

test('許可リストはリスト一致より優先する（利用者の明示的な判断）', () => {
  const r = analyzeUrl('https://plain-example.com/x', {
    blocklistHit: { kind: 'url' }, allowlist: ['plain-example.com'],
  });
  assert.equal(r.verdict, 'allow');
});
