/** 実際のChromeに拡張をロードして、判定エンジンが動くことを確かめる。 */
import { test, expect, evaluateInExtension } from './fixtures.mjs';
import { BENIGN, PHISHING } from '../fixtures/urls.mjs';
import { hashKey, encodeTable, bytesToBase64 } from '../../extension/src/core/blocklist.js';

/** テスト用の成果物を組み立てる（実フィードは使わない）。 */
async function buildArtifact(phishingKeys = [], malwareKeys = []) {
  const table = async (keys) => bytesToBase64(encodeTable(await Promise.all(keys.map(hashKey))));
  return {
    version: 1, algo: 'sha256-64',
    generatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    tables: { url: await table(phishingKeys), host: '', domain: '' },
    malwareTables: { url: await table(malwareKeys), host: '', domain: '' },
  };
}

test('拡張がロードされ service worker が起動する', async ({ serviceWorker, extensionId }) => {
  expect(extensionId).toMatch(/^[a-p]{32}$/);
  const hasApi = await serviceWorker.evaluate(() => typeof globalThis.moribito?.evaluate === 'function');
  expect(hasApi).toBe(true);
});

test('正規サイトをブラウザ内でも誤検知しない', async ({ serviceWorker }) => {
  const failures = [];
  for (const url of BENIGN) {
    const r = await evaluateInExtension(serviceWorker, url);
    if (r.verdict !== 'allow') failures.push(`${r.verdict} ${r.score.toFixed(2)} ${url}`);
  }
  expect(failures, `誤検知:\n${failures.join('\n')}`).toEqual([]);
});

test('フィッシングURLをブラウザ内でもブロック判定する', async ({ serviceWorker }) => {
  const failures = [];
  for (const url of PHISHING) {
    const r = await evaluateInExtension(serviceWorker, url);
    if (r.verdict !== 'block') failures.push(`${r.verdict} ${r.score.toFixed(2)} ${url}`);
  }
  expect(failures, `見逃し:\n${failures.join('\n')}`).toEqual([]);
});

test('offscreen document 上のワーカーが応答する', async ({ serviceWorker }) => {
  // service worker からは Worker を直接作れない。拡張本体と同じ経路で呼ぶ。
  const result = await serviceWorker.evaluate(() =>
    globalThis.moribito.askWorker({
      type: 'analyze',
      url: 'http://amazon.co.jp.account-verify.x7fk2p.top/signin',
      useModel: false,
    }));

  expect(result, 'ワーカーから応答が返ってこなかった').not.toBeNull();
  expect(result.verdict).toBe('block');
  expect(result.signals.map((s) => s.id)).toContain('brand-in-subdomain');
});

test('offscreen document は二重に作られない', async ({ serviceWorker }) => {
  const count = await serviceWorker.evaluate(async () => {
    await globalThis.moribito.ensureOffscreen();
    await globalThis.moribito.ensureOffscreen();
    const contexts = await chrome.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] });
    return contexts.length;
  });
  expect(count).toBe(1);
});

test('モデル未配置でもワーカーは落ちずルールのみで動く', async ({ serviceWorker }) => {
  const state = await serviceWorker.evaluate(() =>
    globalThis.moribito.askWorker({ type: 'warmup', useModel: true }));
  expect(state?.modelState).toBe('unavailable');
});

test('配布された既知リストに一致すれば、他に手がかりが無くてもブロックする', async ({ context, serviceWorker }) => {
  const target = 'https://ordinary-looking-site.example/account/page';
  // ルールだけでは何も出ないURLであることを先に確認する
  const urlOnly = await serviceWorker.evaluate(
    (u) => globalThis.moribito.analyzeUrl(u).score, target);
  expect(urlOnly).toBe(0);

  // 更新経路と同じ場所（storage.local）に成果物を入れる
  const artifact = await buildArtifact(['ordinary-looking-site.example/account/page']);
  await serviceWorker.evaluate(async (a) => {
    await chrome.storage.local.set({ blocklist: a });
    globalThis.moribito.resetBlocklistCache();
  }, artifact);

  const page = await context.newPage();
  await page.goto(target, { waitUntil: 'commit' }).catch(() => {});
  await page.waitForURL(/\/src\/ui\/warning\.html\?token=/, { timeout: 15_000 });
  await expect(page.locator('#signals .signal .title').first())
    .toContainText('既知のフィッシングサイト');
});

test('マルウェア配布として報告されたURLは、その旨を表示する', async ({ context, serviceWorker }) => {
  const target = 'https://download-host.example/setup.msi';
  const artifact = await buildArtifact([], ['download-host.example/setup.msi']);
  await serviceWorker.evaluate(async (a) => {
    await chrome.storage.local.set({ blocklist: a });
    globalThis.moribito.resetBlocklistCache();
  }, artifact);

  const page = await context.newPage();
  await page.goto(target, { waitUntil: 'commit' }).catch(() => {});
  await page.waitForURL(/\/src\/ui\/warning\.html\?token=/, { timeout: 15_000 });
  await expect(page.locator('#signals .signal .title').first())
    .toContainText('マルウェア配布サイト');
});

test('リストに無いURLは、リストがあっても素通しする', async ({ context, serviceWorker }) => {
  const artifact = await buildArtifact(['something-else.example/x']);
  await serviceWorker.evaluate(async (a) => {
    await chrome.storage.local.set({ blocklist: a });
    globalThis.moribito.resetBlocklistCache();
  }, artifact);

  const page = await context.newPage();
  await page.goto('https://ordinary-looking-site.example/account/page', { waitUntil: 'commit' }).catch(() => {});
  await page.waitForTimeout(1500);
  await expect(page).toHaveURL('https://ordinary-looking-site.example/account/page');
});
