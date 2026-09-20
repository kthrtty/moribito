/**
 * 表示コンテンツの検査（2段構え）を実ブラウザで検証する。
 * URLだけではグレーのページが、内容を見て初めて止まることを確かめる。
 */
import { test, expect, evaluateInExtension } from './fixtures.mjs';

const WARNING_URL_RE = /\/src\/ui\/warning\.html\?token=/;

async function goto(page, url) {
  await page.goto(url, { waitUntil: 'commit' }).catch(() => {});
}

test('URLはグレーでも、ブランド詐称ログインフォームがあればブロックする', async ({ context, serviceWorker }) => {
  const url = 'http://mufg-bk-support.cyou/login';
  // URLだけの判定ではブロックに達していないことを先に確認する
  const urlOnly = await serviceWorker.evaluate(
    (target) => globalThis.moribito.analyzeUrl(target).verdict, url);
  expect(urlOnly).toBe('warn');

  const page = await context.newPage();
  await goto(page, url);
  await page.waitForURL(WARNING_URL_RE, { timeout: 15_000 });

  const titles = await page.locator('#signals .signal .title').allTextContents();
  expect(titles.join('\n')).toContain('mufg を名乗っています');
  expect(titles.join('\n')).toContain('暗号化されていない接続');
});

test('検索ボックスだけのページは内容を見ても止めない', async ({ context, serviceWorker }) => {
  const page = await context.newPage();
  await goto(page, 'http://news-example.cyou/');
  await page.waitForTimeout(1500);

  await expect(page).toHaveURL('http://news-example.cyou/');
  await expect(page.locator('#moribito-overlay')).toHaveCount(0);
});

test('正規サイトらしいログインページは止めない', async ({ context, serviceWorker }) => {
  const page = await context.newPage();
  await goto(page, 'https://shop-example-store.com/login');
  await page.waitForTimeout(1500);

  await expect(page).toHaveURL('https://shop-example-store.com/login');
  await expect(page.locator('#moribito-overlay')).toHaveCount(0);
});

test('警告どまりのページには警告バーを出す', async ({ context, serviceWorker }) => {
  const page = await context.newPage();
  await goto(page, 'http://mail-check-center.cyou/');

  await expect(page.locator('#moribito-overlay')).toHaveCount(1, { timeout: 10_000 });
  await expect(page).toHaveURL('http://mail-check-center.cyou/'); // ブロックまではしない
});

test('読み込み後に差し込まれたフォームも、入力しようとした時点で捕まえる', async ({ context, serviceWorker }) => {
  const page = await context.newPage();
  await goto(page, 'http://delayed-form-check.sbs/');
  await page.waitForSelector('#pw', { timeout: 10_000 });

  // 読み込み時点ではまだフォームが無かったので止まっていない
  await expect(page).toHaveURL('http://delayed-form-check.sbs/');

  await page.locator('#pw').focus();   // focusin が再評価の契機になる
  await page.waitForURL(WARNING_URL_RE, { timeout: 15_000 });
});

test('表示内容の検査をOFFにすると内容では止めない', async ({ context, serviceWorker }) => {
  await serviceWorker.evaluate(() => chrome.storage.sync.set({ inspectPages: false }));
  await serviceWorker.evaluate(() => new Promise((r) => setTimeout(r, 200)));

  const page = await context.newPage();
  await goto(page, 'http://mufg-bk-support.cyou/login');
  await page.waitForTimeout(1500);

  await expect(page).toHaveURL('http://mufg-bk-support.cyou/login');
});
