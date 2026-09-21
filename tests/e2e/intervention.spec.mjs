/**
 * 入力欄への介入と、送信直前の受け止め。
 *
 * 画面上部の警告バーは読み飛ばされる。
 * 「まさに入力しようとしている」瞬間と「取り返しがつかなくなる直前」に出すほうが効く。
 */
import { test, expect } from './fixtures.mjs';

const WARN_URL = 'https://x7f3k9qz2m-portal.cyou/login';
const SAFE_URL = 'https://shop-example-store.com/signin';

async function open(context, url) {
  const page = await context.newPage();
  await page.goto(url, { waitUntil: 'commit' }).catch(() => {});
  await page.waitForSelector('#pw', { timeout: 10_000 });
  return page;
}

test('注意レベルのページで入力欄に触れると、その場に注記が出る', async ({ context, serviceWorker }) => {
  const page = await open(context, WARN_URL);

  // 読み込んだだけでは出さない
  await expect(page.locator('#moribito-field-warning')).toHaveCount(0);

  await page.locator('#pw').focus();
  await expect(page.locator('#moribito-field-warning')).toHaveCount(1, { timeout: 10_000 });
});

test('打ち始めたときにも出る（JSで送信する実装への備え）', async ({ context, serviceWorker }) => {
  const page = await open(context, WARN_URL);
  await page.locator('#pw').fill('secret');
  await expect(page.locator('#moribito-field-warning')).toHaveCount(1, { timeout: 10_000 });
});

test('送信しようとすると一度だけ確認が挟まる', async ({ context, serviceWorker }) => {
  const page = await open(context, WARN_URL);
  await page.locator('#pw').fill('secret');
  await expect(page.locator('#moribito-field-warning')).toHaveCount(1, { timeout: 10_000 });

  await page.locator('#go').click();
  await expect(page.locator('#moribito-submit-confirm')).toHaveCount(1, { timeout: 10_000 });
  // 送信は止まっている
  await expect(page).toHaveURL(WARN_URL);
});

test('「送信しない」を選ぶと送信されない', async ({ context, serviceWorker }) => {
  const page = await open(context, WARN_URL);
  await page.locator('#pw').fill('secret');
  await page.locator('#go').click();
  await expect(page.locator('#moribito-submit-confirm')).toHaveCount(1, { timeout: 10_000 });

  // 確認ダイアログは closed shadow root の中にあるので、中のボタンは直接掴めない。
  // 既定のフォーカスは「送信しない」に当たっている。
  await page.keyboard.press('Enter');

  await expect(page.locator('#moribito-submit-confirm')).toHaveCount(0, { timeout: 10_000 });
  await expect(page).toHaveURL(WARN_URL);
});

test('安全なページでは入力欄に触れても介入しない', async ({ context, serviceWorker }) => {
  const page = await open(context, SAFE_URL);
  await page.locator('#pw').fill('secret');
  await page.waitForTimeout(1200);

  await expect(page.locator('#moribito-field-warning')).toHaveCount(0);
  await page.locator('#go').click();
  await expect(page.locator('#moribito-submit-confirm')).toHaveCount(0);
});

test('「それでも送信する」を選べば送信できる（ブロックはしない）', async ({ context, serviceWorker }) => {
  const page = await open(context, WARN_URL);
  await page.locator('#pw').fill('secret');
  await page.locator('#go').click();
  await expect(page.locator('#moribito-submit-confirm')).toHaveCount(1, { timeout: 10_000 });

  await page.keyboard.press('Tab');   // 「送信しない」→「それでも送信する」
  await page.keyboard.press('Enter');

  await expect(page.locator('#moribito-submit-confirm')).toHaveCount(0, { timeout: 10_000 });
  // 送信が通り、確認が二重に出ないこと
  await page.waitForURL(/\/auth/, { timeout: 10_000 });
  await expect(page.locator('#moribito-submit-confirm')).toHaveCount(0);
});
