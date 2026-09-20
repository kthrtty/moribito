/** 実際のナビゲーションを止められるか（拡張の本番経路をそのまま通す）。 */
import { test, expect } from './fixtures.mjs';

const PHISH_URL = 'http://amazon.co.jp.account-verify.x7fk2p.top/signin';
const SAFE_URL = 'https://www.google.com/search?q=hello';

const WARNING_URL_RE = /\/src\/ui\/warning\.html\?token=/;

/** 遷移して、警告画面に差し替えられるまで待つ。 */
async function gotoExpectingBlock(page, url) {
  await page.goto(url, { waitUntil: 'commit' }).catch(() => {});
  await page.waitForURL(WARNING_URL_RE, { timeout: 15_000 });
}

/** 遷移して、差し替えが起きないことを確かめる（少し余裕を持って待つ）。 */
async function gotoExpectingPass(page, url) {
  await page.goto(url, { waitUntil: 'commit' }).catch(() => {});
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await page.waitForTimeout(1500);
}

test('フィッシングURLへの遷移が警告画面に差し替えられる', async ({ context, extensionId, serviceWorker }) => {
  const page = await context.newPage();
  await gotoExpectingBlock(page, PHISH_URL);

  await expect(page).toHaveURL(new RegExp(`^chrome-extension://${extensionId}/src/ui/warning\\.html\\?token=`));
  await expect(page.locator('h1')).toContainText('危険');
  await expect(page.locator('#host')).toHaveText('amazon.co.jp.account-verify.x7fk2p.top');
  await expect(page.locator('#full-url')).toContainText('/signin');
  await expect(page.locator('#verdict')).toHaveText('ブロック');
  // 国際化ドメインでないときは「表示名」の行を出さない
  await expect(page.locator('#unicode-row')).toBeHidden();
  await expect(page.locator('#score')).toContainText('/ 100');

  const signals = page.locator('#signals .signal');
  await expect(signals).not.toHaveCount(0);
  await expect(signals.first().locator('.title')).toContainText('ブランド名');
});

test('正規サイトへの遷移は妨げない', async ({ context, serviceWorker }) => {
  const page = await context.newPage();
  await gotoExpectingPass(page, SAFE_URL);

  await expect(page).toHaveURL(SAFE_URL);
  await expect(page.locator('#stub-page')).toBeVisible();
});

test('ホモグリフドメインの警告画面は実体と表示名の両方を出す', async ({ context, serviceWorker }) => {
  const page = await context.newPage();
  await gotoExpectingBlock(page, 'https://xn--80ak6aa92e.com/jp/verify');

  await expect(page.locator('#host')).toHaveText('xn--80ak6aa92e.com');
  await expect(page.locator('#unicode-row')).toBeVisible();
  await expect(page.locator('#host-unicode')).toHaveText('аррӏе.com');
});

test('「危険を承知で続行」でそのドメインを通過できる', async ({ context, serviceWorker }) => {
  const page = await context.newPage();
  await gotoExpectingBlock(page, PHISH_URL);
  await expect(page.locator('#proceed')).toBeAttached();

  await page.locator('#details-toggle').click();
  await page.locator('#proceed').click();

  await page.waitForURL(PHISH_URL, { timeout: 10_000 });
  await expect(page.locator('#stub-page')).toBeVisible();

  // 同じドメインへの再訪もブロックされない
  const again = await context.newPage();
  await gotoExpectingPass(again, PHISH_URL);
  await expect(again).toHaveURL(PHISH_URL);
});

test('拡張を無効にするとブロックしない', async ({ context, serviceWorker }) => {
  await serviceWorker.evaluate(() => chrome.storage.sync.set({ enabled: false }));
  await serviceWorker.evaluate(() => new Promise((r) => setTimeout(r, 200)));

  const page = await context.newPage();
  await gotoExpectingPass(page, PHISH_URL);
  await expect(page).toHaveURL(PHISH_URL);
});

test('許可リストに入れたドメインはブロックされない', async ({ context, serviceWorker }) => {
  await serviceWorker.evaluate(() => chrome.storage.sync.set({ allowlist: ['x7fk2p.top'] }));
  await serviceWorker.evaluate(() => new Promise((r) => setTimeout(r, 200)));

  const page = await context.newPage();
  await gotoExpectingPass(page, PHISH_URL);
  await expect(page).toHaveURL(PHISH_URL);
});
