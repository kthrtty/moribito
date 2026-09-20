/** ポップアップと設定画面を実ブラウザで操作する。 */
import { test, expect, evaluateInExtension } from './fixtures.mjs';

const PHISH_URL = 'http://amazon.co.jp.account-verify.x7fk2p.top/signin';

/**
 * ページを開き、設定の読み込み（各ページの main()）が終わるまで待つ。
 * 待たずに操作すると、読み込み完了時に入力値が上書きされて落ちる。
 */
async function openPopup(context, extensionId) {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/ui/popup.html`);
  await expect(page.locator('#enabled')).toBeChecked(); // 設定反映済みの印
  return page;
}

async function openOptions(context, extensionId) {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/ui/options.html`);
  // input[type=range] はブラウザが初期値（min/maxの中間）を勝手に入れるので、
  // 「値が空でない」では初期化待ちにならない。
  // 出力欄(<output>)は空から始まるので、こちらが埋まるのを待つ。
  await expect(page.locator('#block-out')).not.toHaveText('');
  return page;
}

test('ポップアップでURLを手動判定できる', async ({ context, extensionId }) => {
  const page = await openPopup(context, extensionId);

  await page.locator('#check-url').fill(PHISH_URL);
  await page.locator('#check-form button[type="submit"]').click();

  await expect(page.locator('#verdict')).toHaveText('危険');
  await expect(page.locator('#host')).toHaveText('amazon.co.jp.account-verify.x7fk2p.top');
  await expect(page.locator('#score')).toHaveText(/^9\d$/);
  await expect(page.locator('#signals .signal').first()).toContainText('ブランド名');
});

test('ポップアップはホモグリフドメインの実体を主に出す', async ({ context, extensionId }) => {
  const page = await openPopup(context, extensionId);

  await page.locator('#check-url').fill('https://xn--80ak6aa92e.com/jp/verify');
  await page.locator('#check-form button[type="submit"]').click();

  // 見た目の「apple.com」ではなく、実体のpunycodeを主見出しにする
  await expect(page.locator('#host')).toHaveText('xn--80ak6aa92e.com');
  await expect(page.locator('#host-sub')).toBeVisible();
  await expect(page.locator('#host-sub')).toContainText('\u0430\u0440\u0440\u04cf\u0435.com');
  await expect(page.locator('#verdict')).toHaveText('危険');
});

test('ポップアップは正規サイトを「問題なし」と表示する', async ({ context, extensionId }) => {
  const page = await openPopup(context, extensionId);

  await page.locator('#check-url').fill('https://www.amazon.co.jp/dp/B01');
  await page.locator('#check-form button[type="submit"]').click();

  await expect(page.locator('#verdict')).toHaveText('問題なし');
  await expect(page.locator('#signals')).toContainText('公式ドメイン');
  await expect(page.locator('#host-sub')).toBeHidden();
});

test('ポップアップから拡張を無効にできる', async ({ context, extensionId, serviceWorker }) => {
  const page = await openPopup(context, extensionId);

  await page.locator('#enabled').uncheck();

  await expect
    .poll(() => serviceWorker.evaluate(() => chrome.storage.sync.get({ enabled: true }).then((s) => s.enabled)))
    .toBe(false);
});

test('設定画面でしきい値を変えると判定が変わる', async ({ context, extensionId, serviceWorker }) => {
  const greyUrl = 'https://paypal-secure-login.com/';
  expect((await evaluateInExtension(serviceWorker, greyUrl)).verdict).toBe('warn');

  const page = await openOptions(context, extensionId);
  await expect(page.locator('#block')).toHaveValue('0.85');

  await page.locator('#block').fill('0.7');
  await page.locator('#allowlist').fill('example-allowed.test');
  await page.locator('#save').click();
  await expect(page.locator('#saved')).toHaveClass(/show/);

  await expect
    .poll(() => evaluateInExtension(serviceWorker, greyUrl).then((r) => r.verdict))
    .toBe('block');

  // 再読み込みしても保存内容が残る
  await page.reload();
  await expect(page.locator('#block')).toHaveValue('0.7');
  await expect(page.locator('#allowlist')).toHaveValue('example-allowed.test');
});

test('設定画面のモデル状態表示はモデル未配置を正しく伝える', async ({ context, extensionId }) => {
  const page = await openOptions(context, extensionId);
  await expect(page.locator('#model-state')).toHaveText(/モデル未配置|未ロード/);
});

test('設定を初期化できる', async ({ context, extensionId }) => {
  const page = await openOptions(context, extensionId);
  // 保存結果は設定画面自身から読む。service worker はアイドルで終了しうるので、
  // そちら経由で読むとフルラン時だけ不安定になる。
  const stored = () => page.evaluate(
    () => chrome.storage.sync.get({ blockThreshold: null }).then((s) => s.blockThreshold));

  await page.locator('#block').fill('0.6');
  await page.locator('#save').click();
  // DOMだけでなく保存されたことまで待つ（UIの非同期初期化と競合しないように）
  await expect.poll(stored).toBe(0.6);
  await expect(page.locator('#block')).toHaveValue('0.6');

  await page.locator('#reset').click();
  await expect.poll(stored).toBe(0.85);
  await expect(page.locator('#block')).toHaveValue('0.85');
});
