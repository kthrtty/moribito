/**
 * 「実行時に外部へ出ない」ことを実ブラウザで確かめる。
 * この性質がこの拡張の前提なので、壊れたら必ず落ちるようにしておく。
 */
import { test, expect } from './fixtures.mjs';

test('既定設定では、判定のために外部へ一切問い合わせない', async ({ context, serviceWorker }) => {
  const requested = [];
  context.on('request', (req) => requested.push(req.url()));

  const page = await context.newPage();
  // グレー判定になるURL（外部照会があるとすればここで走る）
  await page.goto('http://mufg-bk-support.cyou/login', { waitUntil: 'commit' }).catch(() => {});
  await page.waitForURL(/warning\.html/, { timeout: 15_000 });
  await page.waitForTimeout(1000);

  // 拡張自身のリソース(chrome-extension://)はネットワークではないので除く
  const external = requested.filter((url) => /^https?:\/\//.test(url))
    .filter((url) => !url.startsWith('http://mufg-bk-support.cyou/'));
  expect(external, `外部への通信が発生しました:\n${external.join('\n')}`).toEqual([]);
});

test('外部連携の機能フラグは既定ですべて無効', async ({ context, extensionId, serviceWorker }) => {
  const providers = await serviceWorker.evaluate(
    () => chrome.runtime.sendMessage({ type: 'get-providers' }).catch(() => null));

  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/ui/options.html`);
  await expect(page.locator('#providers .provider')).not.toHaveCount(0);

  const checkboxes = page.locator('#providers input[type="checkbox"]');
  const count = await checkboxes.count();
  expect(count).toBeGreaterThanOrEqual(3);
  for (let i = 0; i < count; i++) {
    await expect(checkboxes.nth(i)).not.toBeChecked();
  }
  // 影響の説明が画面に出ていること
  await expect(page.locator('#providers-note')).toContainText('既定で無効');
  await expect(page.locator('#providers-note')).toContainText('閲覧先が相手に伝わります');
  await expect(page.locator('#jev-note')).toContainText('実行時に閲覧先を外部へ送る唯一の機能');
});

test('機能フラグをONにすると設定に保存される', async ({ context, extensionId, serviceWorker }) => {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/ui/options.html`);
  await expect(page.locator('#providers .provider')).not.toHaveCount(0);

  await page.locator('#endpoint-domain-reputation').fill('https://reputation.test/v1/{domain}');
  await page.locator('#provider-domain-reputation').check();

  await expect
    .poll(() => serviceWorker.evaluate(async () => {
      const s = await chrome.storage.sync.get('providerConfig');
      return s.providerConfig?.['domain-reputation']?.enabled ?? null;
    }))
    .toBe(true);
});

test('設定画面に判定レイヤが並び、個別に無効化できる', async ({ context, extensionId, serviceWorker }) => {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/ui/options.html`);

  const rows = page.locator('#detectors .detector');
  await expect(rows).not.toHaveCount(0);
  await expect(page.locator('#detector-url-rules')).toBeChecked();
  await expect(page.locator('#detector-reputation')).not.toBeChecked();

  // URL構造ルールを無効にすると、判定に使われなくなる
  await page.locator('#detector-url-rules').uncheck();
  await expect
    .poll(() => serviceWorker.evaluate(
      () => globalThis.moribito.evaluate('http://amazon.co.jp.verify.x7fk2p.top/signin')
        .then((r) => r.verdict)))
    .toBe('allow');
});

test('偽のトークンでは許可リストに追加できない', async ({ context, extensionId, serviceWorker }) => {
  // 警告画面が渡してきた値をそのまま信じると、任意のドメインを許可させられる。
  // service worker 側は自分が保存したレコードだけを根拠にする。
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/ui/warning.html?token=deadbeef`);

  const res = await page.evaluate(() => chrome.runtime.sendMessage({
    type: 'proceed', token: 'not-a-real-token', permanent: true,
    host: 'evil-attacker.test', url: 'http://evil-attacker.test/',
  }));
  expect(res.ok).toBe(false);

  const allowlist = await serviceWorker.evaluate(
    () => chrome.storage.sync.get({ allowlist: [] }).then((s) => s.allowlist));
  expect(allowlist).toEqual([]);
});

test('設定画面から平文URLを入れても保存されない', async ({ context, extensionId, serviceWorker }) => {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/ui/options.html`);
  await expect(page.locator('#block')).not.toHaveValue('');

  await page.locator('#blocklist-url').fill('http://evil.test/list.json');
  await page.locator('#save').click();

  // https 以外は捨てられる（service worker 側で検証している）
  await expect
    .poll(() => serviceWorker.evaluate(
      () => chrome.storage.sync.get({ blocklistUrl: null }).then((s) => s.blocklistUrl)))
    .toBe('');
});

test('Jevは既定で無効で、APIキーは画面に返らない', async ({ context, extensionId, serviceWorker }) => {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extensionId}/src/ui/options.html`);
  await expect(page.locator('#block')).not.toHaveValue('');

  // 既定は無効
  await expect(page.locator('#detector-jev-remote')).not.toBeChecked();
  await expect(page.locator('#jev-key-status')).toHaveText(/未設定/);

  // 保存しても、画面には値が残らず、状態だけが返る
  await page.locator('#jev-key').fill('sk-test-secret-value');
  await page.locator('#jev-key-save').click();
  await expect(page.locator('#jev-key-status')).toHaveText(/設定済み/);
  await expect(page.locator('#jev-key')).toHaveValue('');

  // 問い合わせても値そのものは返ってこない
  const status = await page.evaluate(() => chrome.runtime.sendMessage({ type: 'secret-status' }));
  expect(status.status.jev).toBe(true);
  expect(JSON.stringify(status)).not.toContain('sk-test-secret-value');

  // storage.sync 側には保存されない（Googleへ同期させない）
  const synced = await serviceWorker.evaluate(() => chrome.storage.sync.get(null));
  expect(JSON.stringify(synced)).not.toContain('sk-test-secret-value');

  // 削除できる
  await page.locator('#jev-key-clear').click();
  await expect(page.locator('#jev-key-status')).toHaveText(/未設定/);
});

test('Jevを有効にしていなければ外部へ出ない', async ({ context, serviceWorker }) => {
  const requested = [];
  context.on('request', (req) => requested.push(req.url()));

  const page = await context.newPage();
  // グレー判定になるURL（Jevが有効なら問い合わせが走る位置）
  await page.goto('https://aeon-card.info/update', { waitUntil: 'commit' }).catch(() => {});
  await page.waitForTimeout(1500);

  const external = requested.filter((url) => /^https?:\/\//.test(url))
    .filter((url) => !url.startsWith('https://aeon-card.info/'));
  expect(external, `外部への通信が発生しました:\n${external.join('\n')}`).toEqual([]);
});
