/**
 * 拡張をロードしたヘッドレスChromiumを立ち上げる共通フィクスチャ。
 * MV3拡張は headless shell では動かないため channel:'chromium'（新ヘッドレス）を使う。
 */
import { test as base, expect, chromium } from '@playwright/test';
import path from 'node:path';
import { htmlFor } from '../fixtures/pages.mjs';

const EXTENSION_PATH = path.resolve(import.meta.dirname, '../../extension');

/**
 * ネットワークに出ないよう、http(s)要求だけをローカルのスタブで返す。
 * chrome-extension:// は決して横取りしない（横取りすると拡張ページの
 * load イベントが上がらなくなり、テストが誤って失敗する）。
 */
async function stubNetwork(context) {
  await context.route(/^https?:\/\//i, async (route) => {
    const url = route.request().url();
    // 正規ドメインからフィッシングへのサーバーリダイレクトを再現する
    if (url.includes('/redirect-to-phishing')) {
      return route.fulfill({
        status: 302,
        headers: { location: 'http://amazon.co.jp.account-verify.x7fk2p.top/signin' },
      });
    }
    await route.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body: htmlFor(url),
    });
  });
}

export const test = base.extend({
  context: async ({}, use) => {
    const context = await chromium.launchPersistentContext('', {
      channel: 'chromium',
      headless: true,
      args: [
        `--disable-extensions-except=${EXTENSION_PATH}`,
        `--load-extension=${EXTENSION_PATH}`,
        '--no-first-run',
        '--no-default-browser-check',
      ],
    });
    await stubNetwork(context);
    await use(context);
    await context.close();
  },

  serviceWorker: async ({ context }, use) => {
    let [sw] = context.serviceWorkers();
    if (!sw) sw = await context.waitForEvent('serviceworker', { timeout: 20_000 });
    await waitForExtensionReady(sw);
    await use(sw);
  },

  extensionId: async ({ serviceWorker }, use) => {
    await use(new URL(serviceWorker.url()).host);
  },
});

/**
 * 拡張が完全に起動しきるのを待つ。
 * --load-extension の直後はまだ service worker が activate しておらず、
 * その間の webNavigation イベントは配送されないため、待たずに遷移すると
 * 「ブロックされない」偽の失敗になる。
 */
async function waitForExtensionReady(serviceWorker, timeoutMs = 10_000) {
  await serviceWorker.evaluate(() => new Promise((r) => chrome.runtime.getPlatformInfo(r)));
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ready = await serviceWorker.evaluate(async () => {
      if (typeof globalThis.moribito?.evaluate !== 'function') return false;
      const contexts = await chrome.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] });
      return contexts.length > 0;
    });
    if (ready) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  // activate 直後のイベント配送が安定するまでの猶予
  await new Promise((r) => setTimeout(r, 300));
}

export { expect };

/** service worker の中で実際の判定を走らせる。 */
export async function evaluateInExtension(serviceWorker, url) {
  return serviceWorker.evaluate(async (target) => {
    const r = await globalThis.moribito.evaluate(target);
    return { verdict: r.verdict, score: r.score, reason: r.reason ?? null, signals: (r.signals ?? []).map((s) => s.id) };
  }, url);
}
