/** 実際のChromeに拡張をロードして、判定エンジンが動くことを確かめる。 */
import { test, expect, evaluateInExtension } from './fixtures.mjs';
import { BENIGN, PHISHING } from '../fixtures/urls.mjs';

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
