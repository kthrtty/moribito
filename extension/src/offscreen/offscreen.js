/**
 * ワーカーのホスト。service worker から来たメッセージをワーカーへ中継する。
 * service worker がアイドル終了してもこのドキュメントは残るので、
 * モデルのロードコストを繰り返し払わずに済む。
 */
import { availability, identifyService, destroySession } from './local-llm.js';

const worker = new Worker(chrome.runtime.getURL('src/worker/detector.worker.js'), {
  type: 'module',
  name: 'moribito-detector',
});

const pending = new Map();
let seq = 0;

worker.onmessage = (event) => {
  const { id } = event.data ?? {};
  const resolve = pending.get(id);
  if (!resolve) return;
  pending.delete(id);
  resolve(event.data);
};

worker.onerror = (event) => {
  console.error('[moribito] worker error:', event.message);
  for (const [id, resolve] of pending) resolve({ id, ok: false, error: event.message });
  pending.clear();
};

function callWorker(payload, timeoutMs = 3000) {
  const id = ++seq;
  return new Promise((resolve) => {
    pending.set(id, resolve);
    worker.postMessage({ ...payload, id });
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        resolve({ id, ok: false, error: 'worker-timeout' });
      }
    }, timeoutMs);
  });
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.target !== 'offscreen') return false;
  const payload = message.payload ?? {};

  // Chrome内蔵AI（Prompt API）はDOMコンテキストにしか無いので、
  // ワーカーへは渡さずこの文書で扱う。
  if (payload.type === 'local-llm-status') {
    availability().then((state) => sendResponse({ state })).catch(() => sendResponse({ state: 'unavailable' }));
    return true;
  }
  if (payload.type === 'local-llm-identify') {
    identifyService(payload.evidence, payload.host)
      .then((result) => sendResponse({ result }))
      .catch(() => sendResponse({ result: null }));
    return true;
  }
  if (payload.type === 'local-llm-reset') {
    destroySession().then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  callWorker(payload).then(sendResponse);
  return true; // 非同期応答
});
