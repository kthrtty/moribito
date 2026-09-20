/**
 * 判定ワーカー（module worker）。
 * MV3の service worker は Worker を生成できないため、
 * offscreen document から起動され、そこ経由で呼ばれる。
 */
import { analyzeUrl, withModel } from '../core/analyze.js';
import { ensureModel, predict, modelState } from './model.js';

const BASE = self.location.href;

self.onmessage = async (event) => {
  const msg = event.data ?? {};
  const { id, type } = msg;

  try {
    if (type === 'analyze') {
      const options = {
        thresholds: msg.thresholds,
        allowlist: msg.allowlist,
      };
      let result = analyzeUrl(msg.url, options);

      if (msg.useModel && result.ok && result.grey) {
        await ensureModel(BASE);
        const p = await predict(msg.url);
        if (p !== null) result = withModel(result, p, options);
      }
      self.postMessage({ id, ok: true, result });
      return;
    }

    if (type === 'predict') {
      await ensureModel(BASE);
      const probability = await predict(msg.url);
      self.postMessage({ id, ok: true, result: { probability } });
      return;
    }

    if (type === 'classify-text') {
      // ローカルLLM / 小型テキスト分類器の差し込み口。
      // モデルを配置するまでは null を返し、判定はルール側に任せる。
      self.postMessage({ id, ok: true, result: { probability: null, label: null } });
      return;
    }

    if (type === 'warmup') {
      const state = msg.useModel ? await ensureModel(BASE) : modelState();
      self.postMessage({ id, ok: true, result: { modelState: state } });
      return;
    }

    self.postMessage({ id, ok: false, error: `unknown message type: ${type}` });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err?.message ?? err) });
  }
};
