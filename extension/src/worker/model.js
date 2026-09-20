/**
 * ローカル軽量分類器の差し込み口。
 *
 * 設計方針:
 *  - モデルは「任意」。同梱されていなければルールのみで動作する（ここが返す null）。
 *  - 実行時に外部APIへ問い合わせない。閲覧中のURLを外へ出さないため。
 *  - 想定は文字レベルの小型分類器を ONNX にしたもの。
 *    学習は tools/train/ 参照（Jevなどのホスト型モデルで付けた確率をソフトラベルにして蒸留する）。
 *
 * 置き場所:
 *   extension/vendor/ort.wasm.min.mjs   … onnxruntime-web（ESM）
 *   extension/model/url-clf.onnx        … 学習済みモデル
 *   extension/model/meta.json           … { maxLen, vocab, threshold }
 * いずれも無ければ state='unavailable' になるだけで、判定は続行する。
 */

const MODEL_DIR = '../../model/';
const ORT_PATH = '../../vendor/ort.wasm.min.mjs';

let state = 'idle'; // idle | loading | ready | unavailable
let session = null;
let meta = null;
let ort = null;

export function modelState() {
  return state;
}

export async function ensureModel(baseUrl) {
  if (state === 'ready' || state === 'unavailable') return state;
  if (state === 'loading') {
    while (state === 'loading') await new Promise((r) => setTimeout(r, 25));
    return state;
  }
  state = 'loading';
  try {
    const metaUrl = new URL(`${MODEL_DIR}meta.json`, baseUrl).href;
    const metaRes = await fetch(metaUrl);
    if (!metaRes.ok) throw new Error('meta.json not found');
    meta = await metaRes.json();

    ort = await import(new URL(ORT_PATH, baseUrl).href);
    if (ort.env?.wasm) {
      ort.env.wasm.numThreads = 1;
      ort.env.wasm.wasmPaths = new URL('../../vendor/', baseUrl).href;
    }
    const modelUrl = new URL(`${MODEL_DIR}${meta.modelFile ?? 'url-clf.onnx'}`, baseUrl).href;
    session = await ort.InferenceSession.create(modelUrl, {
      executionProviders: ['wasm'],
      graphOptimizationLevel: 'all',
    });
    state = 'ready';
  } catch (err) {
    console.info('[moribito] ローカルモデルなし。ルールのみで判定します:', err?.message ?? err);
    state = 'unavailable';
    session = null;
  }
  return state;
}

/** meta.vocab に従って文字レベルのID列へ。学習側と必ず同じ規則を使うこと。 */
export function encodeUrl(url, m = meta) {
  const maxLen = m?.maxLen ?? 200;
  const vocab = m?.vocab ?? {};
  const oov = m?.oovIndex ?? 1;
  const pad = m?.padIndex ?? 0;
  const text = String(url).toLowerCase().slice(0, maxLen);
  const ids = new Array(maxLen).fill(pad);
  for (let i = 0; i < text.length; i++) {
    ids[i] = vocab[text[i]] ?? oov;
  }
  return ids;
}

/** @returns {Promise<number|null>} フィッシング確率。モデルが無ければ null。 */
export async function predict(url) {
  if (state !== 'ready' || !session) return null;
  try {
    const ids = encodeUrl(url);
    const tensor = new ort.Tensor('int32', Int32Array.from(ids), [1, ids.length]);
    const feeds = { [session.inputNames[0]]: tensor };
    const out = await session.run(feeds);
    const data = out[session.outputNames[0]].data;
    if (data.length === 1) return sigmoid(Number(data[0]));
    return softmaxLast(Array.from(data, Number));
  } catch (err) {
    console.warn('[moribito] 推論に失敗:', err);
    return null;
  }
}

function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}

function softmaxLast(logits) {
  const max = Math.max(...logits);
  const exps = logits.map((v) => Math.exp(v - max));
  const sum = exps.reduce((a, b) => a + b, 0);
  return exps[exps.length - 1] / sum;
}
