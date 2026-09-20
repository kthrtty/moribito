/**
 * Jev（TypeSafe AI の System One モデル）への問い合わせ。
 *
 * 位置づけ:
 *   これは「実行時に外部へ送る」唯一の判定層で、**既定では無効**。
 *   有効にすると、閲覧先が TypeSafe に伝わる。UIで明示したうえで利用者が選ぶ。
 *
 * 送信量を抑える工夫:
 *   - URLだけで決着しなかったページ（グレー）に限って呼ぶ
 *   - 既定ではホスト名のみを送る。パスとクエリを送るかは利用者が選ぶ
 *   - 結果はドメイン単位でTTLキャッシュする（呼び出し側の責務）
 *
 * APIの形は docs.typesafe.ai の記載に合わせている。
 * 仕様が変わった場合は buildJevRequest / readJevAnswer を直せばよい。
 */
import { assertSafeEndpoint } from './reputation.js';

export const JEV_DEFAULT_ENDPOINT = 'https://api.typesafe.ai/v1/systemone';
export const JEV_DEFAULT_MODEL = 'jev-latest';
export const JEV_QUESTION_KEY = 'phishing';

/** 何を送るか。既定はホスト名のみ。 */
export function jevStateFor(rawUrl, { sendFullUrl = false } = {}) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return null;
  }
  if (!/^https?:$/.test(u.protocol)) return null;
  if (!sendFullUrl) return u.hostname;
  // 認証情報とフラグメントは送らない
  return `${u.protocol}//${u.host}${u.pathname}${u.search}`;
}

/** Jev のリクエスト本文を組み立てる。 */
export function buildJevRequest(state, { model = JEV_DEFAULT_MODEL } = {}) {
  return {
    state,
    model,
    questions: {
      [JEV_QUESTION_KEY]: {
        type: 'choice',
        instructions:
          'この文字列は、実在するブランドやサービスになりすまして利用者の認証情報や'
          + 'カード情報を詐取するフィッシングサイトのものか。'
          + 'ドメインの構造、ブランド名の使われ方、サブドメインの不自然さを手がかりに判断すること。',
        criteria: {
          phishing:
            '正規サービスになりすましている。ブランド名をサブドメインやパスに置いて'
            + '別の登録ドメインを使う、正規ドメインに酷似させる、といった詐称が見られる。',
          suspicious:
            '断定はできないが不自然。使い捨てドメイン、意味のないランダム文字列、'
            + '認証を連想させる語の多用など、正規サービスとしては考えにくい特徴がある。',
          benign:
            '通常のウェブサイトとして説明がつく。なりすましの意図が読み取れない。',
        },
      },
    },
  };
}

/**
 * 応答から確率を取り出す。
 * @returns {{probability:number, confidence:number, choice:string|null}|null}
 */
export function readJevAnswer(payload) {
  const answer = payload?.answers?.[JEV_QUESTION_KEY];
  if (!answer || typeof answer !== 'object') return null;

  const probabilities = answer.probabilities;
  if (!probabilities || typeof probabilities !== 'object') return null;

  const phishing = toUnit(probabilities.phishing);
  const suspicious = toUnit(probabilities.suspicious);
  const confidence = toUnit(answer.confidence, 1);

  return {
    probability: Math.min(1, phishing + suspicious * 0.5),
    confidence,
    choice: typeof answer.choice === 'string' ? answer.choice : null,
  };
}

function toUnit(value, fallback = 0) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(1, Math.max(0, n));
}

/**
 * 確率と確信度を危険信号の重みへ写像する。
 *
 * 単独でブロックまで到達させない（上限0.8）。外部モデルの較正を
 * こちらで検証できない以上、他の証拠と組み合わさったときだけ効かせる。
 * グレー（0.35以上）でしか呼ばれないので、0.35 + 0.8 でブロックに届く。
 */
export function jevWeight({ probability, confidence }) {
  if (probability <= 0.5) return 0;
  const certainty = 0.5 + confidence * 0.5; // 確信度が低いと効きを弱める
  return Math.min(0.8, (probability - 0.5) * 2 * certainty);
}

/**
 * Jev を呼ぶ。失敗しても例外を投げず null を返す（判定を止めないため）。
 * @param {string} rawUrl
 * @param {{endpoint?:string, model?:string, apiKey:string, sendFullUrl?:boolean}} config
 */
export async function queryJev(rawUrl, config, options = {}) {
  const { fetchImpl = fetch, timeoutMs = 3000 } = options;
  if (!config?.apiKey) return null;

  const state = jevStateFor(rawUrl, config);
  if (!state) return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const endpoint = assertSafeEndpoint(config.endpoint || JEV_DEFAULT_ENDPOINT);
    const res = await fetchImpl(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${config.apiKey}`,
      },
      body: JSON.stringify(buildJevRequest(state, config)),
      signal: controller.signal,
    });

    if (!res.ok) {
      // 429 / 529 はこちらから再試行しない。次のページで自然に再試行される。
      return { error: `HTTP ${res.status}` };
    }
    const answer = readJevAnswer(await res.json());
    return answer ?? { error: 'unexpected-response' };
  } catch (err) {
    return { error: String(err?.name === 'AbortError' ? 'timeout' : err?.message ?? err) };
  } finally {
    clearTimeout(timer);
  }
}
