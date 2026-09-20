/**
 * 外部リピュテーション照会のプロバイダ層。
 *
 * 方針:
 *  - 特定のベンダに依存しない。エンドポイントと応答の読み方を設定で差し替えられる
 *  - プライバシーコストの大きさを型で表し、UIに出す
 *      local   : 通信しない（配布済みハッシュ表との照合）
 *      prefix  : ハッシュの先頭だけ送る（k-匿名。URLそのものは送らない）
 *      domain  : ドメイン名を送る（閲覧先が相手に分かる）
 *      ip      : 名前解決したIPを送る（先にDoHでの解決が必要＝解決先にも分かる）
 *  - 既定は全て無効。有効化は設定画面の機能フラグで明示的に行う
 *  - 問い合わせるのは「URLだけで決着しなかったページ」に限り、結果はTTL付きで再利用する
 */

export const PRIVACY_COST = {
  local: { label: '通信なし', order: 0 },
  prefix: { label: 'ハッシュ接頭辞のみ送信', order: 1 },
  domain: { label: 'ドメイン名を送信', order: 2 },
  ip: { label: 'IPアドレスを送信（名前解決が必要）', order: 3 },
};

/**
 * 同梱するプロバイダの雛形。endpoint / apiKey は利用者が設定する。
 * 各サービスの利用条件・レート制限・料金は提供元の規約に従うこと。
 */
export const PROVIDER_TEMPLATES = [
  {
    id: 'hash-prefix',
    label: 'ハッシュ接頭辞照会（k-匿名）',
    kind: 'prefix',
    enabled: false,
    endpoint: '',
    note: 'URLハッシュの先頭のみを送ります。Safe Browsing の fullHashes 相当、'
      + 'あるいは同等の自前エンドポイントを想定しています。閲覧先URLそのものは送信しません。',
    perf: 'low',
    weight: 0.95,
    hitWhen: { path: 'matches', nonEmpty: true },
  },
  {
    id: 'domain-reputation',
    label: 'ドメイン評価API',
    kind: 'domain',
    enabled: false,
    endpoint: '',
    note: '閲覧先のドメイン名が提供元に伝わります。ページを開くたびに問い合わせが発生し、'
      + '表示が遅くなることがあります。必要な場合だけ有効にしてください。',
    perf: 'high',
    weight: 0.8,
    hitWhen: { path: 'verdict', equalsAny: ['phishing', 'malicious', 'malware', 'suspicious'] },
  },
  {
    id: 'ip-reputation',
    label: 'IP評価API（DoHで名前解決してから照会）',
    kind: 'ip',
    enabled: false,
    endpoint: '',
    note: '名前解決のためDoHリゾルバへ、続けてIP評価APIへ問い合わせます。'
      + '1ページにつき2回の外部通信が発生し、両方に閲覧先が伝わります。',
    perf: 'high',
    weight: 0.6,
    hitWhen: { path: 'malicious', truthy: true },
  },
];

export const DEFAULT_DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query?name={domain}&type=A';

/** 応答から「一致した」と読み取れるかを判定する。 */
export function readHit(payload, hitWhen) {
  if (!hitWhen) return false;
  const value = getPath(payload, hitWhen.path);
  if (hitWhen.nonEmpty) return Array.isArray(value) ? value.length > 0 : Boolean(value);
  if (hitWhen.truthy) return Boolean(value);
  if (hitWhen.equalsAny) {
    const text = String(value ?? '').toLowerCase();
    return hitWhen.equalsAny.some((v) => text === String(v).toLowerCase());
  }
  if (hitWhen.atLeast != null) return Number(value) >= Number(hitWhen.atLeast);
  return false;
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function getPath(obj, path) {
  if (!path) return undefined;
  return String(path).split('.').reduce((acc, key) => {
    if (FORBIDDEN_KEYS.has(key)) return undefined; // プロトタイプ汚染の読み出しを塞ぐ
    if (acc == null) return undefined;
    const index = Number(key);
    return Number.isInteger(index) && Array.isArray(acc) ? acc[index] : acc[key];
  }, obj);
}

/**
 * 設定されたエンドポイントを検証する。
 *  - https のみ（平文での問い合わせを許さない）
 *  - URLに認証情報を埋めさせない
 *  - プライベートIP・localhost を許さない（内部ネットワークへの踏み台化を防ぐ）
 * @throws {Error} 受け付けられない場合
 */
export function assertSafeEndpoint(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new Error('URLとして解釈できません');
  }
  if (u.protocol !== 'https:') throw new Error('https のみ指定できます');
  if (u.username || u.password) throw new Error('URLに認証情報を含められません');
  const host = u.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
    throw new Error('ローカルホストは指定できません');
  }
  if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(host)) {
    throw new Error('プライベートアドレスは指定できません');
  }
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) {
    throw new Error('プライベートアドレスは指定できません');
  }
  if (host === '[::1]' || /^\[(fc|fd|fe80)/i.test(host)) {
    throw new Error('プライベートアドレスは指定できません');
  }
  return u.href;
}

export function isSafeEndpoint(rawUrl) {
  try {
    assertSafeEndpoint(rawUrl);
    return true;
  } catch {
    return false;
  }
}

export function fillTemplate(template, values) {
  return String(template ?? '').replace(/\{(\w+)\}/g, (_, key) => encodeURIComponent(values[key] ?? ''));
}

/** DoHでAレコードを引く。JSON形式（application/dns-json）のリゾルバを想定。 */
export async function resolveIps(domain, endpoint, { fetchImpl = fetch, timeoutMs = 2000 } = {}) {
  const url = fillTemplate(endpoint || DEFAULT_DOH_ENDPOINT, { domain });
  assertSafeEndpoint(url);
  const res = await withTimeout(
    (signal) => fetchImpl(url, { headers: { accept: 'application/dns-json' }, signal }), timeoutMs);
  if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
  const data = await res.json();
  return (data.Answer ?? []).filter((a) => a.type === 1).map((a) => a.data);
}

/**
 * プロバイダを1つ実行する。
 * @returns {Promise<{id:string, hit:boolean, kind:string, weight:number, detail:string}|null>}
 */
export async function queryProvider(provider, context, options = {}) {
  const { fetchImpl = fetch, timeoutMs = 2500 } = options;
  if (!provider?.enabled || !provider.endpoint) return null;

  try {
    let values = { domain: context.domain, url: context.url, prefix: context.prefix ?? '', key: provider.apiKey ?? '' };

    if (provider.kind === 'ip') {
      const ips = context.ips ?? await resolveIps(context.domain, options.dohEndpoint, options);
      if (!ips.length) return null;
      values = { ...values, ip: ips[0], ips: ips.join(',') };
    }

    const target = assertSafeEndpoint(fillTemplate(provider.endpoint, values));
    const res = await withTimeout((signal) => fetchImpl(target, {
      method: provider.method ?? 'GET',
      headers: provider.headers ?? {},
      signal,
    }), timeoutMs);
    if (!res.ok) return null;

    const payload = await res.json();
    const hit = readHit(payload, provider.hitWhen);
    if (!hit) return null;
    return {
      id: provider.id,
      kind: provider.kind,
      weight: Number(provider.weight ?? 0.7),
      detail: provider.label ?? provider.id,
    };
  } catch {
    return null; // 外部要因で判定を止めない
  }
}

/** 有効なプロバイダをまとめて実行する。 */
export async function queryProviders(providers, context, options = {}) {
  const active = (providers ?? []).filter((p) => p.enabled && p.endpoint);
  if (!active.length) return [];
  const results = await Promise.all(active.map((p) => queryProvider(p, context, options)));
  return results.filter(Boolean);
}

/** 照会結果を危険信号へ変換する。 */
export function reputationSignals(results) {
  return (results ?? []).map((r) => ({
    id: `reputation-${r.id}`,
    weight: Math.max(0, Math.min(1, r.weight)),
    title: '外部の評価で危険と判定されています',
    detail: `${r.detail} が、このサイトを危険と報告しました。`,
    from: 'reputation',
  }));
}

/** タイムアウト時は AbortController で実際に中断する（接続を放置しない）。 */
function withTimeout(makeRequest, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return Promise.resolve(makeRequest(controller.signal)).finally(() => clearTimeout(timer));
}
