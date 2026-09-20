/**
 * 既知フィッシングURLのローカル照合。
 *
 * 実行時に外部へ問い合わせない。閲覧中のURLを送れば履歴を渡すのと同じなので、
 * フィードは事前にハッシュ化した成果物として配り、端末内で突き合わせる
 * （Safe Browsing のローカル照合と同じ考え方）。
 *
 * 成果物の作り方は tools/build-blocklist.mjs を参照。
 * PhishTank / OpenPhish / URLhaus のほか、組織で受け取っている非公開フィードも
 * ローカルファイルとして食わせられる。
 */

const PREFIX_BYTES = 8; // SHA-256 の先頭8バイト。誤一致は実質ゼロ。

/** 照合キーの正規化。生成側と照合側で必ず同じ規則を使う。 */
export function urlKeys(rawUrl, domainInfo) {
  const keys = [];
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return keys;
  }
  if (!/^https?:$/.test(u.protocol)) return keys;

  const host = u.hostname.replace(/^www\./, '');
  const path = u.pathname.replace(/\/+$/, '');
  const query = u.search;

  // 完全一致 → クエリ除去 → パスを上位へ辿る → ホスト → 登録ドメイン
  if (query) keys.push({ kind: 'url', key: `${host}${path}${query}` });
  keys.push({ kind: 'url', key: `${host}${path}` });

  const segments = path.split('/').filter(Boolean);
  for (let i = segments.length - 1; i >= 1; i--) {
    keys.push({ kind: 'url', key: `${host}/${segments.slice(0, i).join('/')}` });
  }
  keys.push({ kind: 'host', key: host });
  if (domainInfo?.registrable && domainInfo.registrable !== host) {
    keys.push({ kind: 'domain', key: domainInfo.registrable });
  } else if (domainInfo?.registrable) {
    keys.push({ kind: 'domain', key: domainInfo.registrable });
  }
  return keys.slice(0, 12);
}

/** 文字列 → SHA-256 の先頭64bit（上位/下位の2語）。 */
export async function hashKey(key) {
  const bytes = new TextEncoder().encode(key);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  const view = new DataView(digest.buffer, 0, PREFIX_BYTES);
  return { hi: view.getUint32(0, false), lo: view.getUint32(4, false) };
}

/** ソート済みの (hi, lo) 配列に対する二分探索。BigIntを使わず速い。 */
function includes(hiArr, loArr, hi, lo) {
  let low = 0;
  let high = hiArr.length - 1;
  while (low <= high) {
    const mid = (low + high) >>> 1;
    const midHi = hiArr[mid];
    if (midHi === hi) {
      const midLo = loArr[mid];
      if (midLo === lo) return true;
      if (midLo < lo) low = mid + 1;
      else high = mid - 1;
    } else if (midHi < hi) low = mid + 1;
    else high = mid - 1;
  }
  return false;
}

/** 8バイト×N のバイト列を (hi, lo) の組にほどく。 */
export function decodeTable(bytes) {
  const count = Math.floor(bytes.length / PREFIX_BYTES);
  const hi = new Uint32Array(count);
  const lo = new Uint32Array(count);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let i = 0; i < count; i++) {
    hi[i] = view.getUint32(i * PREFIX_BYTES, false);
    lo[i] = view.getUint32(i * PREFIX_BYTES + 4, false);
  }
  return { hi, lo, count };
}

export function encodeTable(entries) {
  const sorted = [...entries].sort((a, b) => (a.hi - b.hi) || (a.lo - b.lo));
  const bytes = new Uint8Array(sorted.length * PREFIX_BYTES);
  const view = new DataView(bytes.buffer);
  sorted.forEach((entry, i) => {
    view.setUint32(i * PREFIX_BYTES, entry.hi, false);
    view.setUint32(i * PREFIX_BYTES + 4, entry.lo, false);
  });
  return bytes;
}

export function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * 成果物からルックアップ器を作る。
 * artifact: { version, generatedAt, expiresAt, sources, tables: { url, host, domain } }
 */
export function createBlocklist(artifact) {
  if (!artifact?.tables) return null;
  const tables = {};
  for (const kind of ['url', 'host', 'domain']) {
    const base64 = artifact.tables[kind];
    tables[kind] = base64 ? decodeTable(base64ToBytes(base64)) : { hi: new Uint32Array(0), lo: new Uint32Array(0), count: 0 };
  }

  return {
    version: artifact.version ?? 0,
    generatedAt: artifact.generatedAt ?? null,
    expiresAt: artifact.expiresAt ?? null,
    sources: artifact.sources ?? [],
    size: tables.url.count + tables.host.count + tables.domain.count,

    /** @returns {Promise<{kind:string}|null>} */
    async lookup(rawUrl, domainInfo) {
      for (const { kind, key } of urlKeys(rawUrl, domainInfo)) {
        const table = tables[kind];
        if (!table.count) continue;
        const { hi, lo } = await hashKey(key);
        if (includes(table.hi, table.lo, hi, lo)) return { kind, matchedOn: kind };
      }
      return null;
    },
  };
}

/** 期限切れかどうか（フィッシングURLは短命なので古い表は当てにしない）。 */
export function isStale(artifact, now = Date.now()) {
  if (!artifact?.expiresAt) return false;
  return now > Date.parse(artifact.expiresAt);
}
