/**
 * フィッシング報告フィードから、端末内照合用のハッシュ表を作る。
 *
 *   node tools/build-blocklist.mjs \
 *     --source=openphish:https://openphish.com/feed.txt \
 *     --source=urlhaus:https://urlhaus.abuse.ch/downloads/csv_online/ \
 *     --source=plain:./data/private-feed.txt \
 *     --out=extension/data/blocklist.json --ttl-days=14
 *
 * 対応形式: openphish / phishtank / urlhaus / jpcert / phishunt / stix / plain / json
 *           （URLかローカルファイル）
 *
 * stix は OpenCTI などの脅威インテリジェンス基盤からの書き出しを想定している。
 * STIX 2.1 バンドルの url observable と、indicator の pattern を読む。
 * 組織で受け取っている非公開フィード（会員向けのものなど）は plain: で
 * ローカルファイルとして渡す。URLそのものは成果物に残らず、SHA-256の先頭64bitだけが残る。
 *
 * 注意: 各フィードの利用条件（再配布の可否・帰属表示・商用利用）は提供元の規約に従うこと。
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { hashKey, encodeTable, bytesToBase64 } from '../extension/src/core/blocklist.js';
import { splitHost } from '../extension/src/core/psl.js';
import { FREE_HOSTING, POPULAR_DOMAINS, brandOwning } from '../extension/src/core/brands.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const hit = args.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};
const sources = args.filter((a) => a.startsWith('--source=')).map((a) => a.slice(9));
// マルウェア配布URLは別表に入れる。警告文が「フィッシング」では実態と合わないため。
const malwareSources = args.filter((a) => a.startsWith('--malware-source=')).map((a) => a.slice(17));
// IP直打ちのURL（ボットネットの配布サーバ等）はブラウザで踏むことがまずないので既定で除く
const keepIpHosts = args.includes('--keep-ip-hosts');
const out = resolve(ROOT, opt('out', 'extension/data/blocklist.json'));
const ttlDays = Number(opt('ttl-days', 14));
const hostMin = Number(opt('host-min', 2));    // 同一ホストでこの数以上ならホスト単位で登録
const domainMin = Number(opt('domain-min', 5)); // 同一登録ドメインでこの数以上ならドメイン単位
// ドメインごと潰すのは巻き添えが大きいので、明示的に指定されたときだけ行う
const domainLevel = args.includes('--domain-level');

if (!sources.length && !malwareSources.length) {
  console.error('少なくとも1つ --source=<形式>:<URLまたはパス> を指定してください。');
  console.error('例: --source=openphish:https://openphish.com/feed.txt');
  process.exit(1);
}

async function readSource(spec) {
  const separator = spec.indexOf(':');
  const format = spec.slice(0, separator);
  const location = spec.slice(separator + 1);
  let text;
  if (/^https?:\/\//i.test(location)) {
    const res = await fetch(location, { headers: { 'user-agent': 'moribito/0.1 (blocklist builder)' } });
    if (!res.ok) throw new Error(`${location}: HTTP ${res.status}`);
    text = await res.text();
  } else {
    text = readFileSync(resolve(ROOT, location), 'utf8');
  }
  return { format, location, urls: parse(format, text) };
}

function parse(format, text) {
  const lines = text.split(/\r?\n/);
  switch (format) {
    case 'openphish':
    case 'phishunt':
    case 'plain':
      return lines.map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));

    case 'stix': {
      // OpenCTI などからの STIX 2.1 バンドル。
      // url observable と、indicator の pattern [url:value = '...'] を拾う。
      const bundle = JSON.parse(text);
      const objects = Array.isArray(bundle) ? bundle : bundle.objects ?? [];
      const urls = [];
      for (const object of objects) {
        if (object?.type === 'url' && typeof object.value === 'string') {
          urls.push(object.value);
        } else if (object?.type === 'indicator' && typeof object.pattern === 'string') {
          for (const m of object.pattern.matchAll(/url:value\s*=\s*'([^']+)'/g)) urls.push(m[1]);
          for (const m of object.pattern.matchAll(/url:value\s*=\s*"([^"]+)"/g)) urls.push(m[1]);
        }
      }
      return urls;
    }
    case 'json': {
      const data = JSON.parse(text);
      return (Array.isArray(data) ? data : data.urls ?? []).map((e) => (typeof e === 'string' ? e : e.url)).filter(Boolean);
    }
    case 'phishtank':
    case 'jpcert':
    case 'urlhaus': {
      const rows = lines.filter((l) => l && !l.startsWith('#'));
      if (!rows.length) return [];

      // URLhaus は見出し行を「# id,dateadded,url,...」とコメントの中に置く。
      // コメントを落としてから1行目を見出しとみなすと、最初のデータ行を失う。
      const commented = lines
        .filter((l) => l.startsWith('#') && l.toLowerCase().includes('url'))
        .map((l) => l.replace(/^#\s*/, ''))
        .find((l) => splitCsv(l).map((h) => h.trim().toLowerCase()).includes('url'));

      const headerLine = commented ?? rows[0];
      const header = splitCsv(headerLine).map((h) => h.replace(/^"|"$/g, '').trim().toLowerCase());
      const index = header.indexOf('url');
      if (index < 0) throw new Error(`${format}: url列が見つかりません (${header.join(',')})`);

      const body = commented ? rows : rows.slice(1);
      return body.map((row) => splitCsv(row)[index]?.replace(/^"|"$/g, '').trim()).filter(Boolean);
    }
    default:
      throw new Error(`未知の形式: ${format}`);
  }
}

function splitCsv(line) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

/** 生成側の正規化。core/blocklist.js の urlKeys と必ず揃えること。 */
function canonical(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl.includes('://') ? rawUrl : `http://${rawUrl}`);
  } catch {
    return null;
  }
  if (!/^https?:$/.test(u.protocol)) return null;
  const host = u.hostname.toLowerCase().replace(/^www\./, '');
  if (!host || host === 'localhost') return null;
  const path = u.pathname.replace(/\/+$/, '');
  return { host, path, query: u.search, info: splitHost(host) };
}

/** ホスト/ドメイン単位で潰してよいか（正規サイトの巻き添えを避ける）。 */
function safeToWiden(info) {
  if (!info?.registrable) return false;
  if (FREE_HOSTING.has(info.suffix) || FREE_HOSTING.has(info.registrable)) return false;
  if (POPULAR_DOMAINS.has(info.registrable)) return false;
  if (brandOwning(info.registrable)) return false;
  return true;
}

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const report = [];

/** 1つの種別ぶんの集計を作る。 */
async function collect(specs, threat) {
  const urlKeys = new Set();
  const perHost = new Map();
  const perDomain = new Map();

  for (const spec of specs) {
    const { format, location, urls } = await readSource(spec);
    let accepted = 0;
    let skippedIp = 0;
    for (const raw of urls) {
      const c = canonical(raw);
      if (!c) continue;
      if (!keepIpHosts && (IPV4.test(c.host) || c.host.startsWith('['))) { skippedIp++; continue; }
      accepted++;
      urlKeys.add(`${c.host}${c.path}${c.query}`);
      if (c.query) urlKeys.add(`${c.host}${c.path}`); // クエリ違いにも当てる
      if (!safeToWiden(c.info)) continue;
      if (!perHost.has(c.host)) perHost.set(c.host, new Set());
      perHost.get(c.host).add(c.path || '/');
      const domain = c.info.registrable;
      if (!perDomain.has(domain)) perDomain.set(domain, new Set());
      perDomain.get(domain).add(c.host + c.path);
    }
    report.push({ format, location, threat, total: urls.length, accepted, skippedIp });
    console.log(`[${threat}] ${format} ${location}: ${accepted}/${urls.length} 件を取り込み`
      + (skippedIp ? `（IP直打ち ${skippedIp} 件を除外）` : ''));
  }

  const hostKeys = new Set();
  for (const [host, paths] of perHost) if (paths.size >= hostMin) hostKeys.add(host);
  const domainKeys = new Set();
  if (domainLevel) {
    for (const [domain, entries] of perDomain) if (entries.size >= domainMin) domainKeys.add(domain);
  }
  return { urlKeys, hostKeys, domainKeys };
}

const phishing = await collect(sources, 'phishing');
const malware = malwareSources.length ? await collect(malwareSources, 'malware') : null;

async function tableOf(keys) {
  const entries = [];
  for (const key of keys) entries.push(await hashKey(key));
  return bytesToBase64(encodeTable(entries));
}

const generatedAt = new Date();
const expiresAt = new Date(generatedAt.getTime() + ttlDays * 86400_000);
const artifact = {
  version: 1,
  generatedAt: generatedAt.toISOString(),
  expiresAt: expiresAt.toISOString(),
  algo: 'sha256-64',
  sources: report,
  counts: {
    url: phishing.urlKeys.size, host: phishing.hostKeys.size, domain: phishing.domainKeys.size,
    malwareUrl: malware?.urlKeys.size ?? 0, malwareHost: malware?.hostKeys.size ?? 0,
  },
  tables: {
    url: await tableOf(phishing.urlKeys),
    host: await tableOf(phishing.hostKeys),
    domain: await tableOf(phishing.domainKeys),
  },
  ...(malware ? {
    malwareTables: {
      url: await tableOf(malware.urlKeys),
      host: await tableOf(malware.hostKeys),
      domain: await tableOf(malware.domainKeys),
    },
  } : {}),
};

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(artifact));
const sizeKb = (JSON.stringify(artifact).length / 1024).toFixed(0);
console.log(`\n${out} を書き出しました`);
console.log(`  フィッシング: URL ${phishing.urlKeys.size} / ホスト ${phishing.hostKeys.size} / ドメイン ${phishing.domainKeys.size}`);
if (malware) console.log(`  マルウェア:   URL ${malware.urlKeys.size} / ホスト ${malware.hostKeys.size} / ドメイン ${malware.domainKeys.size}`);
console.log(`  成果物サイズ: ${sizeKb} KB`);
console.log(`  有効期限: ${expiresAt.toISOString().slice(0, 10)}（フィッシングURLは短命なので定期更新すること）`);
