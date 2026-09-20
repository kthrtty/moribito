/** Public Suffix List に基づく登録ドメイン抽出。 */
import { RULES, WILDCARDS, EXCEPTIONS } from './psl-data.js';

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIpHost(hostname) {
  const h = String(hostname || '');
  if (h.startsWith('[')) return true; // IPv6リテラル
  const m = IPV4_RE.exec(h);
  if (!m) return false;
  return m.slice(1).every((o) => Number(o) <= 255);
}

/** ホスト名の public suffix（登録可能な階層のひとつ下）を返す。 */
export function publicSuffixOf(hostname) {
  const labels = String(hostname || '').toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length === 0) return '';

  // 例外ルールが最優先
  for (let i = 0; i < labels.length; i++) {
    const cand = labels.slice(i).join('.');
    if (EXCEPTIONS.has(cand)) return labels.slice(i + 1).join('.');
  }

  // 既定ルール: 未知のTLDはそれ自体が public suffix
  let best = labels[labels.length - 1];
  for (let i = labels.length - 1; i >= 0; i--) {
    const cand = labels.slice(i).join('.');
    if (RULES.has(cand)) best = cand;
    if (i >= 1 && WILDCARDS.has(cand)) best = labels.slice(i - 1).join('.');
  }
  return best;
}

/**
 * ホスト名を {suffix, registrable, sub, name} に分解する。
 *  example: a.b.example.co.jp
 *    suffix='co.jp' registrable='example.co.jp' sub='a.b' name='example'
 */
export function splitHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!host) return { host, isIp: false, suffix: '', registrable: '', sub: '', name: '', labels: [] };
  if (isIpHost(host)) {
    return { host, isIp: true, suffix: '', registrable: host, sub: '', name: host, labels: [host] };
  }

  const labels = host.split('.');
  const suffix = publicSuffixOf(host);
  const suffixLabels = suffix ? suffix.split('.').length : 0;

  if (labels.length <= suffixLabels) {
    // public suffix そのもの（例: co.jp 単体）
    return { host, isIp: false, suffix, registrable: '', sub: '', name: '', labels };
  }

  const registrable = labels.slice(labels.length - suffixLabels - 1).join('.');
  const name = labels[labels.length - suffixLabels - 1];
  const sub = labels.slice(0, labels.length - suffixLabels - 1).join('.');
  return { host, isIp: false, suffix, registrable, sub, name, labels };
}

const PRIVATE_SUFFIXES = ['.local', '.internal', '.lan', '.home.arpa', '.localdomain'];

/** 自宅・社内ネットワーク上のホストか（ルーター管理画面などを誤検知しないため）。 */
export function isPrivateHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h === '[::1]' || h === '::1') return true;
  if (PRIVATE_SUFFIXES.some((s) => h.endsWith(s))) return true;
  if (!isIpHost(h)) return false;
  if (h.startsWith('[')) return /^\[(fc|fd|fe80)/i.test(h); // ULA / link-local
  const o = h.split('.').map(Number);
  if (o[0] === 10 || o[0] === 127 || o[0] === 0) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 169 && o[1] === 254) return true;
  return false;
}
