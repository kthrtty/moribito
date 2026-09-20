/**
 * Unicode の confusables.txt から完全版の対応表を生成し、
 * extension/src/core/confusables-data.js を上書きする。
 *   node tools/build-confusables.mjs
 *
 * ASCII（英数字とハイフン）へ落ちるマッピングだけを残す。
 * ドメイン名の判定にはそれで十分で、サイズも小さく保てる。
 */
import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE = 'https://www.unicode.org/Public/security/latest/confusables.txt';
const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../extension/src/core/confusables-data.js');

const res = await fetch(SOURCE);
if (!res.ok) throw new Error(`confusables.txt の取得に失敗しました: ${res.status}`);
const text = await res.text();

const targets = new Map(); // target(ascii 1文字) -> Set<source>
let kept = 0;

for (const rawLine of text.split('\n')) {
  const line = rawLine.split('#')[0].trim();
  if (!line) continue;
  const parts = line.split(';').map((p) => p.trim());
  if (parts.length < 2) continue;

  const source = String.fromCodePoint(...parts[0].split(' ').filter(Boolean).map((h) => parseInt(h, 16)));
  const target = String.fromCodePoint(...parts[1].split(' ').filter(Boolean).map((h) => parseInt(h, 16)));

  if (source.length !== 1) continue;                    // 1文字の置換だけ扱う
  if (!/^[a-zA-Z0-9-]$/.test(target)) continue;         // ASCIIに落ちるものだけ
  if (/^[\x00-\x7f]$/.test(source)) continue;           // ASCII同士は対象外
  if (source.normalize('NFKD').replace(/\p{M}+/gu, '').toLowerCase() === target.toLowerCase()) {
    continue;                                           // NFKD で吸収できるものは持たない
  }

  const key = target.toLowerCase();
  if (!targets.has(key)) targets.set(key, new Set());
  targets.get(key).add(source);
  kept++;
}

const escape = (ch) => {
  const cp = ch.codePointAt(0);
  return `\\u{${cp.toString(16)}}`;
};

const entries = [...targets.entries()].sort(([a], [b]) => a.localeCompare(b));
const body = entries
  .map(([target, set]) => {
    const chars = [...set].sort().map(escape).join('');
    const key = /^[a-z0-9]$/.test(target) ? target : `'${target}'`;
    return `  ${key}: '${chars}',`;
  })
  .join('\n');

const out = `/**
 * confusables（見た目が同じ文字）の対応表データ（自動生成 — 手で編集しない）
 *   生成元: ${SOURCE}
 *   生成日: ${new Date().toISOString().slice(0, 10)}
 *   再生成: node tools/build-confusables.mjs
 */

// target -> その字形に化ける文字の並び
export const CONFUSABLE_TARGETS = {
${body}
};

export const CONFUSABLES_SOURCE = 'unicode.org/Public/security/latest/confusables.txt';
`;

writeFileSync(OUT, out);
console.log(`confusables-data.js を更新しました: targets=${entries.length} mappings=${kept}`);
