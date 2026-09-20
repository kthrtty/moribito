/**
 * Public Suffix List の完全版を取得して extension/src/core/psl-data.js を再生成する。
 *   node tools/build-psl.mjs            (ICANN + PRIVATE 全部)
 *   node tools/build-psl.mjs --icann    (ICANNセクションのみ)
 *
 * 同梱しているのは手当てしたサブセット。実運用前に一度これを流しておくと、
 * 珍しいTLDでの登録ドメイン切り出しが正確になる。
 */
import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE = 'https://publicsuffix.org/list/public_suffix_list.dat';
const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../extension/src/core/psl-data.js');
const icannOnly = process.argv.includes('--icann');

const res = await fetch(SOURCE);
if (!res.ok) throw new Error(`PSLの取得に失敗しました: ${res.status}`);
const text = await res.text();

const rules = [];
const wildcards = [];
const exceptions = [];
let inPrivate = false;

for (const rawLine of text.split('\n')) {
  const line = rawLine.trim();
  if (line.startsWith('// ===BEGIN PRIVATE DOMAINS===')) inPrivate = true;
  if (line.startsWith('// ===END PRIVATE DOMAINS===')) inPrivate = false;
  if (!line || line.startsWith('//')) continue;
  if (inPrivate && icannOnly) continue;

  if (line.startsWith('!')) {
    exceptions.push(line.slice(1));
  } else if (line.startsWith('*.')) {
    wildcards.push(line.slice(2));
  } else if (line.includes('.')) {
    // 単一ラベルのTLDは既定ルールで扱えるので持たない（サイズ削減）
    rules.push(line);
  }
}

const fmt = (arr) => {
  const sorted = [...new Set(arr)].sort();
  const lines = [];
  let current = ' ';
  for (const entry of sorted) {
    const piece = ` '${entry}',`;
    if (current.length + piece.length > 96) {
      lines.push(current);
      current = ' ';
    }
    current += piece;
  }
  if (current.trim()) lines.push(current);
  return lines.join('\n');
};

const out = `/**
 * Public Suffix List（自動生成 — 手で編集しない）
 *   生成元: ${SOURCE}
 *   生成日: ${new Date().toISOString().slice(0, 10)}
 *   再生成: node tools/build-psl.mjs${icannOnly ? ' --icann' : ''}
 *
 * 単一ラベルのTLDはPSLの既定ルール（未知のTLDはそれ自体がpublic suffix）で
 * 扱えるため収録していない。
 */

export const RULES = new Set([
${fmt(rules)}
]);

export const WILDCARDS = new Set([
${fmt(wildcards)}
]);

export const EXCEPTIONS = new Set([
${fmt(exceptions)}
]);

export const PSL_SOURCE = '${icannOnly ? 'publicsuffix.org (ICANN only)' : 'publicsuffix.org (full)'}';
`;

writeFileSync(OUT, out);
console.log(`psl-data.js を更新しました: rules=${rules.length} wildcards=${wildcards.length} exceptions=${exceptions.length}`);
