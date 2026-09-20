/**
 * UTS #39 confusables の実用サブセット。
 * skeleton(): 見た目が同じ文字をASCIIへ畳み込む（判定の中核）
 * collapse():  skeleton に加えて数字置換・複数文字トリック(rn→m 等)まで畳み込む
 *              ブランド名との類似照合専用で、意味が変わるので表示には使わない。
 *
 * 完全版を使いたい場合は tools/build-confusables.mjs で
 * Unicode の confusables.txt から生成し直すこと。
 */
import { stripInvisible } from './unicode.js';
import { CONFUSABLE_TARGETS } from './confusables-data.js';


const MAP = new Map();
for (const [target, sources] of Object.entries(CONFUSABLE_TARGETS)) {
  for (const ch of sources) MAP.set(ch, target);
}

// 数字→英字（ブランド類似照合でのみ使う。例: g00gle → google）
const DIGIT_MAP = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b', 9: 'g' };

// ASCII複数文字による字形トリック（例: rnicrosoft → microsoft）
const MULTI_CHAR = [
  [/rn/g, 'm'],
  [/vv/g, 'w'],
  [/cl/g, 'd'],
  [/nn/g, 'm'],
  [/ii/g, 'n'],
];

/**
 * 見た目の骨格（skeleton）を得る。
 * NFKD → 結合記号除去 → 小文字化 → confusables置換。
 */
export function skeleton(input) {
  const base = stripInvisible(String(input ?? ''))
    .normalize('NFKD')
    .replace(/\p{M}+/gu, '')
    .toLowerCase();
  let out = '';
  for (const ch of base) out += MAP.get(ch) ?? ch;
  return out;
}

/** ブランド照合用により強く畳み込む（数字・複数文字トリック・区切り除去）。 */
export function collapse(input) {
  let s = skeleton(input).replace(/[^a-z0-9]+/g, '');
  s = s.replace(/[01345789]/g, (d) => DIGIT_MAP[d] ?? d);
  for (const [re, to] of MULTI_CHAR) s = s.replace(re, to);
  return s;
}

/** skeleton 適用で変化した＝非ASCIIの字形置換が起きたか。 */
export function hasConfusable(input) {
  const s = stripInvisible(String(input ?? ''));
  if (/^[\x00-\x7f]*$/.test(s)) return false;
  return skeleton(s) !== s.toLowerCase();
}
