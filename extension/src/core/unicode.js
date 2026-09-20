/**
 * スクリプト（文字体系）判定と、不可視文字・BiDi・ドット偽装の検出。
 * UTS #39 の restriction level を簡略化して実装している。
 */

// 目視できない/方向を反転させる制御文字
export const INVISIBLE_RE =
  /[­᠎​‌‍⁠-⁤⁪-⁯﻿￹-￻]/u;
export const BIDI_RE = /[‎‏‪-‮⁦-⁩]/u;

// '.' に見える文字（IDNAマッピング前の生文字列で使う）
export const DOT_LOOKALIKES = ['。', '．', '｡', '․', '‧', '﹒', '·', '∙'];
const DOT_LOOKALIKE_RE = new RegExp(`[${DOT_LOOKALIKES.join('')}]`, 'u');

// 正規表現で判定するスクリプト。環境が未対応ならその項目だけ落とす。
const SCRIPT_NAMES = [
  'Latin', 'Cyrillic', 'Greek', 'Armenian', 'Hebrew', 'Arabic', 'Han', 'Hiragana',
  'Katakana', 'Hangul', 'Thai', 'Devanagari', 'Bengali', 'Tamil', 'Cherokee',
  'Georgian', 'Ethiopic', 'Myanmar', 'Khmer', 'Lao', 'Coptic', 'Tifinagh',
  'Vai', 'Osage', 'Deseret', 'Bopomofo',
];

const SCRIPT_TESTS = [];
for (const name of SCRIPT_NAMES) {
  try {
    SCRIPT_TESTS.push([name, new RegExp(`\\p{Script=${name}}`, 'u')]);
  } catch {
    // このランタイムが知らないスクリプト名は無視する
  }
}

// 共存が自然な組み合わせ（日本語・中国語・韓国語）
const ALLOWED_COMBINATIONS = [
  new Set(['Latin', 'Han', 'Hiragana', 'Katakana']),
  new Set(['Latin', 'Han', 'Bopomofo']),
  new Set(['Latin', 'Han', 'Hangul']),
  new Set(['Latin', 'Han']),
];

export function stripInvisible(s) {
  return String(s).replace(new RegExp(INVISIBLE_RE, 'gu'), '');
}

export function hasInvisible(s) {
  return INVISIBLE_RE.test(String(s));
}

export function hasBidiControl(s) {
  return BIDI_RE.test(String(s));
}

export function hasDotLookalike(s) {
  return DOT_LOOKALIKE_RE.test(String(s));
}

/** 文字列に含まれるスクリプト名の集合（Common/Inherited は数えない）。 */
export function scriptsOf(s) {
  const found = new Set();
  const text = stripInvisible(s);
  for (const ch of text) {
    if (!/\p{L}|\p{N}/u.test(ch)) continue;
    for (const [name, re] of SCRIPT_TESTS) {
      if (re.test(ch)) {
        found.add(name);
        break;
      }
    }
  }
  return found;
}

/**
 * 混在スクリプトの判定結果を返す。
 * kind: 'ascii' | 'single' | 'allowed-cjk' | 'mixed'
 */
export function scriptProfile(s) {
  const text = stripInvisible(s);
  if (!text) return { kind: 'ascii', scripts: [] };
  if (/^[\x00-\x7f]*$/.test(text)) return { kind: 'ascii', scripts: ['Latin'] };

  const scripts = scriptsOf(text);
  const list = [...scripts];

  if (scripts.size <= 1) {
    return { kind: 'single', scripts: list, latin: scripts.has('Latin') };
  }
  for (const allowed of ALLOWED_COMBINATIONS) {
    if (list.every((n) => allowed.has(n))) {
      return { kind: 'allowed-cjk', scripts: list };
    }
  }
  return { kind: 'mixed', scripts: list };
}

/** ラベル単位で混在スクリプトを探す（UTS39はラベル単位で評価するため）。 */
export function mixedScriptLabels(hostname) {
  return String(hostname || '')
    .split('.')
    .filter((label) => scriptProfile(label).kind === 'mixed');
}

/**
 * ページ由来の文字列を、警告画面に出す前に無害化する。
 *
 * BiDi制御文字を残したまま警告文へ埋めると、警告の表示そのものを
 * 攻撃者が反転・改変できてしまう（表示偽装）。長さも必ず打ち切る。
 */
export function sanitizeForDisplay(text, maxLength = 120) {
  return stripInvisible(String(text ?? ''))
    .replace(new RegExp(BIDI_RE, 'gu'), '')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength);
}
