/**
 * RFC 3492 Punycode デコーダ（xn-- ラベルを Unicode に戻す）。
 * URLパーサはIDNをASCII(xn--)化するため、人間が見る文字列へ復元するのに使う。
 */

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const MAX_INT = 0x7fffffff;

function basicToDigit(cp) {
  // 範囲の下限も必ず見る。下限を省くと '!' のような不正文字を
  // 数字として受理してしまい、Chrome本体と復号結果がずれる。
  if (cp >= 0x30 && cp <= 0x39) return cp + 26 - 0x30; // '0'-'9' -> 26..35
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41;      // 'A'-'Z' -> 0..25
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61;      // 'a'-'z' -> 0..25
  return BASE;
}

function adapt(delta, numPoints, firstTime) {
  let k = 0;
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  for (; d > ((BASE - TMIN) * TMAX) >> 1; k += BASE) {
    d = Math.floor(d / (BASE - TMIN));
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

/** Punycode本体（xn--を除いた部分）をデコードする。失敗時は例外。 */
export function decodeLabel(input) {
  const output = [];
  const basic = input.lastIndexOf('-');
  const basicLen = basic < 0 ? 0 : basic;

  for (let j = 0; j < basicLen; j++) {
    const cp = input.charCodeAt(j);
    if (cp >= 0x80) throw new RangeError('not-basic');
    output.push(cp);
  }

  let n = INITIAL_N;
  let bias = INITIAL_BIAS;
  let i = 0;
  let index = basic < 0 ? 0 : basic + 1;

  while (index < input.length) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new RangeError('invalid-input');
      const digit = basicToDigit(input.charCodeAt(index++));
      if (digit >= BASE) throw new RangeError('invalid-input');
      if (digit > Math.floor((MAX_INT - i) / w)) throw new RangeError('overflow');
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      const baseMinusT = BASE - t;
      if (w > Math.floor(MAX_INT / baseMinusT)) throw new RangeError('overflow');
      w *= baseMinusT;
    }

    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    if (Math.floor(i / out) > MAX_INT - n) throw new RangeError('overflow');
    n += Math.floor(i / out);
    i %= out;
    output.splice(i++, 0, n);
  }

  return String.fromCodePoint(...output);
}

/** ホスト名中の xn-- ラベルをUnicodeへ。壊れたラベルはそのまま残す。 */
export function toUnicode(hostname) {
  if (!hostname) return '';
  return String(hostname)
    .split('.')
    .map((label) => {
      if (!/^xn--/i.test(label)) return label;
      try {
        return decodeLabel(label.slice(4));
      } catch {
        return label;
      }
    })
    .join('.');
}

export function punycodeLabels(hostname) {
  return String(hostname || '')
    .split('.')
    .filter((l) => /^xn--/i.test(l));
}
