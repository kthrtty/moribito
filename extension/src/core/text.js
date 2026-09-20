/** 文字列系のユーティリティ（依存なし）。 */

/** 上限付きレーベンシュタイン距離。max超はmax+1を返す（早期打ち切り）。 */
export function levenshtein(a, b, max = Infinity) {
  const s = String(a);
  const t = String(b);
  if (s === t) return 0;
  if (Math.abs(s.length - t.length) > max) return max + 1;
  if (!s.length) return t.length;
  if (!t.length) return s.length;

  let prev = new Array(t.length + 1);
  let cur = new Array(t.length + 1);
  for (let j = 0; j <= t.length; j++) prev[j] = j;

  for (let i = 1; i <= s.length; i++) {
    cur[0] = i;
    let rowMin = cur[0];
    for (let j = 1; j <= t.length; j++) {
      const cost = s[i - 1] === t[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    [prev, cur] = [cur, prev];
  }
  return prev[t.length];
}

/** シャノンエントロピー（bit/文字）。ランダム文字列の判定に使う。 */
export function shannonEntropy(s) {
  const str = String(s);
  if (!str.length) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** 英数トークンへ分解する。 */
export function tokenize(s) {
  return String(s ?? '')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

export function digitRatio(s) {
  const str = String(s ?? '');
  if (!str.length) return 0;
  return (str.match(/\d/g) ?? []).length / str.length;
}

export function countOccurrences(s, ch) {
  return String(s ?? '').split(ch).length - 1;
}

/** 子音が連続する度合い（発音不能＝ランダム生成の指標）。 */
export function maxConsonantRun(s) {
  // 'y' は母音的にも使われるので数えない（monthly を機械生成と誤判定しないため）
  const m = String(s ?? '').toLowerCase().match(/[bcdfghjklmnpqrstvwxz]+/g);
  return m ? Math.max(...m.map((x) => x.length)) : 0;
}
