/**
 * データセットに対して判定精度を測る。
 *   node tools/evaluate.mjs data/phiusiil.csv --url-col=URL --label-col=label
 *   node tools/evaluate.mjs data/urls.csv --sweep
 *
 * CSVは1行目をヘッダとみなす。label は 1/0, phishing/legitimate, true/false を解釈する。
 * PhiUSIIL や OpenPhish/PhishTank のエクスポートをそのまま食わせられる。
 */
import { readFileSync } from 'node:fs';
import { analyzeUrl } from '../extension/src/core/analyze.js';

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith('--'));
if (!file) {
  console.error('使い方: node tools/evaluate.mjs <csv> [--url-col=URL] [--label-col=label] [--sweep] [--limit=N]');
  process.exit(1);
}
const opt = (name, fallback) => {
  const hit = args.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};
const urlCol = opt('url-col', 'url');
const labelCol = opt('label-col', 'label');
const limit = Number(opt('limit', Infinity));
const sweep = args.includes('--sweep');

function parseCsvLine(line) {
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

// データセットによってラベルの向きが違う（PhiUSIIL は 1=正規, 0=フィッシング）。
// --phishing-label=0 のように明示できる。
const explicitPhishing = opt('phishing-label', null);
const PHISH_LABELS = new Set(['1', 'phishing', 'phish', 'true', 'yes', 'malicious', 'bad']);
const isPhishing = (raw) => {
  const value = String(raw ?? '').trim().toLowerCase();
  if (explicitPhishing !== null) return value === String(explicitPhishing).toLowerCase();
  return PHISH_LABELS.has(value);
};

const lines = readFileSync(file, 'utf8').replace(/^\uFEFF/, '').split(/\r?\n/).filter(Boolean);
const header = parseCsvLine(lines[0]).map((h) => h.trim());
const iUrl = header.findIndex((h) => h.toLowerCase() === urlCol.toLowerCase());
const iLabel = header.findIndex((h) => h.toLowerCase() === labelCol.toLowerCase());
if (iUrl < 0) throw new Error(`URL列 "${urlCol}" が見つかりません。ヘッダ: ${header.join(', ')}`);
if (iLabel < 0) throw new Error(`ラベル列 "${labelCol}" が見つかりません。ヘッダ: ${header.join(', ')}`);

const rows = [];
for (const line of lines.slice(1, Number.isFinite(limit) ? limit + 1 : undefined)) {
  const cols = parseCsvLine(line);
  let url = (cols[iUrl] ?? '').trim();
  if (!url) continue;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = `http://${url}`;
  rows.push({ url, phishing: isPhishing(cols[iLabel]) });
}

console.log(`${rows.length} 件を判定します...`);
const scored = [];
const started = Date.now();
for (const row of rows) {
  const r = analyzeUrl(row.url);
  scored.push({ ...row, score: r.score, signals: r.signals?.map((s) => s.id) ?? [] });
}
const elapsed = Date.now() - started;

function metrics(threshold) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const s of scored) {
    const flagged = s.score >= threshold;
    if (s.phishing && flagged) tp++;
    else if (s.phishing) fn++;
    else if (flagged) fp++;
    else tn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const fpr = fp + tn ? fp / (fp + tn) : 0;
  return { threshold, tp, fp, tn, fn, precision, recall, f1, fpr };
}

const pct = (v) => `${(v * 100).toFixed(2)}%`;
const show = (m) =>
  `th=${m.threshold.toFixed(2)}  precision=${pct(m.precision)}  recall=${pct(m.recall)}  ` +
  `F1=${pct(m.f1)}  誤検知率=${pct(m.fpr)}  (TP=${m.tp} FP=${m.fp} FN=${m.fn} TN=${m.tn})`;

console.log(`判定時間: ${elapsed}ms (${(elapsed / rows.length).toFixed(3)}ms/件)\n`);
if (sweep) {
  for (let t = 0.3; t <= 0.96; t += 0.05) console.log(show(metrics(t)));
} else {
  console.log(show(metrics(0.55)), '← 注意しきい値');
  console.log(show(metrics(0.85)), '← ブロックしきい値');
}

// 誤りの上位を見て、ルールの当たり所を確認する
const fps = scored.filter((s) => !s.phishing && s.score >= 0.85).sort((a, b) => b.score - a.score).slice(0, 10);
const fns = scored.filter((s) => s.phishing && s.score < 0.55).sort((a, b) => a.score - b.score).slice(0, 10);
if (fps.length) {
  console.log('\n--- 誤検知の代表例 ---');
  for (const s of fps) console.log(`${s.score.toFixed(2)} ${s.url}\n     ${s.signals.join(', ')}`);
}
if (fns.length) {
  console.log('\n--- 見逃しの代表例 ---');
  for (const s of fns) console.log(`${s.score.toFixed(2)} ${s.url}`);
}
