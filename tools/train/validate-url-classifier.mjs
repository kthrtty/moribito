/**
 * 学習済み分類器を、**学習に使っていない別コーパス**で検証する。
 *
 *   node tools/train/validate-url-classifier.mjs [extension/model/url-classifier.json]
 *
 * なぜ必要か:
 *   同じデータセットを分割しただけの検証では、そのデータセット固有の癖を
 *   学んでいても高いスコアが出る。実際、最初に学習したモデルは
 *   ドメイン単位で分割した検証でAUC 0.94だったが、正規サイトの
 *   github.com や docs.google.com をフィッシング扱いした
 *   （PhiUSIIL の正規側が www. 付きトップページ中心だったため、
 *     「www. で始まれば正規」という癖を学んでいた）。
 *
 * 出荷判断はこのスクリプトの結果で行う。
 */
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadModel, predictHost } from '../../extension/src/core/url-classifier.js';
import { BENIGN, PHISHING, SUSPICIOUS } from '../../tests/fixtures/urls.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const path = resolve(ROOT, process.argv[2] ?? 'extension/model/url-classifier.json');
const thArg = process.argv.find((a) => a.startsWith('--th='))?.slice('--th='.length);
const threshold = Number(thArg ?? 0.85);
if (!Number.isFinite(threshold)) throw new Error(`しきい値を解釈できません: ${thArg}`);

const model = loadModel(JSON.parse(readFileSync(path, 'utf8')));
if (!model) throw new Error(`モデルを読み込めません: ${path}`);

const hostOf = (url) => new URL(url).hostname;
const rows = [
  ...BENIGN.map((url) => ({ url, expect: 'benign' })),
  ...PHISHING.map((url) => ({ url, expect: 'phishing' })),
  ...SUSPICIOUS.map((url) => ({ url, expect: 'phishing' })),
].map((row) => ({ ...row, host: hostOf(row.url), p: predictHost(hostOf(row.url), model) }));

console.log(`モデル: ${path.split('/').pop()}`);
console.log(`  範囲=${model.scope}  buckets=${model.buckets}  学習=${model.trainedAt ?? '不明'}`);
if (model.metrics) console.log(`  同データセット内の検証AUC: ${model.metrics.aucTest?.toFixed(4)}`);
console.log(`  判定しきい値: ${threshold}\n`);

const benign = rows.filter((r) => r.expect === 'benign');
const phishing = rows.filter((r) => r.expect === 'phishing');
const falsePositives = benign.filter((r) => r.p >= threshold);
const detected = phishing.filter((r) => r.p >= threshold);

const line = (r, mark) => `${mark} ${r.p.toFixed(3)}  ${r.host}`;
console.log('--- 正規サイト（しきい値を超えたら誤検知） ---');
for (const r of benign.sort((a, b) => b.p - a.p)) console.log(line(r, r.p >= threshold ? '誤検知' : '    '));
console.log('\n--- フィッシング（しきい値を超えたら検出） ---');
for (const r of phishing.sort((a, b) => b.p - a.p)) console.log(line(r, r.p >= threshold ? ' 検出 ' : '見逃し'));

const fpRate = falsePositives.length / benign.length;
const recall = detected.length / phishing.length;
console.log(`\n誤検知 ${falsePositives.length}/${benign.length} (${(fpRate * 100).toFixed(1)}%)`);
console.log(`検出   ${detected.length}/${phishing.length} (${(recall * 100).toFixed(1)}%)`);

// 出荷可否の目安: 正規サイトを1件でも誤検知するなら、常駐ツールとしては使えない
const verdict = falsePositives.length === 0 && recall >= 0.5;
console.log(`\n判定: ${verdict ? '出荷可（このコーパスでは誤検知ゼロ）' : '出荷不可'}`);
if (!verdict && falsePositives.length) {
  console.log(`  理由: 正規サイトを${falsePositives.length}件誤検知している`);
  console.log(`  ${falsePositives.map((r) => r.host).join(', ')}`);
}
process.exitCode = verdict ? 0 : 1;
