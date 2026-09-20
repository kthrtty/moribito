/**
 * ホスト型の確率判定モデルでURLにソフトラベルを付ける（開発時のみ実行）。
 *
 *   node tools/train/label_with_jev.mjs <in.csv> <out.csv> --endpoint=<URL> [--concurrency=8]
 *   環境変数 CLASSIFIER_API_KEY に APIキーを入れる
 *
 * 注意:
 *  - 出力は「フィッシングである確率」。蒸留ではこの確率をそのまま教師に使う
 *    （0/1に丸めない。確率のままの方が小型モデルの学習効率が良い）。
 *  - リクエスト/レスポンス形式は提供元の仕様に合わせて buildRequest / readProbability を
 *    書き換えること。ここでは「テキストと選択肢を渡すと選択肢ごとの確率が返る」
 *    という一般的な分類APIの形を仮に置いている。
 *  - この処理は拡張の実行時には一切走らない。
 */
import { readFileSync, writeFileSync } from 'node:fs';

const [inFile, outFile] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const arg = (name, fallback) => {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};
const endpoint = arg('endpoint');
const concurrency = Number(arg('concurrency', 8));
const apiKey = process.env.CLASSIFIER_API_KEY;

if (!inFile || !outFile || !endpoint) {
  console.error('使い方: node tools/train/label_with_jev.mjs <in.csv> <out.csv> --endpoint=<URL>');
  process.exit(1);
}
if (!apiKey) {
  console.error('環境変数 CLASSIFIER_API_KEY が未設定です。');
  process.exit(1);
}

const LABELS = ['benign', 'suspicious', 'phishing'];

function buildRequest(url) {
  return {
    input: url,
    question: 'このURLはフィッシングサイトのものか',
    choices: LABELS,
    return_probabilities: true,
  };
}

function readProbability(payload) {
  // 期待する形: { probabilities: { benign: 0.1, suspicious: 0.2, phishing: 0.7 } }
  const p = payload?.probabilities ?? payload?.scores;
  if (!p) throw new Error(`確率を読み取れません: ${JSON.stringify(payload).slice(0, 200)}`);
  const phishing = Number(p.phishing ?? 0);
  const suspicious = Number(p.suspicious ?? 0);
  return Math.min(1, phishing + suspicious * 0.5);
}

const lines = readFileSync(inFile, 'utf8').split(/\r?\n/).filter(Boolean);
const header = lines[0];
const urls = lines.slice(1).map((l) => l.split(',')[0].replace(/^"|"$/g, '').trim()).filter(Boolean);
console.log(`${urls.length} 件にラベルを付けます (並列${concurrency})`);

const results = new Array(urls.length);
let cursor = 0;
let done = 0;

async function worker() {
  while (cursor < urls.length) {
    const index = cursor++;
    const url = urls[index];
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
        body: JSON.stringify(buildRequest(url)),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      results[index] = readProbability(await res.json());
    } catch (err) {
      console.warn(`skip ${url}: ${err.message}`);
      results[index] = null;
    }
    if (++done % 250 === 0) console.log(`  ${done}/${urls.length}`);
  }
}

await Promise.all(Array.from({ length: concurrency }, worker));

const out = ['url,soft_label'];
urls.forEach((url, i) => {
  if (results[i] === null) return;
  out.push(`"${url}",${results[i].toFixed(4)}`);
});
writeFileSync(outFile, out.join('\n'));
console.log(`${out.length - 1} 件を ${outFile} に書き出しました（元ヘッダ: ${header}）`);
