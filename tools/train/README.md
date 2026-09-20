# ローカル分類器の作り方（任意）

ルールだけで大半は判定できるので、この工程は**やらなくても拡張は動く**。
グレーゾーン（既定では score 0.35〜0.90）の精度を上げたいときだけ実施する。

## 方針: ホスト型モデルで教師ラベルを作り、小型モデルに蒸留する

```
 データセット ──┐
 (PhiUSIIL,     │  1) label_with_jev.mjs   確率付きソフトラベルを付与（開発時のみ・オフライン）
  homograph,    ├─▶ 2) train_charcnn.py    文字レベルCNNを学習 → ONNX 出力
  dnstwist生成) │  3) extension/model/ に配置
 ────────────┘  4) 設定画面で「ローカル分類器を使う」をON
```

実行時に外部APIを呼ばないのが要点。閲覧中のURLを外へ出さないため、
ホスト型モデルは**開発時のラベル付けにしか使わない**。

## データセットの候補

| 用途 | データ |
|---|---|
| 実URLの陽性/陰性 | PhiUSIIL Phishing URL Dataset (UCI, CC BY 4.0) |
| ホモグリフ/混在スクリプト | Kaggle の adversarial homograph 系データセット |
| 自社ブランドの陰陽ペア生成 | `dnstwist -r --tld tlds.txt example.co.jp` |
| 鮮度の高い実物 | PhishTank / OpenPhish のフィード |

陰性側に「紛らわしいが正規」なURL（長いサブドメイン、CDN、ハイフン入りの
正規ドメインなど）を多めに混ぜないと、誤検知しやすいモデルになる。

## 1) ラベル付け

```bash
node tools/train/label_with_jev.mjs data/urls.csv data/labeled.csv \
  --endpoint=https://api.example.com/v1/classify --concurrency=8
```

`--endpoint` と認証はスクリプト先頭のコメントを参照。APIのリクエスト形式は
提供元のドキュメントで必ず確認すること（このスクリプトは差し替え前提の実装）。

## 2) 学習と ONNX 化

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install torch onnx onnxruntime numpy
python3 tools/train/train_charcnn.py data/labeled.csv --out extension/model
```

## 3) 配置

```
extension/model/url-clf.onnx   学習済みモデル
extension/model/meta.json      { modelFile, maxLen, vocab, padIndex, oovIndex }
extension/vendor/ort.wasm.min.mjs + *.wasm   onnxruntime-web
```

`meta.json` の vocab は学習時と**完全に同じ**ものを使うこと。
ずれると推論結果が無意味になる（拡張側の encodeUrl がこれを読む）。

## 4) 効果測定

```bash
node tools/evaluate.mjs data/holdout.csv --sweep
```

学習に使っていない hold-out で測ること。
既存ルールと同じデータで調整すると数字だけが良くなる。
