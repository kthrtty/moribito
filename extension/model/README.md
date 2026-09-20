# ここに学習済みモデルを置く（任意）

```
url-clf.onnx   文字レベル分類器
meta.json      { modelFile, maxLen, vocab, padIndex, oovIndex }
```

あわせて `extension/vendor/` に onnxruntime-web（ESM版 `ort.wasm.min.mjs` と
対応する `.wasm`）を置き、設定画面で「ローカル分類器を使う」をONにする。

置かなくても拡張は動く。その場合はルールのみで判定し、
設定画面のモデル状態は「モデル未配置（ルールのみ）」と表示される。

作り方は `tools/train/README.md` を参照。
