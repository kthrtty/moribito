#!/usr/bin/env python3
"""URLの文字レベルCNNを学習し、拡張が読めるONNX + meta.jsonを書き出す。

    python3 tools/train/train_charcnn.py data/labeled.csv --out extension/model

入力CSVは url,soft_label（0.0〜1.0の確率）。0/1のハードラベルでも動く。
モデルは意図的に小さい（数百KB〜数MB）。ブラウザのワーカーで数ms級に収める。
"""
import argparse, csv, json, math, os, random
import torch
import torch.nn as nn

MAX_LEN = 200
VOCAB = "abcdefghijklmnopqrstuvwxyz0123456789:/?.-_=&%@+~#[]!$'()*,;"
PAD, OOV = 0, 1


def encode(url: str):
    ids = [PAD] * MAX_LEN
    for i, ch in enumerate(url.lower()[:MAX_LEN]):
        ids[i] = VOCAB.index(ch) + 2 if ch in VOCAB else OOV
    return ids


class CharCNN(nn.Module):
    def __init__(self, vocab_size, emb=32, channels=96):
        super().__init__()
        self.emb = nn.Embedding(vocab_size, emb, padding_idx=PAD)
        self.convs = nn.ModuleList(
            [nn.Conv1d(emb, channels, k, padding=k // 2) for k in (3, 4, 5)]
        )
        self.drop = nn.Dropout(0.3)
        self.fc = nn.Linear(channels * 3, 1)

    def forward(self, x):
        h = self.emb(x).transpose(1, 2)
        pooled = [torch.relu(c(h)).max(dim=2).values for c in self.convs]
        return self.fc(self.drop(torch.cat(pooled, dim=1))).squeeze(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--out", default="extension/model")
    ap.add_argument("--epochs", type=int, default=6)
    ap.add_argument("--batch", type=int, default=256)
    ap.add_argument("--lr", type=float, default=2e-3)
    args = ap.parse_args()

    rows = []
    with open(args.csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            url = (row.get("url") or "").strip()
            label = row.get("soft_label") or row.get("label") or ""
            if not url:
                continue
            try:
                y = float(label)
            except ValueError:
                y = 1.0 if label.strip().lower() in {"phishing", "phish", "1", "true"} else 0.0
            rows.append((url, min(max(y, 0.0), 1.0)))

    random.seed(0)
    random.shuffle(rows)
    split = int(len(rows) * 0.9)
    train, valid = rows[:split], rows[split:]
    print(f"train={len(train)} valid={len(valid)}")

    def batches(data, size, shuffle=True):
        idx = list(range(len(data)))
        if shuffle:
            random.shuffle(idx)
        for i in range(0, len(idx), size):
            chunk = [data[j] for j in idx[i : i + size]]
            x = torch.tensor([encode(u) for u, _ in chunk], dtype=torch.long)
            y = torch.tensor([v for _, v in chunk], dtype=torch.float)
            yield x, y

    model = CharCNN(len(VOCAB) + 2)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr)
    lossf = nn.BCEWithLogitsLoss()  # ソフトラベルをそのまま受けられる

    for epoch in range(args.epochs):
        model.train()
        total = 0.0
        for x, y in batches(train, args.batch):
            opt.zero_grad()
            loss = lossf(model(x), y)
            loss.backward()
            opt.step()
            total += loss.item() * len(y)
        model.eval()
        correct = seen = 0
        with torch.no_grad():
            for x, y in batches(valid, args.batch, shuffle=False):
                pred = torch.sigmoid(model(x)) >= 0.5
                correct += (pred == (y >= 0.5)).sum().item()
                seen += len(y)
        acc = correct / seen if seen else float("nan")
        print(f"epoch {epoch + 1}: loss={total / len(train):.4f} val_acc={acc:.4f}")

    os.makedirs(args.out, exist_ok=True)
    onnx_path = os.path.join(args.out, "url-clf.onnx")
    model.eval()
    torch.onnx.export(
        model,
        torch.zeros(1, MAX_LEN, dtype=torch.long),
        onnx_path,
        input_names=["input_ids"],
        output_names=["logit"],
        dynamic_axes={"input_ids": {0: "batch"}, "logit": {0: "batch"}},
        opset_version=17,
    )

    meta = {
        "modelFile": "url-clf.onnx",
        "maxLen": MAX_LEN,
        "padIndex": PAD,
        "oovIndex": OOV,
        "vocab": {ch: i + 2 for i, ch in enumerate(VOCAB)},
        "note": "拡張の encodeUrl はこの vocab を使う。学習側と必ず一致させること。",
    }
    with open(os.path.join(args.out, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    size = os.path.getsize(onnx_path) / 1024
    print(f"書き出しました: {onnx_path} ({size:.0f} KB) と meta.json")


if __name__ == "__main__":
    main()
