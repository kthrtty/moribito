/**
 * 拡張アイコン(PNG)を生成する。外部依存なし（zlibでPNGを直接組み立てる）。
 *   node tools/make-icons.mjs
 */
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../extension/assets');
const SIZES = [16, 32, 48, 128];

function crc32(buf) {
  let c;
  const table = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  let crc = 0xffffffff;
  for (const b of buf) crc = table[(crc ^ b) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function png(size, pixels) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;   // bit depth
  ihdr[9] = 6;   // RGBA
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0; // filter: none
    pixels.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** 盾のシルエット + 中央の縦スラッシュ（「弾く」イメージ）。 */
function drawShield(size) {
  const px = Buffer.alloc(size * size * 4);
  const s = (v) => v * size;
  const set = (x, y, [r, g, b, a]) => {
    const i = (y * size + x) * 4;
    const srcA = a / 255;
    px[i] = Math.round(px[i] * (1 - srcA) + r * srcA);
    px[i + 1] = Math.round(px[i + 1] * (1 - srcA) + g * srcA);
    px[i + 2] = Math.round(px[i + 2] * (1 - srcA) + b * srcA);
    px[i + 3] = Math.min(255, px[i + 3] + a);
  };

  const SS = 3; // スーパーサンプリング
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let inShield = 0;
      let inMark = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const fx = (x + (sx + 0.5) / SS) / size;
          const fy = (y + (sy + 0.5) / SS) / size;
          if (shieldContains(fx, fy)) inShield++;
          if (markContains(fx, fy)) inMark++;
        }
      }
      const total = SS * SS;
      if (inShield) set(x, y, [26, 86, 219, Math.round((inShield / total) * 255)]);
      if (inMark) set(x, y, [255, 255, 255, Math.round((inMark / total) * 255)]);
    }
  }
  return px;

  function shieldContains(x, y) {
    if (y < 0.08 || y > 0.94) return false;
    const halfTop = 0.36;
    if (y <= 0.55) {
      return Math.abs(x - 0.5) <= halfTop && x > 0.13 && x < 0.87;
    }
    // 下half: 先細りの三角形
    const t = (y - 0.55) / (0.94 - 0.55);
    const half = halfTop * (1 - t * t);
    return Math.abs(x - 0.5) <= half;
  }

  function markContains(x, y) {
    // 中央の斜めスラッシュ
    const d = Math.abs((x - 0.5) + (y - 0.5) * 0.45);
    return d < 0.075 && y > 0.22 && y < 0.78;
  }
}

mkdirSync(OUT_DIR, { recursive: true });
for (const size of SIZES) {
  const buf = png(size, drawShield(size));
  writeFileSync(resolve(OUT_DIR, `icon${size}.png`), buf);
  console.log(`assets/icon${size}.png  ${buf.length} bytes`);
}
