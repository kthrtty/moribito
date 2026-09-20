/**
 * 特徴量 → 危険信号（signal）へ変換するルール層。
 * weight は「この1つだけで見たときの、フィッシングである確からしさ」。
 * 合成は noisy-OR（score.js）で行う。
 */
import {
  BRANDS, FILLER_TOKENS, SENSITIVE_WORDS, FREE_HOSTING, SUSPICIOUS_TLDS, brandOwning,
} from './brands.js';
import { collapse } from './confusables.js';
import { levenshtein } from './text.js';
import { splitHost } from './psl.js';

// ありふれた一般語。ブランド名と1文字違いになることがあるので
// タイポスクワット候補から外す（finance と binance など）。
const COMMON_WORDS = new Set([
  'finance', 'financial', 'service', 'services', 'online', 'secure', 'market',
  'markets', 'digital', 'global', 'office', 'support', 'mobile', 'media',
  'health', 'travel', 'estate', 'capital', 'energy', 'network', 'systems',
  'solution', 'solutions', 'partner', 'partners', 'center', 'centre', 'group',
  'holdings', 'company', 'studio', 'design', 'school', 'college', 'institute',
  'community', 'magazine', 'monthly', 'weekly', 'journal', 'review', 'daily',
  'science', 'medical', 'clinic', 'garden', 'kitchen', 'coffee', 'fitness',
  'academy', 'agency', 'consulting', 'engineering', 'research', 'technology',
]);

const SENSITIVE_SET = new Set(SENSITIVE_WORDS);
// public suffix に見せかけてサブドメインに置かれる語
const FAKE_SUFFIX_TOKENS = new Set(['com', 'net', 'org', 'jp', 'co', 'ne', 'or', 'go', 'gov', 'edu']);

/** 既知リスト一致の信号。同期経路とパイプラインの両方から使う。 */
export function knownPhishingSignal(hit) {
  const weight = { url: 0.99, host: 0.97, domain: 0.95 }[hit.kind] ?? 0.95;
  const where = { url: 'このURL', host: 'このホスト', domain: 'このドメイン' }[hit.kind] ?? '一致';
  return {
    id: 'known-phishing',
    kind: hit.kind,
    weight,
    title: '既知のフィッシングサイトとして報告されています',
    detail: `${where} が、配布されているフィッシング報告リストと一致しました。`,
    from: 'list',
  };
}

/** ブランド語の長さに応じた信頼度（短い語は誤検知しやすいので割り引く）。 */
function tokenStrength(token) {
  if (token.length >= 6) return 1;
  if (token.length === 5) return 0.95;
  if (token.length === 4) return 0.85;
  return 0.6;
}

/** トークンがブランド語（+よくある修飾語）に一致するか。 */
export function matchBrandToken(token, brand) {
  for (const bt of brand.tokens) {
    if (!/^[a-z0-9]+$/.test(bt)) continue; // 日本語エイリアスは別経路で見る
    if (token === bt) return { brandToken: bt, kind: 'exact' };
    if (bt.length >= 4 && token.length > bt.length) {
      if (token.startsWith(bt) && FILLER_TOKENS.has(token.slice(bt.length))) {
        return { brandToken: bt, kind: 'prefixed' };
      }
      if (token.endsWith(bt) && FILLER_TOKENS.has(token.slice(0, -bt.length))) {
        return { brandToken: bt, kind: 'suffixed' };
      }
    }
  }
  return null;
}

function findBrandInTokens(tokens, brands) {
  for (const token of tokens) {
    for (const brand of brands) {
      const hit = matchBrandToken(token, brand);
      if (hit) return { brand, token, ...hit };
    }
  }
  return null;
}

// ブランド語そのものの集合。paypal と paypay のように実在ブランド同士が
// 1文字違いのことがあるため、「既知のブランド語」はタイポ候補から外す。
const brandWordCache = new Map();
function brandWordSet(brands) {
  let set = brandWordCache.get(brands);
  if (set) return set;
  set = new Set();
  for (const brand of brands) {
    for (const t of brand.tokens) set.add(collapse(t));
    for (const d of brand.domains) set.add(collapse(d.split('.')[0]));
  }
  set.delete('');
  brandWordCache.set(brands, set);
  return set;
}

/** 登録ドメインが「正規ブランドの見た目そっくり」かを調べる。 */
function findLookalike(f, brands) {
  const skel = f.skelRegistrable;
  const collapsedName = f.collapsedName;
  // 「mercarl-jp.shop」のようにブランド語がトークンの片方だけの場合も見る
  const brandWords = brandWordSet(brands);
  const candidates = [...new Set([collapsedName, ...f.nameTokens.map((t) => collapse(t))])]
    .filter((c) => c.length >= 5 && !brandWords.has(c) && !COMMON_WORDS.has(c));

  for (const brand of brands) {
    for (const domain of brand.domains) {
      if (domain === f.registrable) return null; // 本物
      // 1. ホモグリフを畳み込むと正規ドメインと完全一致
      if (skel === domain && skel !== f.registrable) {
        return { brand, domain, kind: 'homoglyph-exact', distance: 0 };
      }
      // 'e-tax.nta.go.jp' の正規名は 'nta'。先頭ラベルではなく登録ドメイン名を使う。
      const brandName = splitHost(domain).name || domain.split('.')[0];
      if (brandName.length < 5) continue;
      const collapsedBrand = collapse(brandName);
      if (!collapsedBrand) continue;

      // 2. 数字置換や rn→m まで畳み込むと一致（g00gle, rnicrosoft, pay-pal）
      if (collapsedName === collapsedBrand && f.name !== brandName) {
        return { brand, domain, kind: 'collapsed-exact', distance: 0 };
      }
      // 3. 1〜2文字違い（タイポスクワット）。
      //    完全一致は brand-in-domain-name 側の担当なので距離1以上だけ拾う。
      const maxDist = collapsedBrand.length >= 8 ? 2 : 1;
      for (const cand of candidates) {
        const d = levenshtein(cand, collapsedBrand, maxDist);
        if (d >= 1 && d <= maxDist) {
          return { brand, domain, kind: 'typosquat', distance: d };
        }
      }
    }
  }
  return null;
}

/**
 * 危険信号の一覧を返す。
 * @returns {Array<{id:string, weight:number, title:string, detail:string}>}
 */
export function evaluateRules(f, opt = {}) {
  const brands = opt.brands ?? BRANDS;
  const signals = [];
  const add = (id, weight, title, detail) => signals.push({ id, weight, title, detail });

  if (!f.ok) {
    add('invalid-url', 0.5, 'URLとして解釈できません', `解析に失敗しました: ${f.error}`);
    return signals;
  }

  const owner = brandOwning(f.registrable);

  // --- 既知フィッシング（配布済みリストとのローカル照合） ---------------
  if (opt.blocklistHit) signals.push(knownPhishingSignal(opt.blocklistHit));

  // --- 文字レベルの偽装 -------------------------------------------------
  if (f.rawArtifacts.bidi) {
    add('bidi-control', 0.9, '文字の並びを反転させる制御文字',
      'BiDi制御文字が含まれています。表示上のURLと実際の宛先が食い違います。');
  }
  if (f.rawArtifacts.invisible) {
    add('invisible-char', 0.85, '目に見えない文字が埋め込まれています',
      'ゼロ幅文字などが含まれ、正規ドメインとの違いを隠しています。');
  }
  if (f.rawArtifacts.dotLookalike) {
    add('dot-lookalike', 0.7, 'ピリオドに似た別の文字',
      '「。」「．」などがドメイン区切りに見せかけて使われています。');
  }
  if (f.rawArtifacts.atSign || f.userinfo) {
    add('userinfo', 0.6, 'URLに「@」が含まれています',
      `@の前は無視されます。実際の接続先は ${f.host} です。`);
  }

  const lookalike = findLookalike(f, brands);
  if (lookalike) {
    const weights = { 'homoglyph-exact': 0.95, 'collapsed-exact': 0.88 };
    // 1文字違いは非常に強い証拠、2文字違いはやや弱める
    const label = weights[lookalike.kind] ?? (lookalike.distance <= 1 ? 0.8 : 0.65);
    add(`lookalike-${lookalike.kind}`, label,
      `正規ドメイン ${lookalike.domain} に似せたドメイン`,
      `「${f.registrableUnicode}」と表示されますが、実体は ${f.registrable} で、`
      + `${lookalike.brand.id} の正規ドメインではありません。`);
  }

  if (f.mixedScriptLabels.length > 0) {
    add('mixed-script', 0.65, '複数の文字体系が混在したドメイン',
      `${f.scripts.join(' / ')} が同じラベル内で混ざっています（例: ラテン文字とキリル文字）。`);
  } else if (f.hasPunycode && f.scriptKind === 'single' && !f.scripts.includes('Latin')) {
    add('non-latin-idn', 0.2, '非ラテン文字の国際化ドメイン',
      `${f.hostUnicode} と表示されます。意図した言語のサイトか確認してください。`);
  } else if (f.hasPunycode) {
    add('punycode', 0.25, '国際化ドメイン（Punycode）',
      `実体は ${f.host} で、「${f.hostUnicode}」と表示されます。`);
  }

  // --- ブランド詐称 -----------------------------------------------------
  if (!owner) {
    const subHit = findBrandInTokens(f.subTokens, brands);
    if (subHit) {
      add('brand-in-subdomain', 0.85 * tokenStrength(subHit.brandToken),
        'サブドメインにブランド名、ただし別ドメイン',
        `「${subHit.token}」はサブドメインにあるだけで、実際の登録ドメインは ${f.registrable} です。`);
    }

    const nameHit = !subHit && findBrandInTokens(f.nameTokens, brands);
    if (nameHit && f.nameTokens.length > 1) {
      add('brand-in-domain-name', 0.7 * tokenStrength(nameHit.brandToken),
        'ドメイン名にブランド名を含む別サイト',
        `${f.registrable} は ${nameHit.brand.id} の正規ドメインではありません。`);
    }

    if (FREE_HOSTING.has(f.suffix) || FREE_HOSTING.has(f.registrable)) {
      const anyBrand = subHit ?? nameHit ?? findBrandInTokens(f.pathTokens, brands);
      if (anyBrand) {
        add('free-hosting-brand', 0.75, '無料ホスティング上のブランド名ページ',
          `${f.suffix || f.registrable} は誰でも開設できるホスティングです。`);
      }
    }

    if (!subHit && !nameHit) {
      const pathHit = findBrandInTokens(f.pathTokens, brands);
      const sensitivePath = f.pathTokens.some((t) => SENSITIVE_SET.has(t));
      if (pathHit && sensitivePath) {
        add('brand-in-path', 0.45, 'パスにブランド名とログイン誘導',
          `${f.registrable} は ${pathHit.brand.id} と無関係のドメインです。`);
      }
    }
  }

  // --- ドメイン構造 -----------------------------------------------------
  const fakeSuffixInSub = f.subTokens.filter((t) => FAKE_SUFFIX_TOKENS.has(t)).length;
  if (fakeSuffixInSub >= 2 || (fakeSuffixInSub >= 1 && f.subLabels.length >= 2)) {
    add('fake-suffix-in-subdomain', 0.55, '本物のドメインに見せかけたサブドメイン',
      `「${f.sub}」はアドレスバーで途中までしか見えないことを狙った構造です。`);
  }

  if (f.subLabels.length >= 4) {
    add('deep-subdomain', 0.35, 'サブドメインの階層が異常に深い',
      `${f.subLabels.length} 段のサブドメインがあります。`);
  } else if (f.subLabels.length === 3) {
    add('deep-subdomain-mild', 0.18, 'サブドメインが多め', `${f.sub}`);
  }

  if (f.subLength >= 25 && f.subEntropy >= 3.4) {
    add('random-subdomain', 0.45, '意味のないランダムなサブドメイン',
      'アドレスバーに収まらない長さにして、本当のドメインを隠す手口です。');
  }
  if (f.name.length >= 10 && f.nameEntropy >= 3.4 && f.maxConsonantRun >= 5) {
    add('random-domain-name', 0.4, '機械生成されたようなドメイン名', `${f.registrable}`);
  }
  if (f.hyphenCount >= 4) {
    add('many-hyphens', 0.3, 'ハイフンが多いドメイン', `ハイフン ${f.hyphenCount} 個。`);
  }
  if (f.digitRatioName >= 0.35 && f.name.length >= 6) {
    add('digit-heavy-domain', 0.25, '数字の比率が高いドメイン名', `${f.registrable}`);
  }

  if (f.isIp) {
    const sensitive = f.pathTokens.some((t) => SENSITIVE_SET.has(t));
    add('ip-host', sensitive ? 0.7 : 0.5,
      'ドメイン名ではなくIPアドレス',
      sensitive ? 'IPアドレス直打ちでログイン系ページを開こうとしています。' : `接続先: ${f.host}`);
  }
  if (f.hasNonStandardPort) {
    add('nonstandard-port', 0.3, '通常使われないポート番号', `ポート ${f.port}`);
  }
  if (SUSPICIOUS_TLDS.has(f.tld)) {
    add('suspicious-tld', 0.35, '濫用が多いTLD', `.${f.tld} は無料・低価格で大量取得されやすいTLDです。`);
  }

  // --- 文脈 -------------------------------------------------------------
  const hostSensitive = [...f.subTokens, ...f.nameTokens].filter((t) => SENSITIVE_SET.has(t));
  if (hostSensitive.length > 0 && !owner) {
    add('sensitive-word-host', hostSensitive.length >= 2 ? 0.45 : 0.35,
      'ドメインに認証を連想させる語',
      `「${hostSensitive.join('」「')}」が含まれます。`);
  }
  if (!f.isHttps) {
    const sensitive = hostSensitive.length > 0 || f.pathTokens.some((t) => SENSITIVE_SET.has(t));
    add('insecure-scheme', sensitive ? 0.4 : 0.15,
      '暗号化されていない接続 (http)',
      sensitive ? '認証情報を入力させるページが http です。' : 'httpsではありません。');
  }
  if (f.urlLength >= 150) {
    add('very-long-url', 0.2, '極端に長いURL', `${f.urlLength} 文字。`);
  }

  return signals;
}
