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
import { randomnessScore } from './naming.js';

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

// クラウドや社内システムのホスト名によく出る語。
// これらが並ぶ長いサブドメインは、隠すためではなく命名規則によるもの。
const INFRA_TOKENS = new Set([
  'api', 'gateway', 'gw', 'lb', 'elb', 'alb', 'nlb', 'cdn', 'edge', 'origin',
  'prod', 'production', 'stg', 'staging', 'dev', 'test', 'qa', 'sandbox',
  'internal', 'intranet', 'corp', 'svc', 'service', 'cluster', 'node', 'pod',
  'us', 'eu', 'ap', 'east', 'west', 'north', 'south', 'central', 'northeast',
  'compute', 'storage', 'db', 'cache', 'queue', 'ci', 'build', 'registry',
  'k8s', 'ingress', 'proxy', 'router', 'vpn', 'bastion', 'metrics', 'logs',
]);

/** 既知リスト一致の信号。同期経路とパイプラインの両方から使う。 */
export function knownPhishingSignal(hit) {
  const weight = { url: 0.99, host: 0.97, domain: 0.95 }[hit.kind] ?? 0.95;
  const where = { url: 'このURL', host: 'このホスト', domain: 'このドメイン' }[hit.kind] ?? '一致';
  const malware = hit.threat === 'malware';
  return {
    id: malware ? 'known-malware' : 'known-phishing',
    kind: hit.kind,
    threat: hit.threat ?? 'phishing',
    weight,
    title: malware
      ? '既知のマルウェア配布サイトとして報告されています'
      : '既知のフィッシングサイトとして報告されています',
    detail: malware
      ? `${where} が、マルウェアを配布しているとして報告されています。ファイルを開かないでください。`
      : `${where} が、配布されているフィッシング報告リストと一致しました。`,
    from: 'list',
  };
}

/**
 * 末尾の年号を除いた数字の比率。
 * project2024 や conference2019 は人が付ける名前なので、
 * 末尾の4桁年号を数字として数えない。
 */
function digitRatioIgnoringYear(name) {
  const withoutYear = String(name ?? '').replace(/(?:19|20)\d{2}$/, '');
  const digits = (withoutYear.match(/\d/g) ?? []).length;
  return digits / Math.max(1, withoutYear.length);
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
  // 数字置換（g00gle）や rn→m を畳み込んでから比較する。
  // 生の文字列だけで比べると g00gle-support.com が素通りする。
  const folded = collapse(token);
  for (const bt of brand.tokens) {
    if (!/^[a-z0-9]+$/.test(bt)) continue; // 日本語エイリアスは別経路で見る
    if (token === bt) return { brandToken: bt, kind: 'exact' };
    if (folded && folded === collapse(bt)) return { brandToken: bt, kind: 'folded' };
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

/**
 * ブランド名を崩した語を探す。
 * 編集距離2まで、または先頭4文字以上を共有するもの。
 * 単独では鳴らさず、登録ドメインが機械生成らしいときだけ使う。
 */
function findBrandLikeToken(tokens, brands) {
  for (const raw of tokens) {
    const token = collapse(raw);
    if (token.length < 4 || COMMON_WORDS.has(token)) continue;
    for (const brand of brands) {
      for (const domain of brand.domains) {
        const brandName = collapse(splitHost(domain).name || domain.split('.')[0]);
        if (brandName.length < 4 || token === brandName) continue;
        const sharedPrefix = Math.max(4, brandName.length - 1);
        if (token.length >= sharedPrefix && token.slice(0, sharedPrefix) === brandName.slice(0, sharedPrefix)) {
          return { brand, token: raw, reason: 'prefix' };
        }
        if (levenshtein(token, brandName, 2) <= 2) return { brand, token: raw, reason: 'distance' };
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
  // サブドメイン側のトークンも見る。
  // 「oricvn.zmbc3c.info」のように、使い捨てドメインの前にブランド名を
  // 少し崩して置く形は国内フィッシングで非常に多い。
  const candidates = [...new Set([
    collapsedName,
    ...f.nameTokens.map((t) => collapse(t)),
    ...f.subTokens.map((t) => collapse(t)),
  ])].filter((c) => c.length >= 5 && !brandWords.has(c) && !COMMON_WORDS.has(c));

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
      const platform = f.suffix || f.registrable;
      const anyBrand = subHit ?? nameHit ?? findBrandInTokens(f.pathTokens, brands);
      if (anyBrand) {
        add('free-hosting-brand', 0.75, '無料ホスティング上のブランド名ページ',
          `${platform} は誰でも開設できるホスティングです。`);
      } else {
        // ブランド名が無くても、使い捨てらしい名前なら弱い信号を出す。
        // 無料ホスティングは正規の個人サイトも多いので、名前の作りで差を付ける。
        add('free-hosting', 0.15, '誰でも開設できるホスティング上のページ',
          `${platform} は無料で取得できるため、使い捨てのフィッシングに使われます。`);

        // 末尾の年号（project2024 など）は人が付ける名前なので数字とみなさない
        const withoutYear = f.name.replace(/(?:19|20)\d{2}$/, '');
        const digitRatio = (withoutYear.match(/\d/g) ?? []).length / Math.max(1, withoutYear.length);
        const throwaway = f.maxConsonantRun >= 5 || digitRatio >= 0.2 || f.name.length >= 16;
        if (throwaway) {
          add('free-hosting-random', 0.5, '無料ホスティング上の自動生成らしい名前',
            `${f.registrable} は、人が付けた名前とは考えにくい作りです。`);
        }
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

  // 使い捨てドメインの前に、ブランド名を崩した語を置く形。
  //   oricvn.zmbc3c.info（orico）、vlew.xxxx.top（View）など国内で非常に多い。
  // 距離だけを緩めると ripple.com ↔ apple のような誤検知を生むので、
  // 「登録ドメインが機械生成らしい」ことと組み合わせたときだけ鳴らす。
  if (!owner && f.subTokens.length) {
    const nameRandomness = randomnessScore(f.nameUnicode) ?? 0;
    const throwawayHost = nameRandomness >= 0.5
      || (f.name.length >= 10 && f.maxConsonantRun >= 5);
    if (throwawayHost) {
      const nearBrand = findBrandLikeToken(f.subTokens, brands);
      if (nearBrand) {
        add('brandlike-sub-on-throwaway', 0.55,
          '使い捨てらしいドメインに、ブランド名に似た名前が付いています',
          `「${nearBrand.token}」は ${nearBrand.brand.id} に似ていますが、`
          + `実際の登録ドメインは ${f.registrable} です。`);
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

  // インフラの命名規則（api-gateway-prod.eu-central-1.elb…）を
  // 「隠すための長さ」と取り違えないようにする
  const infraTokenCount = f.subTokens.filter((t) => INFRA_TOKENS.has(t)).length;
  if (f.subLength >= 25 && f.subEntropy >= 3.4 && infraTokenCount < 2) {
    add('random-subdomain', 0.45, '意味のないランダムなサブドメイン',
      'アドレスバーに収まらない長さにして、本当のドメインを隠す手口です。');
  }
  // 子音の連続だけを条件にすると、数字混じりの自動生成名（a8f3k29dj4mfs…）を
  // 取り逃す。エントロピーは長い複合語でも簡単に上がるので使わない。
  const heuristicRandom = f.name.length >= 10
    && (f.maxConsonantRun >= 5 || digitRatioIgnoringYear(f.nameUnicode) >= 0.25);
  if (heuristicRandom) {
    add('random-domain-name', 0.4, '機械生成されたようなドメイン名', `${f.registrable}`);
  } else {
    // 実在ドメイン20万件から作った文字n-gramモデルで、名前の「現れにくさ」を測る。
    // 子音の連続や数字の比率では拾えない並び（x7f3k9qz2m など）を捉える。
    // 非ラテン文字の名前は対象外（国際化ドメインを巻き込まないため）。
    // 短い名前ほど偶然そう見えやすいので、要求する異常さを上げる。
    // zmbc3c のような6文字でも、統計から大きく外れていれば拾う。
    const randomness = randomnessScore(f.nameUnicode);
    const minRandomness = f.nameUnicode.length >= 8 ? 0.4 : 0.6;
    if (randomness !== null && randomness >= minRandomness && f.nameUnicode.length >= 5) {
      add('unlikely-domain-name', Math.min(0.65, 0.25 + randomness * 0.4),
        '実在するドメイン名の並びから大きく外れています',
        `${f.registrableUnicode} は、20万件の実在ドメインの統計では下位${
          randomness >= 0.99 ? '0.1' : (5 - randomness * 4.9).toFixed(1)}%に入る並びです。`);
    }
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
