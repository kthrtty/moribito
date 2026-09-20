/**
 * 表示コンテンツから集めた証拠の採点。
 *
 * URLだけでは取れない穴（正規ドメインの乗っ取り、ブランド語がURLに出ない新規ドメイン）
 * を埋めるための層。DOMの走査自体は content/page-probe.js が行い、ここは
 * 「集めた証拠をどう評価するか」だけを持つ（chrome.* に依存せずテストできる）。
 *
 * 方針:
 *   1段目 可視の入力欄があるフォームを広く拾う（passwordに限定しない）
 *   2段目 フィールド単位で「何を要求しているか」を採点し、検索欄は減点する
 */
import { BRANDS, brandOwning, isUserGeneratedArea } from './brands.js';
import { matchBrandToken } from './rules.js';
import { skeleton } from './confusables.js';
import { tokenize } from './text.js';
import { splitHost } from './psl.js';
import { sanitizeForDisplay } from './unicode.js';

/** 要求の強さ: 3=認証情報そのもの 2=補助的な秘密 1=識別子 0=なし */
const DEMAND = { none: 0, low: 1, medium: 2, high: 3 };

// name/id/placeholder/ラベルに現れる語彙。日本語のフィッシングは日本語で書かれる。
const FIELD_VOCAB = [
  { id: 'password', level: 'high', patterns: ['password', 'passwd', 'パスワード', '暗証番号', 'あんしょうばんごう'] },
  { id: 'card', level: 'high', patterns: ['cardnumber', 'creditcard', 'カード番号', 'クレジットカード', 'セキュリティコード', 'securitycode', 'cvv', 'cvc', '有効期限', 'expirationdate'] },
  { id: 'bank', level: 'high', patterns: ['口座番号', 'accountnumber', '支店番号', '店番号', 'pinコード'] },
  { id: 'mynumber', level: 'high', patterns: ['マイナンバー', '個人番号'] },
  { id: 'seed', level: 'high', patterns: ['シードフレーズ', 'リカバリーフレーズ', 'seedphrase', 'recoveryphrase', 'mnemonic', '秘密鍵', 'privatekey'] },
  { id: 'otp', level: 'medium', patterns: ['onetimepassword', 'onetimecode', 'ワンタイム', '認証コード', '確認コード', 'verificationcode', 'securitykey'] },
  { id: 'personal', level: 'medium', patterns: ['生年月日', 'dateofbirth', 'birthdate', '住所', '電話番号', 'phonenumber', '氏名'] },
  { id: 'identifier', level: 'low', patterns: ['email', 'mailaddress', 'メールアドレス', 'ログインid', 'loginid', 'ユーザーid', 'userid', 'userna'] },
];

const AUTOCOMPLETE_LEVEL = {
  'current-password': 'high', 'new-password': 'high',
  'cc-number': 'high', 'cc-csc': 'high', 'cc-exp': 'high',
  'cc-exp-month': 'high', 'cc-exp-year': 'high', 'cc-name': 'medium',
  'one-time-code': 'medium', 'bday': 'medium', 'street-address': 'medium', 'tel': 'medium',
  email: 'low', username: 'low', name: 'low', 'postal-code': 'low',
};

/** 照合用の正規化。全角/半角と区切りを吸収する。 */
function normalize(text) {
  return String(text ?? '')
    .normalize('NFKC')
    .toLowerCase()
    .replace(/[\s\-_.()/]+/g, '');
}

function levelOfField(field) {
  let level = 'none';
  const raise = (candidate) => {
    if (DEMAND[candidate] > DEMAND[level]) level = candidate;
  };

  if (field.type === 'password') raise('high');
  const auto = String(field.autocomplete ?? '').toLowerCase().split(/\s+/).pop();
  if (AUTOCOMPLETE_LEVEL[auto]) raise(AUTOCOMPLETE_LEVEL[auto]);

  const hint = normalize(field.hint);
  if (hint) {
    for (const entry of FIELD_VOCAB) {
      if (entry.patterns.some((pattern) => hint.includes(normalize(pattern)))) raise(entry.level);
    }
  }
  if (field.type === 'email' || field.type === 'tel') raise('low');
  return level;
}

/** フォーム全体で「何をどれだけ要求しているか」をまとめる。 */
export function credentialDemand(evidence) {
  const forms = evidence?.forms ?? [];
  const loose = evidence?.looseFields ?? [];
  const matched = new Set();
  let level = 'none';
  let fieldCount = 0;
  let otpGroup = false;
  let seed = false;

  const scan = (fields, searchLike) => {
    if (searchLike) return; // 検索ボックスは要求とみなさない
    for (const field of fields ?? []) {
      fieldCount++;
      const fieldLevel = levelOfField(field);
      if (DEMAND[fieldLevel] > DEMAND[level]) level = fieldLevel;
      const hint = normalize(field.hint);
      for (const entry of FIELD_VOCAB) {
        if (entry.patterns.some((p) => hint.includes(normalize(p)))) matched.add(entry.id);
      }
      if (field.type === 'password') matched.add('password');
      if (field.tag === 'textarea' && /フレーズ|phrase|mnemonic/i.test(field.hint ?? '')) seed = true;
    }
  };

  for (const form of forms) scan(form.fields, form.searchLike);
  scan(loose, false);

  // 1文字入力欄が並ぶ形（OTP）
  for (const form of forms) {
    const small = (form.fields ?? []).filter(
      (f) => (f.inputmode === 'numeric' || f.type === 'tel') && f.maxLength > 0 && f.maxLength <= 8,
    );
    if (small.length >= 4) otpGroup = true;
  }
  if (otpGroup && DEMAND[level] < DEMAND.medium) level = 'medium';
  if (seed) { level = 'high'; matched.add('seed'); }

  return { level, value: DEMAND[level], fieldCount, kinds: [...matched], otpGroup, seed };
}

/** ページが名乗っているブランドを、身元を示す面からだけ拾う。 */
export function brandClaim(identity, brands = BRANDS) {
  // 「Googleでログイン」等のボタン文言は入れない（正規サイトでも出るため）
  const surfaces = [
    ['title', identity?.title, true],
    ['og:site_name', identity?.siteName, true],
    ['application-name', identity?.appName, true],
    ['logo-alt', (identity?.iconAlts ?? []).join(' '), true],
    ['h1', identity?.h1, false],
  ];

  for (const [where, text, strong] of surfaces) {
    if (!text) continue;
    const hit = matchBrandInText(text, brands);
    if (hit) return { ...hit, where, strong };
  }
  return null;
}

function matchBrandInText(text, brands) {
  const normalized = normalize(text);
  const tokens = tokenize(skeleton(text));

  for (const brand of brands) {
    for (const alias of brand.jp ?? []) {
      // ASCIIのみのエイリアスは 'line' が 'online' に当たるなど誤爆するので使わない
      if (!/[^\x00-\x7f]/.test(alias)) continue;
      if (normalized.includes(normalize(alias))) return { brand, via: alias };
    }
    for (const token of tokens) {
      const hit = matchBrandToken(token, brand);
      if (hit) return { brand, via: hit.brandToken };
    }
  }
  return null;
}

/**
 * 表示コンテンツ由来の危険信号を返す。
 * @param {object} f extractFeatures の結果
 * @param {object} evidence content/page-probe.js が集めた証拠
 */
export function evaluatePageEvidence(f, evidence, opt = {}) {
  const brands = opt.brands ?? BRANDS;
  const signals = [];
  const add = (id, weight, title, detail) => signals.push({ id, weight, title, detail, from: 'page' });

  if (!f?.ok || !evidence?.ok) return signals;

  // 信頼済みドメイン（公式・著名）では、入力欄やブランド名の判定はしない。
  // 正規サイトのログインページを疑うことになるため。
  // ただし「広告経由で差し込まれた詐欺」は正規ドメイン上でも起きるので、
  // 構造的な証拠（電話誘導・離脱妨害）だけは見る。
  // 公式ドメインでも、第三者が中身を作れる領域（Googleフォーム等）は
  // 通常どおり中身を見る。ここを公式扱いにすると、定番の器が素通りになる。
  const trustedDomain = Boolean(brandOwning(f.registrable)) && !isUserGeneratedArea(f.host, f.path);
  const structureOnly = opt.mode === 'structure-only' || trustedDomain;

  const demand = structureOnly ? { value: 0, kinds: [], otpGroup: false, seed: false } : credentialDemand(evidence);
  const claim = structureOnly ? null : brandClaim(evidence.identity, brands);

  // ページが別ブランドを名乗っている
  if (!structureOnly && claim) {
    const weight = claim.strong
      ? (demand.value >= 2 ? 0.85 : demand.value === 1 ? 0.55 : 0.3)
      : (demand.value >= 2 ? 0.6 : 0.25);
    add('page-brand-mismatch', weight,
      `ページは ${claim.brand.id} を名乗っていますが別ドメインです`,
      `${claim.where} に「${claim.via}」とありますが、実際の登録ドメインは ${f.registrable} です。`
      + (demand.value >= 2 ? ' 認証情報の入力欄もあります。' : ''));
  }

  // 認証情報を求めるフォームがある
  if (!structureOnly && demand.value >= 3) {
    if (!claim) {
      add('credential-form', 0.35, '認証情報を入力させるフォーム',
        `${labelKinds(demand.kinds)} の入力欄があります。`);
    }
    if (!f.isHttps) {
      add('credential-form-insecure', 0.6, '暗号化なしで認証情報を送信するフォーム',
        'httpのページで認証情報を入力させています。通信路で盗み見られます。');
    }
  } else if (!structureOnly && demand.otpGroup) {
    add('otp-entry-form', 0.3, 'ワンタイムコードの入力欄',
      '認証コードだけを抜き取る多段フィッシングでよく使われる形です。');
  }

  if (!structureOnly && demand.seed) {
    add('seed-phrase-form', 0.75, '復元フレーズ・秘密鍵の入力欄',
      '正規のサービスがこれらを入力させることはありません。');
  }

  // 送信先が別ドメイン
  const pageRegistrable = f.registrable;
  for (const form of structureOnly ? [] : (evidence.forms ?? [])) {
    if (form.searchLike || !form.actionHost) continue;
    const target = splitHost(form.actionHost).registrable;
    if (!target || target === pageRegistrable) continue;
    const formDemand = credentialDemand({ forms: [form] });
    if (formDemand.value >= 2) {
      add('form-cross-origin-post', 0.65, '入力内容が別ドメインへ送信されます',
        `送信先: ${sanitizeForDisplay(form.actionHost, 80)}（表示中のドメインは ${pageRegistrable}）`);
      break;
    }
  }

  // GETで秘密を送る（URLに残る＝正規実装ではまずやらない）
  if (!structureOnly && (evidence.forms ?? []).some((form) => !form.searchLike && form.method === 'get'
      && credentialDemand({ forms: [form] }).value >= 3)) {
    add('credential-form-get', 0.5, '認証情報をURLに載せて送信するフォーム',
      '正規のログイン実装ではまず行いません。');
  }

  // サポート詐欺（偽の警告を出して電話をかけさせる型）。
  // 文面そのものは判定しない。文字列一致で自然言語を判定するのは成立しないため、
  // 「電話への誘導」「離脱妨害」「名乗っているブランド」という構造だけを見る。
  // 文面の判定が要る場合は services.classifyText を注入し、model 段の検出器に任せる。
  const hasPhoneLure = (evidence.telLinks?.length ?? 0) > 0 || (evidence.phoneNumbers?.length ?? 0) > 0;
  const traps = evidence.trapSignals ?? {};
  const trapList = [
    [traps.fullscreenRequested, '全画面化'],
    [traps.autoplayAudio, '音声の自動再生'],
    [(traps.modalOverlayCount ?? 0) > 0, '画面を覆う固定表示'],
    [traps.scrollLocked, 'スクロールの固定'],
  ].filter(([on]) => on).map(([, label]) => label);

  // 「画面を覆う警告の中に電話番号がある」構成。
  // 正規サイトの全画面動画やクッキーバナーとは、ここで明確に分かれる。
  const phoneInsideModal = Boolean(traps.phoneInsideModal);

  // 信頼済みドメイン（広告経由の差し込みを想定）では、
  // 「覆いの中に電話番号」という強い構成が揃ったときだけ鳴らす。
  const scamStructure = structureOnly
    ? phoneInsideModal && trapList.length >= 1
    : hasPhoneLure && trapList.length >= 2;

  if (scamStructure) {
    add('support-scam-structure', claim ? 0.9 : 0.75,
      '電話をかけさせ、ページから離れさせない作り',
      `${phoneInsideModal ? '画面を覆う表示の中に電話番号を出し、' : '電話番号を表示しつつ、'}`
      + `${trapList.join('・')}で操作を妨げています。`
      + (claim ? ` ${claim.brand.id} を名乗っていますが別ドメインです。` : '')
      + ' 表示された番号には電話しないでください。');
  } else if (!structureOnly && hasPhoneLure && claim) {
    add('phone-lure-brand', 0.6, '別ドメインでブランドを名乗り、電話番号を案内しています',
      `${claim.brand.id} の正規ドメインではありません。サポート詐欺の典型的な構成です。`);
  } else if (trapList.length >= 3) {
    add('exit-trap', 0.45, 'ページから離れにくくする仕掛け',
      `${trapList.join('・')}が同時に使われています。`);
  }

  if (!structureOnly && evidence.crossOriginLoginIframe) {
    add('cross-origin-login-iframe', 0.3, '別ドメインのログイン画面を埋め込んでいます',
      '正規サイトを枠内に見せて、周囲で入力を横取りする手口があります。');
  }

  return signals;
}

function labelKinds(kinds) {
  const labels = {
    password: 'パスワード', card: 'カード情報', bank: '口座情報', mynumber: 'マイナンバー',
    seed: '復元フレーズ', otp: '認証コード', personal: '個人情報', identifier: 'ID・メールアドレス',
  };
  const named = kinds.map((k) => labels[k]).filter(Boolean);
  return named.length ? named.join('・') : '認証情報';
}
