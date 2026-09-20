/**
 * 詐称されやすいブランドと、その「正規の登録ドメイン」。
 * ここに載っている登録ドメインは正規サイトとして扱い、
 * ブランド語が出てくるのに登録ドメインが一致しないものを危険信号にする。
 *
 * 誤検知を減らすため domains は広めに（関連ドメインも）登録しておく。
 */
export const BRANDS = [
  { id: 'amazon', tokens: ['amazon', 'amazonjp', 'amazoncojp', 'amzn'],
    jp: ['アマゾン'],
    domains: ['amazon.com', 'amazon.co.jp', 'amazon.jp', 'amazonaws.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca', 'amazon.cn', 'amazon.in', 'amzn.to', 'primevideo.com', 'media-amazon.com', 'ssl-images-amazon.com'] },
  { id: 'apple', tokens: ['apple', 'appleid', 'icloud', 'itunes'],
    jp: ['アップル'],
    domains: ['apple.com', 'icloud.com', 'itunes.com', 'me.com', 'apple.news', 'cdn-apple.com'] },
  { id: 'google', tokens: ['google', 'gmail', 'youtube', 'googleplay'],
    jp: ['グーグル'],
    domains: ['google.com', 'google.co.jp', 'gmail.com', 'youtube.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com', 'withgoogle.com', 'blogger.com', 'goo.gl'] },
  { id: 'microsoft', tokens: ['microsoft', 'outlook', 'office365', 'onedrive', 'sharepoint', 'msn', 'xbox', 'skype'],
    jp: ['マイクロソフト'],
    domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com', 'msn.com', 'sharepoint.com', 'onedrive.com', 'windows.com', 'xbox.com', 'skype.com', 'azure.com', 'bing.com'] },
  { id: 'paypal', tokens: ['paypal'], jp: ['ペイパル'],
    domains: ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal.co.jp'] },
  { id: 'meta', tokens: ['facebook', 'instagram', 'whatsapp', 'messenger'],
    domains: ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'messenger.com', 'meta.com', 'fbcdn.net'] },
  { id: 'netflix', tokens: ['netflix'], jp: ['ネットフリックス'],
    domains: ['netflix.com', 'nflxext.com', 'nflximg.net'] },
  { id: 'x', tokens: ['twitter'], domains: ['x.com', 'twitter.com', 't.co', 'twimg.com'] },
  { id: 'linkedin', tokens: ['linkedin'], domains: ['linkedin.com', 'licdn.com'] },
  { id: 'line', tokens: ['linecorp', 'lineme'], jp: ['ライン公式'],
    domains: ['line.me', 'linecorp.com', 'line-scdn.net', 'lycorp.co.jp'] },
  { id: 'rakuten', tokens: ['rakuten'],
    jp: ['楽天'],
    domains: ['rakuten.co.jp', 'rakuten.com', 'rakuten.ne.jp', 'rakuten-card.co.jp', 'rakuten-bank.co.jp', 'r10s.jp', 'rakuten-sec.co.jp'] },
  { id: 'yahoojp', tokens: ['yahoo', 'yahoojapan'], jp: ['ヤフー'],
    domains: ['yahoo.co.jp', 'yahoo.jp', 'yimg.jp', 'yahoo.com', 'yahooapis.jp'] },
  { id: 'mercari', tokens: ['mercari', 'merpay'], jp: ['メルカリ'],
    domains: ['mercari.com', 'merpay.com', 'mercari.jp', 'mercdn.net'] },
  { id: 'paypay', tokens: ['paypay'], jp: ['ペイペイ'],
    domains: ['paypay.ne.jp', 'paypay-bank.co.jp', 'paypay-card.co.jp'] },
  { id: 'jcb', tokens: ['jcb', 'myjcb'], jp: ['ジェーシービー'],
    domains: ['jcb.co.jp', 'jcb-global.com', 'jcb.jp'] },
  { id: 'smbc', tokens: ['smbc', 'vpass', 'sumitomomitsui'], jp: ['三井住友'],
    domains: ['smbc.co.jp', 'smbc-card.com', 'smbc-cf.com', 'vpass.ne.jp', 'smbcnikko.co.jp'] },
  { id: 'mufg', tokens: ['mufg', 'bkmufg', 'mitsubishiufj'], jp: ['三菱ufj', '三菱ｕｆｊ'],
    domains: ['mufg.jp', 'bk.mufg.jp', 'mufg.co.jp', 'cr.mufg.jp', 'mufgcard.com'] },
  { id: 'mizuho', tokens: ['mizuho', 'mizuhobank'], jp: ['みずほ'],
    domains: ['mizuhobank.co.jp', 'mizuho-fg.co.jp', 'mizuhobank.jp', 'mizuho-sc.com'] },
  { id: 'japanpost', tokens: ['japanpost', 'jpbank', 'yuchobank', 'yucho'],
    jp: ['ゆうちょ', '日本郵便', 'ゆうびん'],
    domains: ['japanpost.jp', 'jp-bank.japanpost.jp', 'post.japanpost.jp', 'jp-network.japanpost.jp'] },
  { id: 'aeon', tokens: ['aeon', 'aeonbank', 'aeoncard'], jp: ['イオン'],
    domains: ['aeon.co.jp', 'aeonbank.co.jp', 'aeon.com', 'aeonretail.com'] },
  { id: 'saison', tokens: ['saison', 'saisoncard'], jp: ['セゾン'],
    domains: ['saisoncard.co.jp', 'saisoncard.com', 'credit-saison.co.jp'] },
  { id: 'epos', tokens: ['epos', 'eposcard'], jp: ['エポス'],
    domains: ['eposcard.co.jp', '0101.co.jp'] },
  { id: 'orico', tokens: ['orico'], jp: ['オリコ'],
    domains: ['orico.co.jp'] },
  { id: 'viewcard', tokens: ['viewcard', 'jreast'], jp: ['ビューカード'],
    domains: ['viewcard.co.jp', 'jreast.co.jp', 'jre-vts.com'] },
  { id: 'docomo', tokens: ['docomo', 'nttdocomo', 'dcard', 'dpoint'],
    jp: ['ドコモ'],
    domains: ['docomo.ne.jp', 'nttdocomo.co.jp', 'docomo.co.jp', 'd-card.jp', 'dpoint.jp', 'smt.docomo.ne.jp'] },
  { id: 'au', tokens: ['kddi', 'auone', 'aupay'], jp: ['auかんたん', 'auペイ'],
    domains: ['au.com', 'kddi.com', 'auone.jp', 'au.kddi.com', 'aupay.wallet.auone.jp'] },
  { id: 'softbank', tokens: ['softbank', 'ymobile'], jp: ['ソフトバンク', 'ワイモバイル'],
    domains: ['softbank.jp', 'softbank.co.jp', 'ymobile.jp', 'sbpayment.jp'] },
  { id: 'ntt', tokens: ['ntt', 'nttfinance', 'nttwest', 'ntteast'], jp: ['エヌ・ティ・ティ'],
    domains: ['ntt.com', 'ntt-west.co.jp', 'ntt-east.co.jp', 'ntt-finance.co.jp', 'ntt.co.jp'] },
  { id: 'sagawa', tokens: ['sagawa', 'sagawaexp'], jp: ['佐川'],
    domains: ['sagawa-exp.co.jp'] },
  { id: 'yamato', tokens: ['kuronekoyamato', 'yamato'], jp: ['クロネコ', 'ヤマト運輸'],
    domains: ['kuronekoyamato.co.jp', 'yamato-hd.co.jp', 'yamatofinancial.jp'] },
  { id: 'etcmeisai', tokens: ['etcmeisai', 'etcplaza'], jp: ['etc利用照会', 'etc利用紹介'],
    domains: ['etc-meisai.jp', 'etc-plaza.jp'] },
  { id: 'nta', tokens: ['etax', 'kokuzei', 'nta'], jp: ['国税庁', '確定申告'],
    domains: ['nta.go.jp', 'e-tax.nta.go.jp', 'keisan.nta.go.jp'] },
  { id: 'digitalgov', tokens: ['myna', 'mynaportal', 'digitalgo'], jp: ['マイナポータル', 'マイナンバーカード', 'デジタル庁'],
    domains: ['myna.go.jp', 'digital.go.jp', 'mynumbercard.go.jp'] },
  { id: 'tepco', tokens: ['tepco'], jp: ['東京電力'],
    domains: ['tepco.co.jp', 'tepco.com'] },
  { id: 'tokyogas', tokens: ['tokyogas'], jp: ['東京ガス'],
    domains: ['tokyo-gas.co.jp'] },
  { id: 'ana', tokens: ['ana', 'anamileage'], jp: ['全日空', 'ａｎａマイレージ'],
    domains: ['ana.co.jp', 'ana.com'] },
  { id: 'jal', tokens: ['jal', 'japanairlines'], jp: ['日本航空'],
    domains: ['jal.co.jp', 'jal.com', 'jalcard.co.jp'] },
  { id: 'steam', tokens: ['steam', 'steamcommunity', 'steampowered'], domains: ['steampowered.com', 'steamcommunity.com', 'valvesoftware.com'] },
  { id: 'binance', tokens: ['binance'], domains: ['binance.com', 'binance.us', 'binance.jp'] },
  { id: 'coinbase', tokens: ['coinbase'], domains: ['coinbase.com'] },
  { id: 'bitflyer', tokens: ['bitflyer'], domains: ['bitflyer.com', 'bitflyer.jp'] },
  { id: 'dhl', tokens: ['dhl'], domains: ['dhl.com', 'dhl.de'] },
  { id: 'fedex', tokens: ['fedex'], domains: ['fedex.com'] },
  { id: 'ups', tokens: ['ups'], domains: ['ups.com'] },
  { id: 'dmm', tokens: ['dmm'], 
    domains: ['dmm.com', 'dmm.co.jp'] },
  { id: 'nintendo', tokens: ['nintendo'], jp: ['任天堂'],
    domains: ['nintendo.com', 'nintendo.co.jp', 'nintendo.net'] },
];
// ブランド語の直後に付きがちな修飾語（appleid, amazon-jp など）
export const FILLER_TOKENS = new Set([
  'id', 'ids', 'account', 'accounts', 'login', 'logon', 'signin', 'sign', 'auth',
  'secure', 'security', 'support', 'help', 'service', 'services', 'center', 'centre',
  'jp', 'japan', 'co', 'com', 'net', 'org', 'online', 'web', 'www', 'mail', 'email',
  'verify', 'verification', 'update', 'confirm', 'confirmation', 'check', 'my',
  'app', 'apps', 'info', 'customer', 'user', 'users', 'member', 'members', 'office',
  'pay', 'payment', 'payments', 'card', 'cards', 'bank', 'billing', 'invoice',
  'portal', 'home', 'top', 'new', 'official', 'global', 'shop', 'store', 'point',
]);
// 認証情報を狙うページによく出る語
export const SENSITIVE_WORDS = [
  'login', 'signin', 'logon', 'account', 'verify', 'verification', 'secure',
  'security', 'update', 'confirm', 'password', 'passwd', 'credential', 'auth',
  'authenticate', 'billing', 'invoice', 'payment', 'wallet', 'unlock', 'suspend',
  'suspended', 'limited', 'restricted', 'recovery', 'reset', 'otp', 'mfa', '2fa',
  'webscr', 'cmd', 'session', 'token', 'kyc', 'refund', 'delivery', 'customs',
];
// 無料/使い捨てホスティング（ここに載る登録ドメイン配下はブランド詐称の温床）
export const FREE_HOSTING = new Set([
  'pages.dev', 'workers.dev', 'r2.dev', 'web.app', 'firebaseapp.com', 'appspot.com',
  'vercel.app', 'netlify.app', 'onrender.com', 'fly.dev', 'surge.sh', 'glitch.me',
  'repl.co', 'replit.dev', 'herokuapp.com', 'azurewebsites.net', 'blob.core.windows.net',
  'github.io', 'gitlab.io', 'amplifyapp.com', 'weebly.com', 'wixsite.com',
  'jimdofree.com', 'webflow.io', '000webhostapp.com', 'neocities.org', 'blogspot.com',
  'duckdns.org', 'ddns.net', 'sytes.net', 'hopto.org', 'zapto.org', 'bounceme.net',
  'ngrok.io', 'ngrok.app', 'ngrok-free.app', 'trycloudflare.com', 'loca.lt',
  'serveo.net', 'localto.net', 'tunnelto.dev', 'storage.googleapis.com',
  'sites.google.com', 'form.jotform.com', 'formrun.page',
]);
// 濫用率が高いTLD（安価・無審査なもの）
export const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'buzz', 'click', 'link', 'work',
  'fit', 'rest', 'country', 'kim', 'men', 'loan', 'download', 'racing', 'win',
  'review', 'bid', 'stream', 'date', 'party', 'trade', 'science', 'cam', 'icu',
  'shop', 'monster', 'quest', 'sbs', 'cfd', 'bond', 'rodeo', 'autos', 'boats',
  'cyou', 'lol', 'mom', 'uno', 'zip', 'mov', 'best', 'beauty', 'hair', 'skin',
  'info', 'biz', 'online', 'site', 'website', 'space', 'store', 'fun', 'life',
  'live', 'today', 'world', 'tech', 'vip', 'asia', 'pro', 'one', 'cc', 'su',
  'makeup', 'christmas', 'gdn', 'wang', 'cn.com', 'ru.com',
]);
// 頻繁に訪れる大手ドメイン（誤検知を抑えるためのホワイト寄せ）
export const POPULAR_DOMAINS = new Set([
  'google.com', 'google.co.jp', 'youtube.com', 'facebook.com', 'instagram.com',
  'x.com', 'twitter.com', 'wikipedia.org', 'yahoo.co.jp', 'amazon.co.jp',
  'amazon.com', 'apple.com', 'microsoft.com', 'live.com', 'office.com',
  'github.com', 'gitlab.com', 'stackoverflow.com', 'reddit.com', 'linkedin.com',
  'netflix.com', 'rakuten.co.jp', 'mercari.com', 'nicovideo.jp', 'pixiv.net',
  'note.com', 'qiita.com', 'zenn.dev', 'hatenablog.com', 'cookpad.com',
  'kakaku.com', 'tabelog.com', 'jorudan.co.jp', 'nhk.or.jp', 'asahi.com',
  'yomiuri.co.jp', 'nikkei.com', 'mainichi.jp', 'digital.go.jp', 'go.jp',
  'openai.com', 'anthropic.com', 'claude.ai', 'cloudflare.com', 'npmjs.com',
  'mozilla.org', 'developer.mozilla.org', 'chatgpt.com', 'slack.com', 'notion.so',
  'atlassian.com', 'zoom.us', 'dropbox.com', 'box.com', 'salesforce.com',
]);
/**
 * 公式ドメインの中にある「誰でも中身を作れる領域」。
 *
 * docs.google.com/forms のようなフォーム作成サービスは、ドメインこそ正規だが
 * 中身は第三者が作る。ここを「公式だから安全」と短絡すると、
 * フィッシングの定番の器がそのまま素通りになる。
 * 判定を打ち切らず、通常のルールと表示内容の検査を通す
 * （＝それ自体を危険とみなすのではなく、特別扱いをやめるだけ）。
 */
export const USER_GENERATED_AREAS = [
  { host: 'sites.google.com' },
  { host: 'docs.google.com', pathPrefix: '/forms/' },
  { host: 'drive.google.com', pathPrefix: '/file/' },
  { host: 'forms.office.com' },
  { host: 'forms.microsoft.com' },
  { host: 'onedrive.live.com' },
  { hostSuffix: '.sharepoint.com' },
  { host: 'firebasestorage.googleapis.com' },
];

export function isUserGeneratedArea(host, path = '') {
  const h = String(host ?? '').toLowerCase();
  const p = String(path ?? '');
  return USER_GENERATED_AREAS.some((area) => {
    if (area.host && area.host !== h) return false;
    if (area.hostSuffix && !h.endsWith(area.hostSuffix)) return false;
    if (area.pathPrefix && !p.startsWith(area.pathPrefix)) return false;
    return true;
  });
}

/** 登録ドメインが正規ブランドのものならそのブランドを返す。 */
export function brandOwning(registrable) {
  if (!registrable) return null;
  for (const brand of BRANDS) {
    if (brand.domains.includes(registrable)) return brand;
  }
  return null;
}
