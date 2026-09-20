/**
 * Public Suffix List の実用サブセット。
 *
 * PSL の既定ルール「未知のTLDはそのTLD自体が public suffix」を利用するため、
 * ここには *複数ラベルのルールだけ* を持つ（単一ラベルTLDの列挙は不要）。
 * 完全版に差し替えるには tools/build-psl.mjs を実行すること。
 */

// 通常ルール（完全一致）
export const RULES = new Set([
  // 日本
  'ac.jp', 'ad.jp', 'co.jp', 'ed.jp', 'go.jp', 'gr.jp', 'lg.jp', 'ne.jp', 'or.jp',
  'hokkaido.jp', 'aomori.jp', 'iwate.jp', 'miyagi.jp', 'akita.jp', 'yamagata.jp',
  'fukushima.jp', 'ibaraki.jp', 'tochigi.jp', 'gunma.jp', 'saitama.jp', 'chiba.jp',
  'tokyo.jp', 'kanagawa.jp', 'niigata.jp', 'toyama.jp', 'ishikawa.jp', 'fukui.jp',
  'yamanashi.jp', 'nagano.jp', 'gifu.jp', 'shizuoka.jp', 'aichi.jp', 'mie.jp',
  'shiga.jp', 'kyoto.jp', 'osaka.jp', 'hyogo.jp', 'nara.jp', 'wakayama.jp',
  'tottori.jp', 'shimane.jp', 'okayama.jp', 'hiroshima.jp', 'yamaguchi.jp',
  'tokushima.jp', 'kagawa.jp', 'ehime.jp', 'kochi.jp', 'fukuoka.jp', 'saga.jp',
  'nagasaki.jp', 'kumamoto.jp', 'oita.jp', 'miyazaki.jp', 'kagoshima.jp', 'okinawa.jp',
  // 英国・豪州・NZ
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk',
  'gov.uk', 'nhs.uk', 'police.uk', 'mod.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz', 'geek.nz',
  // アジア
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'co.kr', 'ne.kr', 'or.kr', 're.kr', 'pe.kr', 'go.kr', 'mil.kr', 'ac.kr',
  'com.hk', 'org.hk', 'net.hk', 'edu.hk', 'gov.hk', 'idv.hk',
  'com.tw', 'org.tw', 'net.tw', 'edu.tw', 'gov.tw', 'idv.tw',
  'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
  'com.my', 'net.my', 'org.my', 'edu.my', 'gov.my',
  'co.th', 'or.th', 'ac.th', 'go.th', 'in.th', 'net.th',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
  'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn',
  'co.id', 'or.id', 'ac.id', 'go.id', 'web.id', 'my.id',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'gov.in', 'nic.in',
  'ac.in', 'edu.in', 'res.in',
  'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il', 'muni.il',
  'com.pk', 'com.bd', 'com.np', 'com.lk', 'org.lk',
  // 欧州・中東・アフリカ・米州
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.mx', 'org.mx', 'gob.mx', 'edu.mx',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar',
  'com.co', 'net.co', 'nom.co',
  'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za', 'web.za',
  'com.ng', 'org.ng', 'co.ke', 'or.ke', 'com.gh', 'com.eg', 'com.sa', 'co.ae',
  'com.ru', 'net.ru', 'org.ru', 'edu.ru', 'gov.ru', 'msk.ru', 'spb.ru',
  'com.ua', 'net.ua', 'org.ua', 'in.ua', 'kiev.ua',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'bel.tr',
  'com.pl', 'net.pl', 'org.pl', 'edu.pl', 'gov.pl', 'waw.pl',
  'com.pt', 'org.pt', 'edu.pt', 'gov.pt',
  'com.gr', 'net.gr', 'org.gr', 'edu.gr', 'gov.gr',
  'com.es', 'org.es', 'nom.es', 'edu.es', 'gob.es',
  'gov.it', 'edu.it', 'com.de', 'co.at', 'or.at', 'co.no', 'com.se',

  // PRIVATE セクション（ホスティング事業者。フィッシングの温床になりやすい）
  'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'r2.dev',
  'web.app', 'firebaseapp.com', 'appspot.com', 'storage.googleapis.com',
  'vercel.app', 'netlify.app', 'onrender.com', 'fly.dev', 'surge.sh',
  'glitch.me', 'repl.co', 'replit.dev', 'herokuapp.com',
  'azurewebsites.net', 'cloudapp.net', 'blob.core.windows.net',
  'amplifyapp.com', 'elasticbeanstalk.com', 'cloudfunctions.net',
  'blogspot.com', 'blogspot.jp', 'wixsite.com', 'weebly.com', 'jimdofree.com',
  'webflow.io', 'square.site', 'myshopify.com', 'bigcartel.com',
  '000webhostapp.com', 'neocities.org', 'altervista.org',
  'duckdns.org', 'ddns.net', 'sytes.net', 'hopto.org', 'zapto.org', 'bounceme.net',
  'ngrok.io', 'ngrok.app', 'ngrok-free.app', 'trycloudflare.com', 'loca.lt',
  'serveo.net', 'localto.net', 'tunnelto.dev',
]);

// ワイルドカードルール（*.<entry>）
export const WILDCARDS = new Set([
  'ck', 'jm', 'mm', 'platform.sh', 's3.amazonaws.com', 'compute.amazonaws.com',
  'sakura.ne.jp', 'kawasaki.jp', 'kitakyushu.jp', 'kobe.jp', 'nagoya.jp',
  'sapporo.jp', 'sendai.jp', 'yokohama.jp',
]);

// 例外ルール（!entry）
export const EXCEPTIONS = new Set([
  'www.ck', 'city.kawasaki.jp', 'city.kitakyushu.jp', 'city.kobe.jp',
  'city.nagoya.jp', 'city.sapporo.jp', 'city.sendai.jp', 'city.yokohama.jp',
]);

export const PSL_SOURCE = 'bundled-subset';
