/** 判定の期待値コーパス。E2Eとユニットの両方から使う。 */

/** 正規サイト。ブロックも警告もしてはいけない。 */
export const BENIGN = [
  'https://www.google.com/search?q=phishing',
  'https://mail.google.com/mail/u/0/#inbox',
  'https://www.amazon.co.jp/dp/B0CXXXXXX?ref=nav_logo',
  'https://www.apple.com/jp/shop/buy-iphone',
  'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc',
  'https://www.paypal.com/jp/signin',
  'https://id.smbc.co.jp/vpass/login',
  'https://www.rakuten.co.jp/',
  'https://www.jcb.co.jp/ordinary/support/index.html',
  'https://www.post.japanpost.jp/service/fuzai_renraku/',
  'https://en.wikipedia.org/wiki/Phishing',
  'https://github.com/anthropics/anthropic-sdk-typescript',
  'https://developer.mozilla.org/ja/docs/Web/API/URL',
  'https://www.digital.go.jp/policies/mynumber',
  'https://zenn.dev/topics/chrome%E6%8B%A1%E5%BC%B5',
  'https://www.nikkei.com/article/DGXZQOUA123456789/',
  'http://192.168.11.1/setup/login.html',
  'http://localhost:5173/dashboard',
  'https://nas.local/admin',
  'https://docs.google.com/spreadsheets/d/1a2b3c/edit#gid=0',
];

/** フィッシングとしてブロックされるべきURL。 */
export const PHISHING = [
  // ホモグリフ（キリル文字のа）
  'https://xn--pypal-4ve.com/signin',
  // ホモグリフ（аррӏе.com）
  'https://xn--80ak6aa92e.com/jp/verify',
  // ブランド名をサブドメインに置き、本体は使い捨てドメイン
  'http://amazon.co.jp.account-verify.x7fk2p.top/signin',
  'https://www.smbc.co.jp.vpass-login.sbs/auth/index.html',
  'http://jp-bank.japanpost.jp.secure-update.cyou/login',
  // 長いランダムサブドメインでアドレスバーを溢れさせる
  'https://mufg-bk-co-jp-secure.a8f3k29dj4mfs0x9alqp2mdk.click/login',
  // 無料ホスティング + ブランド
  'https://rakuten-card-login.pages.dev/',
  // @ による偽装
  'http://www.apple.com@203.0.113.9/verify',
  // タイポスクワット
  'https://arnazon.co.jp/ap/signin',
  'https://mercarl-jp.shop/login',
  // IPアドレス直打ち + ログイン
  'http://198.51.100.24/jcb/login.php',
  // ハイフン連結のブランド詐称
  'https://docomo-ne-jp-id-auth-update.top/webauth',
];

/** 灰色。ブロックまでは求めないが allow で埋もれてもいけない。 */
export const SUSPICIOUS = [
  'https://paypal-secure-login.com/',
  'https://aeon-card.info/update',
];
