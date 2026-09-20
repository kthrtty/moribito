/** E2E用のスタブページ。URLのパスで内容を出し分ける。 */

const page = (title, body, head = '') => `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<title>${title}</title>${head}</head><body>${body}</body></html>`;

const LOGIN_FORM = `
  <h1>ログイン</h1>
  <form method="post" action="/auth">
    <label>ログインID <input type="text" name="loginid" autocomplete="username" style="width:200px;height:24px"></label>
    <label>パスワード <input type="password" name="password" autocomplete="current-password" style="width:200px;height:24px"></label>
    <button type="submit">ログイン</button>
  </form>`;

const SEARCH_FORM = `
  <h1>お知らせ</h1>
  <form method="get" action="/search" role="search">
    <input type="search" name="q" placeholder="サイト内検索" style="width:200px;height:24px">
    <button type="submit">検索</button>
  </form>
  <p>今日のニュースをお届けします。</p>`;

/** 読み込み後にJSでパスワード欄を差し込む（focusin契機の検証用） */
const DELAYED_FORM = `
  <h1>ご確認ください</h1>
  <div id="slot"></div>
  <script>
    setTimeout(() => {
      document.getElementById('slot').innerHTML =
        '<form method="post" action="/auth">' +
        '<input id="pw" type="password" name="password" autocomplete="current-password" style="width:200px;height:24px">' +
        '<button type="submit">送信</button></form>';
    }, 200);
  <\/script>`;

/** 正規ドメイン上に広告経由で差し込まれる、サポート詐欺のオーバーレイ */
const SCAM_OVERLAY = `
  <h1>ニュース記事</h1>
  <p>本文です。</p>
  <audio autoplay src="data:audio/wav;base64,UklGRiQAAABXQVZF"></audio>
  <div id="scam" style="position:fixed;inset:0;z-index:2147483000;background:#003;color:#fff;height:100vh">
    <h2>警告: セキュリティの問題が検出されました</h2>
    <p>サポートへご連絡ください: <a href="tel:0120000000">0120-000-000</a></p>
  </div>
  <script>window.onbeforeunload = () => 'stay';<\/script>`;

const ROUTES = [
  // 公式ドメイン上の、第三者が作れる領域に置かれたフィッシング
  { match: /docs\.google\.com\/forms\//, html: () => page('Amazon アカウント確認', LOGIN_FORM) },
  { match: /docs\.google\.com\/document\//, html: () => page('議事録 - Google ドキュメント', '<h1 id="stub-page">議事録</h1>') },
  { match: /nikkei\.com\/article\/scam/, html: () => page('日本経済新聞', SCAM_OVERLAY) },
  { match: /nikkei\.com\/article\/normal/, html: () => page('日本経済新聞', '<h1 id="stub-page">通常の記事</h1><p>本文です。</p>') },
  { match: /mufg-bk-support\.cyou/, html: () => page('MUFG Bank｜ログイン',
      `<p>第三者による不正なアクセスを検知しました。24時間以内にご確認ください。</p>${LOGIN_FORM}`) },
  { match: /apple-id-check\.sbs/, html: () => page('Apple ID — サインイン', LOGIN_FORM) },
  { match: /delayed-form-check\.sbs/, html: () => page('Apple ID — サインイン', DELAYED_FORM) },
  { match: /mail-check-center\.cyou/, html: () => page('Amazon', '<h1>お知らせ</h1><p>ご案内です。</p>') },
  { match: /news-example\.cyou/, html: () => page('ニュース速報', SEARCH_FORM) },
  { match: /shop-example-store\.com/, html: () => page('Example Store — ログイン', LOGIN_FORM) },
];

export function htmlFor(url) {
  const route = ROUTES.find((r) => r.match.test(url));
  if (route) return route.html(url);
  return page('stub', `<h1 id="stub-page">stub</h1><p id="stub-url">${url.replace(/[<>&"]/g, '')}</p>`);
}
