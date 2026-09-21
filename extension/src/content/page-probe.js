/**
 * ページ内の証拠を集める（必要になったページにだけ注入される）。
 *
 * 方針:
 *  - 常駐させない。URL判定がグレーのページにだけ executeScript で注入する
 *  - 判定はしない。集めるだけで、採点は core/page-evidence.js が行う
 *  - value は絶対に読まない。読むのは作者が書いた属性とラベルだけ
 *  - ページのDOMは攻撃者の入力。文字列として扱い、評価も実行もしない
 *
 * 最後の式の値が executeScript の戻り値になる（初回スキャンの結果）。
 */
(() => {
  const STATE_KEY = '__moribitoProbe__';
  const MAX_FIELDS = 40;
  const MAX_FORMS = 20;
  const MAX_HINT = 120;
  const MAX_BODY = 1500;

  const clip = (text, max) => String(text ?? '').replace(/\s+/g, ' ').trim().slice(0, max);

  /** 目に見えて、実際に入力できる欄か。 */
  function isVisibleInput(el) {
    if (el.disabled || el.readOnly) return false;
    const type = (el.getAttribute('type') || '').toLowerCase();
    if (type === 'hidden') return false;
    if (el.getAttribute('aria-hidden') === 'true') return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 8 || rect.height < 8) return false;
    const style = getComputedStyle(el); // 安い判定を通ったものだけ
    if (style.visibility === 'hidden' || style.display === 'none') return false;
    if (Number(style.opacity) === 0) return false;
    return true;
  }

  /** 作者が書いた手がかりを集める（利用者が入力した値は含めない）。 */
  function hintOf(el) {
    const parts = [
      el.getAttribute('name'), el.id, el.getAttribute('placeholder'),
      el.getAttribute('aria-label'), el.getAttribute('title'),
    ];
    const labels = el.labels && el.labels.length ? el.labels[0].textContent : '';
    const wrapping = !labels && el.closest ? el.closest('label')?.textContent : '';
    parts.push(labels || wrapping || '');
    return clip(parts.filter(Boolean).join(' '), MAX_HINT);
  }

  function describeField(el) {
    return {
      tag: el.tagName.toLowerCase(),
      type: (el.getAttribute('type') || (el.tagName === 'TEXTAREA' ? 'textarea' : 'text')).toLowerCase(),
      autocomplete: clip(el.getAttribute('autocomplete'), 40),
      inputmode: clip(el.getAttribute('inputmode'), 20),
      maxLength: Number(el.getAttribute('maxlength') || 0),
      hint: hintOf(el),
    };
  }

  // 介入の要否はページ側で即断する必要があるので、ここに最小限の語彙を置く。
  // 採点そのものは core/page-evidence.js の担当。
  const CREDENTIAL_AUTOCOMPLETE = new Set([
    'current-password', 'new-password', 'cc-number', 'cc-csc', 'cc-exp',
    'cc-exp-month', 'cc-exp-year', 'one-time-code',
  ]);
  const CREDENTIAL_WORDS = /パスワード|暗証|カード番号|セキュリティコード|認証コード|ワンタイム|口座番号|マイナンバー|個人番号|リカバリーフレーズ|シードフレーズ|password|passwd|cardnumber|securitycode|cvv|cvc|otp/i;

  /** 認証情報を入れる欄か。 */
  function isCredentialField(el) {
    if (!el || !/^(INPUT|TEXTAREA)$/.test(el.tagName)) return false;
    const type = (el.getAttribute('type') || '').toLowerCase();
    if (type === 'password') return true;
    const auto = (el.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/).pop();
    if (CREDENTIAL_AUTOCOMPLETE.has(auto)) return true;
    return CREDENTIAL_WORDS.test(hintOf(el));
  }

  const SEARCH_NAMES = new Set(['q', 's', 'query', 'search', 'keyword', 'kw', 'word', 'k']);

  /** 検索ボックスらしさ（これだけなら「要求」とみなさない）。 */
  function looksLikeSearch(form, fields) {
    if (form) {
      if ((form.getAttribute('role') || '').toLowerCase() === 'search') return true;
      const action = form.getAttribute('action') || '';
      if (/\/(search|find|s)\b/i.test(action)) return true;
    }
    if (fields.length !== 1) return false;
    const field = fields[0];
    if (field.type === 'search') return true;
    const hint = field.hint.toLowerCase();
    if (SEARCH_NAMES.has(hint.split(' ')[0])) return true;
    return /検索|search/i.test(hint);
  }

  function hostOfAction(form) {
    const action = form.getAttribute('action');
    if (!action) return '';
    try {
      const url = new URL(action, location.href);
      return url.host === location.host ? '' : url.host;
    } catch {
      return '';
    }
  }

  function collect(trigger) {
    const selector = 'input, textarea, select';
    const all = [...document.querySelectorAll(selector)].filter(isVisibleInput).slice(0, MAX_FIELDS * 2);
    const seen = new Set();
    const forms = [];

    for (const form of [...document.forms].slice(0, MAX_FORMS)) {
      const fields = all.filter((el) => el.form === form).slice(0, MAX_FIELDS).map((el) => {
        seen.add(el);
        return describeField(el);
      });
      if (!fields.length) continue;
      forms.push({
        method: (form.getAttribute('method') || 'get').toLowerCase(),
        actionHost: hostOfAction(form),
        searchLike: looksLikeSearch(form, fields),
        fields,
      });
    }

    // form要素の外に置かれた入力欄（JSで送信する実装で多い）
    const looseFields = all.filter((el) => !seen.has(el)).slice(0, MAX_FIELDS).map(describeField);

    const meta = (name, attr = 'name') =>
      clip(document.querySelector(`meta[${attr}="${name}"]`)?.getAttribute('content'), 120);

    const iconAlts = [...document.querySelectorAll('header img[alt], .logo img[alt], a[href="/"] img[alt]')]
      .slice(0, 5).map((img) => clip(img.getAttribute('alt'), 60)).filter(Boolean);

    // サポート詐欺（電話をかけさせる型）の痕跡
    const telLinks = [...document.querySelectorAll('a[href^="tel:"]')]
      .slice(0, 5).map((a) => clip(a.getAttribute('href'), 40));
    const visibleText = document.body?.innerText ?? '';
    const phoneMatches = visibleText.match(
      /(?:0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}|\+\d{1,3}[-\s]?\d{2,4}[-\s]?\d{3,4}[-\s]?\d{3,4}|1[-\s]?8(?:00|88|77|66)[-\s]?\d{3}[-\s]?\d{4})/g,
    ) ?? [];
    // 画面を覆う固定表示を探し、その中に電話番号があるかを見る。
    // 「全画面の警告の中に電話番号がある」は、正規サイトの動画や
    // クッキーバナーとサポート詐欺を分ける、最も確実な構造的指標。
    const modals = [...document.querySelectorAll('div, section, aside')].slice(0, 400).filter((el) => {
      const style = getComputedStyle(el);
      if (style.position !== 'fixed') return false;
      if (Number(style.zIndex) <= 1000) return false;
      const rect = el.getBoundingClientRect();
      return rect.height > innerHeight * 0.6 && rect.width > innerWidth * 0.6;
    });
    const phoneInsideModal = modals.some((el) =>
      el.querySelector('a[href^="tel:"]') !== null
      || /(?:0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{3,4}|1[-\s]?8(?:00|88|77|66)[-\s]?\d{3}[-\s]?\d{4})/
        .test(el.innerText ?? ''));

    const trapSignals = {
      // ページ側が設定した onbeforeunload は分離ワールドからは見えないため数えない。
      // 見えるものだけで判断する。
      fullscreenRequested: Boolean(document.fullscreenElement),
      autoplayAudio: [...document.querySelectorAll('audio, video')].some((m) => m.autoplay && !m.muted),
      modalOverlayCount: modals.length,
      phoneInsideModal,
      scrollLocked: getComputedStyle(document.body).overflow === 'hidden',
    };

    const crossOriginLoginIframe = [...document.querySelectorAll('iframe[src]')].some((frame) => {
      try {
        const url = new URL(frame.getAttribute('src'), location.href);
        return url.host && url.host !== location.host && /login|signin|auth|account/i.test(url.href);
      } catch {
        return false;
      }
    });

    return {
      ok: true,
      trigger,
      url: location.href,
      identity: {
        title: clip(document.title, 150),
        siteName: meta('og:site_name', 'property') || meta('og:site_name'),
        appName: meta('application-name'),
        h1: clip(document.querySelector('h1')?.textContent, 120),
        iconAlts,
      },
      forms,
      looseFields,
      crossOriginLoginIframe,
      telLinks,
      phoneNumbers: phoneMatches.slice(0, 5).map((n) => clip(n, 24)),
      trapSignals,
      // innerText はレイアウトを強制するので、1段目を通ったページでだけ読む。
      // 電話誘導型は入力欄が無いので、電話番号が見えている場合も読む。
      bodyText: forms.length || looseFields.length || telLinks.length || phoneMatches.length
        ? clip(visibleText, MAX_BODY) : '',
    };
  }

  /** 警告バーを出す。ページ側のCSSに影響されないよう Shadow DOM に隔離する。 */
  function showOverlay(payload) {
    const existing = document.getElementById('moribito-overlay');
    if (existing) existing.remove();

    const host = document.createElement('div');
    host.id = 'moribito-overlay';
    host.style.cssText = 'position:fixed;inset:0 0 auto 0;z-index:2147483647;';
    const root = host.attachShadow({ mode: 'closed' });

    const wrap = document.createElement('div');
    wrap.setAttribute('role', 'alert');
    wrap.style.cssText = [
      'font:14px/1.6 -apple-system,BlinkMacSystemFont,"Hiragino Sans","Noto Sans JP",sans-serif',
      'background:#7f1d1d', 'color:#fff', 'padding:12px 16px',
      'display:flex', 'gap:12px', 'align-items:flex-start',
      'box-shadow:0 2px 12px rgba(0,0,0,.35)',
    ].join(';');

    const body = document.createElement('div');
    body.style.cssText = 'flex:1;min-width:0';
    const title = document.createElement('div');
    title.style.cssText = 'font-weight:700;margin-bottom:2px';
    title.textContent = '⚠ このページはフィッシングの可能性があります';
    const detail = document.createElement('div');
    detail.style.cssText = 'font-size:13px;opacity:.92';
    detail.textContent = (payload.reasons || []).join(' / ');
    const note = document.createElement('div');
    note.style.cssText = 'font-size:12px;opacity:.8;margin-top:4px';
    note.textContent = 'パスワード・カード番号・認証コードは入力しないでください。';
    body.append(title, detail, note);

    const leave = document.createElement('button');
    leave.textContent = 'このページを離れる';
    leave.style.cssText = 'font:inherit;background:#fff;color:#7f1d1d;border:0;border-radius:6px;padding:6px 12px;cursor:pointer;font-weight:700';
    leave.addEventListener('click', () => {
      if (history.length > 1) history.back();
      else location.replace('about:blank');
    });

    const close = document.createElement('button');
    close.textContent = '閉じる';
    close.style.cssText = 'font:inherit;background:transparent;color:#fff;border:1px solid rgba(255,255,255,.5);border-radius:6px;padding:6px 12px;cursor:pointer';
    close.addEventListener('click', () => host.remove());

    wrap.append(body, leave, close);
    root.append(wrap);
    (document.body || document.documentElement).append(host);
  }

  /** 再評価を依頼する。1ページにつき数回までに抑える。 */
  function report(trigger) {
    const state = window[STATE_KEY];
    if (state.reports >= 3) return;
    state.reports++;
    try {
      chrome.runtime.sendMessage({ type: 'page-evidence', evidence: collect(trigger) });
    } catch {
      // 拡張が再読み込みされた等。ページ側には影響させない。
    }
  }

  /** ページ側のCSSから隔離した入れ物を作る。 */
  function makeHost(id) {
    document.getElementById(id)?.remove();
    const host = document.createElement('div');
    host.id = id;
    return host;
  }

  const WARN_STYLE = 'font:13px/1.5 -apple-system,BlinkMacSystemFont,"Hiragino Sans","Noto Sans JP",sans-serif';

  /**
   * ① 入力欄への介入。
   * 画面上部のバーは読み飛ばされる。実際に入力しようとしている欄のすぐ隣に出す。
   */
  function showFieldWarning(field) {
    const state = window[STATE_KEY];
    if (!state.risk || state.fieldWarned === field) return;
    state.fieldWarned = field;

    const host = makeHost('moribito-field-warning');
    host.style.cssText = 'position:fixed;z-index:2147483646;pointer-events:none';
    const root = host.attachShadow({ mode: 'closed' });

    const box = document.createElement('div');
    box.setAttribute('role', 'alert');
    box.style.cssText = `${WARN_STYLE};background:#7f1d1d;color:#fff;padding:8px 12px;`
      + 'border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.35);max-width:320px;pointer-events:auto';
    const title = document.createElement('div');
    title.style.cssText = 'font-weight:700';
    title.textContent = '⚠ ここに入力する前に確認してください';
    const detail = document.createElement('div');
    detail.style.cssText = 'font-size:12px;opacity:.92;margin-top:2px';
    detail.textContent = (state.risk.reasons ?? []).slice(0, 2).join(' / ')
      || 'このサイトは正規のものではない可能性があります。';
    box.append(title, detail);
    root.append(box);
    (document.body || document.documentElement).append(host);

    const place = () => {
      if (!host.isConnected || !field.isConnected) return;
      const rect = field.getBoundingClientRect();
      const above = rect.top > 90;
      host.style.left = `${Math.max(8, Math.min(rect.left, innerWidth - 336))}px`;
      host.style.top = above ? `${rect.top - 8}px` : `${rect.bottom + 8}px`;
      host.style.transform = above ? 'translateY(-100%)' : 'none';
    };
    place();
    state.placeFieldWarning = place;
    addEventListener('scroll', place, { passive: true, capture: true });
    addEventListener('resize', place, { passive: true });
  }

  /**
   * ② 送信の受け止め。
   * ブロックはせず、取り返しがつかなくなる直前に一度だけ確認を挟む。
   */
  function confirmSubmit(form) {
    return new Promise((resolve) => {
      const host = makeHost('moribito-submit-confirm');
      host.style.cssText = 'position:fixed;inset:0;z-index:2147483647';
      const root = host.attachShadow({ mode: 'closed' });

      const backdrop = document.createElement('div');
      backdrop.style.cssText = 'position:absolute;inset:0;background:rgba(0,0,0,.6);'
        + 'display:flex;align-items:center;justify-content:center;padding:20px';
      const card = document.createElement('div');
      card.setAttribute('role', 'alertdialog');
      card.style.cssText = `${WARN_STYLE};background:#fff;color:#1b1b1f;border-radius:12px;`
        + 'padding:20px;max-width:420px;box-shadow:0 12px 40px rgba(0,0,0,.4)';

      const heading = document.createElement('div');
      heading.style.cssText = 'font-size:16px;font-weight:700;margin-bottom:8px';
      heading.textContent = 'このまま送信しますか？';
      const body = document.createElement('div');
      body.style.cssText = 'font-size:13px;color:#444';
      const state = window[STATE_KEY];
      body.textContent = `${(state.risk?.reasons ?? []).slice(0, 3).join(' / ')
        || 'このサイトは正規のものではない可能性があります。'}`;
      const note = document.createElement('div');
      note.style.cssText = 'font-size:12px;color:#7f1d1d;margin-top:8px';
      note.textContent = '送信すると取り消せません。心当たりが無い場合は送信しないでください。';

      const actions = document.createElement('div');
      actions.style.cssText = 'display:flex;gap:8px;margin-top:16px;justify-content:flex-end';
      const stop = document.createElement('button');
      stop.textContent = '送信しない';
      stop.style.cssText = 'font:inherit;background:#1a56db;color:#fff;border:0;border-radius:8px;padding:8px 16px;cursor:pointer;font-weight:700';
      const proceed = document.createElement('button');
      proceed.textContent = 'それでも送信する';
      proceed.style.cssText = 'font:inherit;background:transparent;color:#7f1d1d;border:1px solid #7f1d1d;border-radius:8px;padding:8px 16px;cursor:pointer';

      const close = (ok) => { host.remove(); resolve(ok); };
      stop.addEventListener('click', () => close(false));
      proceed.addEventListener('click', () => close(true));

      actions.append(stop, proceed);
      card.append(heading, body, note, actions);
      backdrop.append(card);
      root.append(backdrop);
      (document.body || document.documentElement).append(host);
      stop.focus();
    });
  }

  if (!window[STATE_KEY]) {
    window[STATE_KEY] = { reports: 0, risk: null, fieldWarned: null, allowSubmit: null };

    // 入力しようとした瞬間。後から差し込まれるフォームを取りこぼさない。
    document.addEventListener('focusin', (event) => {
      const el = event.target;
      if (!el || !/^(INPUT|TEXTAREA)$/.test(el.tagName)) return;
      report('focusin');
      if (isCredentialField(el)) showFieldWarning(el);
    }, { capture: true, passive: true });

    // 実際に打ち始めたときにも出す。
    // JSで送信する実装では submit イベントが飛ばないので、ここが最後の砦になる。
    document.addEventListener('input', (event) => {
      if (isCredentialField(event.target)) showFieldWarning(event.target);
    }, { capture: true, passive: true });

    // 送信を一度だけ受け止める。ブロックはしない。
    document.addEventListener('submit', (event) => {
      const state = window[STATE_KEY];
      const form = event.target;
      if (!state.risk || !form || state.allowSubmit === form) return;
      const fields = [...form.querySelectorAll('input, textarea')];
      if (!fields.some(isCredentialField)) return;

      event.preventDefault();
      event.stopPropagation();
      confirmSubmit(form).then((ok) => {
        if (!ok) return;
        state.allowSubmit = form;
        // requestSubmit ならページ側の submit ハンドラも動く。
        // form.submit() はそれらを飛ばしてしまうので、使えるときは避ける。
        if (typeof form.requestSubmit === 'function') form.requestSubmit();
        else form.submit();
      });
    }, { capture: true });

    // ここから下は「入力欄を持たない詐欺」向けの契機。
    // サポート詐欺は全画面化・音声再生・クリック誘導のいずれかを必ず伴うので、
    // DOMを監視し続けるのではなく、そのイベント自体を契機にする（常時コストがほぼ無い）。
    document.addEventListener('fullscreenchange', () => {
      if (document.fullscreenElement) report('fullscreen');
    }, { passive: true });

    document.addEventListener('play', (event) => {
      const el = event.target;
      if (el && /^(AUDIO|VIDEO)$/.test(el.tagName) && !el.muted) report('audio');
    }, { capture: true, passive: true, once: true });

    // 最初の操作。詐欺は必ず利用者に何かを押させる。
    document.addEventListener('pointerdown', () => report('interaction'),
      { capture: true, passive: true, once: true });

    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (message?.type === 'show-overlay') {
        showOverlay(message);
        sendResponse({ ok: true });
      }
      if (message?.type === 'set-risk') {
        window[STATE_KEY].risk = message.level ? { level: message.level, reasons: message.reasons ?? [] } : null;
        sendResponse({ ok: true });
      }
      if (message?.type === 'collect-evidence') {
        sendResponse({ ok: true, evidence: collect('request') });
      }
      return false;
    });
  }

  // 監視モード（信頼済みドメイン）では読み込み時の走査をしない。
  // イベントが起きたときだけ収集するので、通常のページに負担をかけない。
  if (globalThis.__moribitoMode === 'watch') {
    return { ok: true, mode: 'watch' };
  }

  // この値が executeScript の戻り値になる
  return collect('load');
})();
