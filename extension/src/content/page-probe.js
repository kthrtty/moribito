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
    const trapSignals = {
      // 戻れなくする / 離脱を邪魔する仕掛け
      beforeUnload: typeof window.onbeforeunload === 'function',
      fullscreenRequested: Boolean(document.fullscreenElement),
      autoplayAudio: [...document.querySelectorAll('audio, video')].some((m) => m.autoplay && !m.muted),
      modalOverlayCount: [...document.querySelectorAll('div, section')].slice(0, 400).filter((el) => {
        const style = getComputedStyle(el);
        return style.position === 'fixed' && Number(style.zIndex) > 1000
          && el.getBoundingClientRect().height > innerHeight * 0.6;
      }).length,
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

  if (!window[STATE_KEY]) {
    window[STATE_KEY] = { reported: false };

    // 実際に入力しようとした瞬間に見直す。後から差し込まれるフォームを取りこぼさない。
    document.addEventListener('focusin', (event) => {
      const el = event.target;
      if (!el || !/^(INPUT|TEXTAREA)$/.test(el.tagName)) return;
      if (window[STATE_KEY].reported) return;
      window[STATE_KEY].reported = true;
      try {
        chrome.runtime.sendMessage({ type: 'page-evidence', evidence: collect('focusin') });
      } catch {
        // 拡張が再読み込みされた等。ページ側には影響させない。
      }
    }, { capture: true, passive: true });

    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      if (message?.type === 'show-overlay') {
        showOverlay(message);
        sendResponse({ ok: true });
      }
      if (message?.type === 'collect-evidence') {
        sendResponse({ ok: true, evidence: collect('request') });
      }
      return false;
    });
  }

  // この値が executeScript の戻り値になる
  return collect('load');
})();
