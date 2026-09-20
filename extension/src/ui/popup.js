/** ツールバーのポップアップ。現在のタブの判定結果を表示する。 */
const $ = (id) => document.getElementById(id);

const VERDICT_LABEL = { block: '危険', warn: '注意', allow: '問題なし' };
const VERDICT_COLOR = { block: 'var(--danger)', warn: 'var(--warn)', allow: 'var(--ok)' };

let current = null;

function render(result) {
  current = result;
  const verdict = result?.verdict ?? 'allow';
  // 偽装ドメインの「見た目」を主見出しに出すと偽装をそのまま再現してしまう。
  // 実体(ASCII)を主、見た目を副として明示する。
  $('host').textContent = result?.host || '—';
  const deceptive = result?.hostUnicode && result.hostUnicode !== result.host;
  $('host-sub').hidden = !deceptive;
  $('host-sub').textContent = deceptive ? `表示される文字: ${result.hostUnicode}` : '';
  $('verdict').textContent = VERDICT_LABEL[verdict];
  $('verdict').className = `badge ${verdict}`;
  const pct = Math.round((result?.score ?? 0) * 100);
  $('score').textContent = String(pct);
  $('meter-fill').style.width = `${pct}%`;
  $('meter-fill').style.background = VERDICT_COLOR[verdict];

  const box = $('signals');
  box.textContent = '';
  const signals = result?.signals ?? [];
  if (!signals.length) {
    const span = document.createElement('span');
    span.className = 'empty';
    span.textContent = reasonText(result) || '危険な特徴は見つかりませんでした。';
    box.append(span);
    return;
  }
  for (const s of signals) {
    const row = document.createElement('div');
    row.className = 'signal';
    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.style.opacity = String(0.35 + s.weight * 0.65);
    const body = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'title';
    title.textContent = s.title;
    const detail = document.createElement('div');
    detail.className = 'detail';
    detail.textContent = s.detail;
    body.append(title, detail);
    row.append(bar, body);
    box.append(row);
  }
}

function reasonText(result) {
  const reason = result?.reason ?? '';
  if (reason.startsWith('official:')) return '正規ブランドの公式ドメインです。';
  if (reason === 'popular-domain') return '広く使われている既知のドメインです。';
  if (reason === 'allowlisted') return 'あなたが許可したドメインです。';
  if (reason === 'private-network') return '社内・自宅ネットワーク上のホストです。';
  if (reason === 'non-web-scheme') return 'このページは判定対象外です（http/https以外）。';
  return '';
}

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const settingsRes = await chrome.runtime.sendMessage({ type: 'get-settings' });
  $('enabled').checked = settingsRes?.settings?.enabled ?? true;

  const res = await chrome.runtime.sendMessage({ type: 'get-verdict', tabId: tab?.id, url: tab?.url });
  render(res?.result);

  $('enabled').addEventListener('change', async (e) => {
    await chrome.runtime.sendMessage({ type: 'set-settings', patch: { enabled: e.target.checked } });
  });

  $('options').addEventListener('click', () => chrome.runtime.openOptionsPage());

  $('allow-domain').addEventListener('click', async () => {
    const host = current?.registrable || current?.host;
    if (!host) return;
    const s = (await chrome.runtime.sendMessage({ type: 'get-settings' }))?.settings;
    const allowlist = [...new Set([...(s?.allowlist ?? []), host])];
    await chrome.runtime.sendMessage({ type: 'set-settings', patch: { allowlist } });
    $('allow-domain').textContent = `${host} を許可しました`;
    $('allow-domain').disabled = true;
  });

  $('check-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = $('check-url').value.trim();
    if (!url) return;
    const normalized = /^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `http://${url}`;
    const r = await chrome.runtime.sendMessage({ type: 'analyze-url', url: normalized });
    render(r?.result);
  });
}

main();
