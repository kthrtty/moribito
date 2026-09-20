/** 警告（インタースティシャル）画面。 */
const params = new URLSearchParams(location.search);
const token = params.get('token');

const $ = (id) => document.getElementById(id);

function renderSignals(signals) {
  const box = $('signals');
  box.textContent = '';
  if (!signals?.length) {
    box.textContent = '詳細な特徴は記録されていません。';
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

async function main() {
  const response = token
    ? await chrome.runtime.sendMessage({ type: 'get-details', token })
    : null;
  const result = response?.result;

  if (!result) {
    $('host').textContent = '(判定情報を取得できませんでした)';
    $('full-url').textContent = '';
    renderSignals([]);
    return;
  }

  $('host').textContent = result.host || '(不明)';
  if (result.hostUnicode && result.hostUnicode !== result.host) {
    $('unicode-row').hidden = false;
    $('host-unicode').textContent = result.hostUnicode;
  }
  $('full-url').textContent = result.url ?? '';
  $('score').textContent = `${Math.round((result.score ?? 0) * 100)} / 100`;
  $('verdict').textContent = result.verdict === 'block' ? 'ブロック' : '警告';
  renderSignals(result.signals);

  $('back').addEventListener('click', () => {
    if (history.length > 1) history.back();
    else chrome.tabs.update({ url: 'about:blank' });
  });

  $('details-toggle').addEventListener('click', () => {
    const adv = $('advanced');
    adv.open = !adv.open;
    adv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });

  $('proceed').addEventListener('click', async () => {
    // 宛先は service worker 側が保存レコードから決める（ここでは指定しない）
    await chrome.runtime.sendMessage({
      type: 'proceed',
      token,
      permanent: $('permanent').checked,
    });
  });
}

main();
