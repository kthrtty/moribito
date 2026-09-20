/** 設定画面。 */
import { PRIVACY_COST } from '../core/reputation.js';

const $ = (id) => document.getElementById(id);

const PERF_LABEL = { low: '負荷: 小', medium: '負荷: 中', high: '負荷: 大' };

/** 判定レイヤ（検出器）の描画。段階順にそのまま並ぶ。 */
function renderDetectors(detectors) {
  const box = $('detectors');
  box.textContent = '';
  for (const detector of detectors) {
    const row = document.createElement('div');
    row.className = 'detector';

    const toggle = document.createElement('input');
    toggle.type = 'checkbox';
    toggle.id = `detector-${detector.id}`;
    toggle.checked = detector.enabled;
    toggle.addEventListener('change', async () => {
      const res = await chrome.runtime.sendMessage({
        type: 'set-detector', id: detector.id, patch: { enabled: toggle.checked },
      });
      if (res?.detectors) renderDetectors(res.detectors);
    });

    const body = document.createElement('div');
    body.className = 'body';
    const name = document.createElement('div');
    name.className = 'name';
    name.textContent = detector.label;
    const desc = document.createElement('div');
    desc.className = 'desc';
    desc.textContent = detector.description;
    body.append(name, desc);

    const stage = document.createElement('span');
    stage.className = 'stage';
    stage.textContent = detector.stage;

    const cost = document.createElement('span');
    const network = detector.cost?.network ?? 'none';
    cost.className = `tag ${network === 'none' ? '' : 'cost-2'}`;
    cost.textContent = network === 'none' ? '通信なし' : '外部通信あり';

    row.append(toggle, body, stage, cost);
    box.append(row);
  }
}

/** 機能フラグ（外部連携）の描画。既定は全て無効。 */
function renderProviders(providers) {
  const box = $('providers');
  box.textContent = '';
  for (const provider of providers) {
    const card = document.createElement('div');
    card.className = 'provider';

    const head = document.createElement('header');
    const toggle = document.createElement('input');
    toggle.type = 'checkbox';
    toggle.id = `provider-${provider.id}`;
    toggle.checked = Boolean(provider.enabled);

    const label = document.createElement('label');
    label.setAttribute('for', toggle.id);
    label.textContent = provider.label;

    const cost = PRIVACY_COST[provider.kind] ?? { label: provider.kind, order: 0 };
    const costTag = document.createElement('span');
    costTag.className = `tag cost-${cost.order}`;
    costTag.textContent = cost.label;

    const perfTag = document.createElement('span');
    perfTag.className = `tag perf-${provider.perf}`;
    perfTag.textContent = PERF_LABEL[provider.perf] ?? '';

    head.append(toggle, label, costTag, perfTag);

    const note = document.createElement('p');
    note.className = 'note';
    note.textContent = provider.note;

    const endpoint = document.createElement('input');
    endpoint.type = 'text';
    endpoint.id = `endpoint-${provider.id}`;
    endpoint.placeholder = 'エンドポイントURL（{domain} {url} {prefix} {ip} {key} を展開します）';
    endpoint.value = provider.endpoint ?? '';

    const save = async () => {
      const res = await chrome.runtime.sendMessage({
        type: 'set-provider',
        id: provider.id,
        patch: { enabled: toggle.checked, endpoint: endpoint.value.trim() },
      });
      if (res?.providers) renderProviders(res.providers);
    };
    toggle.addEventListener('change', save);
    endpoint.addEventListener('change', save);

    card.append(head, note, endpoint);
    box.append(card);
  }
}

/** APIキーは値を受け取らず、設定済みかどうかだけを表示する。 */
async function refreshSecretStatus() {
  const res = await chrome.runtime.sendMessage({ type: 'secret-status' });
  $('jev-key-status').textContent = res?.status?.jev
    ? '状態: 設定済み（値は表示されません）'
    : '状態: 未設定';
}

async function refreshBlocklistStatus() {
  const res = await chrome.runtime.sendMessage({ type: 'blocklist-status' });
  renderBlocklistStatus(res?.status);
}

function renderBlocklistStatus(status) {
  const el = $('blocklist-status');
  if (!status?.available) {
    el.textContent = '状態: リストなし（ルールのみ）';
    return;
  }
  if (!status.size) {
    el.textContent = '状態: 空のリスト（未取得）';
    return;
  }
  const date = status.generatedAt ? status.generatedAt.slice(0, 10) : '不明';
  el.textContent = `状態: ${status.size.toLocaleString()} 件 / ${date} 生成`
    + (status.stale ? '（期限切れ・要更新）' : '');
}

function apply(settings) {
  if (!settings) return;
  $('block').value = settings.blockThreshold;
  $('block-out').value = Number(settings.blockThreshold).toFixed(2);
  $('warn').value = settings.warnThreshold;
  $('warn-out').value = Number(settings.warnThreshold).toFixed(2);
  $('use-model').checked = Boolean(settings.useModel);
  $('inspect-pages').checked = Boolean(settings.inspectPages);
  $('use-blocklist').checked = Boolean(settings.useBlocklist);
  $('blocklist-url').value = settings.blocklistUrl ?? '';
  $('doh-endpoint').value = settings.dohEndpoint ?? '';
  $('jev-model').value = settings.jevConfig?.model ?? '';
  $('jev-endpoint').value = settings.jevConfig?.endpoint ?? '';
  $('jev-full-url').checked = Boolean(settings.jevConfig?.sendFullUrl);
  $('allowlist').value = (settings.allowlist ?? []).join('\n');
  $('stat-checked').textContent = String(settings.stats?.checked ?? 0);
  $('stat-warned').textContent = String(settings.stats?.warned ?? 0);
  $('stat-blocked').textContent = String(settings.stats?.blocked ?? 0);
}

async function main() {
  const res = await chrome.runtime.sendMessage({ type: 'get-settings' });
  apply(res.settings);

  $('block').addEventListener('input', (e) => { $('block-out').value = Number(e.target.value).toFixed(2); });
  $('warn').addEventListener('input', (e) => { $('warn-out').value = Number(e.target.value).toFixed(2); });

  $('save').addEventListener('click', async () => {
    const blockThreshold = Number($('block').value);
    const warnThreshold = Math.min(Number($('warn').value), blockThreshold - 0.01);
    const patch = {
      blockThreshold,
      warnThreshold,
      useModel: $('use-model').checked,
      inspectPages: $('inspect-pages').checked,
      useBlocklist: $('use-blocklist').checked,
      blocklistUrl: $('blocklist-url').value.trim(),
      dohEndpoint: $('doh-endpoint').value.trim(),
      jevConfig: {
        model: $('jev-model').value.trim(),
        endpoint: $('jev-endpoint').value.trim(),
        sendFullUrl: $('jev-full-url').checked,
      },
      allowlist: $('allowlist').value.split('\n').map((s) => s.trim().toLowerCase()).filter(Boolean),
    };
    const saved = await chrome.runtime.sendMessage({ type: 'set-settings', patch });
    apply(saved.settings);
    $('saved').classList.add('show');
    setTimeout(() => $('saved').classList.remove('show'), 1400);
  });

  $('reset').addEventListener('click', async () => {
    const saved = await chrome.runtime.sendMessage({ type: 'reset-settings' });
    apply(saved.settings);
  });

  const detectorRes = await chrome.runtime.sendMessage({ type: 'get-detectors' });
  renderDetectors(detectorRes?.detectors ?? []);

  const providerRes = await chrome.runtime.sendMessage({ type: 'get-providers' });
  renderProviders(providerRes?.providers ?? []);

  await refreshSecretStatus();
  $('jev-key-save').addEventListener('click', async (e) => {
    e.preventDefault();
    const value = $('jev-key').value.trim();
    if (!value) return;
    await chrome.runtime.sendMessage({ type: 'set-secret', id: 'jev', value });
    $('jev-key').value = '';   // 画面には残さない
    await refreshSecretStatus();
  });
  $('jev-key-clear').addEventListener('click', async (e) => {
    e.preventDefault();
    await chrome.runtime.sendMessage({ type: 'set-secret', id: 'jev', value: '' });
    $('jev-key').value = '';
    await refreshSecretStatus();
  });

  await refreshBlocklistStatus();
  $('blocklist-update').addEventListener('click', async (e) => {
    e.preventDefault();
    $('blocklist-status').textContent = '状態: 更新中…';
    const saved = await chrome.runtime.sendMessage({
      type: 'set-settings', patch: { blocklistUrl: $('blocklist-url').value.trim() },
    });
    apply(saved.settings);
    const res = await chrome.runtime.sendMessage({ type: 'blocklist-update' });
    if (!res?.ok) {
      $('blocklist-status').textContent = res?.error === 'no-url'
        ? '状態: 取得元URLが未設定です'
        : `状態: 更新に失敗しました（${res?.error ?? '不明'}）`;
      return;
    }
    renderBlocklistStatus(res.status);
  });

  const state = await chrome.runtime.sendMessage({ type: 'model-state' });
  const labels = { ready: '読み込み済み', unavailable: 'モデル未配置（ルールのみ）', idle: '未ロード', loading: '読み込み中' };
  $('model-state').textContent = `状態: ${labels[state?.state] ?? '不明'}`;
}

main();
