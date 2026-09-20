/** URL から判定用の特徴量を取り出す（ブランド知識には依存しない層）。 */
import { toUnicode, punycodeLabels } from './punycode.js';
import { splitHost, isIpHost, isPrivateHost } from './psl.js';
import { skeleton, collapse, hasConfusable } from './confusables.js';
import {
  hasInvisible, hasBidiControl, hasDotLookalike, scriptProfile, mixedScriptLabels,
} from './unicode.js';
import { shannonEntropy, tokenize, digitRatio, countOccurrences, maxConsonantRun } from './text.js';

const AUTHORITY_RE = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i;

export function extractFeatures(rawUrl) {
  const raw = String(rawUrl ?? '');
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { ok: false, error: 'invalid-url', raw };
  }

  const scheme = u.protocol.replace(':', '');
  const rawAuthority = AUTHORITY_RE.exec(raw)?.[1] ?? '';

  // URLパーサがIDNA処理で消してしまう痕跡は生文字列側で拾う
  const rawArtifacts = {
    invisible: hasInvisible(raw),
    bidi: hasBidiControl(raw),
    dotLookalike: hasDotLookalike(rawAuthority),
    atSign: rawAuthority.includes('@'),
  };

  const hostAscii = u.hostname;                 // xn-- 形式（パーサ正規化済み）
  const hostUnicode = toUnicode(hostAscii);     // 人間が見る形
  const parts = splitHost(hostAscii);

  const subUnicode = toUnicode(parts.sub);
  const nameUnicode = toUnicode(parts.name);
  const registrableUnicode = toUnicode(parts.registrable);

  const path = decodeSafely(u.pathname);
  const query = decodeSafely(u.search);
  const hash = decodeSafely(u.hash);

  const skelHost = skeleton(hostUnicode);
  const skelRegistrable = skeleton(registrableUnicode);
  const skelName = skeleton(nameUnicode);
  const skelSub = skeleton(subUnicode);

  const hostProfile = scriptProfile(hostUnicode);
  const subLabels = parts.sub ? parts.sub.split('.') : [];

  return {
    ok: true,
    raw,
    url: u.href,
    scheme,
    isHttps: scheme === 'https',
    port: u.port,
    hasNonStandardPort: Boolean(u.port) && u.port !== '80' && u.port !== '443',
    userinfo: Boolean(u.username || u.password),
    rawArtifacts,

    host: hostAscii,
    hostUnicode,
    isIp: isIpHost(hostAscii),
    isPrivateNetwork: isPrivateHost(hostAscii),
    suffix: parts.suffix,
    tld: parts.suffix ? parts.suffix.split('.').pop() : '',
    registrable: parts.registrable,
    registrableUnicode,
    name: parts.name,
    nameUnicode,
    sub: parts.sub,
    subUnicode,
    subLabels,
    labelCount: parts.labels.length,

    punycodeLabels: punycodeLabels(hostAscii),
    hasPunycode: punycodeLabels(hostAscii).length > 0,
    hasConfusableChars: hasConfusable(hostUnicode),
    scriptKind: hostProfile.kind,
    scripts: hostProfile.scripts,
    mixedScriptLabels: mixedScriptLabels(hostUnicode),

    skelHost,
    skelRegistrable,
    skelName,
    skelSub,
    collapsedName: collapse(nameUnicode),
    collapsedHost: collapse(hostUnicode),

    hostTokens: tokenize(skelHost),
    subTokens: tokenize(skelSub),
    nameTokens: tokenize(skelName),
    pathTokens: tokenize(`${path} ${query} ${hash}`),

    path,
    query,
    hash,
    urlLength: raw.length,
    hostLength: hostAscii.length,
    subLength: parts.sub.length,
    hyphenCount: countOccurrences(parts.registrable ? `${parts.sub}.${parts.name}` : hostAscii, '-'),
    digitRatioName: digitRatio(nameUnicode),
    subEntropy: shannonEntropy(parts.sub.replace(/\./g, '')),
    nameEntropy: shannonEntropy(nameUnicode),
    maxConsonantRun: maxConsonantRun(nameUnicode),
    pathDepth: path.split('/').filter(Boolean).length,
  };
}

function decodeSafely(s) {
  const str = String(s ?? '');
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}
