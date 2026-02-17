const crypto = require('crypto');

const DEFAULT_TTL_SECONDS = 30 * 60;
const MIN_TTL_SECONDS = 30;
const MAX_TTL_SECONDS = 6 * 60 * 60;
const ALLOWED_PROXY_HOSTS = new Set([
  'video.twimg.com',
  'pbs.twimg.com',
]);

function getSecret() {
  const configured = String(process.env.EMBED_PROXY_SECRET || process.env.JWT_SECRET || '').trim();
  if (configured) return configured;
  return 'catrealm-embed-proxy-fallback-secret';
}

function normalizeHttpUrl(rawUrl) {
  if (typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

function isAllowedEmbedProxyHost(hostname) {
  const host = String(hostname || '').toLowerCase().trim();
  if (!host) return false;
  if (ALLOWED_PROXY_HOSTS.has(host)) return true;
  for (const allowedHost of ALLOWED_PROXY_HOSTS.values()) {
    if (host.endsWith(`.${allowedHost}`)) {
      return true;
    }
  }
  return false;
}

function timingSafeEqualString(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function signEncodedPayload(encodedPayload) {
  return crypto.createHmac('sha256', getSecret()).update(encodedPayload).digest('base64url');
}

function createEmbedProxyToken(rawUrl, ttlSeconds = DEFAULT_TTL_SECONDS) {
  const normalizedUrl = normalizeHttpUrl(rawUrl);
  if (!normalizedUrl) return null;

  let parsed;
  try {
    parsed = new URL(normalizedUrl);
  } catch {
    return null;
  }

  if (!isAllowedEmbedProxyHost(parsed.hostname)) {
    return null;
  }

  const ttl = Math.max(MIN_TTL_SECONDS, Math.min(MAX_TTL_SECONDS, Number(ttlSeconds) || DEFAULT_TTL_SECONDS));
  const exp = Math.floor(Date.now() / 1000) + ttl;
  const payload = { u: normalizedUrl, e: exp };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = signEncodedPayload(encoded);
  return `${encoded}.${signature}`;
}

function verifyEmbedProxyToken(token) {
  const rawToken = String(token || '').trim();
  if (!rawToken) return null;

  const dotIndex = rawToken.indexOf('.');
  if (dotIndex <= 0 || dotIndex === rawToken.length - 1) return null;
  const encoded = rawToken.slice(0, dotIndex);
  const providedSignature = rawToken.slice(dotIndex + 1);
  if (!encoded || !providedSignature) return null;

  const expectedSignature = signEncodedPayload(encoded);
  if (!timingSafeEqualString(expectedSignature, providedSignature)) {
    return null;
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    return null;
  }

  const exp = Number(payload?.e);
  if (!Number.isFinite(exp) || exp <= Math.floor(Date.now() / 1000)) {
    return null;
  }

  const normalizedUrl = normalizeHttpUrl(payload?.u);
  if (!normalizedUrl) return null;

  let parsed;
  try {
    parsed = new URL(normalizedUrl);
  } catch {
    return null;
  }

  if (!isAllowedEmbedProxyHost(parsed.hostname)) {
    return null;
  }

  return { url: normalizedUrl, exp };
}

module.exports = {
  createEmbedProxyToken,
  verifyEmbedProxyToken,
  isAllowedEmbedProxyHost,
};
