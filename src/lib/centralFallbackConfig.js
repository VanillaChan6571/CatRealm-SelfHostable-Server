'use strict';

// Env-only helpers shared by media capability, Central enrollment and the
// startup log, so all three agree on whether Central LiveKit fallback is on.

const LISTEN_ONLY_HOST = /^(0\.0\.0\.0|localhost|127\.\d+\.\d+\.\d+|\[::1?\])$/i;

function isTruthy(value) {
  return /^(1|true|yes|on)$/i.test(String(value ?? '').trim());
}

function trimUrl(value) {
  return String(value || '').trim().replace(/\/+$/, '');
}

function rawPublicUrl(env) {
  return trimUrl(env.PUBLIC_URL || env.PUBLIC_SERVER_URL || env.SERVER_URL);
}

function exactPublicOrigin(raw) {
  try {
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== raw || LISTEN_ONLY_HOST.test(url.hostname)) return null;
    return url.origin;
  } catch { return null; }
}

/**
 * The exact public http(s) origin Central enrolls this realm under, or null.
 * Tries PUBLIC_URL, PUBLIC_SERVER_URL and SERVER_URL in order, skipping
 * listen addresses such as the egg's SERVER_URL=http://0.0.0.0:PORT, then
 * falls back to the HTTPS origin this realm serves when SSL_DOMAIN is set.
 */
function centralFallbackOrigin(env = process.env) {
  const port = trimUrl(env.PORT);
  const candidates = [env.PUBLIC_URL, env.PUBLIC_SERVER_URL, env.SERVER_URL]
    .concat(env.SSL_DOMAIN ? [`https://${trimUrl(env.SSL_DOMAIN)}${port && port !== '443' ? `:${port}` : ''}`] : []);
  for (const candidate of candidates.map(trimUrl).filter(Boolean)) {
    const origin = exactPublicOrigin(candidate);
    if (origin) return origin;
  }
  return null;
}

function isCentralFallbackEnabled(env = process.env) {
  return isTruthy(env.CENTRAL_LIVEKIT_FALLBACK) && !!centralFallbackOrigin(env);
}

function describeCentralFallback(env = process.env) {
  if (!isTruthy(env.CENTRAL_LIVEKIT_FALLBACK)) {
    const seen = env.CENTRAL_LIVEKIT_FALLBACK === undefined ? 'unset' : JSON.stringify(env.CENTRAL_LIVEKIT_FALLBACK);
    return `OFF (CENTRAL_LIVEKIT_FALLBACK is ${seen}; set it to true to use CatRealm Central LiveKit)`;
  }
  const origin = centralFallbackOrigin(env);
  if (!origin) {
    return `OFF: set PUBLIC_URL (or SSL_DOMAIN) so this realm has a public origin, e.g. https://realm.example.com:40500 (current: ${rawPublicUrl(env) || 'unset'})`;
  }
  const key = (env.CENTRAL_MEDIA_RELAY_SECRET || '').length >= 32 ? 'operator-issued key' : 'self-enrolls with Central';
  return origin.startsWith('https:')
    ? `ON for ${origin} (${key})`
    : `ON for ${origin} via the bridge.catrealm.app gateway (${key}; needs a gateway binding)`;
}

module.exports = { centralFallbackOrigin, isCentralFallbackEnabled, describeCentralFallback };
