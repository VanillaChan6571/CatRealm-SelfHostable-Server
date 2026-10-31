'use strict';

// Env-only helpers shared by media capability, Central enrollment and the
// startup log, so all three agree on whether Central LiveKit fallback is on.

const LISTEN_ONLY_HOST = /^(0\.0\.0\.0|localhost|127\.\d+\.\d+\.\d+|\[::1?\])$/i;

function isTruthy(value) {
  return /^(1|true|yes|on)$/i.test(String(value ?? '').trim());
}

function rawPublicUrl(env) {
  return (env.PUBLIC_URL || env.PUBLIC_SERVER_URL || env.SERVER_URL || '').trim().replace(/\/+$/, '');
}

/**
 * The exact public http(s) origin Central enrolls this realm under, or null.
 * A listen address such as the egg's SERVER_URL=http://0.0.0.0:PORT is not
 * reachable from Central, so it never counts.
 */
function centralFallbackOrigin(env = process.env) {
  const raw = rawPublicUrl(env);
  try {
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== raw || LISTEN_ONLY_HOST.test(url.hostname)) return null;
    return url.origin;
  } catch { return null; }
}

function isCentralFallbackEnabled(env = process.env) {
  return isTruthy(env.CENTRAL_LIVEKIT_FALLBACK) && !!centralFallbackOrigin(env);
}

function describeCentralFallback(env = process.env) {
  if (!isTruthy(env.CENTRAL_LIVEKIT_FALLBACK)) {
    return 'OFF (set CENTRAL_LIVEKIT_FALLBACK=true to use CatRealm Central LiveKit)';
  }
  const origin = centralFallbackOrigin(env);
  if (!origin) {
    return `OFF: set PUBLIC_URL to this realm's public origin, e.g. https://realm.example.com:40500 (current: ${rawPublicUrl(env) || 'unset'})`;
  }
  const key = (env.CENTRAL_MEDIA_RELAY_SECRET || '').length >= 32 ? 'operator-issued key' : 'self-enrolls with Central';
  return origin.startsWith('https:')
    ? `ON for ${origin} (${key})`
    : `ON for ${origin} via the bridge.catrealm.app gateway (${key}; needs a gateway binding)`;
}

module.exports = { centralFallbackOrigin, isCentralFallbackEnabled, describeCentralFallback };
