'use strict';

const crypto = require('crypto');
const axios = require('axios');
const { getSetting, setSetting } = require('../settings');
const pteroLog = require('../logger');
const { getSelfHostServerId } = require('./mediaConfig');
const { getPublicRealmIdentity, signRelayPayload } = require('./realmIdentity');
const { centralFallbackOrigin } = require('./centralFallbackConfig');

const FALLBACK_ENABLED = /^(1|true|yes|on)$/i.test((process.env.CENTRAL_LIVEKIT_FALLBACK || '').trim());
const CENTRAL_URL = (process.env.AUTH_SERVER_URL || 'https://auth.catrealm.app').replace(/\/+$/, '');
const ENV_SECRET = process.env.CENTRAL_MEDIA_RELAY_SECRET || '';
const SECRET_SETTING = 'central_media_relay_secret';
const ORIGIN_SETTING = 'central_media_relay_origin';
const GATEWAY_SETTING = 'central_media_gateway_origin';
const GATEWAY_ORIGIN = /^https:\/\/r-[a-f0-9]{40}\.bridge\.catrealm\.app$/;
const ENROLLMENT_TTL_MS = 60 * 1000;

const pendingEnrollments = new Map(); // state -> expiresAt
let enrollmentInFlight = null;

// Read when needed: Auto-SSL can settle the public origin after this loads.
function realmOrigin() {
  return centralFallbackOrigin(process.env) || '';
}

// HTTPS realms enroll directly; HTTP realms enroll through their gateway binding.
function isConfigured() {
  return FALLBACK_ENABLED && !!realmOrigin();
}

function hasPendingEnrollment(state) {
  const expiresAt = pendingEnrollments.get(state);
  return typeof expiresAt === 'number' && expiresAt > Date.now();
}

/** Called after auth verifies an X-CatRealm-Gateway-Origin against the gateway. */
function rememberGatewayOrigin(origin) {
  if (GATEWAY_ORIGIN.test(origin) && getSetting(GATEWAY_SETTING, null) !== origin) setSetting(GATEWAY_SETTING, origin);
}

// The gateway's binding ID is derived from our HTTP origin and identity, so we
// can predict it even before any user has signed in through the gateway.
function gatewayOriginForThisRealm() {
  const remembered = getSetting(GATEWAY_SETTING, null);
  if (remembered && GATEWAY_ORIGIN.test(remembered)) return remembered;
  const identity = getPublicRealmIdentity();
  const id = crypto.createHash('sha256')
    .update(`${realmOrigin()}\n${identity.realmInstanceId}\n${identity.realmKeyFingerprint}`)
    .digest('hex').slice(0, 40);
  return `https://r-${id}.bridge.catrealm.app`;
}

function enrollmentRequest(state) {
  const origin = realmOrigin();
  if (origin.startsWith('https:')) return { origin, body: { origin, state } };
  // Plain HTTP: prove our identity with the key the gateway pinned for us.
  const gatewayOrigin = gatewayOriginForThisRealm();
  const identity = getPublicRealmIdentity();
  const payload = {
    purpose: 'catrealm-central-media-enroll',
    gatewayOrigin,
    nonce: state,
    realmInstanceId: identity.realmInstanceId,
    realmKeyFingerprint: identity.realmKeyFingerprint,
    expiresAt: Math.floor(Date.now() / 1000) + 60,
  };
  const { signature, realmPublicKeyPem } = signRelayPayload(payload);
  return { origin: gatewayOrigin, body: { gatewayOrigin, payload, signature, realmPublicKeyPem } };
}

/**
 * Self-enroll with central and persist the origin-bound relay key. HTTPS realms
 * answer GET {origin}/api/media/central-enrollment/:state; HTTP realms sign
 * the request instead and are enrolled under their gateway origin.
 */
async function enroll() {
  const state = crypto.randomBytes(32).toString('base64url');
  pendingEnrollments.set(state, Date.now() + ENROLLMENT_TTL_MS);
  try {
    const { origin, body } = enrollmentRequest(state);
    const { data } = await axios.post(`${CENTRAL_URL}/api/media/federated/enroll`, body, { timeout: 15000 });
    if (!data?.ok || data.origin !== origin || typeof data.key !== 'string' || data.key.length < 32) return null;
    setSetting(SECRET_SETTING, data.key);
    setSetting(ORIGIN_SETTING, origin);
    pteroLog(`[CentralMediaFallback] Enrolled ${origin} with central media`);
    return { secret: data.key, origin };
  } catch (err) {
    const reason = err.response?.data?.error || err.message;
    pteroLog(`[CentralMediaFallback] Central enrollment failed: ${reason}`);
    return null;
  } finally {
    pendingEnrollments.delete(state);
  }
}

async function getRelayCredentials({ refresh = false } = {}) {
  if (ENV_SECRET.length >= 32) return { secret: ENV_SECRET, origin: realmOrigin(), fromEnv: true };
  if (!refresh) {
    const secret = getSetting(SECRET_SETTING, null);
    const origin = getSetting(ORIGIN_SETTING, null);
    if (secret && origin) return { secret, origin };
  }
  enrollmentInFlight ??= enroll().finally(() => { enrollmentInFlight = null; });
  return enrollmentInFlight;
}

function postSigned(requestPath, body, { secret, origin }) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomBytes(24).toString('base64url');
  const signed = `POST\n${requestPath}\n${origin}\n${timestamp}\n${nonce}\n${body}`;
  const sig = crypto.createHmac('sha256', secret).update(signed).digest('hex');
  return axios.post(`${CENTRAL_URL}${requestPath}`, body, {
    headers: {
      'Content-Type': 'application/json',
      'X-Relay-Sig': sig,
      'X-Relay-Server-URL': origin,
      'X-Relay-Timestamp': timestamp,
      'X-Relay-Nonce': nonce,
    },
    timeout: 8000,
  });
}

/**
 * Request a LiveKit token from central's federated media endpoint.
 * Central validates the realm's origin-bound key and a fresh, single-use request.
 *
 * Returns the token response object or null if unavailable/disabled.
 */
async function requestFederatedMediaToken({ context, channelId, userId, displayName, avatar, publishSources, role }) {
  if (!isConfigured()) return null;
  if (!['voice', 'theater'].includes(context)) return null;

  const serverId = getSelfHostServerId();
  const body = JSON.stringify({
    serverId,
    context,
    channelId: String(channelId),
    userId: String(userId),
    displayName: displayName || null,
    avatar: avatar || null,
    publishSources: Array.isArray(publishSources) ? publishSources : [],
    ...(role ? { role } : {}),
  });
  const requestPath = `/api/media/federated/${context}-token`;

  try {
    let credentials = await getRelayCredentials();
    if (!credentials) return null;
    let response;
    try {
      response = await postSigned(requestPath, body, credentials);
    } catch (err) {
      // A stored key can go stale (central rotated its secret): re-enroll once.
      if (err.response?.status !== 401 || credentials.fromEnv) throw err;
      credentials = await getRelayCredentials({ refresh: true });
      if (!credentials) return null;
      response = await postSigned(requestPath, body, credentials);
    }
    if (response.data?.ok) {
      pteroLog(`[CentralMediaFallback] Got central LiveKit token for ${context} channel ${channelId}`);
      return response.data;
    }
    return null;
  } catch (err) {
    pteroLog(`[CentralMediaFallback] Failed to get central token: ${err.message}`);
    return null;
  }
}

module.exports = { requestFederatedMediaToken, isConfigured, hasPendingEnrollment, rememberGatewayOrigin };
