'use strict';

const crypto = require('crypto');
const axios = require('axios');
const pteroLog = require('../logger');
const { getSelfHostServerId } = require('./mediaConfig');

const FALLBACK_ENABLED = /^(1|true|yes|on)$/i.test((process.env.CENTRAL_LIVEKIT_FALLBACK || '').trim());
const CENTRAL_URL = (process.env.AUTH_SERVER_URL || 'https://auth.catrealm.app').replace(/\/+$/, '');
const RELAY_SECRET = process.env.PUSH_RELAY_SECRET || '';
const SERVER_URL = (process.env.SERVER_URL || process.env.PUBLIC_URL || '').replace(/\/+$/, '');

function isConfigured() {
  return FALLBACK_ENABLED && !!RELAY_SECRET && RELAY_SECRET.length >= 32 && !!SERVER_URL;
}

/**
 * Request a LiveKit token from central's federated media endpoint.
 * Central validates the request via HMAC (same key as push relay).
 *
 * Returns the token response object or null if unavailable/disabled.
 */
async function requestFederatedMediaToken({ context, channelId, userId, displayName, avatar, publishSources }) {
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
  });

  const sig = crypto.createHmac('sha256', RELAY_SECRET).update(body).digest('hex');

  try {
    const response = await axios.post(
      `${CENTRAL_URL}/api/media/federated/${context}-token`,
      body,
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Relay-Sig': sig,
          'X-Relay-Server-URL': SERVER_URL,
        },
        timeout: 8000,
      },
    );
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

module.exports = { requestFederatedMediaToken, isConfigured };
