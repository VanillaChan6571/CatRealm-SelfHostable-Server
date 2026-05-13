'use strict';

const crypto = require('crypto');
const axios = require('axios');
const pteroLog = require('../logger');

const RELAY_ENABLED = !!process.env.PUSH_RELAY_SECRET;
const CENTRAL_URL = (process.env.AUTH_SERVER_URL || 'https://auth.catrealm.app').replace(/\/+$/, '');
const RELAY_SECRET = process.env.PUSH_RELAY_SECRET || '';
const SERVER_URL = (process.env.SERVER_URL || process.env.PUBLIC_URL || '').replace(/\/+$/, '');

/**
 * Relay a server @mention push to the central CatRealm server.
 * Non-fatal — failures are logged but never thrown.
 *
 * @param {{
 *   recipientUserIds: string[],
 *   channelId: string,
 *   channelName: string,
 *   senderUsername: string,
 *   contentPreview: string,
 * }} payload
 */
async function relayMentionPush(payload) {
  if (!RELAY_ENABLED) return;
  if (!payload.recipientUserIds || payload.recipientUserIds.length === 0) return;

  const body = JSON.stringify({
    type: 'server_mention',
    recipientUserIds: payload.recipientUserIds,
    serverId: SERVER_URL,
    channelId: payload.channelId,
    channelName: payload.channelName,
    senderUsername: payload.senderUsername,
    contentPreview: (payload.contentPreview || '').slice(0, 200),
  });

  const sig = crypto.createHmac('sha256', RELAY_SECRET).update(body).digest('hex');

  try {
    await axios.post(`${CENTRAL_URL}/api/push/relay`, body, {
      headers: {
        'Content-Type': 'application/json',
        'X-Relay-Sig': sig,
        'X-Relay-Server-Url': SERVER_URL,
      },
      timeout: 5000,
    });
  } catch (err) {
    pteroLog(`[PushRelay] Relay failed: ${err.message}`);
  }
}

module.exports = { relayMentionPush, RELAY_ENABLED };
