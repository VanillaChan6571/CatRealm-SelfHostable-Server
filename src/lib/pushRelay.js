'use strict';

const crypto = require('crypto');
const axios = require('axios');
const pteroLog = require('../logger');
const db = require('../db');
const { ensureRealmIdentity, signRelayPayload } = require('./realmIdentity');

const RELAY_ENABLED = !!process.env.PUSH_RELAY_SECRET;
const CENTRAL_URL = (process.env.AUTH_SERVER_URL || 'https://auth.catrealm.app').replace(/\/+$/, '');
const RELAY_SECRET = process.env.PUSH_RELAY_SECRET || '';
const SERVER_URL = (process.env.SERVER_URL || process.env.PUBLIC_URL || '').replace(/\/+$/, '');

let registered = false;

function toServerPublicUrl(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  if (!SERVER_URL) return null;
  if (trimmed.startsWith('/')) return `${SERVER_URL}${trimmed}`;
  return `${SERVER_URL}/${trimmed}`;
}

async function ensureRegistered() {
  if (registered || !RELAY_ENABLED || !SERVER_URL) return;
  try {
    await axios.post(`${CENTRAL_URL}/api/push/relay/register`, {
      serverUrl: SERVER_URL,
      relayKey: RELAY_SECRET,
    }, { timeout: 8000 });
    registered = true;
    pteroLog('[PushRelay] Registered with central server');
  } catch (err) {
    pteroLog(`[PushRelay] Registration failed (will retry on next @mention): ${err.message}`);
  }
}

/**
 * Relay a server @mention push to the central CatRealm server.
 * Non-fatal — failures are logged but never thrown.
 *
 * @param {{
 *   recipientUserIds: string[],
 *   channelId: string,
 *   channelName: string,
 *   senderUsername: string,
 *   senderAvatarUrl?: string,
 *   contentPreview: string,
 * }} payload
 */
async function relayMentionPush(payload) {
  if (!RELAY_ENABLED) return;
  if (!payload.recipientUserIds || payload.recipientUserIds.length === 0) return;

  await ensureRegistered();

  const body = JSON.stringify({
    type: 'server_mention',
    recipientUserIds: payload.recipientUserIds,
    serverId: SERVER_URL,
    channelId: payload.channelId,
    channelName: payload.channelName,
    senderUsername: payload.senderUsername,
    senderAvatarUrl: toServerPublicUrl(payload.senderAvatarUrl),
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
    registered = false; // force re-registration on next attempt in case key changed
    pteroLog(`[PushRelay] Relay failed: ${err.message}`);
  }
}

/**
 * Relay durable mention notifications using user-scoped asymmetric grants.
 * Falls back independently from legacy push relay; one failed recipient should
 * not prevent other grant-backed recipients from being notified.
 */
async function relayMentionNotifications(payload) {
  if (!payload?.recipientLocalUserIds?.length || !SERVER_URL) return new Set();
  const identity = ensureRealmIdentity();
  const placeholders = payload.recipientLocalUserIds.map(() => '?').join(',');
  const grants = db.prepare(`
    SELECT grant_id, central_user_id, local_user_id
    FROM realm_notification_whitelist
    WHERE local_user_id IN (${placeholders})
      AND realm_instance_id = ?
      AND revoked_at IS NULL
      AND superseded_at IS NULL
  `).all(...payload.recipientLocalUserIds, identity.realmInstanceId);
  if (grants.length === 0) return new Set();

  const relayed = await Promise.all(grants.map(async (grant) => {
    const relayPayload = {
      centralUserId: grant.central_user_id,
      channelId: payload.channelId,
      channelName: payload.channelName,
      contentPreview: (payload.contentPreview || '').slice(0, 200),
      grantId: grant.grant_id,
      issuedAt: Math.floor(Date.now() / 1000),
      localUserId: grant.local_user_id,
      messageCreatedAt: payload.messageCreatedAt,
      messageId: payload.messageId,
      nonce: crypto.randomUUID(),
      realmInstanceId: identity.realmInstanceId,
      realmUrl: SERVER_URL,
      senderAvatarUrl: toServerPublicUrl(payload.senderAvatarUrl),
      senderUsername: payload.senderUsername,
      type: 'server_mention',
    };
    const signed = signRelayPayload(relayPayload);
    try {
      await axios.post(`${CENTRAL_URL}/api/notifications/realm-relay`, {
        payload: relayPayload,
        realmPublicKeyPem: signed.realmPublicKeyPem,
        signature: signed.signature,
      }, { timeout: 5000 });
      return grant.local_user_id;
    } catch (err) {
      pteroLog(`[PushRelay] Signed mention relay failed for ${grant.local_user_id}: ${err.message}`);
      return null;
    }
  }));
  return new Set(relayed.filter(Boolean));
}

// Register on startup (non-blocking)
void ensureRegistered();

module.exports = { relayMentionPush, relayMentionNotifications, RELAY_ENABLED };
