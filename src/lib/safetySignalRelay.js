'use strict';

const crypto = require('crypto');
const axios = require('axios');
const db = require('../db');
const pteroLog = require('../logger');
const { ensureRealmIdentity, signRelayPayload } = require('./realmIdentity');

const CENTRAL_URL = (process.env.AUTH_SERVER_URL || 'https://auth.catrealm.app').replace(/\/+$/, '');
const REALM_URL = (process.env.PUBLIC_URL || process.env.PUBLIC_SERVER_URL || process.env.SERVER_URL || '').replace(/\/+$/, '');

async function relayChildSafetySignal({ reportId, subjectLocalUserId, reason, artifactKind }) {
  if (!REALM_URL) return { relayed: false, reason: 'no_public_realm_url' };
  const subject = db.prepare('SELECT central_id FROM users WHERE id = ?').get(subjectLocalUserId);
  if (!subject?.central_id) return { relayed: false, reason: 'not_central_identity' };
  const identity = ensureRealmIdentity();
  const grant = db.prepare(`SELECT grant_id FROM realm_notification_whitelist WHERE local_user_id = ? AND central_user_id = ? AND realm_instance_id = ? AND revoked_at IS NULL AND superseded_at IS NULL ORDER BY created_at DESC LIMIT 1`)
    .get(subjectLocalUserId, subject.central_id, identity.realmInstanceId);
  if (!grant) return { relayed: false, reason: 'no_user_approved_realm_grant' };
  const payload = {
    type: 'realm_child_safety_signal',
    grantId: grant.grant_id,
    subjectCentralUserId: subject.central_id,
    subjectLocalUserId,
    realmUrl: REALM_URL,
    realmInstanceId: identity.realmInstanceId,
    realmReportId: reportId,
    reason,
    artifactKind,
    issuedAt: Math.floor(Date.now() / 1000),
    nonce: crypto.randomUUID(),
  };
  const signed = signRelayPayload(payload);
  try {
    await axios.post(`${CENTRAL_URL}/api/notifications/realm-safety-signal`, { payload, realmPublicKeyPem: signed.realmPublicKeyPem, signature: signed.signature }, { timeout: 5000 });
    return { relayed: true };
  } catch (error) {
    pteroLog(`[Safety] Central metadata signal failed: ${error.response?.data?.error || error.message}`);
    return { relayed: false, reason: 'central_relay_failed' };
  }
}

module.exports = { relayChildSafetySignal };
