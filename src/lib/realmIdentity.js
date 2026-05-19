'use strict';

const crypto = require('crypto');
const { getSetting, setSetting } = require('../settings');

const INSTANCE_ID_KEY = 'realm_instance_id';
const PRIVATE_KEY_KEY = 'realm_signing_private_key_pem';
const PUBLIC_KEY_KEY = 'realm_signing_public_key_pem';

function publicKeyFingerprint(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function ensureRealmIdentity() {
  let realmInstanceId = getSetting(INSTANCE_ID_KEY, null);
  let privateKeyPem = getSetting(PRIVATE_KEY_KEY, null);
  let publicKeyPem = getSetting(PUBLIC_KEY_KEY, null);

  if (!realmInstanceId) {
    realmInstanceId = crypto.randomUUID();
    setSetting(INSTANCE_ID_KEY, realmInstanceId);
  }

  if (!privateKeyPem || !publicKeyPem) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    setSetting(PRIVATE_KEY_KEY, privateKeyPem);
    setSetting(PUBLIC_KEY_KEY, publicKeyPem);
  }

  return {
    realmInstanceId,
    privateKeyPem,
    publicKeyPem,
    realmKeyFingerprint: publicKeyFingerprint(publicKeyPem),
  };
}

function getPublicRealmIdentity() {
  const identity = ensureRealmIdentity();
  return {
    realmInstanceId: identity.realmInstanceId,
    realmPublicKeyPem: identity.publicKeyPem,
    realmKeyFingerprint: identity.realmKeyFingerprint,
  };
}

function signRelayPayload(payload) {
  const identity = ensureRealmIdentity();
  const body = Buffer.from(canonicalJson(payload));
  const signature = crypto.sign(null, body, identity.privateKeyPem).toString('base64');
  return {
    ...getPublicRealmIdentity(),
    signature,
  };
}

module.exports = {
  ensureRealmIdentity,
  getPublicRealmIdentity,
  canonicalJson,
  signRelayPayload,
};
