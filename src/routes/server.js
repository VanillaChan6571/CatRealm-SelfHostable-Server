const router = require('express').Router();
const db = require('../db');
const { getSetting } = require('../settings');
const { authenticateToken } = require('../middleware/auth');
const { execSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getPublicRealmIdentity, signRelayPayload } = require('../lib/realmIdentity');

// Read version from package.json
let packageVersion = '1.0.0';
let gitHash = 'unknown';

try {
  const packagePath = path.join(__dirname, '../../package.json');
  const packageData = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  packageVersion = packageData.version || '1.0.0';
} catch (err) {
  console.error('Failed to read package.json version:', err.message);
}

// Get git commit hash (silent fallback when deployment is not a git checkout)
const repoRoot = path.join(__dirname, '../..');
if (fs.existsSync(path.join(repoRoot, '.git'))) {
  try {
    gitHash = execSync('git rev-parse --short HEAD', {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    gitHash = 'unknown';
  }
}

// GET /api/server — public info shown to client before login
router.get('/', (req, res) => {
  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const mode = process.env.SERVER_MODE || 'decentral_only';
  const name = getSetting('server_name', process.env.SERVER_NAME || 'CatRealm Server');
  const description = getSetting(
    'server_description',
    process.env.SERVER_DESCRIPTION || 'A self-hosted CatRealm server'
  );
  const registrationOpen = getSetting(
    'registration_open',
    process.env.REGISTRATION_OPEN !== 'false' ? 'true' : 'false'
  );
  const mentionAlias = getSetting('mention_alias', '@everyone');
  const serverIcon = getSetting('server_icon', null);
  const serverBanner = getSetting('server_banner', null);
  const secureMode = {
    enabled: process.env.CATREALM_SECURE_MODE_EFFECTIVE === '1',
    locked: process.env.CATREALM_SECURE_MODE_LOCKED === '1',
  };
  const welcomeBoardEnabled = getSetting('welcome_board_enabled', '0') === '1';
  const mediaMaxMb = Number(getSetting('media_max_mb', '50'));

  res.json({
    name,
    description,
    mode,             // 'central_only' | 'mixed' | 'decentral_only'
    registrationOpen: registrationOpen === 'true',
    userCount,
    mentionAlias,
    serverIcon,
    serverBanner,
    secureMode,
    welcomeBoardEnabled,
    mediaMaxMb,
    version: packageVersion,
    gitHash: gitHash,
    buildInfo: `v${packageVersion} (${gitHash})`
  });
});

// GET /api/server/identity — stable Realm trust identity.
// A changed instance ID or key fingerprint at the same URL means the Realm was
// reset/replaced and central clients must ask the user to re-approve trust.
router.get('/identity', (_req, res) => {
  res.json(getPublicRealmIdentity());
});

// POST /api/server/identity/attestation — signed proof that the authenticated
// local central-linked user belongs to the requested central identity.
router.post('/identity/attestation', authenticateToken, (req, res) => {
  if (req.user?.accountType !== 'central') {
    return res.status(403).json({ error: 'Central account required' });
  }
  const localUser = db.prepare('SELECT id, central_id FROM users WHERE id = ?').get(req.user.id);
  if (!localUser?.central_id) {
    return res.status(409).json({ error: 'Local account is not linked to a central account' });
  }
  const nonce = typeof req.body?.nonce === 'string' && req.body.nonce.trim()
    ? req.body.nonce.trim()
    : crypto.randomUUID();
  const issuedAt = Math.floor(Date.now() / 1000);
  const identity = getPublicRealmIdentity();
  const payload = {
    centralUserId: localUser.central_id,
    issuedAt,
    localUserId: localUser.id,
    nonce,
    realmInstanceId: identity.realmInstanceId,
    realmKeyFingerprint: identity.realmKeyFingerprint,
  };
  const signed = signRelayPayload(payload);
  res.json({
    payload,
    realmPublicKeyPem: identity.realmPublicKeyPem,
    signature: signed.signature,
  });
});

// POST /api/server/notification-grants — install a Central-issued grant ID for
// this authenticated linked local user. Central remains the final verifier when
// relays arrive, so a fake grant ID is harmless: later relays are rejected.
router.post('/notification-grants', authenticateToken, (req, res) => {
  if (req.user?.accountType !== 'central') {
    return res.status(403).json({ error: 'Central account required' });
  }
  const grantId = typeof req.body?.grantId === 'string' ? req.body.grantId.trim() : '';
  const centralUserId = typeof req.body?.centralUserId === 'string' ? req.body.centralUserId.trim() : '';
  if (!grantId || !centralUserId) {
    return res.status(400).json({ error: 'grantId and centralUserId are required' });
  }
  const localUser = db.prepare('SELECT id, central_id FROM users WHERE id = ?').get(req.user.id);
  if (!localUser?.central_id || localUser.central_id !== centralUserId) {
    return res.status(403).json({ error: 'Central identity does not match local link' });
  }
  const identity = getPublicRealmIdentity();
  db.prepare(`
    INSERT INTO realm_notification_whitelist (
      grant_id, central_user_id, local_user_id, realm_instance_id, central_grant_payload
    ) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(grant_id) DO UPDATE SET
      central_user_id = excluded.central_user_id,
      local_user_id = excluded.local_user_id,
      realm_instance_id = excluded.realm_instance_id,
      central_grant_payload = excluded.central_grant_payload,
      revoked_at = NULL,
      superseded_at = NULL
  `).run(
    grantId,
    centralUserId,
    localUser.id,
    identity.realmInstanceId,
    JSON.stringify(req.body?.grant ?? {}),
  );
  res.json({ success: true, grantId, realmInstanceId: identity.realmInstanceId });
});

module.exports = router;
