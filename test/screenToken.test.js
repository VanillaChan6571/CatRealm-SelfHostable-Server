const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModule, makeDatabase, getUser } = require('./helpers');
const { PERMISSIONS } = require('../src/permissions');

const TRACK_SOURCES = { microphone: 'microphone', camera: 'camera', screenVideo: 'screen_video', screenAudio: 'screen_audio' };

// Loads the media routes against an in-memory realm. `localLiveKit` decides
// whether tokens are minted locally or the request falls back to Central.
function setup({ localLiveKit = true, memberPermissions } = {}) {
  const db = makeDatabase();
  db.prepare("INSERT INTO channels (id, name, type) VALUES ('lobby', 'Lobby', 'voice')").run();
  const P = PERMISSIONS;
  const perms = memberPermissions ?? (P.VIEW_CHANNELS + P.CONNECT_TO_VOICE + P.USE_VOICE_ACTIVITY + P.CAMERA + P.SCREENSHARE);
  db.prepare("UPDATE roles SET permissions = ? WHERE id = 'member'").run(perms);
  const minted = [];
  const federated = [];
  const media = loadModule('src/routes/media.js', {
    '../db': db,
    '../middleware/auth': { authenticateToken: (_req, _res, next) => next() },
    '../lib/mediaConfig': {
      TRACK_SOURCES,
      createMediaToken: (args) => {
        minted.push(args);
        return localLiveKit ? { ok: true, token: 'local', identity: args.identity, publishSources: args.publishSources }
          : { ok: false, status: 503, error: 'Media server unavailable' };
      },
      getMediaCapability: () => ({}),
      getIngressClient: () => null,
      getLiveKitServerSdk: () => null,
      getSelfHostServerId: () => 'srv',
      readLiveKitIngressConfig: () => ({ enabled: false }),
    },
    '../lib/centralMediaFallback': {
      requestFederatedMediaToken: async (args) => { federated.push(args); return { ok: true, token: 'central', identity: 'from-central' }; },
      hasPendingEnrollment: () => false,
    },
    '../lib/hostNetworkLimits': { getHostUdpBufferLimit: () => ({ available: false }) },
  });
  const screenToken = (user = getUser(db)) => media.createSelfHostMediaSessionWithFallback({
    context: 'voice', channelId: 'lobby', user, role: 'screen',
  });
  return { db, media, minted, federated, screenToken };
}

test('a local screen token uses the screen identity and only screen sources', async () => {
  const f = setup();
  const result = await f.screenToken();
  assert.equal(result.ok, true);
  const args = f.minted[0];
  assert.equal(args.identity, 'catrealm-ingress:alice:screen:lobby');
  assert.equal(args.name, 'Alice screen');
  assert.deepEqual([...args.publishSources], ['screen_video', 'screen_audio']);
  assert.equal(args.canPublish, true);
  assert.equal(args.canSubscribe, false);
  assert.equal(args.canPublishData, false);
  assert.equal(args.metadata.role, 'screen');
  assert.equal(f.federated.length, 0);
});

test('a screen token falls back to Central with the screen role', async () => {
  const f = setup({ localLiveKit: false });
  const result = await f.screenToken();
  assert.equal(result.token, 'central');
  assert.equal(f.federated[0].role, 'screen');
  assert.deepEqual([...f.federated[0].publishSources], ['screen_video', 'screen_audio']);
});

test('members without screenshare permission get no screen token, locally or from Central', async () => {
  const P = PERMISSIONS;
  const f = setup({ localLiveKit: false, memberPermissions: P.VIEW_CHANNELS + P.CONNECT_TO_VOICE + P.USE_VOICE_ACTIVITY });
  const result = await f.screenToken();
  assert.equal(result.ok, false);
  assert.equal(result.status, 403);
  assert.equal(f.minted.length, 0);
  assert.equal(f.federated.length, 0);
});

test('a normal voice token is unchanged by the screen role', async () => {
  const f = setup();
  await f.media.createSelfHostMediaSessionWithFallback({ context: 'voice', channelId: 'lobby', user: getUser(f.db) });
  const args = f.minted[0];
  assert.equal(args.identity, 'alice');
  assert.ok(args.publishSources.includes('microphone'));
  assert.equal(args.canSubscribe, undefined);
});
