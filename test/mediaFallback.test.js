const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModule } = require('./helpers');

const loadFallback = env => loadModule('src/lib/centralMediaFallback.js', {
  '../settings': { getSetting: (_key, fallback) => fallback, setSetting: () => {} },
  './realmIdentity': { getPublicRealmIdentity: () => ({}), signRelayPayload: () => ({}) },
  '../logger': () => {},
  './mediaConfig': { getSelfHostServerId: () => 'synthetic-realm' },
}, { process: { env } });

test('central media fallback needs only the toggle and a public realm origin', () => {
  const env = {
    CENTRAL_LIVEKIT_FALLBACK: 'true',
    PUBLIC_SERVER_URL: 'https://realm.example',
    SERVER_URL: 'http://0.0.0.0:40500',
  };
  const mediaConfig = loadModule('src/lib/mediaConfig.js', {
    '../db': {},
    './hostNetworkLimits': { getHostUdpBufferLimit: () => ({ available: false }) },
  }, { process: { env } });
  // No CENTRAL_MEDIA_RELAY_SECRET: the realm self-enrolls with central.
  assert.equal(mediaConfig.readLiveKitConfig().centralLiveKitFallback, true);
  assert.equal(loadFallback(env).isConfigured(), true);

  // HTTP realms enroll through their CatRealm gateway binding instead.
  env.PUBLIC_SERVER_URL = 'http://realm.example';
  assert.equal(mediaConfig.readLiveKitConfig().centralLiveKitFallback, true);
  assert.equal(loadFallback(env).isConfigured(), true);

  env.PUBLIC_SERVER_URL = 'ftp://realm.example';
  assert.equal(mediaConfig.readLiveKitConfig().centralLiveKitFallback, false);
  assert.equal(loadFallback(env).isConfigured(), false);

  env.PUBLIC_SERVER_URL = 'https://realm.example';
  env.CENTRAL_LIVEKIT_FALLBACK = 'false';
  assert.equal(mediaConfig.readLiveKitConfig().centralLiveKitFallback, false);
  assert.equal(loadFallback(env).isConfigured(), false);
});

test('a listen address is not an enrollable origin, and the startup log says why', () => {
  const { describeCentralFallback, centralFallbackOrigin } = require('../src/lib/centralFallbackConfig');
  // The Pterodactyl egg always sets SERVER_URL to a listen address.
  const egg = { CENTRAL_LIVEKIT_FALLBACK: 'true', SERVER_URL: 'http://0.0.0.0:40820' };
  assert.equal(centralFallbackOrigin(egg), null);
  assert.equal(loadFallback(egg).isConfigured(), false);
  assert.match(describeCentralFallback(egg), /^OFF: set PUBLIC_URL .*current: http:\/\/0\.0\.0\.0:40820/);
  for (const url of ['http://localhost:40500', 'http://127.0.0.1', 'https://[::1]:443', 'https://realm.example/path']) {
    assert.equal(centralFallbackOrigin({ PUBLIC_URL: url }), null, url);
  }
  assert.equal(centralFallbackOrigin({ PUBLIC_URL: 'https://realm.example:40820/' }), 'https://realm.example:40820');

  assert.match(describeCentralFallback({}), /^OFF \(CENTRAL_LIVEKIT_FALLBACK is unset; set it to true/);
  assert.match(describeCentralFallback({ CENTRAL_LIVEKIT_FALLBACK: 'false' }), /is "false"/);
  assert.match(describeCentralFallback({ ...egg, PUBLIC_URL: 'https://realm.example:40820' }),
    /^ON for https:\/\/realm\.example:40820 \(self-enrolls with Central\)$/);
  assert.match(describeCentralFallback({ ...egg, PUBLIC_URL: 'http://203.0.113.7:40820' }), /via the bridge\.catrealm\.app gateway/);
});

test('the enrollment challenge only confirms states this realm issued', () => {
  const fallback = loadFallback({ CENTRAL_LIVEKIT_FALLBACK: 'true', PUBLIC_URL: 'https://realm.example' });
  assert.equal(fallback.hasPendingEnrollment('not-issued-by-this-realm'), false);
});

test('only verified-looking gateway origins are remembered', () => {
  const saved = [];
  const fallback = loadModule('src/lib/centralMediaFallback.js', {
    '../settings': { getSetting: (_key, fallback) => fallback, setSetting: (key, value) => saved.push([key, value]) },
    './realmIdentity': { getPublicRealmIdentity: () => ({}), signRelayPayload: () => ({}) },
    '../logger': () => {},
    './mediaConfig': { getSelfHostServerId: () => 'synthetic-realm' },
  }, { process: { env: { CENTRAL_LIVEKIT_FALLBACK: 'true', PUBLIC_URL: 'http://realm.example' } } });
  fallback.rememberGatewayOrigin('https://evil.example');
  fallback.rememberGatewayOrigin(`https://r-${'a'.repeat(40)}.bridge.catrealm.app`);
  assert.deepEqual(saved, [['central_media_gateway_origin', `https://r-${'a'.repeat(40)}.bridge.catrealm.app`]]);
});
