const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModule } = require('./helpers');

test('central media fallback uses its enrolled secret and the public realm origin', () => {
  const env = {
    CENTRAL_LIVEKIT_FALLBACK: 'true',
    CENTRAL_MEDIA_RELAY_SECRET: 'synthetic-media-secret-at-least-32-chars',
    PUBLIC_SERVER_URL: 'https://realm.example',
    SERVER_URL: 'http://0.0.0.0:40500',
  };
  const mediaConfig = loadModule('src/lib/mediaConfig.js', {
    '../db': {},
    './hostNetworkLimits': { getHostUdpBufferLimit: () => ({ available: false }) },
  }, { process: { env } });
  assert.equal(mediaConfig.readLiveKitConfig().centralLiveKitFallback, true);

  const fallback = loadModule('src/lib/centralMediaFallback.js', {
    '../logger': () => {},
    './mediaConfig': { getSelfHostServerId: () => 'synthetic-realm' },
  }, { process: { env } });
  assert.equal(fallback.isConfigured(), true);

  delete env.CENTRAL_MEDIA_RELAY_SECRET;
  env.PUSH_RELAY_SECRET = 'retired-push-secret-at-least-32-chars';
  assert.equal(mediaConfig.readLiveKitConfig().centralLiveKitFallback, false);
  assert.equal(loadModule('src/lib/centralMediaFallback.js', {
    '../logger': () => {},
    './mediaConfig': { getSelfHostServerId: () => 'synthetic-realm' },
  }, { process: { env } }).isConfigured(), false);
});
