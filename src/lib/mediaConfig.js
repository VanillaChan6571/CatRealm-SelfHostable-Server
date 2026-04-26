const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const db = require('../db');

const DEFAULT_TOKEN_TTL_SECONDS = 10 * 60;

const TRACK_SOURCES = {
  microphone: 'microphone',
  camera: 'camera',
  screenVideo: 'screen_video',
  screenAudio: 'screen_audio',
};

const LIVEKIT_PUBLISH_SOURCE_MAP = {
  [TRACK_SOURCES.microphone]: 'microphone',
  [TRACK_SOURCES.camera]: 'camera',
  [TRACK_SOURCES.screenVideo]: 'screen_share',
  [TRACK_SOURCES.screenAudio]: 'screen_share_audio',
};

function isTruthy(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

function readLiveKitConfig() {
  const enabled = isTruthy(process.env.MEDIA_LIVEKIT_ENABLED, false);
  const apiKey = (process.env.MEDIA_LIVEKIT_API_KEY || process.env.LIVEKIT_API_KEY || '').trim();
  const apiSecret = (process.env.MEDIA_LIVEKIT_API_SECRET || process.env.LIVEKIT_API_SECRET || '').trim();
  const serverUrl = (process.env.MEDIA_LIVEKIT_URL || process.env.LIVEKIT_URL || '').trim();
  const publicUrl = (
    process.env.MEDIA_LIVEKIT_PUBLIC_WS_URL ||
    process.env.MEDIA_LIVEKIT_PUBLIC_URL ||
    process.env.LIVEKIT_PUBLIC_WS_URL ||
    process.env.LIVEKIT_URL ||
    ''
  ).trim();
  const fallbackToLegacy = isTruthy(process.env.MEDIA_FALLBACK_TO_LEGACY, true);
  const ttlSeconds = Math.max(
    60,
    Math.min(60 * 60, Number(process.env.MEDIA_TOKEN_TTL_SECONDS || DEFAULT_TOKEN_TTL_SECONDS) || DEFAULT_TOKEN_TTL_SECONDS),
  );
  const configured = !!(apiKey && apiSecret && publicUrl);

  return {
    provider: 'livekit',
    enabled: enabled && configured,
    configured,
    serverUrl,
    publicUrl,
    apiKey,
    apiSecret,
    fallbackToLegacy,
    ttlSeconds,
  };
}

function getSelfHostServerId() {
  const fromEnv = (process.env.CATREALM_SERVER_ID || process.env.SERVER_ID || '').trim();
  if (fromEnv) return fromEnv.replace(/[^A-Za-z0-9._:-]/g, '_');

  const existing = db.prepare('SELECT value FROM server_settings WHERE key = ?').get('server_id')?.value;
  if (existing) return existing;

  const generated = randomUUID();
  db.prepare(`
    INSERT INTO server_settings (key, value)
    VALUES ('server_id', ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(generated);
  return generated;
}

function getMediaCapability(contexts) {
  const config = readLiveKitConfig();
  return {
    version: 1,
    provider: config.provider,
    enabled: config.enabled,
    configured: config.configured,
    fallbackToLegacy: config.fallbackToLegacy,
    publicUrl: config.enabled ? config.publicUrl : null,
    contexts,
    roomNamespace: {
      dm: 'dm:{callId}',
      group: 'group:{callId}',
      voice: 'voice:{serverId}:{channelId}',
      theater: 'theater:{serverId}:{channelId}',
    },
    participantIdentity: 'catrealm-user-id',
    trackSources: Object.values(TRACK_SOURCES),
    privacy: {
      mediaPath: config.enabled ? 'sfu' : 'legacy',
      e2ee: false,
      transportEncrypted: config.enabled,
      label: config.enabled ? 'Transport encrypted, SFU routed' : 'Legacy P2P path',
    },
  };
}

function getLiveKitPublishSources(trackSources) {
  return [...new Set((trackSources || [])
    .map((source) => LIVEKIT_PUBLISH_SOURCE_MAP[source])
    .filter(Boolean))];
}

function createMediaToken({
  identity,
  name,
  metadata,
  roomName,
  canPublish = true,
  canSubscribe = true,
  canPublishData = true,
  publishSources = Object.values(TRACK_SOURCES),
}) {
  const config = readLiveKitConfig();
  if (!config.enabled) {
    return { ok: false, status: 503, error: 'Media server unavailable', capability: getMediaCapability([]) };
  }
  if (!identity || !roomName) {
    return { ok: false, status: 400, error: 'Missing media identity or room' };
  }

  const now = Math.floor(Date.now() / 1000);
  const video = {
    roomJoin: true,
    room: roomName,
    canPublish: !!canPublish,
    canSubscribe: !!canSubscribe,
    canPublishData: !!canPublishData,
  };
  const canPublishSources = getLiveKitPublishSources(publishSources);
  if (canPublishSources.length > 0) {
    video.canPublishSources = canPublishSources;
  }

  const payload = {
    iss: config.apiKey,
    sub: String(identity),
    nbf: now - 5,
    exp: now + config.ttlSeconds,
    video,
  };
  if (name) payload.name = String(name);
  if (metadata) payload.metadata = JSON.stringify(metadata);

  const token = jwt.sign(payload, config.apiSecret, { algorithm: 'HS256' });
  return {
    ok: true,
    token,
    url: config.publicUrl,
    provider: config.provider,
    roomName,
    identity: String(identity),
    expiresAt: payload.exp,
    publishSources,
    privacy: {
      e2ee: false,
      transportEncrypted: true,
      mediaPath: 'sfu',
      label: 'Transport encrypted, SFU routed',
    },
  };
}

module.exports = {
  TRACK_SOURCES,
  createMediaToken,
  getMediaCapability,
  getSelfHostServerId,
  readLiveKitConfig,
};
