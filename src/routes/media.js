const router = require('express').Router();
const db = require('../db');
const { authenticateToken } = require('../middleware/auth');
const {
  PERMISSIONS,
  hasChannelPermission,
} = require('../permissions');
const {
  TRACK_SOURCES,
  createMediaToken,
  getMediaCapability,
  getIngressClient,
  getSelfHostServerId,
  readLiveKitIngressConfig,
} = require('../lib/mediaConfig');
const { requestFederatedMediaToken } = require('../lib/centralMediaFallback');

const LIVEKIT_INGRESS_INPUT_WHIP = 1; // @livekit/protocol IngressInput.WHIP_INPUT

function getSelfHostMediaContexts() {
  return ['voice', 'theater'];
}

function getUserProfile(userId) {
  return db.prepare(`
    SELECT u.id, u.username, u.display_name, u.avatar, u.account_type,
      COALESCE(dno.display_name, u.display_name) AS effective_display_name
    FROM users u
    LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
    WHERE u.id = ?
  `).get(userId);
}

function buildPublishSources(user, channelId) {
  const publishSources = [];
  const permissions = {
    microphone: false,
    camera: false,
    screenVideo: false,
    screenAudio: false,
  };

  const canUseVoiceActivity = hasChannelPermission(user, channelId, PERMISSIONS.USE_VOICE_ACTIVITY, db);
  const canUsePushToTalk = hasChannelPermission(user, channelId, PERMISSIONS.USE_PUSH_TO_TALK, db);
  permissions.microphone = canUseVoiceActivity || canUsePushToTalk;
  if (permissions.microphone) publishSources.push(TRACK_SOURCES.microphone);

  permissions.camera = hasChannelPermission(user, channelId, PERMISSIONS.CAMERA, db);
  if (permissions.camera) publishSources.push(TRACK_SOURCES.camera);

  permissions.screenVideo = hasChannelPermission(user, channelId, PERMISSIONS.SCREENSHARE, db);
  permissions.screenAudio = permissions.screenVideo;
  if (permissions.screenVideo) publishSources.push(TRACK_SOURCES.screenVideo);
  if (permissions.screenAudio) publishSources.push(TRACK_SOURCES.screenAudio);

  return { publishSources, permissions };
}

function sanitizeLiveKitIdentityPart(value) {
  return String(value || '').replace(/[^A-Za-z0-9._:-]/g, '_');
}

function serializeIngressInfo(info) {
  return {
    ingressId: info.ingressId || '',
    name: info.name || '',
    url: info.url || '',
    streamKey: info.streamKey || '',
    inputType: info.inputType ?? null,
    roomName: info.roomName || '',
    participantIdentity: info.participantIdentity || '',
    participantName: info.participantName || '',
    participantMetadata: info.participantMetadata || '',
    enableTranscoding: info.enableTranscoding ?? null,
    bypassTranscoding: info.bypassTranscoding ?? null,
    reusable: info.reusable ?? null,
    enabled: info.enabled ?? null,
    state: info.state
      ? {
          status: info.state.status ?? null,
          startedAt: info.state.startedAt ?? null,
          endedAt: info.state.endedAt ?? null,
          error: info.state.error || '',
          resourceId: info.state.resourceId || '',
          tracks: info.state.tracks ?? [],
        }
      : null,
  };
}

async function deleteStaleWhipIngresses(client, roomName, participantIdentity) {
  let existing = [];
  try {
    existing = await client.listIngress({ roomName });
  } catch {
    return;
  }
  await Promise.all(existing
    .filter((item) => item?.participantIdentity === participantIdentity)
    .map((item) => client.deleteIngress(item.ingressId).catch(() => null)));
}

function normalizeWhipVideoTarget(value) {
  const raw = value && typeof value === 'object' ? value : {};
  const height = Number(raw.height);
  const fps = Number(raw.fps);
  return {
    height: [720, 1080, 1440].includes(height) ? height : null,
    fps: [24, 48, 60].includes(fps) ? fps : null,
  };
}

async function createSelfHostWhipIngressSession({ context, channelId, user, video }) {
  if (!['voice', 'theater'].includes(context)) {
    return { ok: false, status: 400, error: 'Unsupported media context' };
  }
  if (!channelId) {
    return { ok: false, status: 400, error: 'Missing channelId' };
  }

  const ingressConfig = readLiveKitIngressConfig();
  const ingressClient = getIngressClient();
  if (!ingressConfig.enabled || !ingressClient) {
    return { ok: false, status: 503, error: 'WHIP ingress unavailable', capability: getMediaCapability(getSelfHostMediaContexts()) };
  }

  const channel = db.prepare('SELECT id, type FROM channels WHERE id = ?').get(channelId);
  if (!channel || channel.type !== context) {
    return { ok: false, status: 404, error: `Not a ${context} channel` };
  }
  if (!hasChannelPermission(user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
    return { ok: false, status: 403, error: 'Missing permission: view_channels' };
  }
  if (context === 'voice' && !hasChannelPermission(user, channelId, PERMISSIONS.CONNECT_TO_VOICE, db)) {
    return { ok: false, status: 403, error: 'Missing permission: connect_to_voice' };
  }
  if (!hasChannelPermission(user, channelId, PERMISSIONS.SCREENSHARE, db)) {
    return { ok: false, status: 403, error: 'Missing permission: screenshare' };
  }

  const serverId = getSelfHostServerId();
  const roomName = `${context}:${serverId}:${channelId}`;
  const userProfile = getUserProfile(user.id);
  const displayName = userProfile?.effective_display_name || userProfile?.display_name || userProfile?.username || user.username || user.id;
  const participantIdentity = `catrealm-ingress:${sanitizeLiveKitIdentityPart(user.id)}:screen:${sanitizeLiveKitIdentityPart(channelId)}`;
  const videoTarget = normalizeWhipVideoTarget(video);
  const participantMetadata = JSON.stringify({
    mediaRole: 'screen-share-ingress',
    ownerIdentity: String(user.id),
    userId: user.id,
    username: userProfile?.username || user.username || null,
    displayName: userProfile?.effective_display_name || userProfile?.display_name || null,
    avatar: userProfile?.avatar || null,
    accountType: userProfile?.account_type || user.accountType || 'local',
    sourceContext: context,
    serverId,
    channelId,
    transport: 'whip',
    transcoding: false,
    screenShareVideoTarget: videoTarget.height && videoTarget.fps ? videoTarget : null,
  });

  await deleteStaleWhipIngresses(ingressClient, roomName, participantIdentity);

  const ingress = await ingressClient.createIngress(LIVEKIT_INGRESS_INPUT_WHIP, {
    name: `CatRealm screen share ${displayName}`,
    roomName,
    participantIdentity,
    participantName: `${displayName} screen`,
    participantMetadata,
    enableTranscoding: false,
  });

  return {
    ok: true,
    provider: 'livekit',
    context,
    serverId,
    channelId,
    roomName,
    ingress: serializeIngressInfo(ingress),
    whip: {
      url: ingress.url || ingressConfig.publicWhipUrl,
      streamKey: ingress.streamKey || '',
      publicBaseUrl: ingressConfig.publicWhipUrl,
    },
  };
}

function createSelfHostMediaSession({ context, channelId, user }) {
  if (!['voice', 'theater'].includes(context)) {
    return { ok: false, status: 400, error: 'Unsupported media context' };
  }
  if (!channelId) {
    return { ok: false, status: 400, error: 'Missing channelId' };
  }

  const channel = db.prepare('SELECT id, type FROM channels WHERE id = ?').get(channelId);
  if (!channel || channel.type !== context) {
    return { ok: false, status: 404, error: `Not a ${context} channel` };
  }
  if (!hasChannelPermission(user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
    return { ok: false, status: 403, error: 'Missing permission: view_channels' };
  }
  if (context === 'voice' && !hasChannelPermission(user, channelId, PERMISSIONS.CONNECT_TO_VOICE, db)) {
    return { ok: false, status: 403, error: 'Missing permission: connect_to_voice' };
  }

  const serverId = getSelfHostServerId();
  const userProfile = getUserProfile(user.id);
  const { publishSources, permissions } = buildPublishSources(user, channelId);
  const roomName = `${context}:${serverId}:${channelId}`;
  const token = createMediaToken({
    identity: user.id,
    name: userProfile?.effective_display_name || userProfile?.display_name || userProfile?.username || user.id,
    roomName,
    publishSources,
    canPublish: publishSources.length > 0,
    metadata: {
      userId: user.id,
      username: userProfile?.username || user.username || null,
      displayName: userProfile?.effective_display_name || userProfile?.display_name || null,
      avatar: userProfile?.avatar || null,
      accountType: userProfile?.account_type || user.accountType || 'local',
      sourceContext: context,
      serverId,
      channelId,
      permissions,
    },
  });

  if (!token.ok) return token;
  return {
    ...token,
    context,
    serverId,
    channelId,
  };
}

async function createSelfHostMediaSessionWithFallback({ context, channelId, user }) {
  const result = createSelfHostMediaSession({ context, channelId, user });
  if (result.ok || !['voice', 'theater'].includes(context) || !channelId || result.status !== 503) {
    return result;
  }

  try {
    const userProfile = getUserProfile(user.id);
    const { publishSources } = buildPublishSources(user, channelId);
    const fallback = await requestFederatedMediaToken({
      context,
      channelId,
      userId: user.id,
      displayName: userProfile?.effective_display_name || userProfile?.display_name || userProfile?.username || null,
      avatar: userProfile?.avatar || null,
      publishSources,
    });
    if (fallback?.ok) return fallback;
  } catch {
    // Fall through to the original local-media error.
  }

  return result;
}

router.get('/capabilities', (_req, res) => {
  res.json({ ok: true, capability: getMediaCapability(getSelfHostMediaContexts()) });
});

router.post('/token', authenticateToken, async (req, res) => {
  const { context, channelId } = req.body || {};
  const result = await createSelfHostMediaSessionWithFallback({ context, channelId, user: req.user });
  if (!result.ok) {
    return res.status(result.status || 400).json({
      ok: false,
      error: result.error,
      capability: getMediaCapability(getSelfHostMediaContexts()),
    });
  }
  res.json(result);
});

router.post('/ingress/whip', authenticateToken, async (req, res) => {
  const { context, channelId, video } = req.body || {};
  try {
    const result = await createSelfHostWhipIngressSession({ context, channelId, user: req.user, video });
    if (!result.ok) {
      return res.status(result.status || 400).json({
        ok: false,
        error: result.error,
        capability: getMediaCapability(getSelfHostMediaContexts()),
      });
    }
    res.json(result);
  } catch (err) {
    res.status(502).json({
      ok: false,
      error: `Failed to create WHIP ingress: ${err?.message || String(err)}`,
      capability: getMediaCapability(getSelfHostMediaContexts()),
    });
  }
});

module.exports = {
  router,
  createSelfHostMediaSession,
  createSelfHostWhipIngressSession,
  createSelfHostMediaSessionWithFallback,
  getSelfHostMediaContexts,
};
