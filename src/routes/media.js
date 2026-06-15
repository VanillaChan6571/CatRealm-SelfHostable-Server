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
  getLiveKitServerSdk,
  getSelfHostServerId,
  readLiveKitIngressConfig,
} = require('../lib/mediaConfig');
const { requestFederatedMediaToken } = require('../lib/centralMediaFallback');
const { getHostUdpBufferLimit } = require('../lib/hostNetworkLimits');

const LIVEKIT_INGRESS_INPUT_WHIP = 1; // @livekit/protocol IngressInput.WHIP_INPUT
const LIVEKIT_SCREEN_VIDEO_TRACK_NAME_PREFIX = 'catrealm:screen-share-video:';
const WHIP_SIMULCAST_MAX_SOURCE_BITRATE = 22_000_000;
const WHIP_SIMULCAST_MIN_SOURCE_BITRATE = 350_000;
const LIVEKIT_VIDEO_QUALITY = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
};

const WHIP_SIMULCAST_DEFAULT_SOURCE_BITRATE = {
  1440: { 24: 6_000_000, 48: 10_000_000, 60: 14_000_000 },
  1080: { 24: 4_000_000, 48: 7_000_000, 60: 9_000_000 },
   720: { 24: 2_000_000, 48: 3_000_000, 60: 4_000_000 },
};

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
  const safeState = info.state
    ? {
        status: info.state.status ?? null,
        startedAt: serializeJsonSafe(info.state.startedAt ?? null),
        endedAt: serializeJsonSafe(info.state.endedAt ?? null),
        error: info.state.error || '',
        resourceId: info.state.resourceId || '',
      }
    : null;
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
    state: safeState,
  };
}

function serializeJsonSafe(value) {
  if (value === null || value === undefined) return value ?? null;
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number' || typeof value === 'string' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map(serializeJsonSafe);
  if (typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, serializeJsonSafe(entry)]));
  }
  return String(value);
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
  const bitrate = Number(raw.bitrate);
  let normalizedHeight = [720, 1080, 1440].includes(height) ? height : null;
  // Defense in depth: if the host's UDP buffers are at the stock limit, clamp
  // the height server-side too (the client should already have clamped via the
  // capability's ingress.maxHeight, but a stale/old client must not bypass it).
  const maxHeight = getHostUdpBufferLimit().maxHeight;
  if (maxHeight && normalizedHeight && normalizedHeight > maxHeight) {
    normalizedHeight = maxHeight;
  }
  return {
    height: normalizedHeight,
    fps: [24, 48, 60].includes(fps) ? fps : null,
    bitrate: Number.isFinite(bitrate)
      ? Math.max(WHIP_SIMULCAST_MIN_SOURCE_BITRATE, Math.min(WHIP_SIMULCAST_MAX_SOURCE_BITRATE, Math.round(bitrate)))
      : null,
    simulcast: raw.simulcast === true,
  };
}

function getWhipSourceBitrate(videoTarget) {
  if (videoTarget.bitrate) return videoTarget.bitrate;
  const heightKey = videoTarget.height >= 1440 ? 1440 : videoTarget.height >= 1080 ? 1080 : 720;
  const fpsKey = videoTarget.fps >= 60 ? 60 : videoTarget.fps >= 48 ? 48 : 24;
  return WHIP_SIMULCAST_DEFAULT_SOURCE_BITRATE[heightKey][fpsKey];
}

function buildWhipSimulcastLayers(videoTarget) {
  const targetBitrate = getWhipSourceBitrate(videoTarget);
  const mediumHeight = videoTarget.height >= 1080 ? 720 : Math.max(360, Math.round(videoTarget.height / 2));
  const lowHeight = videoTarget.height >= 1080 ? 360 : Math.max(180, Math.round(videoTarget.height / 4));
  const targetWidth = Math.round((videoTarget.height * 16) / 9);
  const mediumWidth = Math.round((mediumHeight * 16) / 9);
  const lowWidth = Math.round((lowHeight * 16) / 9);
  const mediumBitrate = Math.min(Math.round(targetBitrate * 0.45), videoTarget.fps >= 48 ? 4_000_000 : 2_500_000);
  const lowBitrate = Math.min(Math.round(targetBitrate * 0.18), videoTarget.fps >= 48 ? 1_200_000 : 800_000);

  return [
    {
      quality: LIVEKIT_VIDEO_QUALITY.LOW,
      qualityLabel: 'low',
      width: lowWidth,
      height: lowHeight,
      bitrate: Math.max(350_000, lowBitrate),
    },
    {
      quality: LIVEKIT_VIDEO_QUALITY.MEDIUM,
      qualityLabel: 'medium',
      width: mediumWidth,
      height: mediumHeight,
      bitrate: Math.max(900_000, mediumBitrate),
    },
    {
      quality: LIVEKIT_VIDEO_QUALITY.HIGH,
      qualityLabel: 'high',
      width: targetWidth,
      height: videoTarget.height,
      bitrate: targetBitrate,
    },
  ];
}

function buildWhipIngressTranscodingPlan({ ingressConfig, videoTarget }) {
  if (!ingressConfig.simulcastExperiment || !videoTarget.simulcast || !videoTarget.height || !videoTarget.fps) {
    return {
      requested: !!videoTarget.simulcast,
      enabled: false,
      video: undefined,
      layers: [],
    };
  }

  const sdk = getLiveKitServerSdk();
  const hasEncodingSupport = !!(
    sdk?.IngressVideoOptions
    && sdk?.IngressVideoEncodingOptions
    && sdk?.VideoCodec
    && sdk?.TrackSource
  );
  if (!hasEncodingSupport) {
    console.warn('[CatRealm] WHIP simulcast experiment requested, but livekit-server-sdk lacks ingress transcoding constructors. Falling back to single stream.');
    return {
      requested: true,
      enabled: false,
      video: undefined,
      layers: [],
    };
  }

  const layers = buildWhipSimulcastLayers(videoTarget);
  const video = new sdk.IngressVideoOptions({
    name: `${LIVEKIT_SCREEN_VIDEO_TRACK_NAME_PREFIX}${videoTarget.height}p${videoTarget.fps}`,
    source: sdk.TrackSource.SCREEN_SHARE,
    encodingOptions: {
      case: 'options',
      value: new sdk.IngressVideoEncodingOptions({
        videoCodec: sdk.VideoCodec.H264_BASELINE,
        frameRate: videoTarget.fps,
        layers: layers.map(({ quality, width, height, bitrate }) => ({ quality, width, height, bitrate })),
      }),
    },
  });

  return {
    requested: true,
    enabled: true,
    video,
    layers: layers.map(({ qualityLabel, width, height, bitrate }) => ({
      quality: qualityLabel,
      width,
      height,
      bitrate,
      fps: videoTarget.fps,
    })),
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
  const transcodingPlan = buildWhipIngressTranscodingPlan({ ingressConfig, videoTarget });
  const buildParticipantMetadata = (plan) => JSON.stringify({
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
    transcoding: plan.enabled,
    simulcast: plan.enabled,
    screenShareVideoTarget: videoTarget.height && videoTarget.fps
      ? { height: videoTarget.height, fps: videoTarget.fps }
      : null,
    screenShareSimulcast: plan.enabled
      ? {
          experimental: true,
          layers: plan.layers,
        }
      : null,
  });
  const buildIngressOptions = (plan) => ({
    name: `CatRealm screen share ${displayName}`,
    roomName,
    participantIdentity,
    participantName: `${displayName} screen`,
    participantMetadata: buildParticipantMetadata(plan),
    enableTranscoding: plan.enabled,
    ...(plan.enabled && plan.video ? { video: plan.video } : {}),
  });

  await deleteStaleWhipIngresses(ingressClient, roomName, participantIdentity);

  let effectiveTranscodingPlan = transcodingPlan;
  let ingress;
  try {
    ingress = await ingressClient.createIngress(LIVEKIT_INGRESS_INPUT_WHIP, buildIngressOptions(effectiveTranscodingPlan));
  } catch (err) {
    if (!effectiveTranscodingPlan.enabled) throw err;
    console.warn(`[CatRealm] WHIP simulcast ingress creation failed, falling back to single stream: ${err?.message || String(err)}`);
    effectiveTranscodingPlan = {
      requested: transcodingPlan.requested,
      enabled: false,
      video: undefined,
      layers: [],
      fallbackReason: 'ingress-create-failed',
    };
    ingress = await ingressClient.createIngress(LIVEKIT_INGRESS_INPUT_WHIP, buildIngressOptions(effectiveTranscodingPlan));
  }

  return {
    ok: true,
    provider: 'livekit',
    context,
    serverId,
    channelId,
    roomName,
    ingress: serializeIngressInfo(ingress),
    simulcast: {
      requested: effectiveTranscodingPlan.requested,
      enabled: effectiveTranscodingPlan.enabled,
      experimental: ingressConfig.simulcastExperiment,
      layers: effectiveTranscodingPlan.layers,
    },
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
