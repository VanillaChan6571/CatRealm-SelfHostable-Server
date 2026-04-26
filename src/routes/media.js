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
  getSelfHostServerId,
} = require('../lib/mediaConfig');

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

router.get('/capabilities', (_req, res) => {
  res.json({ ok: true, capability: getMediaCapability(getSelfHostMediaContexts()) });
});

router.post('/token', authenticateToken, (req, res) => {
  const { context, channelId } = req.body || {};
  const result = createSelfHostMediaSession({ context, channelId, user: req.user });
  if (!result.ok) {
    return res.status(result.status || 400).json({
      ok: false,
      error: result.error,
      capability: getMediaCapability(getSelfHostMediaContexts()),
    });
  }
  res.json(result);
});

module.exports = {
  router,
  createSelfHostMediaSession,
  getSelfHostMediaContexts,
};
