const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const path = require('path');
const fs = require('fs');
const db = require('../db');
const { JWT_SECRET } = require('../middleware/auth');
const {
  PERMISSIONS,
  ALL_PERMISSIONS,
  computePermissionsForUser,
  hasPermission,
  hasChannelPermission,
  computeUserChannelPermissions,
} = require('../permissions');
const { applyRoleViewToUser } = require('../viewAsRole');
const pteroLog = require('../logger');
const { encryptMessageContent, decryptMessageContent } = require('../messageCrypto');
const { queueMessageCreatedEvent } = require('../webhooks');
const COMPACT_EXTERNAL_TOKEN_REGEX = /:(https?:\/\/[^\s:]+(?::\d{1,5})?):(?:(sticker):)?([a-z0-9_-]{1,64})(?::([a-z0-9_-]{3,128}))?:/gi;

// Track online users: userId -> { username, role, is_owner, role_color, avatar, status, sockets: Set<socketId> }
const onlineUsers = new Map();
// Track voice rooms: channelId -> Map<userId, { socketId, muted, deafened, user }>
const voiceRooms = new Map();
// Track when a voice room first became occupied, using server time as the source of truth.
const voiceRoomStartedAt = new Map();
// Track theater rooms: channelId -> Map<userId, { socketId, user }>
const theaterRooms = new Map();
// Per-theater-room sync intervals
const theaterSyncIntervals = new Map();
// Per-user reaction rate limiting: userId -> { count, resetAt }
const theaterReactionLimits = new Map();

// Cleanup expired voice messages hourly
setInterval(() => {
  try {
    const now = Date.now();
    const expiredMessages = db.prepare(
      'SELECT id, attachment_url FROM messages WHERE voice_expires_at IS NOT NULL AND voice_expires_at < ?'
    ).all(now);
    if (expiredMessages.length === 0) return;
    const UGC_IMAGES_DIR = process.env.UGC_IMAGES_DIR || path.join(__dirname, '../../data/ugc/images');
    for (const msg of expiredMessages) {
      if (msg.attachment_url && msg.attachment_url.startsWith('/ugc/images/')) {
        const filePath = path.join(UGC_IMAGES_DIR, msg.attachment_url.replace('/ugc/images/', ''));
        fs.unlink(filePath, () => {});
      }
    }
    const ids = expiredMessages.map((m) => m.id);
    const placeholders = ids.map(() => '?').join(', ');
    db.prepare(`DELETE FROM messages WHERE id IN (${placeholders})`).run(...ids);
    pteroLog(`[CatRealm] Cleaned up ${ids.length} expired voice message(s)`);
  } catch (err) {
    pteroLog(`[CatRealm] Voice message cleanup error: ${err}`);
  }
}, 60 * 60 * 1000);

// Publish scheduled messages every 30 seconds
setInterval(() => {
  try {
    if (!ioInstance) return;
    const now = Math.floor(Date.now() / 1000);
    const due = db.prepare(`
      SELECT m.*, u.username, u.avatar,
        COALESCE(dno.display_name, u.display_name) as display_name
      FROM messages m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN display_name_overrides dno ON dno.user_id = m.user_id
      WHERE m.scheduled_at IS NOT NULL AND m.scheduled_at <= ?
    `).all(now);

    const clearStmt = db.prepare('UPDATE messages SET scheduled_at = NULL WHERE id = ?');

    for (const msg of due) {
      const nsfwTags = db.prepare('SELECT tag FROM message_nsfw_tags WHERE message_id = ?')
        .all(msg.id).map(r => r.tag);
      let attachments = [];
      try { if (msg.attachments) attachments = JSON.parse(msg.attachments); } catch {}

      const payload = {
        id: msg.id, channel_id: msg.channel_id, thread_id: msg.thread_id || null,
        user_id: msg.user_id, username: msg.username, avatar: msg.avatar || null,
        display_name: msg.display_name || null, content: decryptMessageContent(msg.content),
        edited: 0, created_at: msg.created_at, scheduled_at: null,
        attachment_url: msg.attachment_url, attachments,
        nsfw_tags: nsfwTags, message_type: msg.message_type || 'user',
        embeds_enabled: msg.embeds_enabled, voice_expires_at: msg.voice_expires_at ?? null,
      };

      clearStmt.run(msg.id);

      if (msg.thread_id) ioInstance.to(`thread:${msg.thread_id}`).emit('message:new', payload);
      else ioInstance.to(msg.channel_id).emit('message:new', payload);
    }
    if (due.length > 0) pteroLog(`[CatRealm] Published ${due.length} scheduled message(s)`);
  } catch (err) {
    pteroLog(`[CatRealm] Scheduled publish error: ${err}`);
  }
}, 30_000);

let ioInstance = null;

function collectMessageAttachmentUrls(message) {
  const urls = new Set();
  if (typeof message?.attachment_url === 'string' && message.attachment_url.startsWith('/ugc/images/')) {
    urls.add(message.attachment_url);
  }
  if (typeof message?.attachments === 'string' && message.attachments.trim()) {
    try {
      const attachments = JSON.parse(message.attachments);
      if (Array.isArray(attachments)) {
        for (const att of attachments) {
          if (typeof att?.url === 'string' && att.url.startsWith('/ugc/images/')) {
            urls.add(att.url);
          }
        }
      }
    } catch {}
  }
  return Array.from(urls);
}

function unlinkUgcImageIfUnreferenced(attachmentUrl) {
  if (!attachmentUrl || !attachmentUrl.startsWith('/ugc/images/')) return;
  const refByAttachment = db.prepare(
    'SELECT COUNT(*) AS c FROM messages WHERE attachment_url = ?'
  ).get(attachmentUrl).c;
  const refByAttachments = db.prepare(
    'SELECT COUNT(*) AS c FROM messages WHERE attachments LIKE ?'
  ).get(`%${attachmentUrl}%`).c;
  if (refByAttachment > 0 || refByAttachments > 0) return;

  const urlSuffix = attachmentUrl.replace('/ugc/images/', '');
  const baseDir = process.env.UGC_IMAGES_DIR || path.join(__dirname, '../../data/ugc/images');
  const filePath = path.join(baseDir, urlSuffix);
  try {
    fs.rmSync(filePath, { force: true });
  } catch {}
}

function emitMessage(channelId, message) {
  if (!ioInstance) return;
  ioInstance.to(channelId).emit('message:new', message);
}

function emitServerInfoUpdate(info) {
  if (!ioInstance) return;
  ioInstance.emit('server:info', info);
}

function emitPermissionsChanged() {
  if (!ioInstance) return;
  for (const [, socket] of ioInstance.sockets.sockets) {
    if (!socket.authUser?.id) continue;
    const dbUser = db.prepare('SELECT id, username, role, is_owner FROM users WHERE id = ?').get(socket.authUser.id);
    if (!dbUser) continue;
    const authUser = {
      ...socket.authUser,
      ...dbUser,
      is_owner: dbUser.is_owner ? 1 : 0,
      permissions: computePermissionsForUser(dbUser.id, dbUser.role, dbUser.is_owner, db),
    };
    const { user, session } = applyRoleViewToUser(authUser, db);
    socket.authUser = authUser;
    socket.user = user;
    socket.viewAsRole = session;
  }
  refreshAllOnlineRoleMetadata();
  ioInstance.emit('permissions:changed');
  broadcastChannelUpdate();
}

function emitServerImportStatus(status, data) {
  if (!ioInstance) return;
  ioInstance.emit('server:import:status', { status, ...data });
}

function kickUserFromServer(userId, payload = {}) {
  if (!ioInstance || !userId) return 0;
  const entry = onlineUsers.get(userId);
  if (!entry?.sockets?.size) return 0;
  let count = 0;
  for (const socketId of Array.from(entry.sockets)) {
    const socket = ioInstance.sockets.sockets.get(socketId);
    if (!socket) continue;
    try {
      socket.emit('server:kicked', { removeServer: true, ...payload });
    } catch (_err) {
      // Best-effort notify before disconnect.
    }
    socket.disconnect(true);
    count += 1;
  }
  return count;
}

function detectExternalExpressionUsage(text) {
  if (typeof text !== 'string' || !text.includes(':')) {
    return { usesExternalEmote: false, usesExternalSticker: false };
  }
  let usesExternalEmote = false;
  let usesExternalSticker = false;
  COMPACT_EXTERNAL_TOKEN_REGEX.lastIndex = 0;
  for (const match of text.matchAll(COMPACT_EXTERNAL_TOKEN_REGEX)) {
    if (match?.[2] === 'sticker') usesExternalSticker = true;
    else usesExternalEmote = true;
    if (usesExternalEmote && usesExternalSticker) break;
  }
  return { usesExternalEmote, usesExternalSticker };
}

// Helper function to filter channels based on user's NSFW preferences
function filterChannelsForUser(user, channels) {
  const canManageNsfwChannels = hasPermission(user, PERMISSIONS.MANAGE_CHANNELS);
  if (!canManageNsfwChannels) {
    let allowNsfw = false;
    const prefs = db.prepare('SELECT * FROM user_content_social_prefs WHERE user_id = ?').get(user.id);
    if (prefs) {
      try {
        const parsed = JSON.parse(prefs.preferences);
        allowNsfw = parsed?.allowNsfw === true;
      } catch (_err) {
        // Keep secure default for malformed preferences.
        allowNsfw = false;
      }
    }
    const visibleChannels = [];
    for (const ch of channels) {
      if (!hasChannelPermission(user, ch.id, PERMISSIONS.VIEW_CHANNELS, db)) continue;
      if (!allowNsfw && ch.nsfw) continue;
      visibleChannels.push({
        ...ch,
        effective_permissions: computeUserChannelPermissions(user, ch.id, db),
      });
    }
    return visibleChannels;
  }
  return channels
    .filter((ch) => hasChannelPermission(user, ch.id, PERMISSIONS.VIEW_CHANNELS, db))
    .map((ch) => ({
      ...ch,
      effective_permissions: computeUserChannelPermissions(user, ch.id, db),
    }));
}

function canSendToChannel(user, channelId, channelType, threadId) {
  if (threadId) return hasChannelPermission(user, channelId, PERMISSIONS.SEND_MESSAGES_IN_THREADS, db);
  if (channelType === 'forum') return hasChannelPermission(user, channelId, PERMISSIONS.SEND_MESSAGES_IN_POSTS, db);
  return hasChannelPermission(user, channelId, PERMISSIONS.SEND_MESSAGES, db);
}

function canReadChannelHistory(user, channelId) {
  return hasChannelPermission(user, channelId, PERMISSIONS.READ_CHAT_HISTORY, db);
}

function setupSocketHandlers(io) {
  ioInstance = io;

  // ── Auth middleware for sockets ──────────────────────────────────────────────
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('No token'));
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      const dbUser = db.prepare('SELECT id, username, role, is_owner, is_member FROM users WHERE id = ?').get(payload.id);
      if (!dbUser) return next(new Error('Invalid token'));
      if (db.prepare('SELECT 1 FROM bans WHERE user_id = ?').get(dbUser.id)) {
        return next(new Error('Banned from server'));
      }
      if (Number(dbUser.is_member ?? 1) !== 1) return next(new Error('Removed from server'));
      const authUser = {
        ...payload,
        id: dbUser.id,
        username: dbUser.username,
        role: dbUser.role,
        is_owner: dbUser.is_owner ? 1 : 0,
        permissions: computePermissionsForUser(dbUser.id, dbUser.role, dbUser.is_owner, db),
      };
      const { user, session } = applyRoleViewToUser(authUser, db);
      socket.authUser = authUser;
      socket.user = user;
      socket.viewAsRole = session;
      next();
    } catch {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    const user = socket.user;
    const authUser = socket.authUser || socket.user;
    pteroLog(`[CatRealm] ${authUser.username} connected`);

    // Register as online
    const existingEntry = onlineUsers.get(authUser.id);
    if (existingEntry) {
      existingEntry.sockets.add(socket.id);
    } else {
      const topRole = db.prepare(`
        SELECT r.color, r.hoist, r.icon, r.name, r.position, r.style_type, r.style_colors FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = ?
        ORDER BY r.position DESC
        LIMIT 1
      `).get(authUser.id);
      const userRow = db.prepare(`
        SELECT u.avatar, u.status, u.display_name, u.custom_status_text, u.activity_type, u.activity_text, u.activity_started_at, u.account_type,
          COALESCE(dno.display_name, u.display_name) as effective_display_name
        FROM users u
        LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
        WHERE u.id = ?
      `).get(authUser.id);
      onlineUsers.set(authUser.id, {
        username: authUser.username,
        role: authUser.role,
        is_owner: authUser.is_owner ? 1 : 0,
        role_color: topRole?.color || null,
        role_hoist: topRole?.hoist || 0,
        role_icon: topRole?.icon || null,
        role_name: topRole?.name || null,
        role_position: topRole?.position || 0,
        role_style_type: topRole?.style_type || 'solid',
        role_style_colors: topRole?.style_colors || null,
        avatar: userRow?.avatar || null,
        status: userRow?.status || 'online',
        display_name: userRow?.effective_display_name || null,
        custom_status_text: userRow?.custom_status_text || null,
        activity_type: userRow?.activity_type || null,
        activity_text: userRow?.activity_text || null,
        activity_started_at: userRow?.activity_started_at || null,
        account_type: userRow?.account_type || 'local',
        verified: authUser.verified || false,
        sockets: new Set([socket.id]),
      });
    }
    io.emit('presence:update', buildOnlineList());

    // Join channel rooms based on user's NSFW preferences and send channel list
    const allChannels = db.prepare('SELECT * FROM channels ORDER BY position').all();
    const userChannels = filterChannelsForUser(user, allChannels);
    for (const ch of userChannels) {
      socket.join(ch.id);
    }

    // Send initial data to the newly connected client
    socket.emit('channel:list', userChannels);

    // Send categories
    const categories = db.prepare('SELECT * FROM categories ORDER BY position').all();
    socket.emit('category:list', categories);

    // Send server info
    const { getSetting } = require('../settings');
    const serverName = getSetting('server_name', process.env.SERVER_NAME || 'CatRealm Server');
    const serverDescription = getSetting('server_description', process.env.SERVER_DESCRIPTION || '');
    const mode = process.env.SERVER_MODE || 'decentralized';
    const registrationOpen = getSetting('registration_open', process.env.REGISTRATION_OPEN !== 'false' ? 'true' : 'false');
    const mentionAlias = getSetting('mention_alias', '@everyone');
    const serverIcon = getSetting('server_icon', null);
    const serverBanner = getSetting('server_banner', null);
    socket.emit('server:info', {
      name: serverName,
      description: serverDescription,
      mode,
      registrationOpen: registrationOpen === 'true',
      mentionAlias,
      serverIcon,
      serverBanner,
    });

    // ── Voice: join/leave/signaling ───────────────────────────────────────────────
    socket.on('voice:join', ({ channelId, muted = false, deafened = false }, ack) => {
      if (!channelId) {
        if (typeof ack === 'function') ack({ ok: false, channelId, error: 'Missing channel' });
        return socket.emit('voice:join:failed', { channelId, error: 'Missing channel' });
      }
      const channel = db.prepare('SELECT id, type FROM channels WHERE id = ?').get(channelId);
      if (!channel) {
        if (typeof ack === 'function') ack({ ok: false, channelId, error: 'Channel not found' });
        return socket.emit('voice:join:failed', { channelId, error: 'Channel not found' });
      }
      if (channel.type !== 'voice') {
        if (typeof ack === 'function') ack({ ok: false, channelId, error: 'Not a voice channel' });
        return socket.emit('voice:join:failed', { channelId, error: 'Not a voice channel' });
      }
      if (!hasChannelPermission(user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
        const error = 'Missing permission: view_channels';
        if (typeof ack === 'function') ack({ ok: false, channelId, error });
        return socket.emit('voice:join:failed', { channelId, error });
      }
      if (!hasChannelPermission(user, channelId, PERMISSIONS.CONNECT_TO_VOICE, db)) {
        const error = 'Missing permission: connect_to_voice';
        if (typeof ack === 'function') ack({ ok: false, channelId, error });
        return socket.emit('voice:join:failed', { channelId, error });
      }
      const canUseVoiceActivity = hasChannelPermission(user, channelId, PERMISSIONS.USE_VOICE_ACTIVITY, db);
      const canUsePushToTalk = hasChannelPermission(user, channelId, PERMISSIONS.USE_PUSH_TO_TALK, db);
      if (!canUseVoiceActivity && !canUsePushToTalk) {
        muted = true;
      }

      // Check user limit
      const channelSettings = db.prepare('SELECT user_limit FROM channel_settings WHERE channel_id = ?').get(channelId);
      if (channelSettings && channelSettings.user_limit > 0) {
        const room = voiceRooms.get(channelId);
        const currentSize = room ? room.size : 0;
        // Don't count if user is already in the room (reconnection case)
        const isReconnect = room && room.has(user.id);
        if (!isReconnect && currentSize >= channelSettings.user_limit) {
          const error = `Channel full (${currentSize}/${channelSettings.user_limit})`;
          if (typeof ack === 'function') ack({ ok: false, channelId, error });
          return socket.emit('voice:join:failed', { channelId, error });
        }
      }

      pteroLog(`[CatRealm] ${authUser.username} join voice ${channelId}`);
      if (socket.currentVoiceChannel && socket.currentVoiceChannel !== channelId) {
        leaveVoiceRoom(io, socket, socket.currentVoiceChannel, user.id);
      }

      const online = onlineUsers.get(user.id);
      const voiceUser = {
        id: user.id,
        username: online?.display_name || authUser.display_name || authUser.username,
        role: authUser.role,
        isOwner: !!authUser.is_owner,
        roleColor: online?.role_color || null,
        avatar: online?.avatar || null,
        status: online?.status || 'online',
        accountType: online?.account_type || 'local',
        muted: !!muted,
        deafened: !!deafened,
      };

      let room = voiceRooms.get(channelId);
      if (!room) {
        room = new Map();
        voiceRooms.set(channelId, room);
      }
      if (!voiceRoomStartedAt.has(channelId) || room.size === 0) {
        voiceRoomStartedAt.set(channelId, Date.now());
      }
      const existingInTargetRoom = room.get(user.id);
      const replacedExistingSession = !!existingInTargetRoom && existingInTargetRoom.socketId !== socket.id;

      // Enforce one active voice session per account across all clients/devices.
      for (const [otherChannelId, otherRoom] of voiceRooms.entries()) {
        if (otherChannelId === channelId) continue;
        const otherEntry = otherRoom.get(user.id);
        if (!otherEntry || otherEntry.socketId === socket.id) continue;
        const otherSocket = io.sockets.sockets.get(otherEntry.socketId);
        if (otherSocket) {
          otherSocket.emit('voice:force-disconnect', {
            channelId: otherChannelId,
            reason: 'duplicate_client',
            message: 'Meow! You were disconnected because you connected on a different cat client!',
          });
          leaveVoiceRoom(io, otherSocket, otherChannelId, user.id);
        } else {
          otherRoom.delete(user.id);
          if (otherRoom.size === 0) {
            voiceRooms.delete(otherChannelId);
            voiceRoomStartedAt.delete(otherChannelId);
            emitVoiceRoomCount(io, otherChannelId);
            io.emit('voice:room-sync', { channelId: otherChannelId, users: [], startedAt: null });
          } else {
            io.to(`voice:${otherChannelId}`).emit('voice:user-left', { channelId: otherChannelId, userId: user.id });
            emitVoiceRoomCount(io, otherChannelId);
            emitVoiceRoomSync(io, otherChannelId);
          }
        }
      }

      if (replacedExistingSession) {
        const previousSocket = io.sockets.sockets.get(existingInTargetRoom.socketId);
        if (previousSocket) {
          previousSocket.emit('voice:force-disconnect', {
            channelId,
            reason: 'duplicate_client',
            message: 'Meow! You were disconnected because you connected on a different cat client!',
          });
          previousSocket.leave(`voice:${channelId}`);
          if (previousSocket.currentVoiceChannel === channelId) {
            previousSocket.currentVoiceChannel = null;
          }
        }
      }
      room.set(user.id, { socketId: socket.id, muted: !!muted, deafened: !!deafened, user: voiceUser });
      socket.currentVoiceChannel = channelId;
      socket.join(`voice:${channelId}`);

      const payload = {
        channelId,
        users: Array.from(room.values()).map((entry) => entry.user),
        startedAt: voiceRoomStartedAt.get(channelId) ?? Date.now(),
        you: user.id,
      };
      socket.emit('voice:users', payload);
      socket.emit('voice:join:ok', payload);
      if (typeof ack === 'function') {
        ack({ ok: true, ...payload });
      }
      if (!replacedExistingSession) {
        socket.to(`voice:${channelId}`).emit('voice:user-joined', { channelId, user: voiceUser });
      }
      emitVoiceRoomCount(io, channelId);
      emitVoiceRoomSync(io, channelId);
    });

    socket.on('voice:ping', (ack) => {
      if (typeof ack === 'function') ack({ ok: true, ts: Date.now() });
    });

    socket.on('voice:leave', ({ channelId }) => {
      if (!channelId) return;
      leaveVoiceRoom(io, socket, channelId, user.id);
    });

    socket.on('voice:rooms:get', (ack) => {
      if (typeof ack !== 'function') return;
      ack({ rooms: buildVoiceRoomCounts() });
    });

    socket.on('voice:state', ({ channelId, muted, deafened }) => {
      if (!channelId) return;
      const room = voiceRooms.get(channelId);
      if (!room) return;
      const entry = room.get(user.id);
      if (!entry) return;
      if (!muted) {
        const canUseVoiceActivity = hasChannelPermission(user, channelId, PERMISSIONS.USE_VOICE_ACTIVITY, db);
        const canUsePushToTalk = hasChannelPermission(user, channelId, PERMISSIONS.USE_PUSH_TO_TALK, db);
        if (!canUseVoiceActivity && !canUsePushToTalk) {
          muted = true;
        }
      }
      entry.muted = !!muted;
      entry.deafened = !!deafened;
      entry.user.muted = !!muted;
      entry.user.deafened = !!deafened;
      room.set(user.id, entry);
      io.to(`voice:${channelId}`).emit('voice:user-state', {
        channelId,
        userId: user.id,
        muted: !!muted,
        deafened: !!deafened,
      });
      io.to(`voice:${channelId}`).emit('voice:sync', {
        channelId,
        users: Array.from(room.values()).map((e) => e.user),
      });
      emitVoiceRoomSync(io, channelId);
    });

    socket.on('voice:signal', ({ channelId, to, data }) => {
      if (!channelId || !to || !data) return;
      if (!hasChannelPermission(user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) return;

      const sdp = data && typeof data === 'object' && typeof data.sdp === 'string' ? data.sdp : '';
      if (sdp && /\bm=video\b/i.test(sdp)) {
        const canSendVideo = hasChannelPermission(user, channelId, PERMISSIONS.SCREENSHARE, db)
          || hasChannelPermission(user, channelId, PERMISSIONS.CAMERA, db);
        if (!canSendVideo) {
          socket.emit('error', 'Missing permission: screenshare_or_camera');
          return;
        }
      }

      const room = voiceRooms.get(channelId);
      if (!room) return;
      if (!room.get(user.id)) return;
      const target = room.get(to);
      if (target && io.sockets.sockets.has(target.socketId)) {
        io.to(target.socketId).emit('voice:signal', {
          channelId,
          from: user.id,
          data,
        });
        return;
      }
      // Fallback for stale room socket mappings (e.g. reconnects / multi-session).
      const online = onlineUsers.get(to);
      if (!online?.sockets?.size) return;
      for (const socketId of online.sockets) {
        io.to(socketId).emit('voice:signal', {
          channelId,
          from: user.id,
          data,
        });
      }
    });

    socket.on('voice:mod:state', ({ channelId, userId, muted, deafened }, ack) => {
      if (!channelId || !userId) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing channelId or userId' });
        return;
      }
      const room = voiceRooms.get(channelId);
      if (!room) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Voice room not found' });
        return;
      }
      const entry = room.get(userId);
      if (!entry) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Member is not in this voice channel' });
        return;
      }

      const nextMuted = typeof muted === 'boolean' ? muted : entry.muted;
      const nextDeafened = typeof deafened === 'boolean' ? deafened : entry.deafened;
      if (nextMuted === entry.muted && nextDeafened === entry.deafened) {
        if (typeof ack === 'function') ack({ ok: true, unchanged: true });
        return;
      }

      if (nextMuted !== entry.muted && !hasChannelPermission(user, channelId, PERMISSIONS.SERVER_MUTE_MEMBERS, db)) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing permission: server_mute_members' });
        return;
      }
      if (nextDeafened !== entry.deafened && !hasChannelPermission(user, channelId, PERMISSIONS.SERVER_DEAFEN_MEMBERS, db)) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing permission: server_deafen_members' });
        return;
      }

      entry.muted = !!nextMuted;
      entry.deafened = !!nextDeafened;
      entry.user.muted = !!nextMuted;
      entry.user.deafened = !!nextDeafened;
      room.set(userId, entry);

      io.to(`voice:${channelId}`).emit('voice:user-state', {
        channelId,
        userId,
        muted: !!nextMuted,
        deafened: !!nextDeafened,
      });
      io.to(`voice:${channelId}`).emit('voice:sync', {
        channelId,
        users: Array.from(room.values()).map((e) => e.user),
      });
      emitVoiceRoomSync(io, channelId);
      if (typeof ack === 'function') ack({ ok: true });
    });

    socket.on('voice:mod:move', ({ fromChannelId, toChannelId, userId }, ack) => {
      if (!fromChannelId || !toChannelId || !userId) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing fromChannelId, toChannelId, or userId' });
        return;
      }
      if (fromChannelId === toChannelId) {
        if (typeof ack === 'function') ack({ ok: true, unchanged: true });
        return;
      }

      const fromChannel = db.prepare('SELECT id, type FROM channels WHERE id = ?').get(fromChannelId);
      const toChannel = db.prepare('SELECT id, type FROM channels WHERE id = ?').get(toChannelId);
      if (!fromChannel || !toChannel || fromChannel.type !== 'voice' || toChannel.type !== 'voice') {
        if (typeof ack === 'function') ack({ ok: false, error: 'Invalid voice channel target' });
        return;
      }
      if (!hasChannelPermission(user, fromChannelId, PERMISSIONS.MOVE_VOICE_MEMBERS, db) || !hasChannelPermission(user, toChannelId, PERMISSIONS.MOVE_VOICE_MEMBERS, db)) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing permission: move_voice_members' });
        return;
      }

      const fromRoom = voiceRooms.get(fromChannelId);
      if (!fromRoom) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Source voice room not found' });
        return;
      }
      const sourceEntry = fromRoom.get(userId);
      if (!sourceEntry) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Member is not in the source voice channel' });
        return;
      }
      const targetSocket = io.sockets.sockets.get(sourceEntry.socketId);
      if (!targetSocket) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Target client is no longer connected' });
        return;
      }

      const targetSettings = db.prepare('SELECT user_limit FROM channel_settings WHERE channel_id = ?').get(toChannelId);
      const existingTargetRoom = voiceRooms.get(toChannelId);
      const targetCount = existingTargetRoom ? existingTargetRoom.size : 0;
      const alreadyInTarget = !!existingTargetRoom?.has(userId);
      if (targetSettings && targetSettings.user_limit > 0 && !alreadyInTarget && targetCount >= targetSettings.user_limit) {
        if (typeof ack === 'function') ack({ ok: false, error: `Target voice channel is full (${targetCount}/${targetSettings.user_limit})` });
        return;
      }

      const online = onlineUsers.get(userId);
      const movedVoiceUser = {
        ...sourceEntry.user,
        username: online?.display_name || sourceEntry.user.username,
        roleColor: online?.role_color || sourceEntry.user.roleColor || null,
        avatar: online?.avatar || sourceEntry.user.avatar || null,
        status: online?.status || sourceEntry.user.status || 'online',
        muted: !!sourceEntry.muted,
        deafened: !!sourceEntry.deafened,
      };

      leaveVoiceRoom(io, targetSocket, fromChannelId, userId);

      let targetRoom = voiceRooms.get(toChannelId);
      if (!targetRoom) {
        targetRoom = new Map();
        voiceRooms.set(toChannelId, targetRoom);
      }
      if (!voiceRoomStartedAt.has(toChannelId) || targetRoom.size === 0) {
        voiceRoomStartedAt.set(toChannelId, Date.now());
      }
      targetRoom.set(userId, {
        socketId: sourceEntry.socketId,
        muted: !!sourceEntry.muted,
        deafened: !!sourceEntry.deafened,
        user: movedVoiceUser,
      });
      targetSocket.currentVoiceChannel = toChannelId;
      targetSocket.join(`voice:${toChannelId}`);

      const payload = {
        channelId: toChannelId,
        users: Array.from(targetRoom.values()).map((entry) => entry.user),
        startedAt: voiceRoomStartedAt.get(toChannelId) ?? Date.now(),
        you: userId,
      };
      targetSocket.emit('voice:users', payload);
      targetSocket.emit('voice:join:ok', payload);
      targetSocket.to(`voice:${toChannelId}`).emit('voice:user-joined', { channelId: toChannelId, user: movedVoiceUser });
      emitVoiceRoomCount(io, toChannelId);
      emitVoiceRoomSync(io, toChannelId);
      if (typeof ack === 'function') ack({ ok: true });
    });

    socket.on('voice:mod:disconnect', ({ channelId, userId }, ack) => {
      if (!channelId || !userId) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing channelId or userId' });
        return;
      }
      if (!hasChannelPermission(user, channelId, PERMISSIONS.MOVE_VOICE_MEMBERS, db)) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing permission: move_voice_members' });
        return;
      }
      const room = voiceRooms.get(channelId);
      if (!room) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Voice room not found' });
        return;
      }
      const entry = room.get(userId);
      if (!entry) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Member is not in this voice channel' });
        return;
      }
      const targetSocket = io.sockets.sockets.get(entry.socketId);
      if (!targetSocket) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Target client is no longer connected' });
        return;
      }
      leaveVoiceRoom(io, targetSocket, channelId, userId);
      targetSocket.emit('voice:force-disconnect', { channelId, reason: 'mod-disconnect', message: 'You were disconnected from voice by a moderator.' });
      if (typeof ack === 'function') ack({ ok: true });
    });

    // ── Theater ────────────────────────────────────────────────────────────────
    socket.on('theater:join', ({ channelId }, ack) => {
      if (!channelId) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing channelId' });
        return;
      }
      const channel = db.prepare('SELECT id, type FROM channels WHERE id = ?').get(channelId);
      if (!channel || channel.type !== 'theater') {
        if (typeof ack === 'function') ack({ ok: false, error: 'Not a theater channel' });
        return;
      }
      if (!hasChannelPermission(user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing permission: view_channels' });
        return;
      }

      const online = onlineUsers.get(user.id);
      const theaterUser = {
        id: user.id,
        username: online?.display_name || authUser.display_name || authUser.username,
        avatar: online?.avatar || null,
        accountType: authUser.account_type || 'local',
        roleColor: online?.role_color || null,
        cameraEnabled: false,
        micEnabled: false,
        deafened: false,
        muted: false,
      };

      let room = theaterRooms.get(channelId);
      if (!room) {
        room = new Map();
        theaterRooms.set(channelId, room);
      }
      room.set(user.id, { socketId: socket.id, user: theaterUser });
      socket.currentTheaterChannel = channelId;
      socket.join(`theater:${channelId}`);

      // Start sync interval if not running
      if (!theaterSyncIntervals.has(channelId)) {
        const interval = setInterval(() => {
          emitTheaterSync(io, channelId);
        }, 5000);
        theaterSyncIntervals.set(channelId, interval);
      }

      const queue = db.prepare(`
        SELECT tq.*, u.username as added_by_username
        FROM theater_queue tq LEFT JOIN users u ON u.id = tq.added_by
        WHERE tq.channel_id = ? ORDER BY tq.position ASC, tq.created_at ASC
      `).all(channelId);
      const state = db.prepare('SELECT * FROM theater_state WHERE channel_id = ?').get(channelId);

      const payload = {
        ok: true,
        channelId,
        users: Array.from(room.values()).map((e) => e.user),
        queue,
        state: state || null,
        you: user.id,
      };
      if (typeof ack === 'function') ack(payload);
      socket.emit('theater:users', { channelId, users: payload.users, you: user.id });
      socket.to(`theater:${channelId}`).emit('theater:user-joined', { channelId, user: theaterUser });
      io.emit('theater:room-count', { channelId, count: room.size });
    });

    socket.on('theater:leave', ({ channelId }) => {
      if (!channelId) return;
      leaveTheaterRoom(io, socket, channelId, user.id);
    });

    socket.on('theater:signal', ({ channelId, to, data }) => {
      if (!channelId || !to || !data) return;
      if (!hasChannelPermission(user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) return;

      // Only allow camera, block screenshare SDP
      const sdp = data && typeof data === 'object' && typeof data.sdp === 'string' ? data.sdp : '';
      if (sdp && /\bm=video\b/i.test(sdp)) {
        if (!hasChannelPermission(user, channelId, PERMISSIONS.CAMERA, db)) {
          socket.emit('error', 'Missing permission: camera');
          return;
        }
      }

      const room = theaterRooms.get(channelId);
      if (!room || !room.get(user.id)) return;
      const target = room.get(to);
      if (target && io.sockets.sockets.has(target.socketId)) {
        io.to(target.socketId).emit('theater:signal', { channelId, from: user.id, data });
        return;
      }
      const online = onlineUsers.get(to);
      if (!online?.sockets?.size) return;
      for (const socketId of online.sockets) {
        io.to(socketId).emit('theater:signal', { channelId, from: user.id, data });
      }
    });

    socket.on('theater:camera-state', ({ channelId, cameraEnabled }) => {
      const room = theaterRooms.get(channelId);
      if (!room) return;
      const entry = room.get(user.id);
      if (!entry) return;
      entry.user.cameraEnabled = !!cameraEnabled;
      io.to(`theater:${channelId}`).emit('theater:user-state', { channelId, userId: user.id, cameraEnabled: !!cameraEnabled });
    });

    socket.on('theater:mic-state', ({ channelId, micEnabled }) => {
      const room = theaterRooms.get(channelId);
      if (!room) return;
      const entry = room.get(user.id);
      if (!entry) return;
      entry.user.micEnabled = !!micEnabled;
      io.to(`theater:${channelId}`).emit('theater:user-state', { channelId, userId: user.id, micEnabled: !!micEnabled });
    });

    socket.on('theater:deafen-state', ({ channelId, deafened }) => {
      const room = theaterRooms.get(channelId);
      if (!room) return;
      const entry = room.get(user.id);
      if (!entry) return;
      entry.user.deafened = !!deafened;
      io.to(`theater:${channelId}`).emit('theater:user-state', { channelId, userId: user.id, deafened: !!deafened });
    });

    socket.on('theater:state', ({ channelId, playing, positionMs, currentItemId }, ack) => {
      if (!channelId) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing channelId' });
        return;
      }
      // Permission check: must be PLAY_IN_THEATER or have MANAGE_CHANNELS, or be delegated host
      const canControl = (() => {
        if (user.is_owner || user.role === 'owner') return true;
        if (hasPermission(user, PERMISSIONS.MANAGE_CHANNELS)) return true;
        if (hasPermission(user, PERMISSIONS.ADMINISTRATOR)) return true;
        if (hasChannelPermission(user, channelId, PERMISSIONS.PLAY_IN_THEATER, db)) return true;
        const state = db.prepare('SELECT host_user_id FROM theater_state WHERE channel_id = ?').get(channelId);
        return state?.host_user_id === user.id;
      })();
      if (!canControl) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing permission: play_in_theater' });
        return;
      }
      db.prepare(`
        INSERT INTO theater_state (channel_id, position_ms, playing, updated_at) VALUES (?, 0, 0, unixepoch())
        ON CONFLICT(channel_id) DO NOTHING
      `).run(channelId);
      const fields = ['updated_at = unixepoch()'];
      const values = [];
      if (typeof playing === 'boolean') { fields.push('playing = ?'); values.push(playing ? 1 : 0); }
      if (typeof positionMs === 'number') { fields.push('position_ms = ?'); values.push(Math.max(0, positionMs)); }
      if (currentItemId !== undefined) { fields.push('current_item_id = ?'); values.push(currentItemId || null); }
      values.push(channelId);
      db.prepare(`UPDATE theater_state SET ${fields.join(', ')} WHERE channel_id = ?`).run(...values);
      emitTheaterSync(io, channelId);
      if (typeof ack === 'function') ack({ ok: true });
    });

    socket.on('theater:reaction', ({ channelId, emoji }) => {
      if (!channelId || !emoji || typeof emoji !== 'string') return;
      const room = theaterRooms.get(channelId);
      if (!room || !room.has(user.id)) return;

      // Check theater_reactions_enabled setting
      const settings = db.prepare('SELECT theater_reactions_enabled FROM channel_settings WHERE channel_id = ?').get(channelId);
      if (!settings?.theater_reactions_enabled) return;

      // Rate limit: max 3 per user per second
      const now = Date.now();
      let limit = theaterReactionLimits.get(user.id);
      if (!limit || now > limit.resetAt) {
        limit = { count: 0, resetAt: now + 1000 };
        theaterReactionLimits.set(user.id, limit);
      }
      if (limit.count >= 3) return;
      limit.count += 1;

      const online = onlineUsers.get(user.id);
      const username = online?.display_name || authUser.display_name || authUser.username;
      io.to(`theater:${channelId}`).emit('theater:reaction', {
        channelId,
        userId: user.id,
        username,
        emoji: emoji.slice(0, 8), // limit length
        at: now,
      });
    });

    socket.on('theater:host:grant', ({ channelId, userId }, ack) => {
      if (!channelId || !userId) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing channelId or userId' });
        return;
      }
      if (!hasPermission(user, PERMISSIONS.MANAGE_CHANNELS) && !hasPermission(user, PERMISSIONS.ADMINISTRATOR) && !(user.is_owner || user.role === 'owner')) {
        if (typeof ack === 'function') ack({ ok: false, error: 'Missing permission: manage_channels' });
        return;
      }
      db.prepare(`
        INSERT INTO theater_state (channel_id, host_user_id, updated_at) VALUES (?, ?, unixepoch())
        ON CONFLICT(channel_id) DO UPDATE SET host_user_id = excluded.host_user_id, updated_at = unixepoch()
      `).run(channelId, userId);
      io.to(`theater:${channelId}`).emit('theater:host-changed', { channelId, hostUserId: userId });
      if (typeof ack === 'function') ack({ ok: true });
    });

    // ── Set active channel (for typing indicators only) ────────────────────────
    socket.on('channel:join', (channelId) => {
      const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(channelId);
      if (!channel) return socket.emit('error', 'Channel not found');
      if (!hasChannelPermission(user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
        return socket.emit('error', 'Missing permission: view_channels');
      }
      socket.currentChannel = channelId;
    });

    socket.on('thread:join', (threadId) => {
      const thread = db.prepare('SELECT id, channel_id FROM threads WHERE id = ?').get(threadId);
      if (!thread) return socket.emit('error', 'Thread not found');
      if (!hasChannelPermission(user, thread.channel_id, PERMISSIONS.VIEW_CHANNELS, db)) {
        return socket.emit('error', 'Missing permission: view_channels');
      }
      socket.join(`thread:${threadId}`);
    });

    // ── Send a message ─────────────────────────────────────────────────────────
    socket.on('message:send', ({ channelId, content, attachment, attachments: attachmentsRaw, threadId, replyToId, forwardFromId, forwardMeta, nsfwTags, voice_expires_at, scheduled_at }) => {
      // Normalize to array — accept both legacy single `attachment` and new `attachments[]`
      const attachmentsArray = (Array.isArray(attachmentsRaw) ? attachmentsRaw : [])
        .filter((a) => a && typeof a.url === 'string');
      if (attachmentsArray.length === 0 && attachment && typeof attachment.url === 'string') {
        attachmentsArray.push(attachment);
      }
      const hasText = typeof content === 'string' && content.trim().length > 0;
      const hasAttachment = attachmentsArray.length > 0;
      if (!channelId || (!hasText && !hasAttachment)) return;
      if (content && content.length > 2000) return socket.emit('error', 'Message too long (max 2000 chars)');
      if (!hasChannelPermission(user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
        return socket.emit('error', 'Missing permission: view_channels');
      }
      if (!canReadChannelHistory(user, channelId)) {
        return socket.emit('error', 'Missing permission: read_chat_history');
      }
      const channel = db.prepare('SELECT id, type FROM channels WHERE id = ?').get(channelId);
      if (!channel) return socket.emit('error', 'Channel not found');
      if (!canSendToChannel(user, channelId, channel.type, threadId)) {
        return socket.emit('error', 'Missing permission: send_messages');
      }
      if (hasAttachment && !hasChannelPermission(user, channelId, PERMISSIONS.ATTACH_FILES, db)) {
        return socket.emit('error', 'Missing permission: send_media');
      }
      const canEmbedLinks = hasChannelPermission(user, channelId, PERMISSIONS.EMBED_LINKS, db);
      if (threadId) {
        const thread = db.prepare('SELECT id, channel_id FROM threads WHERE id = ?').get(threadId);
        if (!thread || thread.channel_id !== channelId) return socket.emit('error', 'Thread not found');
      }
      if (channel.type === 'media' && hasText) {
        return socket.emit('error', 'Media channels do not allow text-only messages');
      }

      // Check slowmode
      const channelSettings = db.prepare('SELECT slowmode FROM channel_settings WHERE channel_id = ?').get(channelId);
      if (channelSettings && channelSettings.slowmode > 0) {
        const hasBypass = hasChannelPermission(user, channelId, PERMISSIONS.BYPASS_SLOWMODE, db);
        if (!hasBypass) {
          const lastMessage = db.prepare(`
            SELECT created_at FROM messages
            WHERE channel_id = ? AND user_id = ? AND message_type = 'user' AND scheduled_at IS NULL
            ORDER BY created_at DESC
            LIMIT 1
          `).get(channelId, user.id);
          if (lastMessage) {
            const now = Math.floor(Date.now() / 1000);
            const timeSince = now - lastMessage.created_at;
            if (timeSince < channelSettings.slowmode) {
              const remaining = channelSettings.slowmode - timeSince;
              return socket.emit('error', `Slowmode active: please wait ${remaining}s before sending another message`);
            }
          }
        }
      }

      // Validate and normalize scheduled_at
      let normalizedScheduledAt = null;
      if (scheduled_at != null) {
        if (!hasChannelPermission(user, channelId, PERMISSIONS.SCHEDULE_MESSAGES, db)) {
          return socket.emit('error', 'Missing permission: schedule_messages');
        }
        const nowSec = Math.floor(Date.now() / 1000);
        const parsed = typeof scheduled_at === 'number' ? Math.floor(scheduled_at) : null;
        const maxSec = nowSec + 30 * 24 * 60 * 60; // 30 days
        if (!parsed || parsed < nowSec + 30 || parsed > maxSec) {
          return socket.emit('error', 'Invalid scheduled_at');
        }
        normalizedScheduledAt = parsed;
      }

      // Validate replyToId
      let replyTo = null;
      if (replyToId) {
        replyTo = db.prepare(`
          SELECT m.id, m.user_id, m.content, m.channel_id, u.username
          FROM messages m
          JOIN users u ON u.id = m.user_id
          WHERE m.id = ?
        `).get(replyToId);
        if (!replyTo) return socket.emit('error', 'Reply target not found');
        replyTo.content = decryptMessageContent(replyTo.content);
      }

      // Validate forwardFromId / forwardMeta
      let forwardFrom = null;
      if (forwardFromId) {
        forwardFrom = db.prepare(`
          SELECT m.id, m.user_id, m.content, m.channel_id, u.username, c.name as channel_name
          FROM messages m
          JOIN users u ON u.id = m.user_id
          JOIN channels c ON c.id = m.channel_id
          WHERE m.id = ?
        `).get(forwardFromId);
        if (!forwardFrom) return socket.emit('error', 'Forward source not found');
        forwardFrom.content = decryptMessageContent(forwardFrom.content);
      } else if (forwardMeta && typeof forwardMeta.serverName === 'string') {
        // Media-only forward: no message ID lookup required
        forwardFrom = {
          id: null,
          username: null,
          channel_name: String(forwardMeta.serverName).substring(0, 100),
          forwarded_at: typeof forwardMeta.at === 'number' ? Math.floor(forwardMeta.at) : null,
        };
      }

      const id = randomUUID();
      const now = Math.floor(Date.now() / 1000);

      let trimmed = hasText ? content.trim() : '';
      if (trimmed) {
        // Replace @uuid with @username where possible
        trimmed = trimmed.replace(/@([0-9a-fA-F-]{36})/g, (match, id) => {
          const u = db.prepare('SELECT username FROM users WHERE id = ?').get(id);
          if (!u?.username) return match;
          return `@${u.username}`;
        });

        const externalUse = detectExternalExpressionUsage(trimmed);
        if (externalUse.usesExternalEmote && !hasChannelPermission(user, channelId, PERMISSIONS.USE_EXTERNAL_EMOTES, db)) {
          return socket.emit('error', 'Missing permission: use_external_emotes');
        }
        if (externalUse.usesExternalSticker && !hasChannelPermission(user, channelId, PERMISSIONS.USE_EXTERNAL_STICKERS, db)) {
          return socket.emit('error', 'Missing permission: use_external_stickers');
        }
      }
      const firstAtt = attachmentsArray[0] ?? null;
      const attachmentUrl = firstAtt ? firstAtt.url : null;
      const attachmentType = firstAtt ? firstAtt.mime : null;
      const attachmentSize = firstAtt ? firstAtt.size : null;
      const attachmentsJson = attachmentsArray.length > 0 ? JSON.stringify(attachmentsArray) : null;
      const normalizedNsfwTags = hasAttachment && Array.isArray(nsfwTags)
        ? Array.from(new Set(
          nsfwTags
            .filter((tag) => typeof tag === 'string')
            .map((tag) => String(tag).toLowerCase().trim())
            .filter((tag) => ['blood', 'gore', 'violence', 'lewd', 'sexual', 'disturbing', 'spoiler'].includes(tag))
        ))
        : [];
      const normalizedVoiceExpiresAt = (typeof voice_expires_at === 'number' && Number.isFinite(voice_expires_at))
        ? voice_expires_at
        : null;
      db.prepare(`
        INSERT INTO messages (
          id, channel_id, user_id, content, created_at,
          attachment_url, attachment_type, attachment_size, attachments, message_type, thread_id,
          reply_to_id, forward_from_id, forward_from_user, forward_from_channel, forward_from_at, embeds_enabled,
          voice_expires_at, scheduled_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, channelId, user.id, encryptMessageContent(trimmed), now,
        attachmentUrl, attachmentType, attachmentSize, attachmentsJson, 'user', threadId || null,
        replyToId || null,
        forwardFrom?.id || null,
        forwardFrom?.username || null,
        forwardFrom?.channel_name || null,
        forwardFrom?.forwarded_at ?? null,
        canEmbedLinks ? 1 : 0,
        normalizedVoiceExpiresAt,
        normalizedScheduledAt
      );
      if (normalizedNsfwTags.length > 0) {
        const insertTagStmt = db.prepare('INSERT OR IGNORE INTO message_nsfw_tags (message_id, tag) VALUES (?, ?)');
        for (const tag of normalizedNsfwTags) {
          insertTagStmt.run(id, tag);
        }
      }

      const topRole = db.prepare(`
        SELECT r.color, r.hoist, r.icon FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = ?
        ORDER BY r.position DESC
        LIMIT 1
      `).get(user.id);
      const userInfo = db.prepare(`
        SELECT u.avatar, COALESCE(dno.display_name, u.display_name) as display_name
        FROM users u
        LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
        WHERE u.id = ?
      `).get(user.id);
      const message = {
        id,
        channel_id: channelId,
        user_id:    user.id,
        username:   authUser.username,
        content:    trimmed,
        edited:     0,
        is_owner:   authUser.is_owner ? 1 : 0,
        role_color: topRole?.color || null,
        avatar: userInfo?.avatar || null,
        display_name: userInfo?.display_name || null,
        verified: authUser.verified || false,
        attachment_url: attachmentUrl,
        attachment_type: attachmentType,
        attachment_size: attachmentSize,
        attachments: attachmentsArray,
        nsfw_tags: normalizedNsfwTags,
        message_type: 'user',
        thread_id: threadId || null,
        created_at: now,
        reply_to_id: replyToId || null,
        reply_to: replyTo ? {
          id: replyTo.id,
          user_id: replyTo.user_id,
          content: replyTo.content.substring(0, 100),
          username: replyTo.username,
          channel_id: replyTo.channel_id,
        } : null,
        forward_from_id: forwardFrom?.id || null,
        forward_from_user: forwardFrom?.username || null,
        forward_from_channel: forwardFrom?.channel_name || null,
        forward_from_at: forwardFrom?.forwarded_at ?? null,
        embeds_enabled: canEmbedLinks ? 1 : 0,
        voice_expires_at: normalizedVoiceExpiresAt,
      };

      if (normalizedScheduledAt) {
        socket.emit('message:scheduled', { ...message, scheduled_at: normalizedScheduledAt });
      } else {
        if (threadId) {
          io.to(`thread:${threadId}`).emit('message:new', message);
        } else {
          io.to(channelId).emit('message:new', message);
        }
        queueMessageCreatedEvent(message);
      }

      // Auto-reaction (if configured)
      if (channelSettings && channelSettings.default_reaction) {
        // TODO: Implement reactions system
        // For now, this would emit a reaction event once reactions are implemented
        // io.to(channelId).emit('reaction:add', { messageId: id, emoji: channelSettings.default_reaction, userId: 'system' });
      }
    });

    // ── Edit a message ─────────────────────────────────────────────────────────
    socket.on('message:edit', ({ messageId, content }) => {
      if (!content?.trim()) return;
      const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(messageId);
      if (!msg) return socket.emit('error', 'Message not found');
      if (!hasChannelPermission(user, msg.channel_id, PERMISSIONS.VIEW_CHANNELS, db)) return socket.emit('error', 'Not allowed');
      // Message edits are sender-only. Moderation permissions allow delete, not content rewrite.
      if (msg.user_id !== user.id) return socket.emit('error', 'Not allowed');
      const canEmbedLinks = hasChannelPermission(user, msg.channel_id, PERMISSIONS.EMBED_LINKS, db);
      const channel = db.prepare('SELECT type FROM channels WHERE id = ?').get(msg.channel_id);
      if (channel?.type === 'media') {
        return socket.emit('error', 'Media channels do not allow text edits');
      }

      db.prepare('UPDATE messages SET content = ?, edited = 1, embeds_enabled = ? WHERE id = ?').run(encryptMessageContent(content.trim()), canEmbedLinks ? 1 : 0, messageId);
      const payload = { messageId, content: content.trim(), threadId: msg.thread_id || null, embeds_enabled: canEmbedLinks ? 1 : 0 };
      if (msg.thread_id) {
        io.to(`thread:${msg.thread_id}`).emit('message:edited', payload);
      } else {
        io.to(msg.channel_id).emit('message:edited', payload);
      }
    });

    // ── Delete a message ───────────────────────────────────────────────────────
    socket.on('message:delete', ({ messageId }) => {
      const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(messageId);
      if (!msg) return socket.emit('error', 'Message not found');
      if (!hasChannelPermission(user, msg.channel_id, PERMISSIONS.VIEW_CHANNELS, db)) return socket.emit('error', 'Not allowed');
      const canDelete = msg.user_id === user.id || hasChannelPermission(user, msg.channel_id, PERMISSIONS.DELETE_MESSAGES, db);
      if (!canDelete) return socket.emit('error', 'Not allowed');

      const attachmentUrls = collectMessageAttachmentUrls(msg);
      db.prepare('DELETE FROM messages WHERE id = ?').run(messageId);
      for (const attachmentUrl of attachmentUrls) {
        unlinkUgcImageIfUnreferenced(attachmentUrl);
      }
      if (msg.thread_id) {
        io.to(`thread:${msg.thread_id}`).emit('message:deleted', { messageId, channelId: msg.channel_id, threadId: msg.thread_id });
      } else {
        io.to(msg.channel_id).emit('message:deleted', { messageId, channelId: msg.channel_id });
      }
    });

    // ── Typing indicator ───────────────────────────────────────────────────────
    socket.on('typing:start', ({ channelId }) => {
      if (!hasChannelPermission(user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) return;
      if (!canSendToChannel(user, channelId, db.prepare('SELECT type FROM channels WHERE id = ?').get(channelId)?.type, null)) return;
      socket.to(channelId).emit('typing:update', { userId: user.id, username: authUser.username, typing: true });
    });

    socket.on('typing:stop', ({ channelId }) => {
      if (!hasChannelPermission(user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) return;
      socket.to(channelId).emit('typing:update', { userId: user.id, username: authUser.username, typing: false });
    });

    // ── Disconnect ─────────────────────────────────────────────────────────────
    socket.on('disconnect', () => {
      pteroLog(`[CatRealm] ${authUser.username} disconnected`);
      const entry = onlineUsers.get(authUser.id);
      if (entry) {
        entry.sockets.delete(socket.id);
        if (entry.sockets.size === 0) {
          onlineUsers.delete(authUser.id);
        }
      }
      io.emit('presence:update', buildOnlineList());
      if (socket.currentVoiceChannel) {
        leaveVoiceRoom(io, socket, socket.currentVoiceChannel, user.id);
      }
      if (socket.currentTheaterChannel) {
        leaveTheaterRoom(io, socket, socket.currentTheaterChannel, user.id);
      }
    });
  });
}

function buildOnlineList() {
  return Array.from(onlineUsers.entries()).map(([id, info]) => ({
    id,
    username: info.username,
    role:     info.role,
    isOwner:  !!info.is_owner,
    roleColor: info.role_color || null,
    roleHoist: info.role_hoist || 0,
    roleIcon: info.role_icon || null,
    roleName: info.role_name || null,
    rolePosition: info.role_position || 0,
    roleStyleType: info.role_style_type || 'solid',
    roleStyleColors: info.role_style_colors || null,
    avatar: info.avatar || null,
    status: info.status || 'online',
    displayName: info.display_name || null,
    customStatusText: info.custom_status_text || null,
    activityType: info.activity_type || null,
    activityText: info.activity_text || null,
    activityStartedAt: info.activity_started_at || null,
    accountType: info.account_type || 'local',
    verified: info.verified || false,
  }));
}

function refreshAllOnlineRoleMetadata() {
  if (!ioInstance) return;
  if (onlineUsers.size === 0) return;

  const topRoleStmt = db.prepare(`
    SELECT r.color, r.hoist, r.icon, r.name, r.position, r.style_type, r.style_colors
    FROM roles r
    JOIN user_roles ur ON ur.role_id = r.id
    WHERE ur.user_id = ?
    ORDER BY r.position DESC
    LIMIT 1
  `);
  const userStmt = db.prepare(`
    SELECT
      u.username,
      u.role,
      u.is_owner,
      u.avatar,
      u.status,
      u.custom_status_text,
      u.activity_type,
      u.activity_text,
      u.activity_started_at,
      u.account_type,
      COALESCE(dno.display_name, u.display_name) as effective_display_name
    FROM users u
    LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
    WHERE u.id = ?
  `);

  for (const [userId, entry] of onlineUsers.entries()) {
    const topRole = topRoleStmt.get(userId);
    const userRow = userStmt.get(userId);
    if (!userRow) continue;
    entry.username = userRow.username || entry.username;
    entry.role = userRow.role || entry.role;
    entry.is_owner = userRow.is_owner ? 1 : 0;
    entry.role_color = topRole?.color || null;
    entry.role_hoist = topRole?.hoist || 0;
    entry.role_icon = topRole?.icon || null;
    entry.role_name = topRole?.name || null;
    entry.role_position = topRole?.position || 0;
    entry.role_style_type = topRole?.style_type || 'solid';
    entry.role_style_colors = topRole?.style_colors || null;
    entry.avatar = userRow.avatar || null;
    entry.status = userRow.status || 'online';
    entry.display_name = userRow.effective_display_name || null;
    entry.custom_status_text = userRow.custom_status_text || null;
    entry.activity_type = userRow.activity_type || null;
    entry.activity_text = userRow.activity_text || null;
    entry.activity_started_at = userRow.activity_started_at || null;
    entry.account_type = userRow.account_type || entry.account_type || 'local';
    onlineUsers.set(userId, entry);
  }

  ioInstance.emit('presence:update', buildOnlineList());
}
// Broadcast channel list changes to all connected clients
function broadcastChannelUpdate() {
  if (!ioInstance) return;
  const allChannels = db.prepare('SELECT * FROM channels ORDER BY position').all();
  const categories = db.prepare('SELECT * FROM categories ORDER BY position').all();

  // Send filtered channel list to each user based on their preferences
  for (const [, socket] of ioInstance.sockets.sockets) {
    if (!socket.user) continue;

    const userChannels = filterChannelsForUser(socket.user, allChannels);
    socket.emit('channel:list', userChannels);
    socket.emit('category:list', categories);

    // Also join socket to any new channel rooms they're allowed to see
    for (const ch of userChannels) {
      socket.join(ch.id);
    }
  }
}

function emitToChannel(channelId, event, data) {
  if (!ioInstance) return;
  ioInstance.to(channelId).emit(event, data);
}

module.exports = setupSocketHandlers;
module.exports.broadcastChannelUpdate = broadcastChannelUpdate;
module.exports.emitMessage = emitMessage;
module.exports.emitToChannel = emitToChannel;
module.exports.emitServerInfoUpdate = emitServerInfoUpdate;
module.exports.emitServerImportStatus = emitServerImportStatus;
module.exports.emitPermissionsChanged = emitPermissionsChanged;
module.exports.kickUserFromServer = kickUserFromServer;
module.exports.updateOnlineUserAvatar = (userId, avatar) => {
  const entry = onlineUsers.get(userId);
  if (!entry || !ioInstance) return;
  entry.avatar = avatar || null;
  onlineUsers.set(userId, entry);
  ioInstance.emit('presence:update', buildOnlineList());
};

module.exports.updateOnlineUserStatus = (userId, status) => {
  const entry = onlineUsers.get(userId);
  if (!entry || !ioInstance) return;
  entry.status = status || 'online';
  onlineUsers.set(userId, entry);
  ioInstance.emit('presence:update', buildOnlineList());
};

module.exports.updateOnlineUserDisplayName = (userId, displayName) => {
  const entry = onlineUsers.get(userId);
  if (!entry || !ioInstance) return;
  entry.display_name = displayName || null;
  onlineUsers.set(userId, entry);
  ioInstance.emit('presence:update', buildOnlineList());
};

module.exports.updateOnlineUserCustomStatus = (userId, customStatusText) => {
  const entry = onlineUsers.get(userId);
  if (!entry || !ioInstance) return;
  entry.custom_status_text = customStatusText || null;
  onlineUsers.set(userId, entry);
  ioInstance.emit('presence:update', buildOnlineList());
};

module.exports.updateOnlineUserActivity = (userId, activityType, activityText, activityStartedAt) => {
  const entry = onlineUsers.get(userId);
  if (!entry || !ioInstance) return;
  entry.activity_type = activityType || null;
  entry.activity_text = activityText || null;
  entry.activity_started_at = activityStartedAt || null;
  onlineUsers.set(userId, entry);
  ioInstance.emit('presence:update', buildOnlineList());
};

module.exports.getActiveVoiceUserCount = () => {
  let total = 0;
  for (const room of voiceRooms.values()) {
    total += room.size;
  }
  return total;
};

module.exports.getActiveVoiceRoomCount = () => voiceRooms.size;
module.exports.broadcastTheaterQueueUpdate = (channelId) => {
  if (ioInstance) ioInstance.to(`theater:${channelId}`).emit('theater:queue-updated', { channelId });
};
module.exports.broadcastTheaterSync = (channelId) => {
  if (ioInstance) emitTheaterSync(ioInstance, channelId);
};
module.exports.advanceTheaterQueue = (channelId) => {
  advanceTheaterQueue(channelId);
  if (ioInstance) emitTheaterSync(ioInstance, channelId);
};

// ── Theater helpers ────────────────────────────────────────────────────────────
function leaveTheaterRoom(io, socket, channelId, userId) {
  const room = theaterRooms.get(channelId);
  if (!room) return;
  if (room.has(userId)) {
    room.delete(userId);
    socket.leave(`theater:${channelId}`);
    io.to(`theater:${channelId}`).emit('theater:user-left', { channelId, userId });
  }
  if (room.size === 0) {
    theaterRooms.delete(channelId);
    // Stop sync interval
    const interval = theaterSyncIntervals.get(channelId);
    if (interval) {
      clearInterval(interval);
      theaterSyncIntervals.delete(channelId);
    }
    // Clear state and cleanup cache
    db.prepare('UPDATE theater_state SET playing = 0 WHERE channel_id = ?').run(channelId);
    const { deleteChannelCache } = require('../lib/theaterDownload');
    deleteChannelCache(channelId).catch(() => {});
    // Mark all queue items as pending to prevent stale ready state
    db.prepare("UPDATE theater_queue SET cache_status = 'pending', cache_progress = 0, cached_path = NULL WHERE channel_id = ?").run(channelId);
    db.prepare('DELETE FROM theater_queue WHERE channel_id = ?').run(channelId);
    db.prepare('DELETE FROM theater_state WHERE channel_id = ?').run(channelId);
    db.prepare('DELETE FROM theater_skip_votes WHERE channel_id = ?').run(channelId);
    io.emit('theater:room-count', { channelId, count: 0 });
  } else {
    io.emit('theater:room-count', { channelId, count: room.size });
  }
  if (socket.currentTheaterChannel === channelId) {
    socket.currentTheaterChannel = null;
  }
}

function emitTheaterSync(io, channelId) {
  const state = db.prepare('SELECT * FROM theater_state WHERE channel_id = ?').get(channelId);
  if (!state) {
    io.to(`theater:${channelId}`).emit('theater:sync', {
      channelId,
      currentItemId: null,
      positionMs: 0,
      playing: false,
      updatedAt: Date.now(),
      videoUrl: null,
    });
    return;
  }
  let videoUrl = null;
  if (state.current_item_id) {
    const item = db.prepare('SELECT cached_path FROM theater_queue WHERE id = ?').get(state.current_item_id);
    if (item?.cached_path) {
      const path = require('path');
      const basename = path.basename(item.cached_path);
      videoUrl = `/ugc/temp-theater/${channelId}/${basename}`;
    }
  }
  io.to(`theater:${channelId}`).emit('theater:sync', {
    channelId,
    currentItemId: state.current_item_id,
    positionMs: state.position_ms,
    playing: !!state.playing,
    updatedAt: state.updated_at * 1000,
    hostUserId: state.host_user_id,
    videoUrl,
  });
}

function advanceTheaterQueue(channelId) {
  const state = db.prepare('SELECT * FROM theater_state WHERE channel_id = ?').get(channelId);
  const currentItemId = state?.current_item_id;

  // Mark current item as played
  if (currentItemId) {
    db.prepare("UPDATE theater_queue SET cache_status = 'played' WHERE id = ?").run(currentItemId);
    db.prepare('DELETE FROM theater_skip_votes WHERE channel_id = ?').run(channelId);
  }

  // Find next ready item
  const nextItem = db.prepare(`
    SELECT id FROM theater_queue
    WHERE channel_id = ? AND cache_status = 'ready' AND id != COALESCE(?, '')
    ORDER BY position ASC, created_at ASC
    LIMIT 1
  `).get(channelId, currentItemId || null);

  db.prepare(`
    INSERT INTO theater_state (channel_id, current_item_id, position_ms, playing, updated_at)
    VALUES (?, ?, 0, ?, unixepoch())
    ON CONFLICT(channel_id) DO UPDATE SET
      current_item_id = excluded.current_item_id,
      position_ms = 0,
      playing = excluded.playing,
      updated_at = unixepoch()
  `).run(channelId, nextItem?.id || null, nextItem ? 1 : 0);
}

function leaveVoiceRoom(io, socket, channelId, userId) {
  const room = voiceRooms.get(channelId);
  if (!room) return;
  if (room.has(userId)) {
    room.delete(userId);
    socket.leave(`voice:${channelId}`);
    io.to(`voice:${channelId}`).emit('voice:user-left', { channelId, userId });
    if (room.size > 0) {
      emitVoiceRoomCount(io, channelId);
      emitVoiceRoomSync(io, channelId);
    }
  }
  if (room.size === 0) {
    voiceRooms.delete(channelId);
    voiceRoomStartedAt.delete(channelId);
    emitVoiceRoomCount(io, channelId);
    io.emit('voice:room-sync', { channelId, users: [], startedAt: null });
  }
  if (socket.currentVoiceChannel === channelId) {
    socket.currentVoiceChannel = null;
  }
}

function emitVoiceRoomCount(io, channelId) {
  const room = voiceRooms.get(channelId);
  io.emit('voice:room-count', {
    channelId,
    count: room ? room.size : 0,
    startedAt: room && room.size > 0 ? (voiceRoomStartedAt.get(channelId) ?? null) : null,
  });
}

function emitVoiceRoomSync(io, channelId) {
  const room = voiceRooms.get(channelId);
  io.emit('voice:room-sync', {
    channelId,
    users: room ? Array.from(room.values()).map((entry) => entry.user) : [],
    startedAt: room && room.size > 0 ? (voiceRoomStartedAt.get(channelId) ?? null) : null,
  });
}

function buildVoiceRoomCounts() {
  return Array.from(voiceRooms.entries()).map(([channelId, room]) => ({
    channelId,
    count: room.size,
    users: Array.from(room.values()).map((entry) => entry.user),
    startedAt: room.size > 0 ? (voiceRoomStartedAt.get(channelId) ?? null) : null,
  }));
}
