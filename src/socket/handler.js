const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const path = require('path');
const fs = require('fs');
const db = require('../db');
const { JWT_SECRET } = require('../middleware/auth');
const { PERMISSIONS, ALL_PERMISSIONS, computePermissionsForUser, hasPermission } = require('../permissions');
const pteroLog = require('../logger');
const { encryptMessageContent, decryptMessageContent } = require('../messageCrypto');

// Track online users: userId -> { username, role, is_owner, role_color, avatar, status, sockets: Set<socketId> }
const onlineUsers = new Map();
// Track voice rooms: channelId -> Map<userId, { socketId, muted, deafened, user }>
const voiceRooms = new Map();

let ioInstance = null;
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
  refreshAllOnlineRoleMetadata();
  ioInstance.emit('permissions:changed');
}

function emitServerImportStatus(status, data) {
  if (!ioInstance) return;
  ioInstance.emit('server:import:status', { status, ...data });
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
    if (!allowNsfw) return channels.filter(ch => !ch.nsfw);
  }
  return channels;
}

function setupSocketHandlers(io) {
  ioInstance = io;

  // ── Auth middleware for sockets ──────────────────────────────────────────────
  io.use((socket, next) => {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('No token'));
    try {
      socket.user = jwt.verify(token, JWT_SECRET);
      next();
    } catch {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    const user = socket.user;
    if (user && !user.permissions) {
      // Hydrate permissions for local accounts
      const dbUser = db.prepare('SELECT id, role, is_owner FROM users WHERE id = ?').get(user.id);
      if (dbUser) {
        const permissions = computePermissionsForUser(dbUser.id, dbUser.role, dbUser.is_owner, db);
        user.permissions = permissions;
        user.is_owner = dbUser.is_owner ? 1 : 0;
        user.role = dbUser.role;
      }
    }
    pteroLog(`[CatRealm] ${user.username} connected`);

    // Register as online
    const existingEntry = onlineUsers.get(user.id);
    if (existingEntry) {
      existingEntry.sockets.add(socket.id);
    } else {
      const topRole = db.prepare(`
        SELECT r.color, r.hoist, r.icon, r.name, r.position FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = ?
        ORDER BY r.position DESC
        LIMIT 1
      `).get(user.id);
      const userRow = db.prepare(`
        SELECT u.avatar, u.status, u.display_name, u.activity_type, u.activity_text, u.account_type,
          COALESCE(dno.display_name, u.display_name) as effective_display_name
        FROM users u
        LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
        WHERE u.id = ?
      `).get(user.id);
      onlineUsers.set(user.id, {
        username: user.username,
        role: user.role,
        is_owner: user.is_owner ? 1 : 0,
        role_color: topRole?.color || null,
        role_hoist: topRole?.hoist || 0,
        role_icon: topRole?.icon || null,
        role_name: topRole?.name || null,
        role_position: topRole?.position || 0,
        avatar: userRow?.avatar || null,
        status: userRow?.status || 'online',
        display_name: userRow?.effective_display_name || null,
        activity_type: userRow?.activity_type || null,
        activity_text: userRow?.activity_text || null,
        account_type: userRow?.account_type || 'local',
        verified: user.verified || false,
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

      pteroLog(`[CatRealm] ${user.username} join voice ${channelId}`);
      if (socket.currentVoiceChannel && socket.currentVoiceChannel !== channelId) {
        leaveVoiceRoom(io, socket, socket.currentVoiceChannel, user.id);
      }

      const online = onlineUsers.get(user.id);
      const voiceUser = {
        id: user.id,
        username: user.username,
        role: user.role,
        isOwner: !!user.is_owner,
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
      room.set(user.id, { socketId: socket.id, muted: !!muted, deafened: !!deafened, user: voiceUser });
      socket.currentVoiceChannel = channelId;
      socket.join(`voice:${channelId}`);

      const payload = {
        channelId,
        users: Array.from(room.values()).map((entry) => entry.user),
        you: user.id,
      };
      socket.emit('voice:users', payload);
      socket.emit('voice:join:ok', payload);
      if (typeof ack === 'function') {
        ack({ ok: true, ...payload });
      }
      socket.to(`voice:${channelId}`).emit('voice:user-joined', { channelId, user: voiceUser });
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
      const room = voiceRooms.get(channelId);
      if (!room) return;
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

    // ── Set active channel (for typing indicators only) ────────────────────────
    socket.on('channel:join', (channelId) => {
      const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(channelId);
      if (!channel) return socket.emit('error', 'Channel not found');
      socket.currentChannel = channelId;
    });

    socket.on('thread:join', (threadId) => {
      const thread = db.prepare('SELECT id FROM threads WHERE id = ?').get(threadId);
      if (!thread) return socket.emit('error', 'Thread not found');
      socket.join(`thread:${threadId}`);
    });

    // ── Send a message ─────────────────────────────────────────────────────────
    socket.on('message:send', ({ channelId, content, attachment, threadId, replyToId, forwardFromId, nsfwTags }) => {
      const hasText = typeof content === 'string' && content.trim().length > 0;
      const hasAttachment = attachment && typeof attachment.url === 'string';
      if (!channelId || (!hasText && !hasAttachment)) return;
      if (content && content.length > 2000) return socket.emit('error', 'Message too long (max 2000 chars)');
      if (hasAttachment && !((user.is_owner || user.role === 'owner') || ((user.permissions & PERMISSIONS.SEND_MEDIA) !== 0))) {
        return socket.emit('error', 'Missing permission: send_media');
      }
      const canEmbedLinks = (user.is_owner || user.role === 'owner') || ((user.permissions & PERMISSIONS.EMBED_LINKS) !== 0);

      const channel = db.prepare('SELECT id, type FROM channels WHERE id = ?').get(channelId);
      if (!channel) return socket.emit('error', 'Channel not found');
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
        const hasBypass = (user.is_owner || user.role === 'owner') || ((user.permissions & PERMISSIONS.BYPASS_SLOWMODE) !== 0);
        if (!hasBypass) {
          const lastMessage = db.prepare(`
            SELECT created_at FROM messages
            WHERE channel_id = ? AND user_id = ? AND message_type = 'user'
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

      // Validate forwardFromId
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
      }
      const attachmentUrl = hasAttachment ? attachment.url : null;
      const attachmentType = hasAttachment ? attachment.mime : null;
      const attachmentSize = hasAttachment ? attachment.size : null;
      const normalizedNsfwTags = hasAttachment && Array.isArray(nsfwTags)
        ? Array.from(new Set(
          nsfwTags
            .filter((tag) => typeof tag === 'string')
            .map((tag) => String(tag).toLowerCase().trim())
            .filter((tag) => ['blood', 'gore', 'violence', 'lewd', 'sexual', 'disturbing'].includes(tag))
        ))
        : [];
      db.prepare(`
        INSERT INTO messages (
          id, channel_id, user_id, content, created_at,
          attachment_url, attachment_type, attachment_size, message_type, thread_id,
          reply_to_id, forward_from_id, forward_from_user, forward_from_channel, embeds_enabled
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id, channelId, user.id, encryptMessageContent(trimmed), now,
        attachmentUrl, attachmentType, attachmentSize, 'user', threadId || null,
        replyToId || null,
        forwardFrom?.id || null,
        forwardFrom?.username || null,
        forwardFrom?.channel_name || null,
        canEmbedLinks ? 1 : 0
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
        username:   user.username,
        content:    trimmed,
        edited:     0,
        is_owner:   user.is_owner ? 1 : 0,
        role_color: topRole?.color || null,
        avatar: userInfo?.avatar || null,
        display_name: userInfo?.display_name || null,
        verified: user.verified || false,
        attachment_url: attachmentUrl,
        attachment_type: attachmentType,
        attachment_size: attachmentSize,
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
        embeds_enabled: canEmbedLinks ? 1 : 0,
      };

      if (threadId) {
        io.to(`thread:${threadId}`).emit('message:new', message);
      } else {
        io.to(channelId).emit('message:new', message);
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
      const canEdit = msg.user_id === user.id || (user.is_owner || user.role === 'owner') || ((user.permissions & PERMISSIONS.EDIT_MESSAGES) !== 0);
      if (!canEdit) return socket.emit('error', 'Not allowed');
      const canEmbedLinks = (user.is_owner || user.role === 'owner') || ((user.permissions & PERMISSIONS.EMBED_LINKS) !== 0);
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
      const canDelete = msg.user_id === user.id || (user.is_owner || user.role === 'owner') || ((user.permissions & PERMISSIONS.DELETE_MESSAGES) !== 0);
      if (!canDelete) return socket.emit('error', 'Not allowed');

      db.prepare('DELETE FROM messages WHERE id = ?').run(messageId);
      if (msg.attachment_url && msg.attachment_url.startsWith('/ugc/images/')) {
        const baseDir = process.env.UGC_IMAGES_DIR || path.join(__dirname, '../../data/ugc/images');
        const filePath = path.join(baseDir, msg.attachment_url.replace('/ugc/images/', ''));
        fs.unlink(filePath, () => {});
      }
      if (msg.thread_id) {
        io.to(`thread:${msg.thread_id}`).emit('message:deleted', { messageId, channelId: msg.channel_id, threadId: msg.thread_id });
      } else {
        io.to(msg.channel_id).emit('message:deleted', { messageId, channelId: msg.channel_id });
      }
    });

    // ── Typing indicator ───────────────────────────────────────────────────────
    socket.on('typing:start', ({ channelId }) => {
      socket.to(channelId).emit('typing:update', { userId: user.id, username: user.username, typing: true });
    });

    socket.on('typing:stop', ({ channelId }) => {
      socket.to(channelId).emit('typing:update', { userId: user.id, username: user.username, typing: false });
    });

    // ── Disconnect ─────────────────────────────────────────────────────────────
    socket.on('disconnect', () => {
      pteroLog(`[CatRealm] ${user.username} disconnected`);
      const entry = onlineUsers.get(user.id);
      if (entry) {
        entry.sockets.delete(socket.id);
        if (entry.sockets.size === 0) {
          onlineUsers.delete(user.id);
        }
      }
      io.emit('presence:update', buildOnlineList());
      if (socket.currentVoiceChannel) {
        leaveVoiceRoom(io, socket, socket.currentVoiceChannel, user.id);
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
    avatar: info.avatar || null,
    status: info.status || 'online',
    displayName: info.display_name || null,
    activityType: info.activity_type || null,
    activityText: info.activity_text || null,
    accountType: info.account_type || 'local',
    verified: info.verified || false,
  }));
}

function refreshAllOnlineRoleMetadata() {
  if (!ioInstance) return;
  if (onlineUsers.size === 0) return;

  const topRoleStmt = db.prepare(`
    SELECT r.color, r.hoist, r.icon, r.name, r.position
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
      u.activity_type,
      u.activity_text,
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
    entry.avatar = userRow.avatar || null;
    entry.status = userRow.status || 'online';
    entry.display_name = userRow.effective_display_name || null;
    entry.activity_type = userRow.activity_type || null;
    entry.activity_text = userRow.activity_text || null;
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

module.exports = setupSocketHandlers;
module.exports.broadcastChannelUpdate = broadcastChannelUpdate;
module.exports.emitMessage = emitMessage;
module.exports.emitServerInfoUpdate = emitServerInfoUpdate;
module.exports.emitServerImportStatus = emitServerImportStatus;
module.exports.emitPermissionsChanged = emitPermissionsChanged;
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

module.exports.updateOnlineUserActivity = (userId, activityType, activityText) => {
  const entry = onlineUsers.get(userId);
  if (!entry || !ioInstance) return;
  entry.activity_type = activityType || null;
  entry.activity_text = activityText || null;
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
    emitVoiceRoomCount(io, channelId);
    io.emit('voice:room-sync', { channelId, users: [] });
  }
  if (socket.currentVoiceChannel === channelId) {
    socket.currentVoiceChannel = null;
  }
}

function emitVoiceRoomCount(io, channelId) {
  const room = voiceRooms.get(channelId);
  io.emit('voice:room-count', { channelId, count: room ? room.size : 0 });
}

function emitVoiceRoomSync(io, channelId) {
  const room = voiceRooms.get(channelId);
  io.emit('voice:room-sync', {
    channelId,
    users: room ? Array.from(room.values()).map((entry) => entry.user) : [],
  });
}

function buildVoiceRoomCounts() {
  return Array.from(voiceRooms.entries()).map(([channelId, room]) => ({
    channelId,
    count: room.size,
    users: Array.from(room.values()).map((entry) => entry.user),
  }));
}
