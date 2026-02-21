const router = require('express').Router();
const { randomUUID } = require('crypto');
const db = require('../db');
const {
  PERMISSIONS,
  hasPermission,
  hasChannelPermission,
  computeUserChannelPermissions,
} = require('../permissions');
const { broadcastChannelUpdate, emitMessage, emitPermissionsChanged } = require('../socket/handler');
const { getSetting } = require('../settings');
const { encryptMessageContent, decryptMessageRows } = require('../messageCrypto');

function allowsNsfw(userId) {
  const prefs = db.prepare('SELECT preferences FROM user_content_social_prefs WHERE user_id = ?').get(userId);
  if (!prefs) return false;
  try {
    const parsed = JSON.parse(prefs.preferences);
    return parsed?.allowNsfw === true;
  } catch (_err) {
    return false;
  }
}

function visibleChannelListForUser(user, channels) {
  const canManageNsfwChannels = hasPermission(user, PERMISSIONS.MANAGE_CHANNELS);
  const allowNsfw = canManageNsfwChannels ? true : allowsNsfw(user.id);
  const visible = [];
  for (const channel of channels) {
    const effectivePermissions = computeUserChannelPermissions(user, channel.id, db);
    if (!hasChannelPermission(user, channel.id, PERMISSIONS.VIEW_CHANNELS, db)) continue;
    if (!allowNsfw && channel.nsfw) continue;
    visible.push({
      ...channel,
      effective_permissions: effectivePermissions,
    });
  }
  return visible;
}

// GET /api/channels - list all channels
router.get('/', (req, res) => {
  const channels = db.prepare('SELECT * FROM channels ORDER BY position ASC').all();
  res.json(visibleChannelListForUser(req.user, channels));
});

// POST /api/channels - create channel (admin only)
router.post('/', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  const { name, description, type, categoryId, allowDisplayName } = req.body;
  if (!name) return res.status(400).json({ error: 'Channel name required' });

  const maxPos = db.prepare('SELECT MAX(position) as m FROM channels').get().m || 0;
  const id = randomUUID();
  const channelType = ['basic', 'media', 'voice', 'announcement', 'forum'].includes(type) ? type : 'basic';
  const channelName = allowDisplayName ? name.trim() : name.toLowerCase().replace(/\s+/g, '-');
  db.prepare('INSERT INTO channels (id, name, description, type, position, category_id) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, channelName, description || null, channelType, maxPos + 1, categoryId || null);

  const channel = db.prepare('SELECT * FROM channels WHERE id = ?').get(id);
  broadcastChannelUpdate();
  res.status(201).json(channel);
});

// DELETE /api/channels/:id - delete channel (admin only)
router.delete('/:id', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  db.prepare('DELETE FROM channels WHERE id = ?').run(req.params.id);
  broadcastChannelUpdate();
  res.json({ success: true });
});

// PATCH /api/channels/:id - edit channel
router.patch('/:id', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  const { name, description, type, categoryId, position, allowDisplayName } = req.body ?? {};
  const channel = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  if (typeof name === 'string' && name.trim().length >= 2) {
    const nextName =
      allowDisplayName === true
        ? name.trim()
        : allowDisplayName === false
          ? name.toLowerCase().replace(/\s+/g, '-')
          : name.trim();
    db.prepare('UPDATE channels SET name = ? WHERE id = ?').run(nextName, req.params.id);
  }
  if (typeof description === 'string') {
    db.prepare('UPDATE channels SET description = ? WHERE id = ?').run(description.trim(), req.params.id);
  }
  if (typeof type === 'string' && ['basic', 'media', 'voice', 'announcement', 'forum'].includes(type)) {
    db.prepare('UPDATE channels SET type = ? WHERE id = ?').run(type, req.params.id);
  }
  if (typeof categoryId === 'string' || categoryId === null) {
    db.prepare('UPDATE channels SET category_id = ? WHERE id = ?').run(categoryId, req.params.id);
  }
  if (typeof req.body.nsfw === 'boolean') {
    db.prepare('UPDATE channels SET nsfw = ? WHERE id = ?').run(req.body.nsfw ? 1 : 0, req.params.id);
  }
  if (typeof position === 'number') {
    db.prepare('UPDATE channels SET position = ? WHERE id = ?').run(position, req.params.id);
  }
  const updated = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  broadcastChannelUpdate();
  res.json(updated);
});

// POST /api/channels/:id/duplicate
router.post('/:id/duplicate', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  const channel = db.prepare('SELECT * FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  const maxPos = db.prepare('SELECT MAX(position) as m FROM channels').get().m || 0;
  const id = randomUUID();
  const name = `${channel.name}-copy`;
  db.prepare('INSERT INTO channels (id, name, description, type, position, category_id) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, name, channel.description, channel.type, maxPos + 1, channel.category_id);
  const newChannel = db.prepare('SELECT * FROM channels WHERE id = ?').get(id);
  broadcastChannelUpdate();
  res.status(201).json(newChannel);
});

// GET /api/channels/:id/pins
router.get('/:id/pins', (req, res) => {
  const { id } = req.params;
  const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  if (!hasChannelPermission(req.user, id, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  if (!hasChannelPermission(req.user, id, PERMISSIONS.READ_CHAT_HISTORY, db)) {
    return res.status(403).json({ error: 'Missing permission: read_chat_history' });
  }
  const pins = db.prepare(`
    SELECT p.message_id, p.pinned_at, p.pinned_by, m.content, m.created_at, u.username
    FROM pins p
    JOIN messages m ON m.id = p.message_id
    JOIN users u ON u.id = p.pinned_by
    WHERE p.channel_id = ?
    ORDER BY p.pinned_at DESC
  `).all(id);
  res.json(decryptMessageRows(pins));
});

// POST /api/channels/:id/pins
router.post('/:id/pins', (req, res) => {
  if (!hasChannelPermission(req.user, req.params.id, PERMISSIONS.PIN_MESSAGES, db)) {
    return res.status(403).json({ error: 'Missing permission: pin_messages' });
  }
  const { messageId } = req.body ?? {};
  if (!messageId) return res.status(400).json({ error: 'messageId required' });
  const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  const msg = db.prepare('SELECT id, channel_id FROM messages WHERE id = ?').get(messageId);
  if (!msg || msg.channel_id !== req.params.id) {
    return res.status(400).json({ error: 'Message not in channel' });
  }
  const maxPins = Number(getSetting('max_pins', '300'));
  const pinCount = db.prepare('SELECT COUNT(*) as c FROM pins WHERE channel_id = ?').get(req.params.id).c;
  if (pinCount >= maxPins) return res.status(400).json({ error: 'Pin limit reached' });
  db.prepare('INSERT OR IGNORE INTO pins (channel_id, message_id, pinned_by) VALUES (?, ?, ?)')
    .run(req.params.id, messageId, req.user.id);

  // Post a system-style message
  const { randomUUID } = require('crypto');
  const now = Math.floor(Date.now() / 1000);
  const sysId = randomUUID();
  const content = `${req.user.username} pinned a message.`;
  db.prepare(`
    INSERT INTO messages (id, channel_id, user_id, content, created_at, message_type, attachment_url)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(sysId, req.params.id, req.user.id, encryptMessageContent(content), now, 'system', messageId);

  emitMessage(req.params.id, {
    id: sysId,
    channel_id: req.params.id,
    user_id: req.user.id,
    username: req.user.username,
    content,
    edited: 0,
    is_owner: req.user.is_owner ? 1 : 0,
    role_color: null,
    message_type: 'system',
    attachment_url: messageId,
    created_at: now,
  });
  res.json({ success: true });
});

// DELETE /api/channels/:id/pins/:messageId
router.delete('/:id/pins/:messageId', (req, res) => {
  if (!hasChannelPermission(req.user, req.params.id, PERMISSIONS.PIN_MESSAGES, db)) {
    return res.status(403).json({ error: 'Missing permission: pin_messages' });
  }
  db.prepare('DELETE FROM pins WHERE channel_id = ? AND message_id = ?')
    .run(req.params.id, req.params.messageId);
  res.json({ success: true });
});

// PATCH /api/channels/:id/prefs
router.patch('/:id/prefs', (req, res) => {
  const { muted, lastReadAt } = req.body ?? {};
  const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  if (!hasChannelPermission(req.user, req.params.id, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  const current = db.prepare('SELECT * FROM channel_prefs WHERE user_id = ? AND channel_id = ?').get(req.user.id, req.params.id);
  const nextMuted = typeof muted === 'boolean' ? (muted ? 1 : 0) : (current?.muted ?? 0);
  const nextRead = typeof lastReadAt === 'number' ? lastReadAt : (current?.last_read_at ?? 0);
  db.prepare(`
    INSERT INTO channel_prefs (user_id, channel_id, muted, last_read_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id, channel_id)
    DO UPDATE SET muted = excluded.muted, last_read_at = excluded.last_read_at
  `).run(req.user.id, req.params.id, nextMuted, nextRead);
  res.json({ muted: !!nextMuted, lastReadAt: nextRead });
});

// GET /api/channels/:id/settings - Get channel settings
router.get('/:id/settings', (req, res) => {
  const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  if (!hasChannelPermission(req.user, req.params.id, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }

  const settings = db.prepare('SELECT * FROM channel_settings WHERE channel_id = ?').get(req.params.id);
  res.json(settings || { channel_id: req.params.id, slowmode: 0, default_reaction: null });
});

// PATCH /api/channels/:id/settings - Update channel settings
router.patch('/:id/settings', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  const { slowmode, defaultReaction, userLimit, bitrate, videoQualityMode } = req.body ?? {};
  const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });

  // Validate slowmode (0-120 seconds)
  if (typeof slowmode === 'number' && (slowmode < 0 || slowmode > 120)) {
    return res.status(400).json({ error: 'Slowmode must be between 0 and 120 seconds' });
  }

  // Validate userLimit (0-99)
  if (typeof userLimit === 'number' && (userLimit < 0 || userLimit > 99)) {
    return res.status(400).json({ error: 'User limit must be between 0 and 99' });
  }

  // Validate bitrate (8000-384000)
  if (typeof bitrate === 'number' && (bitrate < 8000 || bitrate > 384000)) {
    return res.status(400).json({ error: 'Bitrate must be between 8000 and 384000' });
  }

  // Validate videoQualityMode
  if (typeof videoQualityMode === 'string' && !['auto', '720p', '1080p'].includes(videoQualityMode)) {
    return res.status(400).json({ error: 'Video quality mode must be auto, 720p, or 1080p' });
  }

  const current = db.prepare('SELECT * FROM channel_settings WHERE channel_id = ?').get(req.params.id);
  const nextSlowmode = typeof slowmode === 'number' ? slowmode : (current?.slowmode ?? 0);
  const nextReaction = typeof defaultReaction === 'string' || defaultReaction === null ? defaultReaction : (current?.default_reaction ?? null);
  const nextUserLimit = typeof userLimit === 'number' ? userLimit : (current?.user_limit ?? 0);
  const nextBitrate = typeof bitrate === 'number' ? bitrate : (current?.bitrate ?? 64000);
  const nextVideoQuality = typeof videoQualityMode === 'string' ? videoQualityMode : (current?.video_quality_mode ?? 'auto');

  db.prepare(`
    INSERT INTO channel_settings (channel_id, slowmode, default_reaction, user_limit, bitrate, video_quality_mode)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(channel_id)
    DO UPDATE SET
      slowmode = excluded.slowmode,
      default_reaction = excluded.default_reaction,
      user_limit = excluded.user_limit,
      bitrate = excluded.bitrate,
      video_quality_mode = excluded.video_quality_mode
  `).run(req.params.id, nextSlowmode, nextReaction, nextUserLimit, nextBitrate, nextVideoQuality);

  res.json({
    slowmode: nextSlowmode,
    defaultReaction: nextReaction,
    userLimit: nextUserLimit,
    bitrate: nextBitrate,
    videoQualityMode: nextVideoQuality
  });
});

// POST /api/channels/:id/permissions/sync-from-category
router.post('/:id/permissions/sync-from-category', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  const channel = db.prepare('SELECT id, category_id FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  if (!channel.category_id) {
    return res.status(400).json({ error: 'Channel is not inside a category' });
  }

  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(channel.category_id);
  if (!category) return res.status(404).json({ error: 'Category not found' });

  const categoryOverwrites = db.prepare(`
    SELECT target_type, target_id, allow, deny
    FROM category_permission_overwrites
    WHERE category_id = ?
  `).all(channel.category_id);

  const syncTransaction = db.transaction((channelId, overwrites) => {
    db.prepare('DELETE FROM channel_permission_overwrites WHERE channel_id = ?').run(channelId);
    const insert = db.prepare(`
      INSERT INTO channel_permission_overwrites (id, channel_id, target_type, target_id, allow, deny)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    for (const overwrite of overwrites) {
      insert.run(
        randomUUID(),
        channelId,
        overwrite.target_type,
        overwrite.target_id,
        Number(overwrite.allow || 0),
        Number(overwrite.deny || 0)
      );
    }
  });
  syncTransaction(channel.id, categoryOverwrites);

  const synced = db.prepare(`
    SELECT * FROM channel_permission_overwrites
    WHERE channel_id = ?
    ORDER BY created_at
  `).all(channel.id);
  emitPermissionsChanged();
  res.json({ synced: true, direction: 'from-category', count: synced.length, overwrites: synced });
});

// POST /api/channels/:id/permissions/sync-to-category
router.post('/:id/permissions/sync-to-category', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  const channel = db.prepare('SELECT id, category_id FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  if (!channel.category_id) {
    return res.status(400).json({ error: 'Channel is not inside a category' });
  }

  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(channel.category_id);
  if (!category) return res.status(404).json({ error: 'Category not found' });

  const channelOverwrites = db.prepare(`
    SELECT target_type, target_id, allow, deny
    FROM channel_permission_overwrites
    WHERE channel_id = ?
  `).all(channel.id);

  const syncTransaction = db.transaction((categoryId, overwrites) => {
    db.prepare('DELETE FROM category_permission_overwrites WHERE category_id = ?').run(categoryId);
    const insert = db.prepare(`
      INSERT INTO category_permission_overwrites (id, category_id, target_type, target_id, allow, deny)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    for (const overwrite of overwrites) {
      insert.run(
        randomUUID(),
        categoryId,
        overwrite.target_type,
        overwrite.target_id,
        Number(overwrite.allow || 0),
        Number(overwrite.deny || 0)
      );
    }
  });
  syncTransaction(channel.category_id, channelOverwrites);

  const synced = db.prepare(`
    SELECT * FROM category_permission_overwrites
    WHERE category_id = ?
    ORDER BY created_at
  `).all(channel.category_id);
  emitPermissionsChanged();
  res.json({ synced: true, direction: 'to-category', count: synced.length, overwrites: synced });
});

// GET /api/channels/:id/permissions - List all permission overwrites
router.get('/:id/permissions', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });

  const overwrites = db.prepare('SELECT * FROM channel_permission_overwrites WHERE channel_id = ? ORDER BY created_at').all(req.params.id);
  res.json(overwrites);
});

// POST /api/channels/:id/permissions - Create permission overwrite
router.post('/:id/permissions', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  const { targetType, targetId, allow, deny } = req.body ?? {};
  if (!targetType || !targetId) {
    return res.status(400).json({ error: 'targetType and targetId required' });
  }
  if (!['role', 'user'].includes(targetType)) {
    return res.status(400).json({ error: 'targetType must be role or user' });
  }

  const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(req.params.id);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });

  // Verify target exists
  if (targetType === 'role') {
    const role = db.prepare('SELECT id FROM roles WHERE id = ?').get(targetId);
    if (!role) return res.status(404).json({ error: 'Role not found' });
  } else {
    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(targetId);
    if (!user) return res.status(404).json({ error: 'User not found' });
  }

  const id = randomUUID();
  const allowBits = typeof allow === 'number' ? allow : 0;
  const denyBits = typeof deny === 'number' ? deny : 0;
  const existing = db.prepare(`
    SELECT * FROM channel_permission_overwrites
    WHERE channel_id = ? AND target_type = ? AND target_id = ?
    LIMIT 1
  `).get(req.params.id, targetType, targetId);
  if (existing) {
    db.prepare('UPDATE channel_permission_overwrites SET allow = ?, deny = ? WHERE id = ?')
      .run(allowBits, denyBits, existing.id);
    const updated = db.prepare('SELECT * FROM channel_permission_overwrites WHERE id = ?').get(existing.id);
    emitPermissionsChanged();
    return res.json(updated);
  }

  db.prepare(`
    INSERT INTO channel_permission_overwrites (id, channel_id, target_type, target_id, allow, deny)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, req.params.id, targetType, targetId, allowBits, denyBits);

  const overwrite = db.prepare('SELECT * FROM channel_permission_overwrites WHERE id = ?').get(id);
  emitPermissionsChanged();
  res.status(201).json(overwrite);
});

// PATCH /api/channels/:id/permissions/:overwriteId - Update permission overwrite
router.patch('/:id/permissions/:overwriteId', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  const { allow, deny } = req.body ?? {};
  const overwrite = db.prepare('SELECT * FROM channel_permission_overwrites WHERE id = ? AND channel_id = ?').get(req.params.overwriteId, req.params.id);
  if (!overwrite) return res.status(404).json({ error: 'Overwrite not found' });

  if (typeof allow === 'number') {
    db.prepare('UPDATE channel_permission_overwrites SET allow = ? WHERE id = ?').run(allow, req.params.overwriteId);
  }
  if (typeof deny === 'number') {
    db.prepare('UPDATE channel_permission_overwrites SET deny = ? WHERE id = ?').run(deny, req.params.overwriteId);
  }

  const updated = db.prepare('SELECT * FROM channel_permission_overwrites WHERE id = ?').get(req.params.overwriteId);
  emitPermissionsChanged();
  res.json(updated);
});

// DELETE /api/channels/:id/permissions/:overwriteId - Remove permission overwrite
router.delete('/:id/permissions/:overwriteId', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  db.prepare('DELETE FROM channel_permission_overwrites WHERE id = ? AND channel_id = ?').run(req.params.overwriteId, req.params.id);
  emitPermissionsChanged();
  res.json({ success: true });
});

module.exports = router;
