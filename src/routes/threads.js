const router = require('express').Router();
const { randomUUID } = require('crypto');
const db = require('../db');
const { PERMISSIONS, hasPermission, hasChannelPermission } = require('../permissions');
const { decryptMessageRows } = require('../messageCrypto');
const { emitToChannel } = require('../socket/handler');

function attachNsfwTags(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return messages;
  const ids = messages.map((m) => m.id).filter(Boolean);
  if (ids.length === 0) return messages;
  const placeholders = ids.map(() => '?').join(', ');
  const rows = db.prepare(
    `SELECT message_id, tag FROM message_nsfw_tags WHERE message_id IN (${placeholders})`
  ).all(...ids);
  const tagMap = new Map();
  for (const row of rows) {
    const list = tagMap.get(row.message_id) || [];
    list.push(row.tag);
    tagMap.set(row.message_id, list);
  }
  return messages.map((message) => ({
    ...message,
    nsfw_tags: tagMap.get(message.id) || [],
  }));
}

// GET /api/threads?channelId=...
router.get('/', (req, res) => {
  const { channelId } = req.query;
  if (!channelId) return res.status(400).json({ error: 'channelId required' });
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.READ_CHAT_HISTORY, db)) {
    return res.status(403).json({ error: 'Missing permission: read_chat_history' });
  }
  const threads = db.prepare('SELECT * FROM threads WHERE channel_id = ? ORDER BY created_at DESC').all(channelId);
  res.json(threads);
});

// GET /api/threads/forum?channelId=&archived=
// Must be before /:id routes to prevent 'forum' being matched as an id
router.get('/forum', (req, res) => {
  const { channelId, archived } = req.query;
  if (!channelId) return res.status(400).json({ error: 'channelId required' });
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.READ_CHAT_HISTORY, db)) {
    return res.status(403).json({ error: 'Missing permission: read_chat_history' });
  }
  const showArchived = archived === '1' ? 1 : 0;
  const rows = db.prepare(`
    SELECT t.id, t.channel_id, t.parent_message_id, t.name, t.created_by, t.created_at,
      ts.archived, ts.last_message_at, ts.cover_image,
      u.username AS author_username, u.avatar AS author_avatar, u.account_type AS author_account_type,
      COALESCE(dno.display_name, u.display_name) AS author_display_name,
      m.content AS preview_content, m.attachments AS body_attachments_raw,
      (SELECT COUNT(*) FROM messages WHERE thread_id = t.id) AS reply_count
    FROM threads t
    LEFT JOIN thread_settings ts ON ts.thread_id = t.id
    JOIN users u ON u.id = t.created_by
    LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
    JOIN messages m ON m.id = t.parent_message_id
    WHERE t.channel_id = ?
      AND (? = 1 OR COALESCE(ts.archived, 0) = 0)
    ORDER BY COALESCE(ts.last_message_at, t.created_at) DESC
  `).all(channelId, showArchived);

  const result = rows.map((r) => {
    const [decrypted] = decryptMessageRows([{ content: r.preview_content }]);
    let body_attachments = [];
    if (r.body_attachments_raw) {
      try { body_attachments = JSON.parse(r.body_attachments_raw); } catch { body_attachments = []; }
    }
    const { body_attachments_raw, ...rest } = r;
    return {
      ...rest,
      preview_content: (decrypted?.content ?? r.preview_content ?? '').slice(0, 1000),
      body_attachments,
    };
  });

  res.json(result);
});

// POST /api/threads
router.post('/', (req, res) => {
  const { channelId, messageId, name, coverImage } = req.body ?? {};
  if (!channelId || !messageId) return res.status(400).json({ error: 'channelId and messageId required' });
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }

  const channel = db.prepare('SELECT type FROM channels WHERE id = ?').get(channelId);
  const canPost = channel?.type === 'forum'
    ? hasPermission(req.user, PERMISSIONS.CREATE_POST_IN_FORUMS) || hasPermission(req.user, PERMISSIONS.CREATE_THREADS)
    : hasPermission(req.user, PERMISSIONS.CREATE_THREADS);
  if (!canPost) return res.status(403).json({ error: 'Missing permission' });
  const msg = db.prepare('SELECT id, channel_id FROM messages WHERE id = ?').get(messageId);
  if (!msg || msg.channel_id !== channelId) {
    return res.status(400).json({ error: 'Message not in channel' });
  }

  // Check thread creation cooldown
  const channelSettings = db.prepare('SELECT thread_creation_cooldown FROM channel_settings WHERE channel_id = ?').get(channelId);
  if (channelSettings && channelSettings.thread_creation_cooldown > 0) {
    const hasBypass = hasPermission(req.user, PERMISSIONS.CREATE_PRIVATE_THREADS);
    if (!hasBypass) {
      const lastThread = db.prepare(`
        SELECT created_at FROM threads
        WHERE channel_id = ? AND created_by = ?
        ORDER BY created_at DESC
        LIMIT 1
      `).get(channelId, req.user.id);
      if (lastThread) {
        const now = Math.floor(Date.now() / 1000);
        const timeSince = now - lastThread.created_at;
        if (timeSince < channelSettings.thread_creation_cooldown) {
          const remaining = channelSettings.thread_creation_cooldown - timeSince;
          return res.status(429).json({ error: `Please wait ${remaining}s before creating another thread` });
        }
      }
    }
  }

  const id = randomUUID();
  const threadName = (typeof name === 'string' && name.trim().length > 0) ? name.trim() : 'Thread';
  db.prepare('INSERT INTO threads (id, channel_id, parent_message_id, name, created_by) VALUES (?, ?, ?, ?, ?)')
    .run(id, channelId, messageId, threadName, req.user.id);

  // Initialize thread settings
  const safeCoverImage = (typeof coverImage === 'string' && /^(https?:\/\/|\/uploads\/|\/ugc\/)/.test(coverImage.trim()))
    ? coverImage.trim() : null;
  db.prepare(`
    INSERT INTO thread_settings (thread_id, last_message_at, cover_image)
    VALUES (?, unixepoch(), ?)
  `).run(id, safeCoverImage);

  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(id);
  res.status(201).json(thread);

  // Emit live forum post creation to all clients viewing this channel
  if (channel?.type === 'forum') {
    try {
      const author = db.prepare(`
        SELECT u.username, u.avatar, u.account_type,
          COALESCE(dno.display_name, u.display_name) AS display_name
        FROM users u
        LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
        WHERE u.id = ?
      `).get(req.user.id);
      const parentMsg = db.prepare('SELECT content, attachments FROM messages WHERE id = ?').get(messageId);
      const [decrypted] = decryptMessageRows([{ content: parentMsg?.content ?? '' }]);
      let body_attachments = [];
      if (parentMsg?.attachments) {
        try { body_attachments = JSON.parse(parentMsg.attachments); } catch { body_attachments = []; }
      }
      const forumPost = {
        id,
        channel_id: channelId,
        parent_message_id: messageId,
        name: threadName,
        created_by: req.user.id,
        created_at: thread.created_at,
        archived: null,
        last_message_at: null,
        cover_image: safeCoverImage,
        author_username: author?.username ?? '',
        author_avatar: author?.avatar ?? null,
        author_account_type: author?.account_type ?? 'local',
        author_display_name: author?.display_name ?? null,
        preview_content: (decrypted?.content ?? '').slice(0, 1000),
        reply_count: 0,
        body_attachments,
      };
      emitToChannel(channelId, 'forum:created', forumPost);
    } catch { /* non-critical */ }
  }
});

// PATCH /api/threads/:id
router.patch('/:id', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.CREATE_THREADS)) {
    return res.status(403).json({ error: 'Missing permission: create_threads' });
  }
  const { name } = req.body ?? {};
  if (typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: 'Thread name required' });
  }
  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(req.params.id);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  db.prepare('UPDATE threads SET name = ? WHERE id = ?').run(name.trim(), req.params.id);
  const updated = db.prepare('SELECT * FROM threads WHERE id = ?').get(req.params.id);
  res.json(updated);
});

// DELETE /api/threads/:id
router.delete('/:id', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.CREATE_THREADS)) {
    return res.status(403).json({ error: 'Missing permission: create_threads' });
  }
  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(req.params.id);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  db.prepare('DELETE FROM threads WHERE id = ?').run(req.params.id);
  res.json({ success: true });
  emitToChannel(thread.channel_id, 'forum:deleted', { id: req.params.id, channel_id: thread.channel_id });
});

// GET /api/threads/:id/messages
router.get('/:id/messages', (req, res) => {
  const { id } = req.params;
  const before = req.query.before ? parseInt(req.query.before) : null;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(id);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!hasChannelPermission(req.user, thread.channel_id, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  if (!hasChannelPermission(req.user, thread.channel_id, PERMISSIONS.READ_CHAT_HISTORY, db)) {
    return res.status(403).json({ error: 'Missing permission: read_chat_history' });
  }

  let messages;
  if (before) {
    messages = db.prepare(`
      SELECT m.*, u.username, u.avatar, u.is_owner,
        COALESCE(dno.display_name, u.display_name) as display_name,
        (SELECT r.color FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY r.position DESC
         LIMIT 1) AS role_color,
        rm.id as reply_to_msg_id,
        rm.user_id as reply_to_user_id,
        rm.content as reply_to_content,
        ru.username as reply_to_username
      FROM messages m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
      LEFT JOIN messages rm ON rm.id = m.reply_to_id
      LEFT JOIN users ru ON ru.id = rm.user_id
      WHERE m.thread_id = ? AND m.created_at < ?
      ORDER BY m.created_at DESC LIMIT ?
    `).all(id, before, limit);
  } else {
    messages = db.prepare(`
      SELECT m.*, u.username, u.avatar, u.is_owner,
        COALESCE(dno.display_name, u.display_name) as display_name,
        (SELECT r.color FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY r.position DESC
         LIMIT 1) AS role_color,
        rm.id as reply_to_msg_id,
        rm.user_id as reply_to_user_id,
        rm.content as reply_to_content,
        ru.username as reply_to_username
      FROM messages m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
      LEFT JOIN messages rm ON rm.id = m.reply_to_id
      LEFT JOIN users ru ON ru.id = rm.user_id
      WHERE m.thread_id = ?
      ORDER BY m.created_at DESC LIMIT ?
    `).all(id, limit);
  }

  messages = decryptMessageRows(messages);

  // Transform reply metadata
  messages = messages.map(m => ({
    ...m,
    reply_to: m.reply_to_msg_id ? {
      id: m.reply_to_msg_id,
      user_id: m.reply_to_user_id,
      content: m.reply_to_content,
      username: m.reply_to_username,
    } : null
  }));
  messages = attachNsfwTags(messages);

  // Normalize attachments: parse JSON column or build from legacy single-attachment fields
  messages = messages.map((m) => {
    let attachments = null;
    if (m.attachments) {
      try { attachments = JSON.parse(m.attachments); } catch { attachments = null; }
    }
    if (!attachments && m.attachment_url) {
      attachments = [{ url: m.attachment_url, mime: m.attachment_type, size: m.attachment_size }];
    }
    return { ...m, attachments: attachments ?? [] };
  });

  res.json(messages.reverse());
});

// POST /api/threads/:id/archive - Manually archive thread
router.post('/:id/archive', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_POSTS)) {
    return res.status(403).json({ error: 'Missing permission: manage_posts' });
  }
  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(req.params.id);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  db.prepare(`
    INSERT INTO thread_settings (thread_id, archived, last_message_at)
    VALUES (?, 1, unixepoch())
    ON CONFLICT(thread_id)
    DO UPDATE SET archived = 1
  `).run(req.params.id);

  res.json({ success: true, archived: true });
});

// POST /api/threads/:id/unarchive - Unarchive thread
router.post('/:id/unarchive', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_POSTS)) {
    return res.status(403).json({ error: 'Missing permission: manage_posts' });
  }
  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(req.params.id);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

  db.prepare(`
    INSERT INTO thread_settings (thread_id, archived, archive_at, last_message_at)
    VALUES (?, 0, NULL, unixepoch())
    ON CONFLICT(thread_id)
    DO UPDATE SET archived = 0, archive_at = NULL
  `).run(req.params.id);

  res.json({ success: true, archived: false });
});

module.exports = router;
