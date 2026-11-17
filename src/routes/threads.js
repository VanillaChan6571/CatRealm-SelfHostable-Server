const router = require('express').Router();
const { randomUUID } = require('crypto');
const db = require('../db');
const { PERMISSIONS, hasPermission, hasChannelPermission } = require('../permissions');
const { decryptMessageRows, encryptMessageContent } = require('../messageCrypto');
const { attachSafetyArtifacts } = require('../safety');
const { attachReactionsToMessages } = require('../reactions');
const { emitToChannel, emitToChannelEach, emitMessage, messageAuthorFields, relayMentions } = require('../socket/handler');
const { queueMessageCreatedEvent } = require('../webhooks');
const { recordThreadActivity } = require('../threadActivity');
const { channelPolicy, isThreadHidden } = require('../channelPolicy');

const THREAD_NAME_MAX = 100;
const MESSAGE_MAX = 2000;

function canManageThread(user, thread) {
  return hasChannelPermission(user, thread.channel_id, PERMISSIONS.VIEW_CHANNELS, db)
    && hasChannelPermission(user, thread.channel_id, PERMISSIONS.READ_CHAT_HISTORY, db)
    && (thread.created_by === user.id
      || hasChannelPermission(user, thread.channel_id, PERMISSIONS.MANAGE_POSTS, db));
}

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
  const rows = db.prepare(`
    SELECT t.*, (SELECT COUNT(*) FROM messages m WHERE m.thread_id = t.id) AS reply_count,
      COALESCE(ts.last_message_at, t.created_at) AS last_activity_at, ts.auto_hide_minutes
    FROM threads t LEFT JOIN thread_settings ts ON ts.thread_id = t.id
    WHERE t.channel_id = ? ORDER BY t.created_at DESC
  `).all(channelId);
  // Auto-hide: a thread that has been quiet for longer than its setting leaves the list
  // (and comes back when someone writes in it). Staff can ask for them with includeHidden=1.
  const autoHideMinutes = channelPolicy(db, channelId)?.effective.threadAutoHideMinutes ?? 0;
  const threads = rows.map(({ last_activity_at, auto_hide_minutes, ...thread }) => ({
    ...thread,
    last_message_at: last_activity_at,
    hidden: isThreadHidden(last_activity_at, auto_hide_minutes ?? autoHideMinutes),
  }));
  // A thread nobody has written in is only listed for its creator and for staff, so
  // abandoned empty threads do not pile up in everyone's channel list. Forum posts are
  // listed by /forum and always show.
  const channel = db.prepare('SELECT type FROM channels WHERE id = ?').get(channelId);
  if (channel?.type === 'forum') return res.json(threads.map((thread) => ({ ...thread, hidden: false })));
  const canManage = hasChannelPermission(req.user, channelId, PERMISSIONS.MANAGE_POSTS, db);
  const includeHidden = canManage && req.query.includeHidden === '1';
  res.json(threads.filter((thread) => (includeHidden || !thread.hidden)
    && (thread.reply_count > 0 || canManage || thread.created_by === req.user.id)));
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
  const { channelId, messageId, name, coverImage, firstMessage } = req.body ?? {};
  if (!channelId || !messageId) return res.status(400).json({ error: 'channelId and messageId required' });
  // Optional opening message, posted into the new thread by its creator.
  const opening = typeof firstMessage === 'string' ? firstMessage.trim() : '';
  if (opening.length > MESSAGE_MAX) return res.status(400).json({ error: `Message too long (max ${MESSAGE_MAX} chars)` });
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }

  const channel = db.prepare('SELECT type FROM channels WHERE id = ?').get(channelId);
  const canPost = channel?.type === 'forum'
    ? hasPermission(req.user, PERMISSIONS.CREATE_POST_IN_FORUMS) || hasPermission(req.user, PERMISSIONS.CREATE_THREADS)
    : hasPermission(req.user, PERMISSIONS.CREATE_THREADS);
  if (!canPost) return res.status(403).json({ error: 'Missing permission' });
  if (opening && channel?.type !== 'forum'
    && !hasChannelPermission(req.user, channelId, PERMISSIONS.SEND_MESSAGES_IN_THREADS, db)) {
    return res.status(403).json({ error: 'Missing permission: send_messages_in_threads' });
  }
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
  const threadName = (typeof name === 'string' && name.trim().length > 0) ? name.trim().slice(0, THREAD_NAME_MAX) : 'Thread';
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

  // Threads in ordinary channels: post the opening message, announce the thread in the
  // channel, and tell connected clients so it appears in their lists straight away.
  if (channel?.type !== 'forum') {
    const now = Math.floor(Date.now() / 1000);
    let replyCount = 0;
    if (opening) {
      const openingId = randomUUID();
      db.prepare(`
        INSERT INTO messages (id, channel_id, user_id, content, created_at, message_type, thread_id)
        VALUES (?, ?, ?, ?, ?, 'user', ?)
      `).run(openingId, channelId, req.user.id, encryptMessageContent(opening), now, id);
      replyCount = 1;
      // Same shape and side effects as a message sent over the socket: author styling,
      // webhook and bot delivery, and mention notifications.
      const openingMessage = {
        id: openingId, channel_id: channelId, thread_id: id, user_id: req.user.id, username: req.user.username,
        content: opening, edited: 0, is_owner: req.user.is_owner ? 1 : 0, ...messageAuthorFields(req.user.id),
        message_type: 'user', created_at: now, attachments: [], nsfw_tags: [],
      };
      emitToChannel(`thread:${id}`, 'message:new', openingMessage);
      queueMessageCreatedEvent(openingMessage);
      relayMentions({
        authorId: req.user.id, authorUsername: req.user.username, authorAvatar: openingMessage.avatar,
        bot: req.user.is_bot ? req.bot : null,
        channelId, messageId: openingId, createdAt: now, content: opening,
      });
      try {
        const activity = recordThreadActivity(db, openingMessage);
        if (activity) emitToChannel(channelId, 'thread:activity', activity);
      } catch { /* non-critical */ }
    }

    if (replyCount > 0) {
      const announcementId = randomUUID();
      const announcement = `🧶 ${req.user.username} made a thread called ${threadName}`;
      // attachment_url carries the message the thread grew from, as pin notices do, so older
      // clients can jump to it. attachment_type names the thread, so newer ones can open it.
      const threadRef = `thread:${id}`;
      db.prepare(`
        INSERT INTO messages (id, channel_id, user_id, content, created_at, message_type, attachment_url, attachment_type)
        VALUES (?, ?, ?, ?, ?, 'system', ?, ?)
      `).run(announcementId, channelId, req.user.id, encryptMessageContent(announcement), now, messageId, threadRef);
      emitMessage(channelId, {
        id: announcementId, channel_id: channelId, user_id: req.user.id, username: req.user.username,
        content: announcement, edited: 0, is_owner: req.user.is_owner ? 1 : 0, role_color: null,
        message_type: 'system', attachment_url: messageId, attachment_type: threadRef, created_at: now,
      });
    }
    // An empty thread is only listed for its creator and staff (see GET /), so only they
    // hear about it. Everyone else learns of it from thread:activity once someone writes.
    const created = { ...thread, reply_count: replyCount };
    if (replyCount > 0) emitToChannel(channelId, 'thread:created', created);
    else {
      emitToChannelEach(channelId, 'thread:created', (user) => (user.id === req.user.id
        || hasChannelPermission(user, channelId, PERMISSIONS.MANAGE_POSTS, db) ? created : null));
    }
    return res.status(201).json({ ...thread, reply_count: replyCount });
  }

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

// GET /api/threads/:id — one thread, including one that has auto-hidden from the list,
// so a link to it (such as its announcement) still opens it.
router.get('/:id', (req, res) => {
  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(req.params.id);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!hasChannelPermission(req.user, thread.channel_id, PERMISSIONS.VIEW_CHANNELS, db)
    || !hasChannelPermission(req.user, thread.channel_id, PERMISSIONS.READ_CHAT_HISTORY, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  res.json(thread);
});

// PATCH /api/threads/:id
router.patch('/:id', (req, res) => {
  const { name } = req.body ?? {};
  if (typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: 'Thread name required' });
  }
  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(req.params.id);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!canManageThread(req.user, thread)) return res.status(403).json({ error: 'Not allowed to manage this thread' });
  db.prepare('UPDATE threads SET name = ? WHERE id = ?').run(name.trim().slice(0, THREAD_NAME_MAX), req.params.id);
  const updated = db.prepare('SELECT * FROM threads WHERE id = ?').get(req.params.id);
  res.json(updated);
  const replyCount = db.prepare('SELECT COUNT(*) AS count FROM messages WHERE thread_id = ?').get(updated.id).count;
  if (replyCount > 0) emitToChannel(updated.channel_id, 'thread:updated', updated);
  else {
    emitToChannelEach(updated.channel_id, 'thread:updated', (user) => (user.id === updated.created_by
      || hasChannelPermission(user, updated.channel_id, PERMISSIONS.MANAGE_POSTS, db) ? updated : null));
  }
});

// DELETE /api/threads/:id
router.delete('/:id', (req, res) => {
  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(req.params.id);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });
  if (!canManageThread(req.user, thread)) return res.status(403).json({ error: 'Not allowed to manage this thread' });
  db.prepare('DELETE FROM threads WHERE id = ?').run(req.params.id);
  res.json({ success: true });
  emitToChannel(thread.channel_id, 'forum:deleted', { id: req.params.id, channel_id: thread.channel_id });
  emitToChannel(thread.channel_id, 'thread:deleted', { id: req.params.id, channel_id: thread.channel_id });
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
      SELECT m.*, u.username, u.avatar, u.is_owner, u.is_bot,
        COALESCE(dno.display_name, u.display_name) as display_name,
        (SELECT r.color FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY (COALESCE(r.color, '') != '') DESC, r.position DESC
         LIMIT 1) AS role_color,
        (SELECT r.style_type FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY (COALESCE(r.color, '') != '') DESC, r.position DESC
         LIMIT 1) AS role_style_type,
        (SELECT r.style_colors FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY (COALESCE(r.color, '') != '') DESC, r.position DESC
         LIMIT 1) AS role_style_colors,
        rm.id as reply_to_msg_id,
        rm.user_id as reply_to_user_id,
        rm.content as reply_to_content,
        ru.username as reply_to_username
      FROM messages m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
      LEFT JOIN messages rm ON rm.id = m.reply_to_id AND rm.channel_id = m.channel_id AND rm.scheduled_at IS NULL
      LEFT JOIN users ru ON ru.id = rm.user_id
      WHERE m.thread_id = ? AND m.created_at < ?
      ORDER BY m.created_at DESC LIMIT ?
    `).all(id, before, limit);
  } else {
    messages = db.prepare(`
      SELECT m.*, u.username, u.avatar, u.is_owner, u.is_bot,
        COALESCE(dno.display_name, u.display_name) as display_name,
        (SELECT r.color FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY (COALESCE(r.color, '') != '') DESC, r.position DESC
         LIMIT 1) AS role_color,
        (SELECT r.style_type FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY (COALESCE(r.color, '') != '') DESC, r.position DESC
         LIMIT 1) AS role_style_type,
        (SELECT r.style_colors FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY (COALESCE(r.color, '') != '') DESC, r.position DESC
         LIMIT 1) AS role_style_colors,
        rm.id as reply_to_msg_id,
        rm.user_id as reply_to_user_id,
        rm.content as reply_to_content,
        ru.username as reply_to_username
      FROM messages m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
      LEFT JOIN messages rm ON rm.id = m.reply_to_id AND rm.channel_id = m.channel_id AND rm.scheduled_at IS NULL
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

  messages = attachReactionsToMessages(messages);

  res.json(attachSafetyArtifacts(messages.reverse(), req.user.id));
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
