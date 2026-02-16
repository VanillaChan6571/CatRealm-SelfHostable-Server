const router = require('express').Router();
const { randomUUID } = require('crypto');
const db = require('../db');
const { PERMISSIONS, hasPermission } = require('../permissions');
const { decryptMessageRows } = require('../messageCrypto');

// GET /api/threads?channelId=...
router.get('/', (req, res) => {
  const { channelId } = req.query;
  if (!channelId) return res.status(400).json({ error: 'channelId required' });
  const threads = db.prepare('SELECT * FROM threads WHERE channel_id = ? ORDER BY created_at DESC').all(channelId);
  res.json(threads);
});

// POST /api/threads
router.post('/', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.CREATE_THREADS)) {
    return res.status(403).json({ error: 'Missing permission: create_threads' });
  }
  const { channelId, messageId, name } = req.body ?? {};
  if (!channelId || !messageId) return res.status(400).json({ error: 'channelId and messageId required' });
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
  db.prepare(`
    INSERT INTO thread_settings (thread_id, last_message_at)
    VALUES (?, unixepoch())
  `).run(id);

  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(id);
  res.status(201).json(thread);
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
});

// GET /api/threads/:id/messages
router.get('/:id/messages', (req, res) => {
  const { id } = req.params;
  const before = req.query.before ? parseInt(req.query.before) : null;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const thread = db.prepare('SELECT * FROM threads WHERE id = ?').get(id);
  if (!thread) return res.status(404).json({ error: 'Thread not found' });

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
