const router = require('express').Router();
const db = require('../db');
const { PERMISSIONS, hasChannelPermission } = require('../permissions');
const { decryptMessageRows } = require('../messageCrypto');

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

// GET /api/messages/:channelId?before=<timestamp>&limit=50
router.get('/:channelId', (req, res) => {
  const { channelId } = req.params;
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  const before = req.query.before ? parseInt(req.query.before) : null;

  const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(channelId);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.READ_CHAT_HISTORY, db)) {
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
      WHERE m.channel_id = ? AND m.thread_id IS NULL AND m.created_at < ?
      ORDER BY m.created_at DESC LIMIT ?
    `).all(channelId, before, limit);
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
      WHERE m.channel_id = ? AND m.thread_id IS NULL
      ORDER BY m.created_at DESC LIMIT ?
    `).all(channelId, limit);
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

  res.json(messages.reverse()); // Return oldest-first
});

module.exports = router;
