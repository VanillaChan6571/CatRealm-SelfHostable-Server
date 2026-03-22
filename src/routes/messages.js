const router = require('express').Router();
const { randomUUID } = require('crypto');
const db = require('../db');
const { PERMISSIONS, hasChannelPermission } = require('../permissions');
const { decryptMessageRows, isSecureModeEnabled, encryptMessageContent } = require('../messageCrypto');

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
        (SELECT r.icon FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY r.position DESC
         LIMIT 1) AS role_icon,
        (SELECT r.style_type FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY r.position DESC
         LIMIT 1) AS role_style_type,
        (SELECT r.style_colors FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY r.position DESC
         LIMIT 1) AS role_style_colors,
        rm.id as reply_to_msg_id,
        rm.user_id as reply_to_user_id,
        rm.content as reply_to_content,
        ru.username as reply_to_username
      FROM messages m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
      LEFT JOIN messages rm ON rm.id = m.reply_to_id
      LEFT JOIN users ru ON ru.id = rm.user_id
      WHERE m.channel_id = ? AND m.thread_id IS NULL AND m.created_at < ? AND (m.scheduled_at IS NULL OR m.user_id = ?)
      ORDER BY m.created_at DESC LIMIT ?
    `).all(channelId, before, req.user.id, limit);
  } else {
    messages = db.prepare(`
      SELECT m.*, u.username, u.avatar, u.is_owner,
        COALESCE(dno.display_name, u.display_name) as display_name,
        (SELECT r.color FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY r.position DESC
         LIMIT 1) AS role_color,
        (SELECT r.icon FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY r.position DESC
         LIMIT 1) AS role_icon,
        (SELECT r.style_type FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY r.position DESC
         LIMIT 1) AS role_style_type,
        (SELECT r.style_colors FROM roles r
         JOIN user_roles ur ON ur.role_id = r.id
         WHERE ur.user_id = u.id
         ORDER BY r.position DESC
         LIMIT 1) AS role_style_colors,
        rm.id as reply_to_msg_id,
        rm.user_id as reply_to_user_id,
        rm.content as reply_to_content,
        ru.username as reply_to_username
      FROM messages m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
      LEFT JOIN messages rm ON rm.id = m.reply_to_id
      LEFT JOIN users ru ON ru.id = rm.user_id
      WHERE m.channel_id = ? AND m.thread_id IS NULL AND (m.scheduled_at IS NULL OR m.user_id = ?)
      ORDER BY m.created_at DESC LIMIT ?
    `).all(channelId, req.user.id, limit);
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

  res.json(messages.reverse()); // Return oldest-first
});

// POST /api/messages/forum - Create a forum post body message, returns it with id
router.post('/forum', (req, res) => {
  const { channelId, content, attachments } = req.body ?? {};
  if (!channelId || typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'channelId and content required' });
  }
  const channel = db.prepare('SELECT id, type FROM channels WHERE id = ?').get(channelId);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  if (channel.type !== 'forum') return res.status(400).json({ error: 'Channel is not a forum' });
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.SEND_MESSAGES, db)) {
    return res.status(403).json({ error: 'Missing permission: send_messages' });
  }

  const id = randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const stored = encryptMessageContent(content.trim());
  const attachmentsJson = Array.isArray(attachments) && attachments.length > 0
    ? JSON.stringify(attachments.map((a) => ({ url: a.url, mime: a.mime ?? null, size: a.size ?? null })))
    : null;
  db.prepare('INSERT INTO messages (id, channel_id, user_id, content, attachments, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, channelId, req.user.id, stored, attachmentsJson, now);

  const msg = db.prepare(`
    SELECT m.*, u.username, u.avatar, u.account_type,
      COALESCE(dno.display_name, u.display_name) AS display_name
    FROM messages m
    JOIN users u ON u.id = m.user_id
    LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
    WHERE m.id = ?
  `).get(id);

  const [decrypted] = decryptMessageRows([msg]);
  let parsedAttachments = [];
  if (decrypted.attachments) {
    try { parsedAttachments = JSON.parse(decrypted.attachments); } catch { parsedAttachments = []; }
  }
  res.status(201).json({ ...decrypted, attachments: parsedAttachments });
});

const SEARCH_SELECT = `
  SELECT m.id, m.content, m.created_at, m.user_id,
    u.username, u.avatar,
    COALESCE(dno.display_name, u.display_name) as display_name,
    (SELECT r.color FROM roles r
     JOIN user_roles ur ON ur.role_id = r.id
     WHERE ur.user_id = u.id
     ORDER BY r.position DESC LIMIT 1) AS role_color,
    (SELECT r.icon FROM roles r
     JOIN user_roles ur ON ur.role_id = r.id
     WHERE ur.user_id = u.id
     ORDER BY r.position DESC LIMIT 1) AS role_icon,
    (SELECT r.style_type FROM roles r
     JOIN user_roles ur ON ur.role_id = r.id
     WHERE ur.user_id = u.id
     ORDER BY r.position DESC LIMIT 1) AS role_style_type,
    (SELECT r.style_colors FROM roles r
     JOIN user_roles ur ON ur.role_id = r.id
     WHERE ur.user_id = u.id
     ORDER BY r.position DESC LIMIT 1) AS role_style_colors
  FROM messages m
  JOIN users u ON u.id = m.user_id
  LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
`;

/**
 * Regex that matches emote/sticker expression tokens so they can be stripped
 * before checking for real URLs in content.
 * Mirrors the client-side MESSAGE_TOKEN_REGEX from messageTokenParser.ts.
 */
const EXPRESSION_TOKEN_RE = /\[\[(emote|sticker):[^|\]]+\|[^\]]+\]\]|:(https?:\/\/[^\s:]+(?::\d{1,5})?):(?:sticker:)?[a-z0-9_-]{1,64}(?::[a-z0-9_-]{3,128})?:|:(?:sticker:)?[a-z0-9_-]{1,64}(?::[a-z0-9_-]{3,128})?:/gi;

function stripExpressionTokens(content) {
  return content.replace(EXPRESSION_TOKEN_RE, ' ');
}

/** Split comma-separated query param into trimmed non-empty strings. */
function parseCsvParam(val) {
  if (!val) return [];
  return String(val).split(',').map((s) => s.trim()).filter(Boolean);
}

/**
 * Build extra SQL conditions + params from filter query params.
 * These conditions do NOT depend on decrypted content and are safe to use
 * in both plain and secure modes.
 */
function buildSqlFilters(query) {
  const fromUsers  = parseCsvParam(query.from);
  const hasTypes   = parseCsvParam(query.has);
  const dateAfter  = query.date_after  ? parseInt(query.date_after)  : null;
  const dateBefore = query.date_before ? parseInt(query.date_before) : null;

  const conds  = [];
  const params = [];

  // from: match username or display_name (case-insensitive)
  if (fromUsers.length > 0) {
    const parts = fromUsers.map(() =>
      `(LOWER(u.username) = LOWER(?) OR LOWER(COALESCE(dno.display_name, u.display_name)) = LOWER(?))`
    ).join(' OR ');
    conds.push(`(${parts})`);
    fromUsers.forEach((u) => params.push(u, u));
  }

  // has: attachment/content-type conditions (content-independent)
  for (const type of hasTypes) {
    if (type === 'image') {
      conds.push(`(m.attachments LIKE '%"image/%' OR m.attachment_type LIKE 'image/%')`);
    } else if (type === 'video') {
      conds.push(`(m.attachments LIKE '%"video/%' OR m.attachment_type LIKE 'video/%')`);
    } else if (type === 'file') {
      conds.push(`(m.attachment_url IS NOT NULL OR (m.attachments IS NOT NULL AND m.attachments NOT IN ('', '[]')))`);
    } else if (type === 'forward') {
      conds.push(`m.forward_from_id IS NOT NULL`);
    }
    // link / embed / sticker: content-dependent, handled in JS below
  }

  // date bounds
  if (dateAfter !== null && !isNaN(dateAfter)) {
    conds.push(`m.created_at >= ?`);
    params.push(dateAfter);
  }
  if (dateBefore !== null && !isNaN(dateBefore)) {
    conds.push(`m.created_at <= ?`);
    params.push(dateBefore);
  }

  const sql = conds.length > 0 ? ' AND ' + conds.join(' AND ') : '';
  return { sql, params };
}

/**
 * Build a JS post-filter function for content-dependent conditions
 * (text query, mentions, link/embed detection).
 */
function buildJsFilter(q, query) {
  const mentionUsers = parseCsvParam(query.mentions);
  const hasTypes     = parseCsvParam(query.has);
  const hasLink      = hasTypes.includes('link') || hasTypes.includes('embed');
  const qLower       = q ? q.toLowerCase() : null;

  return function jsFilter(row) {
    const content = (row.content || '').toLowerCase();
    if (qLower && !content.includes(qLower)) return false;
    if (mentionUsers.length > 0 && !mentionUsers.some((u) => content.includes('@' + u.toLowerCase()))) return false;
    if (hasLink && !/https?:\/\//.test(stripExpressionTokens(row.content || ''))) return false;
    return true;
  };
}

// GET /api/messages/:channelId/search?q=<query>&before=<unix_seconds>&limit=25
//   Additional filter params:
//   from=user1,user2  — sender username(s)
//   has=image,video,file,link,embed,forward  — content type(s)
//   mentions=user1,user2  — @mentioned username(s)
//   date_after=<unix_seconds>  — messages after this time
//   date_before=<unix_seconds> — messages before this time (filter, distinct from pagination `before`)
router.get('/:channelId/search', (req, res) => {
  const { channelId } = req.params;
  const q = (req.query.q || '').trim();
  const limit = Math.min(parseInt(req.query.limit) || 25, 50);
  const before = req.query.before ? parseInt(req.query.before) : null; // pagination cursor

  // Require at least a text query or one active filter
  const mentionUsers  = parseCsvParam(req.query.mentions);
  const hasTypes      = parseCsvParam(req.query.has);
  const fromUsers     = parseCsvParam(req.query.from);
  const hasDateFilter = !!(req.query.date_after || req.query.date_before);
  const hasAnyFilter  = q || fromUsers.length || hasTypes.length || mentionUsers.length || hasDateFilter;
  if (!hasAnyFilter) return res.json({ results: [], hasMore: false });

  const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(channelId);
  if (!channel) return res.status(404).json({ error: 'Channel not found' });
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.READ_CHAT_HISTORY, db)) {
    return res.status(403).json({ error: 'Missing permission: read_chat_history' });
  }

  const WHERE_BASE  = `WHERE m.channel_id = ? AND m.thread_id IS NULL AND (m.message_type IS NULL OR m.message_type = 'user')`;
  const ORDER_LIMIT = `ORDER BY m.created_at DESC LIMIT ?`;

  const { sql: filterSql, params: filterParams } = buildSqlFilters(req.query);
  const jsFilter = buildJsFilter(q, req.query);

  if (!isSecureModeEnabled()) {
    // Non-secure: apply all conditions in SQL
    let contentSql = '';
    const contentParams = [];

    if (q) {
      const like = `%${q.replace(/([%_\\])/g, '\\$&')}%`;
      contentSql += ` AND m.content LIKE ? ESCAPE '\\'`;
      contentParams.push(like);
    }
    if (mentionUsers.length > 0) {
      const parts = mentionUsers.map(() => `m.content LIKE ?`).join(' OR ');
      contentSql += ` AND (${parts})`;
      mentionUsers.forEach((u) => contentParams.push(`%@${u}%`));
    }
    // link/embed: handled in jsFilter after token stripping (avoids false positives from emote URLs)

    const paginationSql    = before ? ` AND m.created_at < ?` : '';
    const paginationParams = before ? [before] : [];

    const needsJsFilter = hasTypes.includes('link') || hasTypes.includes('embed');
    const fetchLimit = needsJsFilter ? limit * 3 + 1 : limit + 1;

    const fullSql = `${SEARCH_SELECT} ${WHERE_BASE}${filterSql}${contentSql}${paginationSql} ${ORDER_LIMIT}`;
    const allParams = [channelId, ...filterParams, ...contentParams, ...paginationParams, fetchLimit];
    const rows = db.prepare(fullSql).all(...allParams);
    const decrypted = decryptMessageRows(rows);

    if (needsJsFilter) {
      const filtered = decrypted.filter(jsFilter);
      const hasMore = filtered.length > limit;
      if (hasMore) filtered.pop();
      return res.json({ results: filtered, hasMore });
    }

    const hasMore = decrypted.length > limit;
    if (hasMore) decrypted.pop();
    return res.json({ results: decrypted, hasMore });
  }

  // Secure mode: SQL for non-content filters, then decrypt + JS filter
  const BATCH = 100;
  const found = [];
  let cursor = before;
  let exhausted = false;

  while (!exhausted && found.length <= limit) {
    const paginationSql    = cursor ? ` AND m.created_at < ?` : '';
    const paginationParams = cursor ? [cursor] : [];
    const batchSql = `${SEARCH_SELECT} ${WHERE_BASE}${filterSql}${paginationSql} ${ORDER_LIMIT}`;
    const batchParams = [channelId, ...filterParams, ...paginationParams, BATCH];
    const batch = db.prepare(batchSql).all(...batchParams);

    if (batch.length === 0) { exhausted = true; break; }
    if (batch.length < BATCH) exhausted = true;

    for (const row of decryptMessageRows(batch)) {
      if (jsFilter(row)) {
        found.push(row);
        if (found.length > limit) break;
      }
    }
    cursor = batch[batch.length - 1].created_at;
  }

  const hasMore = found.length > limit;
  if (hasMore) found.pop();
  return res.json({ results: found, hasMore });
});

module.exports = router;
