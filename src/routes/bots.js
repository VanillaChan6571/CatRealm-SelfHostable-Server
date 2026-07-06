const router = require('express').Router();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { randomUUID } = require('crypto');
const db = require('../db');
const { PERMISSIONS, hasPermission } = require('../permissions');
const { AUDIT_ACTIONS, logAuditAction } = require('../lib/auditLog');
const { encryptMessageContent, decryptMessageContent } = require('../messageCrypto');
const { getSetting } = require('../settings');
const {
  validateBotUsername,
  createBotAccount,
  rotateBotToken,
  getBotById,
  serializeBot,
} = require('../bots/core');
const {
  ALL_BOT_SCOPES,
  normalizeRequestedScopes,
  getBotConsent,
  saveBotConsent,
  parseJsonSafe,
} = require('../bots/scopes');
const {
  disconnectUserSockets,
  emitBotCommandsUpdated,
  updateOnlineUserAvatar,
  updateOnlineUserDisplayName,
} = require('../socket/handler');
const { getPluginStatuses, approvePluginInstall } = require('../bots/pluginManager');

function requirePermission(permission) {
  return (req, res, next) => {
    if (!hasPermission(req.user, permission)) {
      return res.status(403).json({ error: 'Missing permission' });
    }
    next();
  };
}

function requireBot(req, res, next) {
  if (!req.bot) return res.status(403).json({ error: 'Bot token required' });
  next();
}

const COMMAND_NAME_RE = /^[a-z0-9_-]{1,32}$/;
const COMMAND_OPTION_TYPES = ['string', 'user', 'channel', 'integer', 'boolean'];
const MAX_COMMANDS_PER_BOT = 50;

// ── Uploads (admin sets the bot's avatar/banner) ─────────────────────────────
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, '../../data/uploads');
const AVATAR_DIR = path.join(UPLOADS_DIR, 'avatars');
const BANNER_DIR = path.join(UPLOADS_DIR, 'banners');
if (!fs.existsSync(AVATAR_DIR)) fs.mkdirSync(AVATAR_DIR, { recursive: true });
if (!fs.existsSync(BANNER_DIR)) fs.mkdirSync(BANNER_DIR, { recursive: true });

const MIME_TO_EXT = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/webp': '.webp',
  'image/gif': '.gif',
};

const botImageUpload = multer({
  storage: multer.diskStorage({
    destination: (req, _file, cb) => cb(null, req.uploadType === 'banner' ? BANNER_DIR : AVATAR_DIR),
    filename: (req, file, cb) => {
      const ext = MIME_TO_EXT[file.mimetype];
      if (!ext) return cb(new Error('Invalid file type'));
      const safeId = String(req.params.id).replace(/[^a-zA-Z0-9_-]/g, '');
      cb(null, `bot-${safeId}-${Date.now()}${ext}`);
    },
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!MIME_TO_EXT[file.mimetype]) return cb(new Error('Invalid file type'));
    cb(null, true);
  },
});

// ═══ Bot-facing (token auth) ══════════════════════════════════════════════════

// GET /api/bots/self — the bot introspects itself
router.get('/self', requireBot, (req, res) => {
  res.json(serializeBot(db, req.bot));
});

// PUT /api/bots/self/commands — full replace of the bot's command set
router.put('/self/commands', requireBot, (req, res) => {
  const commands = Array.isArray(req.body?.commands) ? req.body.commands : null;
  if (!commands) return res.status(400).json({ error: 'commands array required' });
  if (commands.length > MAX_COMMANDS_PER_BOT) {
    return res.status(400).json({ error: `Too many commands (max ${MAX_COMMANDS_PER_BOT})` });
  }

  const normalized = [];
  const seen = new Set();
  for (const cmd of commands) {
    const name = String(cmd?.name || '').toLowerCase().trim();
    if (!COMMAND_NAME_RE.test(name)) {
      return res.status(400).json({ error: `Invalid command name: ${name || '(empty)'}` });
    }
    if (seen.has(name)) return res.status(400).json({ error: `Duplicate command name: ${name}` });
    seen.add(name);
    const description = String(cmd?.description || '').slice(0, 200);
    const options = [];
    if (Array.isArray(cmd?.options)) {
      for (const opt of cmd.options.slice(0, 10)) {
        const optName = String(opt?.name || '').toLowerCase().trim();
        if (!COMMAND_NAME_RE.test(optName)) continue;
        options.push({
          name: optName,
          description: String(opt?.description || '').slice(0, 200),
          type: COMMAND_OPTION_TYPES.includes(opt?.type) ? opt.type : 'string',
          required: opt?.required === true,
        });
      }
    }
    normalized.push({ name, description, options });
  }

  const replaceCommands = db.transaction(() => {
    db.prepare('DELETE FROM bot_commands WHERE bot_id = ?').run(req.bot.id);
    const insert = db.prepare(`
      INSERT INTO bot_commands (id, bot_id, name, description, options, updated_at)
      VALUES (?, ?, ?, ?, ?, unixepoch())
    `);
    for (const cmd of normalized) {
      insert.run(randomUUID(), req.bot.id, cmd.name, cmd.description, JSON.stringify(cmd.options));
    }
  });
  replaceCommands();
  emitBotCommandsUpdated();
  res.json({ commands: normalized });
});

// ═══ User-facing (any authenticated member) ═══════════════════════════════════

// GET /api/bots/commands — all commands of enabled bots (composer typeahead)
router.get('/commands', (req, res) => {
  const rows = db.prepare(`
    SELECT bc.name, bc.description, bc.options, b.id as bot_id, b.user_id as bot_user_id,
      u.username, u.display_name, u.avatar
    FROM bot_commands bc
    JOIN bots b ON b.id = bc.bot_id
    JOIN users u ON u.id = b.user_id
    WHERE b.enabled = 1
    ORDER BY bc.name
  `).all();
  res.json({
    commands: rows.map((r) => ({
      botId: r.bot_id,
      botUserId: r.bot_user_id,
      botUsername: r.username,
      botDisplayName: r.display_name || null,
      botAvatar: r.avatar || null,
      name: r.name,
      description: r.description,
      options: parseJsonSafe(r.options, []),
    })),
  });
});

// ── Bot DMs ───────────────────────────────────────────────────────────────────

// GET /api/bots/dms — my conversations, newest first
router.get('/dms', (req, res) => {
  const rows = db.prepare(`
    SELECT b.id as bot_id, b.user_id as bot_user_id, u.username, u.display_name, u.avatar,
      (SELECT COUNT(*) FROM bot_dm_messages m WHERE m.bot_id = b.id AND m.user_id = ? AND m.sender = 'bot' AND m.read = 0) as unread,
      (SELECT MAX(created_at) FROM bot_dm_messages m WHERE m.bot_id = b.id AND m.user_id = ?) as last_message_at
    FROM bots b
    JOIN users u ON u.id = b.user_id
    WHERE EXISTS (SELECT 1 FROM bot_dm_messages m WHERE m.bot_id = b.id AND m.user_id = ?)
    ORDER BY last_message_at DESC
  `).all(req.user.id, req.user.id, req.user.id);
  res.json({
    conversations: rows.map((r) => ({
      botId: r.bot_id,
      botUserId: r.bot_user_id,
      username: r.username,
      displayName: r.display_name || null,
      avatar: r.avatar || null,
      unread: r.unread,
      lastMessageAt: r.last_message_at,
    })),
  });
});

// GET /api/bots/dms/:botId?before=&limit= — messages in one conversation
router.get('/dms/:botId', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
  const before = parseInt(req.query.before, 10) || null;
  const params = [req.params.botId, req.user.id];
  let sql = 'SELECT * FROM bot_dm_messages WHERE bot_id = ? AND user_id = ?';
  if (before) {
    sql += ' AND created_at < ?';
    params.push(before);
  }
  sql += ' ORDER BY created_at DESC LIMIT ?';
  params.push(limit + 1);
  const rows = db.prepare(sql).all(...params);
  const hasMore = rows.length > limit;
  const messages = rows.slice(0, limit).reverse().map((m) => ({
    id: m.id,
    botId: m.bot_id,
    sender: m.sender,
    content: decryptMessageContent(m.content),
    created_at: m.created_at,
    read: !!m.read,
  }));
  res.json({ messages, hasMore });
});

// POST /api/bots/dms/:botId/read — mark the conversation read
router.post('/dms/:botId/read', (req, res) => {
  db.prepare(`
    UPDATE bot_dm_messages SET read = 1
    WHERE bot_id = ? AND user_id = ? AND sender = 'bot' AND read = 0
  `).run(req.params.botId, req.user.id);
  res.json({ ok: true });
});

// ── Consent ───────────────────────────────────────────────────────────────────

// GET /api/bots/:id/consent — my consent state + the bot's requested scopes
router.get('/:id/consent', (req, res) => {
  const bot = getBotById(db, req.params.id);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  res.json({
    botId: bot.id,
    requestedScopes: parseJsonSafe(bot.requested_scopes, []),
    consent: getBotConsent(db, bot.id, req.user.id),
  });
});

// PUT /api/bots/:id/consent  { decision: 'allowed'|'denied', scopes: {scope: bool} }
router.put('/:id/consent', (req, res) => {
  if (req.user.is_bot) return res.status(403).json({ error: 'Bots cannot set consent' });
  const bot = getBotById(db, req.params.id);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  const decision = req.body?.decision === 'allowed' ? 'allowed' : 'denied';
  const requested = new Set(normalizeRequestedScopes(parseJsonSafe(bot.requested_scopes, [])));
  const scopes = {};
  for (const scope of ALL_BOT_SCOPES) {
    // Only scopes the bot actually requested can be granted.
    scopes[scope] = requested.has(scope) && req.body?.scopes?.[scope] === true;
  }
  const saved = saveBotConsent(db, bot.id, req.user.id, decision, scopes);
  res.json({ botId: bot.id, consent: saved });
});

// ═══ Admin (MANAGE_BOTS) ══════════════════════════════════════════════════════

// GET /api/bots — list all bots
router.get('/', requirePermission(PERMISSIONS.MANAGE_BOTS), (req, res) => {
  const { getOnlineUserIds } = require('../socket/handler');
  const online = typeof getOnlineUserIds === 'function' ? getOnlineUserIds() : null;
  const pluginStatuses = getPluginStatuses();
  const bots = db.prepare('SELECT * FROM bots ORDER BY created_at').all();
  res.json({
    bots: bots.map((b) => serializeBot(db, b, {
      onlineUserIds: online,
      pluginStatus: b.kind === 'plugin' ? (pluginStatuses.get(b.plugin_name) || 'stopped') : null,
    })),
  });
});

// POST /api/bots  { username, requestedScopes } — token shown only in this response
router.post('/', requirePermission(PERMISSIONS.MANAGE_BOTS), (req, res) => {
  const username = typeof req.body?.username === 'string' ? req.body.username.trim() : '';
  const usernameError = validateBotUsername(db, username);
  if (usernameError) return res.status(400).json({ error: usernameError });

  const { botId, userId, token } = createBotAccount(db, {
    username,
    requestedScopes: req.body?.requestedScopes,
    createdBy: req.user.id,
    kind: 'token',
  });

  logAuditAction(AUDIT_ACTIONS.BOT_CREATE, req.user.id, {
    targetType: 'bot',
    targetId: botId,
    details: { username, userId },
  });

  const bot = getBotById(db, botId);
  res.status(201).json({ bot: serializeBot(db, bot), token });
});

// POST /api/bots/:id/install — owner approves a plugin's npm install
router.post('/:id/install', requirePermission(PERMISSIONS.MANAGE_BOTS), (req, res) => {
  const bot = getBotById(db, req.params.id);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  if (bot.kind !== 'plugin' || !bot.plugin_name) {
    return res.status(400).json({ error: 'Not a plugin bot' });
  }
  const result = approvePluginInstall(bot.plugin_name);
  if (!result.ok) return res.status(400).json({ error: result.message });
  logAuditAction(AUDIT_ACTIONS.BOT_UPDATE, req.user.id, {
    targetType: 'bot',
    targetId: bot.id,
    details: { installApproved: bot.plugin_name },
  });
  res.json({ ok: true, message: result.message });
});

// POST /api/bots/:id/regenerate-token — old token dies immediately
router.post('/:id/regenerate-token', requirePermission(PERMISSIONS.MANAGE_BOTS), (req, res) => {
  const bot = getBotById(db, req.params.id);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  const token = rotateBotToken(db, bot.id, bot.user_id);
  disconnectUserSockets(bot.user_id);
  logAuditAction(AUDIT_ACTIONS.BOT_TOKEN_REGENERATE, req.user.id, {
    targetType: 'bot',
    targetId: bot.id,
  });
  res.json({ token });
});

// PATCH /api/bots/:id  { requestedScopes?, enabled? }
router.patch('/:id', requirePermission(PERMISSIONS.MANAGE_BOTS), (req, res) => {
  const bot = getBotById(db, req.params.id);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });

  if (Array.isArray(req.body?.requestedScopes)) {
    const scopes = normalizeRequestedScopes(req.body.requestedScopes);
    db.prepare('UPDATE bots SET requested_scopes = ?, updated_at = unixepoch() WHERE id = ?')
      .run(JSON.stringify(scopes), bot.id);
    logAuditAction(AUDIT_ACTIONS.BOT_UPDATE, req.user.id, {
      targetType: 'bot',
      targetId: bot.id,
      details: { requestedScopes: scopes },
    });
  }

  if (typeof req.body?.enabled === 'boolean') {
    const enabled = req.body.enabled ? 1 : 0;
    if (enabled !== Number(bot.enabled)) {
      db.prepare('UPDATE bots SET enabled = ?, updated_at = unixepoch() WHERE id = ?').run(enabled, bot.id);
      if (!enabled) disconnectUserSockets(bot.user_id);
      const { setPluginEnabled } = require('../bots/pluginManager');
      if (bot.kind === 'plugin' && bot.plugin_name) setPluginEnabled(bot.plugin_name, !!enabled);
      logAuditAction(enabled ? AUDIT_ACTIONS.BOT_ENABLE : AUDIT_ACTIONS.BOT_DISABLE, req.user.id, {
        targetType: 'bot',
        targetId: bot.id,
      });
    }
  }

  res.json({ bot: serializeBot(db, getBotById(db, bot.id)) });
});

// PATCH /api/bots/:id/profile  { bio?, displayName? }
router.patch('/:id/profile', requirePermission(PERMISSIONS.MANAGE_BOTS), (req, res) => {
  const bot = getBotById(db, req.params.id);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  if (typeof req.body?.bio === 'string') {
    const bio = req.body.bio.trim();
    if (bio.length > 500) return res.status(400).json({ error: 'Bio must be 500 characters or less' });
    db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(bio, bot.user_id);
  }
  if (typeof req.body?.displayName === 'string') {
    const displayName = req.body.displayName.trim().slice(0, 32) || null;
    db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName, bot.user_id);
    updateOnlineUserDisplayName(bot.user_id, displayName);
  }
  logAuditAction(AUDIT_ACTIONS.BOT_UPDATE, req.user.id, {
    targetType: 'bot',
    targetId: bot.id,
    details: { profile: true },
  });
  res.json({ bot: serializeBot(db, getBotById(db, bot.id)) });
});

// POST /api/bots/:id/avatar  (multipart, field "avatar")
router.post('/:id/avatar', requirePermission(PERMISSIONS.MANAGE_BOTS), botImageUpload.single('avatar'), (req, res) => {
  const bot = getBotById(db, req.params.id);
  if (!bot) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(404).json({ error: 'Bot not found' });
  }
  if (!req.file) return res.status(400).json({ error: 'Avatar file required' });
  const maxBytes = Number(getSetting('avatar_max_mb', '10')) * 1024 * 1024;
  if (req.file.size > maxBytes) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: `Avatar exceeds ${getSetting('avatar_max_mb', '10')}MB limit` });
  }
  const existing = db.prepare('SELECT avatar FROM users WHERE id = ?').get(bot.user_id);
  const avatarPath = `/uploads/avatars/${req.file.filename}`;
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(avatarPath, bot.user_id);
  updateOnlineUserAvatar(bot.user_id, avatarPath);
  if (existing?.avatar && existing.avatar.startsWith('/uploads/avatars/')) {
    fs.unlink(path.join(UPLOADS_DIR, existing.avatar.replace('/uploads/', '')), () => {});
  }
  res.json({ bot: serializeBot(db, getBotById(db, bot.id)) });
});

// POST /api/bots/:id/banner  (multipart, field "banner")
router.post('/:id/banner', requirePermission(PERMISSIONS.MANAGE_BOTS), (req, _res, next) => {
  req.uploadType = 'banner';
  next();
}, botImageUpload.single('banner'), (req, res) => {
  const bot = getBotById(db, req.params.id);
  if (!bot) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(404).json({ error: 'Bot not found' });
  }
  if (!req.file) return res.status(400).json({ error: 'Banner file required' });
  const maxBytes = Number(getSetting('avatar_max_mb', '10')) * 1024 * 1024;
  if (req.file.size > maxBytes) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: `Banner exceeds ${getSetting('avatar_max_mb', '10')}MB limit` });
  }
  const existing = db.prepare('SELECT banner FROM users WHERE id = ?').get(bot.user_id);
  const bannerPath = `/uploads/banners/${req.file.filename}`;
  db.prepare('UPDATE users SET banner = ? WHERE id = ?').run(bannerPath, bot.user_id);
  if (existing?.banner && existing.banner.startsWith('/uploads/banners/')) {
    fs.unlink(path.join(UPLOADS_DIR, existing.banner.replace('/uploads/', '')), () => {});
  }
  res.json({ bot: serializeBot(db, getBotById(db, bot.id)) });
});

// DELETE /api/bots/:id — soft-delete: hard-deleting the user row would cascade
// away the bot's message history (messages.user_id ON DELETE CASCADE).
router.delete('/:id', requirePermission(PERMISSIONS.MANAGE_BOTS), (req, res) => {
  const bot = getBotById(db, req.params.id);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(bot.user_id);
  disconnectUserSockets(bot.user_id);
  const remove = db.transaction(() => {
    db.prepare('DELETE FROM bots WHERE id = ?').run(bot.id);
    db.prepare('UPDATE users SET is_member = 0 WHERE id = ?').run(bot.user_id);
  });
  remove();
  emitBotCommandsUpdated();
  logAuditAction(AUDIT_ACTIONS.BOT_DELETE, req.user.id, {
    targetType: 'bot',
    targetId: bot.id,
    details: { username: user?.username || null },
  });
  res.json({ ok: true });
});

module.exports = router;
