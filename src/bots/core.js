const crypto = require('crypto');
const { randomUUID } = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { normalizeRequestedScopes, parseJsonSafe } = require('./scopes');

// Same fallback as middleware/auth.js; required here directly to avoid a
// require cycle (middleware/auth needs this module for bot verification).
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';

const BOT_TOKEN_PREFIX = 'crbt_';

function hashToken(rawToken) {
  return crypto.createHash('sha256').update(String(rawToken), 'utf8').digest('hex');
}

function buildTokenPreview(rawToken) {
  const s = String(rawToken || '');
  return s.length <= 16 ? s : `${s.slice(0, 9)}...${s.slice(-4)}`;
}

// Non-expiring credential; revocation is enforced by the token_hash check on
// every verify, so a regenerate (new jti → new hash) kills old tokens instantly.
function generateBotToken(botId, userId) {
  const token = BOT_TOKEN_PREFIX + jwt.sign(
    { type: 'bot', botId, id: userId, jti: crypto.randomBytes(16).toString('hex') },
    JWT_SECRET
  );
  return { token, hash: hashToken(token), preview: buildTokenPreview(token) };
}

function isBotToken(rawToken) {
  return typeof rawToken === 'string' && rawToken.startsWith(BOT_TOKEN_PREFIX);
}

// Verifies a `crbt_...` token. Returns { bot, payload } or throws an Error
// with .status set (401/403) for the caller to translate.
function resolveBotToken(db, rawToken) {
  const jwtPart = String(rawToken).slice(BOT_TOKEN_PREFIX.length);
  let payload;
  try {
    payload = jwt.verify(jwtPart, JWT_SECRET);
  } catch {
    const err = new Error('Invalid bot token');
    err.status = 401;
    throw err;
  }
  if (payload.type !== 'bot' || !payload.botId) {
    const err = new Error('Invalid bot token');
    err.status = 401;
    throw err;
  }
  const bot = db.prepare('SELECT * FROM bots WHERE id = ?').get(payload.botId);
  if (!bot || !bot.token_hash || bot.token_hash !== hashToken(rawToken)) {
    const err = new Error('Bot token revoked');
    err.status = 401;
    throw err;
  }
  if (Number(bot.enabled) !== 1) {
    const err = new Error('Bot is disabled');
    err.status = 403;
    throw err;
  }
  return { bot, payload };
}

function validateBotUsername(db, username) {
  if (!username || typeof username !== 'string') return 'Username required';
  if (username.length < 3 || username.length > 32) return 'Username must be 3-32 characters';
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return 'Username can only contain letters, numbers, and underscores';
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) return 'Username already taken';
  return null;
}

// Creates the bot's user row (a real member so roles/permissions apply) plus
// its bots row and first token. Password is random and unusable — bots only
// authenticate with their token.
function createBotAccount(db, { username, requestedScopes, createdBy = null, kind = 'token', pluginName = null }) {
  const userId = randomUUID();
  const botId = randomUUID();
  const unusablePassword = bcrypt.hashSync(crypto.randomBytes(24).toString('hex'), 10);
  const scopes = normalizeRequestedScopes(requestedScopes);

  const create = db.transaction(() => {
    db.prepare(`
      INSERT INTO users (id, username, password, role, avatar, created_at, is_member, account_type, is_bot)
      VALUES (?, ?, ?, 'member', NULL, unixepoch(), 1, 'bot', 1)
    `).run(userId, username, unusablePassword);
    const defaultRole = db.prepare('SELECT id FROM roles WHERE is_default = 1').get();
    if (defaultRole) {
      db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)').run(userId, defaultRole.id);
    }
    db.prepare(`
      INSERT INTO bots (id, user_id, kind, plugin_name, requested_scopes, enabled, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 1, ?, unixepoch(), unixepoch())
    `).run(botId, userId, kind === 'plugin' ? 'plugin' : 'token', pluginName, JSON.stringify(scopes), createdBy);
  });
  create();

  const token = rotateBotToken(db, botId, userId);
  return { botId, userId, token };
}

// Issues a fresh token and stores its hash; any previously issued token is
// dead the moment this commits.
function rotateBotToken(db, botId, userId) {
  const { token, hash, preview } = generateBotToken(botId, userId);
  db.prepare('UPDATE bots SET token_hash = ?, token_preview = ?, updated_at = unixepoch() WHERE id = ?')
    .run(hash, preview, botId);
  return token;
}

function getBotById(db, botId) {
  return db.prepare('SELECT * FROM bots WHERE id = ?').get(botId);
}

function getBotByUserId(db, userId) {
  return db.prepare('SELECT * FROM bots WHERE user_id = ?').get(userId);
}

function serializeBot(db, bot, { onlineUserIds = null, pluginStatus = null } = {}) {
  const user = db.prepare('SELECT id, username, display_name, avatar, banner, bio, is_member FROM users WHERE id = ?').get(bot.user_id);
  const commandCount = db.prepare('SELECT COUNT(*) AS c FROM bot_commands WHERE bot_id = ?').get(bot.id).c;
  return {
    id: bot.id,
    userId: bot.user_id,
    username: user?.username || null,
    displayName: user?.display_name || null,
    avatar: user?.avatar || null,
    banner: user?.banner || null,
    bio: user?.bio || null,
    kind: bot.kind,
    pluginName: bot.plugin_name || null,
    tokenPreview: bot.token_preview || null,
    requestedScopes: parseJsonSafe(bot.requested_scopes, []),
    enabled: Number(bot.enabled) === 1,
    commandCount,
    online: onlineUserIds ? onlineUserIds.has(bot.user_id) : undefined,
    pluginStatus: pluginStatus || undefined,
    createdBy: bot.created_by || null,
    createdAt: bot.created_at,
  };
}

module.exports = {
  BOT_TOKEN_PREFIX,
  hashToken,
  generateBotToken,
  isBotToken,
  resolveBotToken,
  validateBotUsername,
  createBotAccount,
  rotateBotToken,
  getBotById,
  getBotByUserId,
  serializeBot,
};
