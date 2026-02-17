const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const pteroLog = require('./logger');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '../data/catrealm.db');

// Make sure data directory exists
const fs = require('fs');
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(DB_PATH);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function isTruthy(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

function ensureEnvFile() {
  const envPath = path.join(__dirname, '../.env');
  const envExamplePath = path.join(__dirname, '../.env.example');
  if (!fs.existsSync(envPath) && fs.existsSync(envExamplePath)) {
    fs.copyFileSync(envExamplePath, envPath);
  }
  return envPath;
}

function readEnvFileValue(rawKey) {
  const envPath = path.join(__dirname, '../.env');
  if (!fs.existsSync(envPath)) return undefined;
  const envContents = fs.readFileSync(envPath, 'utf8');
  const escapedKey = rawKey.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = envContents.match(new RegExp(`^\\s*${escapedKey}\\s*=\\s*(.*)\\s*$`, 'm'));
  if (!match) return undefined;
  return (match[1] || '').trim();
}

function getEnvValue(keys) {
  for (const key of keys) {
    const envValue = process.env[key];
    if (envValue !== undefined && envValue !== null && String(envValue).trim() !== '') {
      return String(envValue).trim();
    }
  }
  for (const key of keys) {
    const fileValue = readEnvFileValue(key);
    if (fileValue !== undefined && fileValue !== null && String(fileValue).trim() !== '') {
      return String(fileValue).trim();
    }
  }
  return '';
}

function persistEnvValue(key, value) {
  const envPath = ensureEnvFile();
  let envContents = '';
  if (fs.existsSync(envPath)) {
    envContents = fs.readFileSync(envPath, 'utf8');
  }

  const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`^${escapedKey}=.*$`, 'm');
  if (pattern.test(envContents)) {
    envContents = envContents.replace(pattern, `${key}=${value}`);
  } else {
    envContents = `${envContents.trimEnd()}\n${key}=${value}\n`;
  }

  fs.writeFileSync(envPath, envContents, 'utf8');
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(String(value), 'utf8').digest('hex');
}

// ── Schema ─────────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member',  -- 'owner' | 'admin' | 'member'
    avatar      TEXT,
    banner      TEXT,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS channels (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    type        TEXT NOT NULL DEFAULT 'text',    -- 'text' | 'announcement'
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS categories (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS threads (
    id              TEXT PRIMARY KEY,
    channel_id      TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    parent_message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    created_by      TEXT NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,
    channel_id  TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content     TEXT NOT NULL,
    edited      INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at);

  CREATE TABLE IF NOT EXISTS admin_tokens (
    token       TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS server_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS roles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    color       TEXT,
    permissions INTEGER NOT NULL DEFAULT 0,
    position    INTEGER NOT NULL DEFAULT 0,
    is_default  INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
  );

  CREATE TABLE IF NOT EXISTS pins (
    channel_id  TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    message_id  TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    pinned_by   TEXT NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    pinned_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (channel_id, message_id)
  );

  CREATE TABLE IF NOT EXISTS channel_prefs (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel_id  TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    muted       INTEGER NOT NULL DEFAULT 0,
    last_read_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, channel_id)
  );

  CREATE TABLE IF NOT EXISTS display_name_overrides (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    PRIMARY KEY (user_id)
  );

  CREATE TABLE IF NOT EXISTS friend_nicknames (
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nickname       TEXT NOT NULL,
    PRIMARY KEY (user_id, target_user_id)
  );

  CREATE TABLE IF NOT EXISTS channel_settings (
    channel_id TEXT PRIMARY KEY REFERENCES channels(id) ON DELETE CASCADE,
    slowmode INTEGER NOT NULL DEFAULT 0,
    default_reaction TEXT,
    user_limit INTEGER DEFAULT 0,
    bitrate INTEGER DEFAULT 64000,
    video_quality_mode TEXT DEFAULT 'auto',
    thread_auto_archive INTEGER DEFAULT 1440,
    thread_creation_cooldown INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS channel_permission_overwrites (
    id TEXT PRIMARY KEY,
    channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK(target_type IN ('role', 'user')),
    target_id TEXT NOT NULL,
    allow INTEGER NOT NULL DEFAULT 0,
    deny INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_overwrites_channel ON channel_permission_overwrites(channel_id);
  CREATE INDEX IF NOT EXISTS idx_overwrites_target ON channel_permission_overwrites(target_id);
`);

const secureModeEnvRaw = getEnvValue(['SECURE_MODE', 'secure-mode']);
const secureModeRequested = isTruthy(secureModeEnvRaw, false);
const secureModeLockRow = db.prepare('SELECT value FROM server_settings WHERE key = ?').get('secure_mode_locked');
const secureModeLocked = secureModeLockRow?.value === '1';
let secureModeEnabled = secureModeLocked || secureModeRequested;
const secureModeJustEnabled = secureModeRequested && !secureModeLocked;

if (secureModeRequested && !secureModeLocked) {
  db.prepare(`
    INSERT INTO server_settings (key, value)
    VALUES ('secure_mode_locked', '1')
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run();
  pteroLog('[CatRealm] Secure mode has been enabled and permanently locked.');
}

if (secureModeLocked && !secureModeRequested && secureModeEnvRaw !== undefined) {
  pteroLog('[CatRealm] secure-mode=0 ignored because secure mode is permanently locked.');
}

if (secureModeEnabled) {
  let secureModeKey = getEnvValue(['SECURE_MODE_KEY', 'secure-mode-key']);
  const encryptedMessageCount = db.prepare(`
    SELECT COUNT(*) as c
    FROM messages
    WHERE content LIKE 'enc:v1:%'
  `).get().c;
  const storedKeyHashRow = db.prepare('SELECT value FROM server_settings WHERE key = ?').get('secure_mode_key_hash');
  const storedKeyHash = storedKeyHashRow?.value || '';

  if (String(secureModeKey).trim().length < 16) {
    if (encryptedMessageCount > 0 || storedKeyHash) {
      throw new Error('[CatRealm] SECURE_MODE_KEY is missing/invalid while encrypted messages already exist. Restore the original key from backup.');
    }
    secureModeKey = crypto.randomBytes(48).toString('hex');
    persistEnvValue('SECURE_MODE_KEY', secureModeKey);
    pteroLog('[CatRealm] Generated SECURE_MODE_KEY and saved it to .env');
  }

  process.env.SECURE_MODE_KEY = secureModeKey;

  const keyHash = sha256Hex(secureModeKey);
  if (storedKeyHash && storedKeyHash !== keyHash) {
    throw new Error('[CatRealm] SECURE_MODE_KEY does not match the original secure-mode key. Refusing to start to prevent data corruption.');
  }
  if (!storedKeyHash) {
    db.prepare(`
      INSERT INTO server_settings (key, value)
      VALUES ('secure_mode_key_hash', ?)
      ON CONFLICT(key) DO UPDATE SET value = excluded.value
    `).run(keyHash);
  }
}

process.env.CATREALM_SECURE_MODE_EFFECTIVE = secureModeEnabled ? '1' : '0';
process.env.CATREALM_SECURE_MODE_LOCKED = (secureModeLocked || secureModeRequested) ? '1' : '0';
pteroLog(`[CatRealm] Secure mode: ${secureModeEnabled ? 'ENABLED' : 'DISABLED'} (locked=${(secureModeLocked || secureModeRequested) ? '1' : '0'})`);

if (secureModeEnabled) {
  const { encryptMessageContent } = require('./messageCrypto');
  const rows = db.prepare(`
    SELECT id, content
    FROM messages
    WHERE content NOT LIKE 'enc:v1:%'
  `).all();

  if (rows.length > 0) {
    const updateMessage = db.prepare('UPDATE messages SET content = ? WHERE id = ?');
    const migrateMessages = db.transaction((items) => {
      for (const row of items) {
        updateMessage.run(encryptMessageContent(row.content || ''), row.id);
      }
    });
    migrateMessages(rows);
  }

  if (rows.length > 0) {
    const context = secureModeJustEnabled ? 'initial enable' : 'startup self-heal';
    pteroLog(`[CatRealm] Secure mode migration complete (${context}). Encrypted ${rows.length} plaintext messages.`);
  }
}

// ── Thread Settings Migrations ───────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS thread_settings (
    thread_id TEXT PRIMARY KEY REFERENCES threads(id) ON DELETE CASCADE,
    archived INTEGER NOT NULL DEFAULT 0,
    archive_at INTEGER,
    last_message_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS message_nsfw_tags (
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    tag TEXT NOT NULL CHECK(tag IN ('blood', 'gore', 'violence', 'lewd', 'sexual', 'disturbing')),
    PRIMARY KEY (message_id, tag)
  );

  CREATE INDEX IF NOT EXISTS idx_message_nsfw ON message_nsfw_tags(message_id);

  CREATE TABLE IF NOT EXISTS user_nsfw_preferences (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    preferences TEXT NOT NULL,
    age_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS moderation_settings (
    id              INTEGER PRIMARY KEY DEFAULT 1,
    banned_words    TEXT,
    default_slowmode INTEGER DEFAULT 0,
    timeout_defaults TEXT
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id          TEXT PRIMARY KEY,
    action_type TEXT NOT NULL,
    moderator_id TEXT NOT NULL REFERENCES users(id),
    target_id   TEXT,
    details     TEXT,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS bans (
    user_id    TEXT PRIMARY KEY,
    banned_by  TEXT NOT NULL REFERENCES users(id),
    reason     TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS timeouts (
    user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    reason     TEXT,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS invites (
    code           TEXT PRIMARY KEY,
    channel_id     TEXT REFERENCES channels(id) ON DELETE SET NULL,
    creator_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    max_uses       INTEGER DEFAULT 0,
    current_uses   INTEGER NOT NULL DEFAULT 0,
    expires_at     INTEGER,
    created_at     INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_invites_creator ON invites(creator_user_id);
  CREATE INDEX IF NOT EXISTS idx_invites_expires ON invites(expires_at);

  CREATE TABLE IF NOT EXISTS expressions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL CHECK(type IN ('emotes', 'anim-emotes', 'stickers', 'anim-stickers')),
    file_url    TEXT NOT NULL,
    mime_type   TEXT NOT NULL,
    file_size   INTEGER NOT NULL DEFAULT 0,
    created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE UNIQUE INDEX IF NOT EXISTS idx_expressions_name_type ON expressions(name COLLATE NOCASE, type);
  CREATE INDEX IF NOT EXISTS idx_expressions_type ON expressions(type);
`);

// â”€â”€ Migrations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const userColumns = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
if (!userColumns.includes('central_id')) {
  db.prepare('ALTER TABLE users ADD COLUMN central_id TEXT').run();
  pteroLog('[CatRealm] Added users.central_id column');
}
if (!userColumns.includes('account_type')) {
  db.prepare("ALTER TABLE users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'local'").run();
  pteroLog('[CatRealm] Added users.account_type column');
}
if (!userColumns.includes('bio')) {
  db.prepare('ALTER TABLE users ADD COLUMN bio TEXT').run();
  pteroLog('[CatRealm] Added users.bio column');
}
if (!userColumns.includes('is_owner')) {
  db.prepare('ALTER TABLE users ADD COLUMN is_owner INTEGER NOT NULL DEFAULT 0').run();
  pteroLog('[CatRealm] Added users.is_owner column');
}
if (!userColumns.includes('status')) {
  db.prepare("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'online'").run();
  pteroLog('[CatRealm] Added users.status column');
}
if (!userColumns.includes('display_name')) {
  db.prepare('ALTER TABLE users ADD COLUMN display_name TEXT').run();
  pteroLog('[CatRealm] Added users.display_name column');
}
if (!userColumns.includes('activity_type')) {
  db.prepare('ALTER TABLE users ADD COLUMN activity_type TEXT').run();
  pteroLog('[CatRealm] Added users.activity_type column');
}
if (!userColumns.includes('activity_text')) {
  db.prepare('ALTER TABLE users ADD COLUMN activity_text TEXT').run();
  pteroLog('[CatRealm] Added users.activity_text column');
}
if (!userColumns.includes('banner')) {
  db.prepare('ALTER TABLE users ADD COLUMN banner TEXT').run();
  pteroLog('[CatRealm] Added users.banner column');
}

const messageColumns = db.prepare('PRAGMA table_info(messages)').all().map((c) => c.name);
if (!messageColumns.includes('attachment_url')) {
  db.prepare('ALTER TABLE messages ADD COLUMN attachment_url TEXT').run();
  pteroLog('[CatRealm] Added messages.attachment_url column');
}
if (!messageColumns.includes('attachment_type')) {
  db.prepare('ALTER TABLE messages ADD COLUMN attachment_type TEXT').run();
  pteroLog('[CatRealm] Added messages.attachment_type column');
}
if (!messageColumns.includes('attachment_size')) {
  db.prepare('ALTER TABLE messages ADD COLUMN attachment_size INTEGER').run();
  pteroLog('[CatRealm] Added messages.attachment_size column');
}
if (!messageColumns.includes('message_type')) {
  db.prepare("ALTER TABLE messages ADD COLUMN message_type TEXT NOT NULL DEFAULT 'user'").run();
  pteroLog('[CatRealm] Added messages.message_type column');
}
if (!messageColumns.includes('thread_id')) {
  db.prepare('ALTER TABLE messages ADD COLUMN thread_id TEXT').run();
  pteroLog('[CatRealm] Added messages.thread_id column');
}
if (!messageColumns.includes('reply_to_id')) {
  db.prepare('ALTER TABLE messages ADD COLUMN reply_to_id TEXT REFERENCES messages(id) ON DELETE SET NULL').run();
  pteroLog('[CatRealm] Added messages.reply_to_id column');
}
if (!messageColumns.includes('forward_from_id')) {
  db.prepare('ALTER TABLE messages ADD COLUMN forward_from_id TEXT').run();
  pteroLog('[CatRealm] Added messages.forward_from_id column');
}
if (!messageColumns.includes('forward_from_user')) {
  db.prepare('ALTER TABLE messages ADD COLUMN forward_from_user TEXT').run();
  pteroLog('[CatRealm] Added messages.forward_from_user column');
}
if (!messageColumns.includes('forward_from_channel')) {
  db.prepare('ALTER TABLE messages ADD COLUMN forward_from_channel TEXT').run();
  pteroLog('[CatRealm] Added messages.forward_from_channel column');
}
if (!messageColumns.includes('embeds_enabled')) {
  db.prepare("ALTER TABLE messages ADD COLUMN embeds_enabled INTEGER NOT NULL DEFAULT 1").run();
  pteroLog('[CatRealm] Added messages.embeds_enabled column');
}

// Create indexes after columns exist
try {
  db.prepare('CREATE INDEX IF NOT EXISTS idx_messages_reply_to ON messages(reply_to_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_messages_forward_from ON messages(forward_from_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_display_name_overrides_user ON display_name_overrides(user_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_friend_nicknames_user ON friend_nicknames(user_id)').run();
  db.prepare('CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at DESC)').run();
} catch (err) {
  // Indexes may already exist, ignore
}

const channelColumns = db.prepare('PRAGMA table_info(channels)').all().map((c) => c.name);
if (!channelColumns.includes('category_id')) {
  db.prepare('ALTER TABLE channels ADD COLUMN category_id TEXT').run();
  pteroLog('[CatRealm] Added channels.category_id column');
}

const { ALL_PERMISSIONS } = require('./permissions');
const roleColumns = db.prepare('PRAGMA table_info(roles)').all().map((c) => c.name);
const roleCount = db.prepare('SELECT COUNT(*) as c FROM roles').get().c;
if (roleCount === 0) {
  const { randomUUID } = require('crypto');
  const memberRoleId = randomUUID();
  const adminRoleId = randomUUID();
  db.prepare('INSERT INTO roles (id, name, permissions, position, is_default) VALUES (?, ?, ?, ?, ?)')
    .run(memberRoleId, 'Member', 0, 0, 1);
  db.prepare('INSERT INTO roles (id, name, permissions, position, is_default) VALUES (?, ?, ?, ?, ?)')
    .run(adminRoleId, 'Admin', ALL_PERMISSIONS, 10, 0);
  pteroLog('[CatRealm] Seeded default roles');
}

if (!roleColumns.includes('mentionable')) {
  db.prepare('ALTER TABLE roles ADD COLUMN mentionable INTEGER NOT NULL DEFAULT 0').run();
  pteroLog('[CatRealm] Added roles.mentionable column');
}
if (!roleColumns.includes('hoist')) {
  db.prepare('ALTER TABLE roles ADD COLUMN hoist INTEGER NOT NULL DEFAULT 0').run();
  pteroLog('[CatRealm] Added roles.hoist column');
}
if (!roleColumns.includes('icon')) {
  db.prepare('ALTER TABLE roles ADD COLUMN icon TEXT').run();
  pteroLog('[CatRealm] Added roles.icon column');
}

// Ensure Admin role has all permissions
const adminRole = db.prepare('SELECT id, permissions FROM roles WHERE name = ?').get('Admin');
if (adminRole && (adminRole.permissions & ALL_PERMISSIONS) !== ALL_PERMISSIONS) {
  db.prepare('UPDATE roles SET permissions = ? WHERE id = ?').run(ALL_PERMISSIONS, adminRole.id);
  pteroLog('[CatRealm] Updated Admin role permissions');
}

// Ensure all users have the default role
const defaultRole = db.prepare('SELECT id FROM roles WHERE is_default = 1').get();
if (defaultRole) {
  const usersWithout = db.prepare(`
    SELECT u.id FROM users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    WHERE ur.role_id IS NULL
  `).all();
  for (const u of usersWithout) {
    db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)').run(u.id, defaultRole.id);
  }

  // Migrate legacy admin role to Admin role
  const adminRole = db.prepare('SELECT id FROM roles WHERE name = ?').get('Admin');
  if (adminRole) {
    const legacyAdmins = db.prepare(`SELECT id FROM users WHERE role = 'admin'`).all();
    for (const u of legacyAdmins) {
      db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)').run(u.id, adminRole.id);
    }
  }
}

// ── Seed: default channel + admin ─────────────────────────────────────────────
const { randomUUID } = require('crypto');

  const channelCount = db.prepare('SELECT COUNT(*) as c FROM channels').get().c;
  if (channelCount === 0) {
    db.prepare(`INSERT INTO channels (id, name, description, position) VALUES (?, ?, ?, ?)`)
      .run(randomUUID(), 'general', 'General chat', 0);
    pteroLog('[CatRealm] Created default #general channel');
  }

// Migrate legacy channel types to new type names
db.prepare(`UPDATE channels SET type = 'basic' WHERE type IN ('text', 'announcement')`).run();

// Add NSFW column to channels
const channelColumns2 = db.prepare('PRAGMA table_info(channels)').all().map((c) => c.name);
if (!channelColumns2.includes('nsfw')) {
  db.prepare('ALTER TABLE channels ADD COLUMN nsfw INTEGER NOT NULL DEFAULT 0').run();
  pteroLog('[CatRealm] Added channels.nsfw column');
}

// Seed default moderation settings
const modSettingsCount = db.prepare('SELECT COUNT(*) as c FROM moderation_settings').get().c;
if (modSettingsCount === 0) {
  db.prepare(`INSERT INTO moderation_settings (id, banned_words, default_slowmode, timeout_defaults) VALUES (?, ?, ?, ?)`)
    .run(1, '[]', 0, '{}');
  pteroLog('[CatRealm] Created default moderation settings');
}

// Create user_content_social_prefs table for Content & Social settings
db.exec(`
  CREATE TABLE IF NOT EXISTS user_content_social_prefs (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    preferences TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS import_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );
`);

const adminExists = db.prepare(`SELECT id FROM users WHERE role IN ('admin', 'owner') OR is_owner = 1`).get();
const tokenRow = db.prepare('SELECT token FROM admin_tokens').get();
if (!adminExists && !tokenRow) {
  const token = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO admin_tokens (token) VALUES (?)').run(token);
  pteroLog('╔══════════════════════════════════════════════════════════╗');
  pteroLog('║              OWNER SETUP TOKEN (one-time)               ║');
  pteroLog(`║  ${token}  ║`);
  pteroLog('║  Register an account, then use this token to claim owner ║');
  pteroLog('╚══════════════════════════════════════════════════════════╝');
} else if (!adminExists && tokenRow) {
  pteroLog('╔══════════════════════════════════════════════════════════╗');
  pteroLog('║              OWNER SETUP TOKEN (unclaimed)              ║');
  pteroLog(`║  ${tokenRow.token}  ║`);
  pteroLog('║  Register an account, then use this token to claim owner ║');
  pteroLog('╚══════════════════════════════════════════════════════════╝');
}

module.exports = db;


