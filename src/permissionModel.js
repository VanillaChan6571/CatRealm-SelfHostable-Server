'use strict';

// Canonical permissions are stable names. Numeric masks exist only for older
// clients and bot SDKs; new permissions need no bit assignment.
const LEGACY_POSITIONS = Object.freeze({
  VIEW_CHANNELS: 0, READ_CHAT_HISTORY: 1, SEND_MESSAGES: 2,
  SEND_MESSAGES_IN_THREADS: 3, SEND_MESSAGES_IN_POSTS: 4, SEND_VOICE_MESSAGES: 5,
  CREATE_PUBLIC_THREADS: 6, CREATE_POST_IN_FORUMS: 7, EMBED_LINKS: 8,
  ATTACH_FILES: 9, ADD_REACTIONS: 10, SCREENSHARE: 11, CAMERA: 12,
  CONNECT_TO_VOICE: 13, USE_VOICE_ACTIVITY: 14, USE_PUSH_TO_TALK: 15,
  SEND_AUTO_TTS: 16, CHANGE_SELF_NICKNAME: 17, BYPASS_SLOWMODE: 18,
  MANAGE_MESSAGES: 19, PIN_MESSAGES: 20, TIMEOUT_USER: 21,
  MOVE_VOICE_MEMBERS: 22, SERVER_DEAFEN_MEMBERS: 23, SERVER_MUTE_MEMBERS: 24,
  ACCEPT_OR_REJECT_MEMBER_APPLICATION: 25, CREATE_EVENTS: 26,
  CREATE_POLLS: 27, CREATE_PRIVATE_THREADS: 28, KICK_MEMBER: 29,
  MENTION_EVERYONE: 30, MANAGE_NICKNAMES: 31, MANAGE_POSTS: 32,
  MANAGE_EVENTS: 33, MANAGE_CUSTOM_EMOTES: 34, MANAGE_CUSTOM_STICKERS: 35,
  VIEW_AUDIT_LOG: 36, BAN_MEMBER: 37, TOGGLE_LOCAL_REGISTERING: 38,
  MANAGE_WEBHOOKS: 39, MANAGE_CHANNELS: 40, MANAGE_ROLES: 41,
  CREATE_INVITE: 42, ADMINISTRATOR: 43, USE_EXTERNAL_EMOTES: 44,
  USE_EXTERNAL_STICKERS: 45, SCHEDULE_MESSAGES: 46, PLAY_IN_THEATER: 47,
  MANAGE_BOTS: 48,
});

const ALIASES = Object.freeze({
  SEND_MEDIA: 'ATTACH_FILES', MANAGE_SERVER: 'MANAGE_ROLES',
  ASSIGN_ROLES: 'MANAGE_ROLES', EDIT_MESSAGES: 'MANAGE_MESSAGES',
  DELETE_MESSAGES: 'MANAGE_MESSAGES', CREATE_THREADS: 'CREATE_PUBLIC_THREADS',
  CREATE_INVITES: 'CREATE_INVITE', USE_EXTERNAL_EMOJIS: 'USE_EXTERNAL_EMOTES',
});

// Add future permissions here without assigning another JavaScript number bit.
const NAMED_ONLY_KEYS = Object.freeze([
  // Tracker channels
  'CREATE_ISSUES', 'COMMENT_ON_ISSUES', 'ASSIGN_ISSUES', 'MANAGE_ISSUES',
  // Board channels
  'CREATE_CARDS', 'COMMENT_ON_CARDS', 'ASSIGN_CARDS', 'MANAGE_BOARDS',
]);
const KEYS = Object.freeze([...Object.keys(LEGACY_POSITIONS), ...NAMED_ONLY_KEYS]);
const KEY_SET = new Set(KEYS);
const LEGACY_MASK = KEYS.reduce((bits, key) => LEGACY_POSITIONS[key] === undefined
  ? bits : bits | (1n << BigInt(LEGACY_POSITIONS[key])), 0n);

function normalizeKeys(value) {
  if (!Array.isArray(value) || value.length > 1024) throw new RangeError('Invalid permission keys');
  const keys = new Set();
  for (const raw of value) {
    if (typeof raw !== 'string') throw new RangeError('Invalid permission key');
    const key = ALIASES[raw] || raw;
    if (!KEY_SET.has(key)) throw new RangeError(`Unknown permission key: ${raw}`);
    keys.add(key);
  }
  return [...keys];
}

function legacyBits(value) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) throw new RangeError('Unsafe permission mask');
  return value < 0 ? BigInt(value >>> 0) : BigInt(value);
}

function decodeLegacy(value) {
  const bits = legacyBits(value);
  if ((bits & ~LEGACY_MASK) !== 0n) throw new RangeError('Unknown legacy permission bit');
  return KEYS.filter((key) => LEGACY_POSITIONS[key] !== undefined &&
    (bits & (1n << BigInt(LEGACY_POSITIONS[key]))) !== 0n);
}

function splitLegacy(value) {
  const bits = legacyBits(value);
  return {
    keys: KEYS.filter((key) => LEGACY_POSITIONS[key] !== undefined &&
      (bits & (1n << BigInt(LEGACY_POSITIONS[key]))) !== 0n),
    unmapped: bits & ~LEGACY_MASK,
  };
}

function encodeLegacy(keys) {
  const bits = normalizeKeys(keys).reduce((mask, key) =>
    LEGACY_POSITIONS[key] === undefined ? mask : mask | (1n << BigInt(LEGACY_POSITIONS[key])), 0n);
  return Number(bits);
}

function requiredKeys(permission) {
  if (typeof permission === 'string') return normalizeKeys([permission]);
  return decodeLegacy(permission);
}

function createTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS permission_catalog (
      permission_key TEXT PRIMARY KEY
    );
    CREATE TABLE IF NOT EXISTS legacy_permission_positions (
      permission_key TEXT PRIMARY KEY REFERENCES permission_catalog(permission_key),
      mask INTEGER NOT NULL UNIQUE
    );
    CREATE TABLE IF NOT EXISTS role_permission_grants (
      role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
      permission_key TEXT NOT NULL REFERENCES permission_catalog(permission_key),
      PRIMARY KEY (role_id, permission_key)
    );
    CREATE TABLE IF NOT EXISTS channel_permission_rules (
      overwrite_id TEXT NOT NULL REFERENCES channel_permission_overwrites(id) ON DELETE CASCADE,
      permission_key TEXT NOT NULL REFERENCES permission_catalog(permission_key),
      effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
      PRIMARY KEY (overwrite_id, permission_key)
    );
    CREATE TABLE IF NOT EXISTS category_permission_rules (
      overwrite_id TEXT NOT NULL REFERENCES category_permission_overwrites(id) ON DELETE CASCADE,
      permission_key TEXT NOT NULL REFERENCES permission_catalog(permission_key),
      effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
      PRIMARY KEY (overwrite_id, permission_key)
    );
    CREATE TABLE IF NOT EXISTS permission_schema_meta (version INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS permission_migration_unmapped (
      source_type TEXT NOT NULL,
      source_id TEXT NOT NULL,
      mask TEXT NOT NULL,
      PRIMARY KEY (source_type, source_id)
    );
  `);
  const insertKey = db.prepare('INSERT OR IGNORE INTO permission_catalog (permission_key) VALUES (?)');
  for (const key of KEYS) insertKey.run(key);
  const insert = db.prepare('INSERT OR IGNORE INTO legacy_permission_positions (permission_key, mask) VALUES (?, ?)');
  for (const [key, position] of Object.entries(LEGACY_POSITIONS)) insert.run(key, 2 ** position);
}

function createCompatibilityTriggers(db) {
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS role_permissions_insert AFTER INSERT ON roles BEGIN
      INSERT OR IGNORE INTO role_permission_grants (role_id, permission_key)
      SELECT NEW.id, permission_key FROM legacy_permission_positions WHERE ((CASE WHEN NEW.permissions < 0 THEN NEW.permissions & 4294967295 ELSE NEW.permissions END) & mask) != 0;
    END;
    CREATE TRIGGER IF NOT EXISTS role_permissions_update AFTER UPDATE OF permissions ON roles BEGIN
      DELETE FROM role_permission_grants WHERE role_id = NEW.id;
      INSERT INTO role_permission_grants (role_id, permission_key)
      SELECT NEW.id, permission_key FROM legacy_permission_positions WHERE ((CASE WHEN NEW.permissions < 0 THEN NEW.permissions & 4294967295 ELSE NEW.permissions END) & mask) != 0;
    END;
    CREATE TRIGGER IF NOT EXISTS channel_rules_insert AFTER INSERT ON channel_permission_overwrites BEGIN
      INSERT OR REPLACE INTO channel_permission_rules (overwrite_id, permission_key, effect)
      SELECT NEW.id, permission_key, 'deny' FROM legacy_permission_positions WHERE ((CASE WHEN NEW.deny < 0 THEN NEW.deny & 4294967295 ELSE NEW.deny END) & mask) != 0;
      INSERT OR REPLACE INTO channel_permission_rules (overwrite_id, permission_key, effect)
      SELECT NEW.id, permission_key, 'allow' FROM legacy_permission_positions WHERE ((CASE WHEN NEW.allow < 0 THEN NEW.allow & 4294967295 ELSE NEW.allow END) & mask) != 0;
    END;
    CREATE TRIGGER IF NOT EXISTS channel_rules_update AFTER UPDATE OF allow, deny ON channel_permission_overwrites BEGIN
      DELETE FROM channel_permission_rules WHERE overwrite_id = NEW.id;
      INSERT OR REPLACE INTO channel_permission_rules (overwrite_id, permission_key, effect)
      SELECT NEW.id, permission_key, 'deny' FROM legacy_permission_positions WHERE ((CASE WHEN NEW.deny < 0 THEN NEW.deny & 4294967295 ELSE NEW.deny END) & mask) != 0;
      INSERT OR REPLACE INTO channel_permission_rules (overwrite_id, permission_key, effect)
      SELECT NEW.id, permission_key, 'allow' FROM legacy_permission_positions WHERE ((CASE WHEN NEW.allow < 0 THEN NEW.allow & 4294967295 ELSE NEW.allow END) & mask) != 0;
    END;
    CREATE TRIGGER IF NOT EXISTS category_rules_insert AFTER INSERT ON category_permission_overwrites BEGIN
      INSERT OR REPLACE INTO category_permission_rules (overwrite_id, permission_key, effect)
      SELECT NEW.id, permission_key, 'deny' FROM legacy_permission_positions WHERE ((CASE WHEN NEW.deny < 0 THEN NEW.deny & 4294967295 ELSE NEW.deny END) & mask) != 0;
      INSERT OR REPLACE INTO category_permission_rules (overwrite_id, permission_key, effect)
      SELECT NEW.id, permission_key, 'allow' FROM legacy_permission_positions WHERE ((CASE WHEN NEW.allow < 0 THEN NEW.allow & 4294967295 ELSE NEW.allow END) & mask) != 0;
    END;
    CREATE TRIGGER IF NOT EXISTS category_rules_update AFTER UPDATE OF allow, deny ON category_permission_overwrites BEGIN
      DELETE FROM category_permission_rules WHERE overwrite_id = NEW.id;
      INSERT OR REPLACE INTO category_permission_rules (overwrite_id, permission_key, effect)
      SELECT NEW.id, permission_key, 'deny' FROM legacy_permission_positions WHERE ((CASE WHEN NEW.deny < 0 THEN NEW.deny & 4294967295 ELSE NEW.deny END) & mask) != 0;
      INSERT OR REPLACE INTO category_permission_rules (overwrite_id, permission_key, effect)
      SELECT NEW.id, permission_key, 'allow' FROM legacy_permission_positions WHERE ((CASE WHEN NEW.allow < 0 THEN NEW.allow & 4294967295 ELSE NEW.allow END) & mask) != 0;
    END;
  `);
}

function writeRoleKeys(db, roleId, keys) {
  const normalized = normalizeKeys(keys);
  db.prepare('UPDATE roles SET permissions = ? WHERE id = ?').run(encodeLegacy(normalized), roleId);
  db.prepare('DELETE FROM role_permission_grants WHERE role_id = ?').run(roleId);
  const insert = db.prepare('INSERT INTO role_permission_grants (role_id, permission_key) VALUES (?, ?)');
  for (const key of normalized) insert.run(roleId, key);
}

function writeOverwriteKeys(db, scope, overwriteId, allowKeys, denyKeys) {
  if (scope !== 'channel' && scope !== 'category') throw new RangeError('Invalid overwrite scope');
  const allow = normalizeKeys(allowKeys);
  const deny = normalizeKeys(denyKeys);
  if (allow.some((key) => deny.includes(key))) throw new RangeError('Permission cannot be both allowed and denied');
  const rules = `${scope}_permission_rules`;
  const overwrites = `${scope}_permission_overwrites`;
  db.prepare(`UPDATE ${overwrites} SET allow = ?, deny = ? WHERE id = ?`)
    .run(encodeLegacy(allow), encodeLegacy(deny), overwriteId);
  db.prepare(`DELETE FROM ${rules} WHERE overwrite_id = ?`).run(overwriteId);
  const insert = db.prepare(`INSERT INTO ${rules} (overwrite_id, permission_key, effect) VALUES (?, ?, ?)`);
  for (const key of allow) insert.run(overwriteId, key, 'allow');
  for (const key of deny) insert.run(overwriteId, key, 'deny');
}

function roleKeys(db, roleId) {
  try {
    return db.prepare('SELECT permission_key FROM role_permission_grants WHERE role_id = ?').all(roleId).map((r) => r.permission_key);
  } catch (error) {
    if (!/no such table: role_permission_grants/.test(error.message)) throw error;
    const role = db.prepare('SELECT permissions FROM roles WHERE id = ?').get(roleId);
    return role ? decodeLegacy(role.permissions || 0) : [];
  }
}

function overwriteKeys(db, scope, overwrite) {
  if (overwrite._permissionRules) return overwrite._permissionRules;
  const rules = `${scope}_permission_rules`;
  try {
    const rows = db.prepare(`SELECT permission_key, effect FROM ${rules} WHERE overwrite_id = ?`).all(overwrite.id);
    return {
      allow: rows.filter((r) => r.effect === 'allow').map((r) => r.permission_key),
      deny: rows.filter((r) => r.effect === 'deny').map((r) => r.permission_key),
    };
  } catch (error) {
    if (!new RegExp(`no such table: ${rules}`).test(error.message)) throw error;
    return { allow: decodeLegacy(overwrite.allow || 0), deny: decodeLegacy(overwrite.deny || 0) };
  }
}

function listOverwrites(db, scope, scopeId) {
  if (scope !== 'channel' && scope !== 'category') throw new RangeError('Invalid overwrite scope');
  const rows = db.prepare(`SELECT * FROM ${scope}_permission_overwrites WHERE ${scope}_id = ?`).all(scopeId);
  if (rows.length === 0) return rows;
  try {
    const rules = db.prepare(`SELECT r.overwrite_id, r.permission_key, r.effect
      FROM ${scope}_permission_rules r JOIN ${scope}_permission_overwrites o ON o.id = r.overwrite_id
      WHERE o.${scope}_id = ?`).all(scopeId);
    const byId = new Map(rows.map((row) => [row.id, { allow: [], deny: [] }]));
    for (const rule of rules) byId.get(rule.overwrite_id)?.[rule.effect].push(rule.permission_key);
    return rows.map((row) => ({ ...row, _permissionRules: byId.get(row.id) }));
  } catch (error) {
    if (!/no such table:/.test(error.message)) throw error;
    return rows;
  }
}

function parseOverwriteInput(value) {
  const hasNames = value?.allowKeys !== undefined || value?.denyKeys !== undefined;
  const allow = hasNames ? normalizeKeys(value.allowKeys || []) : decodeLegacy(value?.allow ?? 0);
  const deny = hasNames ? normalizeKeys(value.denyKeys || []) : decodeLegacy(value?.deny ?? 0);
  if (allow.includes('ADMINISTRATOR') || deny.includes('ADMINISTRATOR')) {
    throw new RangeError('Administrator cannot be a channel or category overwrite');
  }
  if (allow.some((key) => deny.includes(key))) throw new RangeError('Permission cannot be both allowed and denied');
  return { allowKeys: allow, denyKeys: deny, allow: encodeLegacy(allow), deny: encodeLegacy(deny) };
}

function hasNamedOnlyRules(db, scope, scopeId) {
  if (scope !== 'channel' && scope !== 'category') throw new RangeError('Invalid overwrite scope');
  try {
    return !!db.prepare(`SELECT 1 FROM ${scope}_permission_rules r
      JOIN ${scope}_permission_overwrites o ON o.id = r.overwrite_id
      LEFT JOIN legacy_permission_positions p ON p.permission_key = r.permission_key
      WHERE o.${scope}_id = ? AND p.permission_key IS NULL LIMIT 1`).get(scopeId);
  } catch (error) {
    if (/no such table:/.test(error.message)) return false;
    throw error;
  }
}

function migrate(db) {
  createTables(db);
  if (!db.prepare('SELECT version FROM permission_schema_meta LIMIT 1').get()) {
    db.transaction(() => {
      const grant = db.prepare('INSERT INTO role_permission_grants (role_id, permission_key) VALUES (?, ?)');
      const unmapped = db.prepare('INSERT INTO permission_migration_unmapped (source_type, source_id, mask) VALUES (?, ?, ?)');
      for (const role of db.prepare('SELECT id, permissions FROM roles').all()) {
        const decoded = splitLegacy(role.permissions);
        for (const key of decoded.keys) grant.run(role.id, key);
        if (decoded.unmapped) unmapped.run('role', role.id, decoded.unmapped.toString());
      }
      for (const scope of ['channel', 'category']) {
        const insert = db.prepare(`INSERT OR REPLACE INTO ${scope}_permission_rules
          (overwrite_id, permission_key, effect) VALUES (?, ?, ?)`);
        for (const row of db.prepare(`SELECT id, allow, deny FROM ${scope}_permission_overwrites`).all()) {
          const allow = splitLegacy(row.allow);
          const deny = splitLegacy(row.deny);
          for (const key of deny.keys) insert.run(row.id, key, 'deny');
          for (const key of allow.keys) insert.run(row.id, key, 'allow');
          if (allow.unmapped) unmapped.run(`${scope}_allow`, row.id, allow.unmapped.toString());
          if (deny.unmapped) unmapped.run(`${scope}_deny`, row.id, deny.unmapped.toString());
        }
      }
      db.prepare('INSERT INTO permission_schema_meta (version) VALUES (1)').run();
    })();
  }
  createCompatibilityTriggers(db);
}

module.exports = {
  KEYS, LEGACY_POSITIONS, normalizeKeys, decodeLegacy, encodeLegacy, requiredKeys,
  migrate, writeRoleKeys, writeOverwriteKeys, roleKeys, overwriteKeys,
  parseOverwriteInput, hasNamedOnlyRules, listOverwrites,
};
