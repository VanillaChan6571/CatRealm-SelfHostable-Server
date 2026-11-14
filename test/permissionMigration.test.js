const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const { createHash } = require('crypto');
const model = require('../src/permissionModel');
const { computePermissionKeysForUser, hasChannelPermission, PERMISSIONS } = require('../src/permissions');
const { prepareDiscordTemplate, importDiscordTemplate, mapDiscordPermissions } = require('../src/discordTemplateImport');

function fixture(includeUnmapped = false) {
  const db = new Database(':memory:');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, role TEXT, is_owner INTEGER);
    CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT, permissions INTEGER NOT NULL DEFAULT 0,
      position INTEGER, is_default INTEGER DEFAULT 0, color TEXT, mentionable INTEGER, hoist INTEGER);
    CREATE TABLE user_roles (user_id TEXT, role_id TEXT);
    CREATE TABLE categories (id TEXT PRIMARY KEY, name TEXT, position INTEGER);
    CREATE TABLE channels (id TEXT PRIMARY KEY, name TEXT, type TEXT, position INTEGER,
      category_id TEXT REFERENCES categories(id), nsfw INTEGER);
    CREATE TABLE channel_permission_overwrites (id TEXT PRIMARY KEY, channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
      target_type TEXT, target_id TEXT, allow INTEGER DEFAULT 0, deny INTEGER DEFAULT 0);
    CREATE TABLE category_permission_overwrites (id TEXT PRIMARY KEY, category_id TEXT REFERENCES categories(id) ON DELETE CASCADE,
      target_type TEXT, target_id TEXT, allow INTEGER DEFAULT 0, deny INTEGER DEFAULT 0);
    CREATE TABLE import_tokens (token TEXT PRIMARY KEY, user_id TEXT, used INTEGER DEFAULT 0, expires_at INTEGER);
    INSERT INTO users VALUES ('owner', 'owner', 1), ('member', 'member', 0);
    INSERT INTO roles (id, name, permissions, position, is_default) VALUES
      ('everyone', 'Member', 1, 0, 1), ('high', 'High', 137438953472, 1, 0);
    INSERT INTO user_roles VALUES ('member', 'everyone'), ('member', 'high');
    INSERT INTO categories VALUES ('old-category', 'Old', 0);
    INSERT INTO channels VALUES ('old-channel', 'Old', 'basic', 0, 'old-category', 0);
    INSERT INTO channel_permission_overwrites VALUES
      ('deny-high', 'old-channel', 'role', 'high', 0, 137438953472);
  `);
  const tokenHash = createHash('sha256').update('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA').digest('hex');
  db.prepare('INSERT INTO import_tokens VALUES (?, ?, 0, unixepoch() + 600)').run(tokenHash, 'owner');
  if (includeUnmapped) {
    db.prepare('INSERT INTO roles (id, name, permissions, position) VALUES (?, ?, ?, ?)')
      .run('future', 'Future', 2 ** 50, 2);
  }
  model.migrate(db);
  return db;
}

test('migration preserves high legacy bits and channel precedence, then tracks legacy writes', () => {
  const db = fixture();
  try {
    assert.deepEqual(computePermissionKeysForUser('member', 'member', 0, db).sort(), ['BAN_MEMBER', 'VIEW_CHANNELS']);
    const user = { id: 'member', role: 'member', permissions: 1 + PERMISSIONS.BAN_MEMBER };
    assert.equal(hasChannelPermission(user, 'old-channel', PERMISSIONS.BAN_MEMBER, db), false);
    db.prepare('UPDATE roles SET permissions = ? WHERE id = ?').run(PERMISSIONS.MANAGE_BOTS, 'high');
    assert.deepEqual(model.roleKeys(db, 'high'), ['MANAGE_BOTS']);
    db.prepare('UPDATE roles SET permissions = ? WHERE id = ?').run(-1, 'high');
    assert.equal(model.roleKeys(db, 'high').includes('MANAGE_BOTS'), false);
    assert.equal(model.roleKeys(db, 'high').includes('MANAGE_ROLES'), false);
    assert.equal(model.roleKeys(db, 'high').includes('VIEW_CHANNELS'), true);
    db.prepare('UPDATE channel_permission_overwrites SET deny = ? WHERE id = ?').run(PERMISSIONS.MANAGE_BOTS, 'deny-high');
    assert.deepEqual(model.overwriteKeys(db, 'channel', { id: 'deny-high' }).deny, ['MANAGE_BOTS']);
    db.prepare('UPDATE channel_permission_overwrites SET deny = ? WHERE id = ?').run(-1, 'deny-high');
    assert.equal(model.overwriteKeys(db, 'channel', { id: 'deny-high' }).deny.includes('MANAGE_BOTS'), false);
  } finally { db.close(); }
});

test('migration records unrecognized legacy bits without granting or deleting them', () => {
  const db = fixture(true);
  try {
    assert.equal(db.prepare('SELECT permissions FROM roles WHERE id = ?').get('future').permissions, 2 ** 50);
    assert.deepEqual(model.roleKeys(db, 'future'), []);
    assert.equal(db.prepare('SELECT mask FROM permission_migration_unmapped WHERE source_id = ?').get('future').mask, String(2 ** 50));
  } finally { db.close(); }
});

test('Discord high flags map without 32 bit truncation, and invalid masks fail closed', () => {
  assert.deepEqual(mapDiscordPermissions(String(1n << 40n)), ['TIMEOUT_USER']);
  assert.deepEqual(mapDiscordPermissions(String(1n << 37n)), ['USE_EXTERNAL_STICKERS']);
  assert.deepEqual(mapDiscordPermissions(String(1n << 3n)), ['ADMINISTRATOR']);
  assert.throws(() => mapDiscordPermissions('not-a-number'), /decimal string/);
  assert.throws(() => model.decodeLegacy(Number.MAX_SAFE_INTEGER), /Unknown legacy permission bit/);
  assert.throws(() => model.parseOverwriteInput({ allowKeys: ['BAN_MEMBER'], denyKeys: ['BAN_MEMBER'] }), /both allowed and denied/);
  assert.throws(() => model.parseOverwriteInput({ allowKeys: ['ADMINISTRATOR'] }), /cannot be a channel/);
});

const template = {
  name: 'Imported', description: 'Test',
  roles: [
    { id: '100', name: '@everyone', permissions: '1024', color: 0 },
    { id: '101', name: 'Mods', permissions: String(1n << 40n), color: 0 },
  ],
  channels: [
    { id: '200', name: 'Chats', type: 4, permission_overwrites: [
      { id: '100', type: 0, allow: '0', deny: '1024' },
    ] },
    { id: '201', name: 'private', type: 0, parent_id: '200', permission_overwrites: [
      { id: '100', type: 0, allow: '0', deny: '1024' },
      { id: '101', type: 0, allow: '1024', deny: '0' },
    ] },
  ],
};

test('import preserves everyone and role overrides; token and replacement are atomic', () => {
  const db = fixture();
  try {
    const prepared = prepareDiscordTemplate(template);
    assert.throws(() => importDiscordTemplate(db, prepared, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'owner', () => {
      throw new Error('settings failed');
    }), /settings failed/);
    assert.equal(db.prepare('SELECT used FROM import_tokens').get().used, 0);
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM channels').get().count, 1);
    const result = importDiscordTemplate(db, prepared, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'owner', () => {});
    assert.equal(result.roles.length, 1);
    assert.equal(db.prepare('SELECT used FROM import_tokens').get().used, 1);
    assert.deepEqual(model.roleKeys(db, 'everyone'), ['VIEW_CHANNELS']);
    const channelId = result.channels[0].id;
    const categoryRules = db.prepare('SELECT permission_key, effect FROM category_permission_rules').all();
    assert.deepEqual(categoryRules, [{ permission_key: 'VIEW_CHANNELS', effect: 'deny' }]);
    const member = { id: 'member', role: 'member', permissions: 1 };
    assert.equal(hasChannelPermission(member, channelId, PERMISSIONS.VIEW_CHANNELS, db), false);
    db.prepare('INSERT INTO user_roles VALUES (?, ?)').run('member', result.roles[0].id);
    assert.equal(hasChannelPermission(member, channelId, PERMISSIONS.VIEW_CHANNELS, db), true);
    assert.throws(() => importDiscordTemplate(db, prepared, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'owner', () => {}), /Invalid or expired/);
  } finally { db.close(); }
});

test('template preview rejects an Administrator grant to everyone', () => {
  const unsafe = structuredClone(template);
  unsafe.roles[0].permissions = '8';
  assert.throws(() => prepareDiscordTemplate(unsafe), /Administrator to @everyone/);
});
