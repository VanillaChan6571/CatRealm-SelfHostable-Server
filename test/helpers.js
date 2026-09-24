const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const { createRequire } = require('node:module');
const Database = require('better-sqlite3');
const permissions = require('../src/permissions');

function loadModule(relative, overrides = {}, globals = {}) {
  const filename = path.resolve(__dirname, '..', relative);
  const nativeRequire = createRequire(filename);
  const module = { exports: {} };
  const context = {
    module, exports: module.exports, __dirname: path.dirname(filename), __filename: filename,
    require: id => Object.hasOwn(overrides, id) ? overrides[id] : nativeRequire(id),
    process: { env: {} }, Buffer, console, URL,
    setTimeout, clearTimeout, setInterval, clearInterval, setImmediate,
    ...globals,
  };
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context, { filename });
  return module.exports;
}

function makeDatabase() {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT, role TEXT DEFAULT 'member', is_owner INTEGER DEFAULT 0,
      is_member INTEGER DEFAULT 1, avatar TEXT, status TEXT, display_name TEXT, custom_status_text TEXT,
      activity_type TEXT, activity_text TEXT, activity_started_at INTEGER, account_type TEXT DEFAULT 'local', is_bot INTEGER DEFAULT 0);
    CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT, permissions INTEGER, position INTEGER DEFAULT 0,
      color TEXT, hoist INTEGER, icon TEXT, style_type TEXT, style_colors TEXT, is_default INTEGER DEFAULT 0);
    CREATE TABLE user_roles (user_id TEXT, role_id TEXT);
    CREATE TABLE display_name_overrides (user_id TEXT, display_name TEXT);
    CREATE TABLE user_content_social_prefs (user_id TEXT, preferences TEXT);
    CREATE TABLE channels (id TEXT PRIMARY KEY, name TEXT, type TEXT DEFAULT 'basic', position INTEGER DEFAULT 0, category_id TEXT, nsfw INTEGER DEFAULT 0);
    CREATE TABLE categories (id TEXT, position INTEGER);
    CREATE TABLE channel_permission_overwrites (channel_id TEXT, target_type TEXT, target_id TEXT, allow INTEGER DEFAULT 0, deny INTEGER DEFAULT 0);
    CREATE TABLE category_permission_overwrites (category_id TEXT, target_type TEXT, target_id TEXT, allow INTEGER, deny INTEGER);
    CREATE TABLE channel_settings (channel_id TEXT, slowmode INTEGER, default_reaction TEXT);
    CREATE TABLE threads (id TEXT PRIMARY KEY, channel_id TEXT, created_by TEXT, name TEXT);
    CREATE TABLE messages (id TEXT PRIMARY KEY, channel_id TEXT, user_id TEXT, content TEXT, created_at INTEGER DEFAULT 1,
      attachment_url TEXT, attachment_type TEXT, attachment_size INTEGER, attachments TEXT, message_type TEXT,
      thread_id TEXT, reply_to_id TEXT, forward_from_id TEXT, forward_from_user TEXT, forward_from_channel TEXT,
      forward_from_at INTEGER, embeds_enabled INTEGER, voice_expires_at INTEGER, scheduled_at INTEGER,
      edited INTEGER DEFAULT 0, interaction_meta TEXT);
    CREATE TABLE message_nsfw_tags (message_id TEXT, tag TEXT);
    CREATE TABLE bans (user_id TEXT);
    INSERT INTO users (id, username) VALUES ('alice', 'Alice'), ('bob', 'Bob');
    INSERT INTO channels (id, name) VALUES ('public', 'Public'), ('private', 'Private');
    INSERT INTO threads VALUES ('public-thread', 'public', 'bob', 'Bob thread'), ('private-thread', 'private', 'bob', 'Private thread');
    INSERT INTO user_roles VALUES ('alice', 'member'), ('bob', 'member');
    INSERT INTO messages (id, channel_id, user_id, content) VALUES ('public-message', 'public', 'bob', 'Public content'), ('private-message', 'private', 'bob', 'Private content');
  `);
  const p = permissions.PERMISSIONS;
  const base = p.VIEW_CHANNELS + p.READ_CHAT_HISTORY + p.SEND_MESSAGES + p.SEND_MESSAGES_IN_THREADS + p.ATTACH_FILES + p.CREATE_THREADS;
  db.prepare('INSERT INTO roles (id, name, permissions, is_default) VALUES (?, ?, ?, 1)').run('member', 'Member', base);
  return db;
}

function getUser(db, id = 'alice') {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  return { ...user, permissions: permissions.computePermissionsForUser(id, user.role, user.is_owner, db) };
}

function makeSocketHarness(db, { directory, fakeFs, clientType = 'desktop' } = {}) {
  const intervalCallbacks = [];
  const handlers = {};
  const middleware = [];
  const events = [];
  let connect;
  const io = {
    sockets: { sockets: new Map() },
    use() {}, on: (_event, callback) => { connect = callback; },
    emit: (event, data) => events.push({ event, data }),
    to: room => ({ emit: (event, data) => events.push({ room, event, data }) }),
  };
  const socket = {
    id: 'socket-alice', user: getUser(db), authUser: getUser(db), handshake: { auth: { clientType } },
    rooms: new Set(['socket-alice']),
    on: (event, callback) => { handlers[event] = callback; },
    use: callback => middleware.push(callback),
    emit: (event, data) => events.push({ event, data }),
    to: io.to,
    join(room) { this.rooms.add(room); }, leave(room) { this.rooms.delete(room); },
  };
  io.sockets.sockets.set(socket.id, socket);
  const api = loadModule('src/socket/handler.js', {
    '../db': db, '../middleware/auth': { JWT_SECRET: 'synthetic-secret' },
    '../bots/core': {}, '../bots/scopes': {}, '../logger': () => {},
    '../webhooks': { queueMessageCreatedEvent() {} }, '../reactions': {},
    '../lib/pushRelay': {}, '../lib/auditLog': { logAuditAction() {}, AUDIT_ACTIONS: {} },
    '../routes/media': {}, '../lib/mediaConfig': {},
    '../settings': { getSetting: (_key, fallback) => fallback },
    ...(fakeFs ? { fs: fakeFs } : {}),
  }, {
    process: { env: directory ? { UGC_IMAGES_DIR: directory } : {} },
    setInterval: (callback, delay) => { intervalCallbacks.push({ callback, delay }); return 0; },
  });
  api(io);
  connect(socket);
  return {
    api, socket, events, intervalCallbacks,
    dispatch(event, payload, ack) {
      for (const callback of middleware) callback([event, payload], () => {});
      handlers[event](payload, ack);
    },
  };
}

module.exports = { loadModule, makeDatabase, getUser, makeSocketHarness };
