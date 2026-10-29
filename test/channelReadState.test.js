const test = require('node:test');
const assert = require('node:assert/strict');
const { PERMISSIONS } = require('../src/permissions');
const { loadModule, makeDatabase, getUser } = require('./helpers');

function loadReadStateRoute(db) {
  const routes = {};
  const router = new Proxy({}, {
    get: (_target, method) => (path, ...handlers) => { routes[`${String(method)} ${path}`] = handlers.at(-1); },
  });
  loadModule('src/routes/channels.js', {
    express: { Router: () => router },
    '../db': db,
    '../socket/handler': {},
    '../settings': {},
    '../messageCrypto': {},
    '../webhooks': {},
    '../lib/auditLog': { AUDIT_ACTIONS: {} },
  });
  return (user) => {
    let body;
    routes['get /read-state']({ user }, { json: (data) => { body = data; } });
    return JSON.parse(JSON.stringify(body.channels)); // sandbox objects have foreign prototypes
  };
}

test('read-state flags channels with newer messages from others, per user', (t) => {
  const db = makeDatabase();
  t.after(() => db.close());
  db.exec('CREATE TABLE channel_prefs (user_id TEXT, channel_id TEXT, muted INTEGER DEFAULT 0, last_read_at INTEGER DEFAULT 0, PRIMARY KEY (user_id, channel_id))');
  db.prepare("UPDATE messages SET created_at = 100, message_type = 'user'").run();
  // Hide "private" from members so it never appears in the response.
  db.prepare("INSERT INTO channel_permission_overwrites (channel_id, target_type, target_id, deny) VALUES ('private', 'role', 'member', ?)")
    .run(PERMISSIONS.VIEW_CHANNELS);
  const readState = loadReadStateRoute(db);

  // Bob posted at 100 and Alice never read: unread for Alice, not for Bob (it's his own message).
  assert.deepEqual(readState(getUser(db, 'alice')), { public: { lastMessageAt: 100, lastReadAt: 0, muted: false, unread: true, unreadCount: 1 } });
  assert.equal(readState(getUser(db, 'bob')).public.unread, false);

  // Reading past it clears it; thread replies and pending scheduled messages don't bring it back.
  db.prepare("INSERT INTO channel_prefs (user_id, channel_id, last_read_at) VALUES ('alice', 'public', 150)").run();
  db.prepare(`INSERT INTO messages (id, channel_id, user_id, content, created_at, message_type, thread_id, scheduled_at) VALUES
    ('in-thread', 'public', 'bob', 'x', 200, 'user', 'public-thread', NULL),
    ('scheduled', 'public', 'bob', 'x', 210, 'user', NULL, 9999),
    ('system', 'public', 'bob', 'x', 220, 'system', NULL, NULL)`).run();
  assert.equal(readState(getUser(db, 'alice')).public.unread, false);

  db.prepare("INSERT INTO messages (id, channel_id, user_id, content, created_at, message_type) VALUES ('new', 'public', 'bob', 'x', 300, 'user')").run();
  db.prepare("INSERT INTO messages (id, channel_id, user_id, content, created_at, message_type) VALUES ('new2', 'public', 'bob', 'x', 310, 'user')").run();
  // Counts only Bob's visible messages after the read position (not the thread/scheduled/system ones).
  assert.deepEqual(readState(getUser(db, 'alice')).public, { lastMessageAt: 310, lastReadAt: 150, muted: false, unread: true, unreadCount: 2 });
});
