const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const { recordThreadActivity, backfillThreadActivity } = require('../src/threadActivity');

function setup() {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE channels (id TEXT PRIMARY KEY, name TEXT, type TEXT);
    CREATE TABLE threads (id TEXT PRIMARY KEY, channel_id TEXT, name TEXT);
    CREATE TABLE thread_settings (thread_id TEXT PRIMARY KEY, archived INTEGER NOT NULL DEFAULT 0,
      archive_at INTEGER, last_message_at INTEGER NOT NULL DEFAULT (unixepoch()), cover_image TEXT);
    CREATE TABLE messages (id TEXT PRIMARY KEY, thread_id TEXT, created_at INTEGER, scheduled_at INTEGER);
    INSERT INTO channels VALUES ('help', 'help', 'forum'), ('chat', 'chat', 'basic');
    INSERT INTO threads VALUES ('post', 'help', 'How do I…'), ('side', 'chat', 'Side talk'), ('bare', 'chat', 'No settings row');
    INSERT INTO thread_settings (thread_id, archived, last_message_at, cover_image) VALUES ('post', 0, 100, '/ugc/images/c.png'), ('side', 1, 100, NULL);
  `);
  const lastActivity = (id) => db.prepare('SELECT last_message_at FROM thread_settings WHERE thread_id = ?').get(id)?.last_message_at;
  return { db, lastActivity };
}

test('a reply stamps the thread and describes the activity for the whole channel', () => {
  const { db, lastActivity } = setup();
  db.exec("INSERT INTO messages VALUES ('m1', 'post', 150, NULL), ('m2', 'post', 200, NULL)");
  const message = { id: 'm2', channel_id: 'help', thread_id: 'post', user_id: 'alice', content: 'me too', created_at: 200 };
  const activity = recordThreadActivity(db, message);
  assert.deepEqual(activity, {
    channelId: 'help', threadId: 'post', threadName: 'How do I…', isForumPost: true,
    lastMessageAt: 200, replyCount: 2, message,
  });
  assert.equal(lastActivity('post'), 200);
  const kept = db.prepare('SELECT archived, cover_image FROM thread_settings WHERE thread_id = ?').get('post');
  assert.deepEqual({ ...kept }, { archived: 0, cover_image: '/ugc/images/c.png' }, 'other settings are untouched');

  // An older message publishing late does not move the thread backwards.
  assert.equal(recordThreadActivity(db, { ...message, id: 'm0', created_at: 120 }).lastMessageAt, 200);
});

test('threads in ordinary channels and threads without a settings row are covered', () => {
  const { db, lastActivity } = setup();
  const side = recordThreadActivity(db, { id: 'a', thread_id: 'side', created_at: 300 });
  assert.equal(side.isForumPost, false);
  assert.equal(side.channelId, 'chat');
  assert.equal(recordThreadActivity(db, { id: 'b', thread_id: 'bare', created_at: 400 }).lastMessageAt, 400);
  assert.equal(lastActivity('bare'), 400);
});

test('messages outside a thread, or in a deleted one, produce nothing', () => {
  const { db } = setup();
  assert.equal(recordThreadActivity(db, { id: 'x', channel_id: 'chat', thread_id: null, created_at: 1 }), null);
  assert.equal(recordThreadActivity(db, { id: 'y', thread_id: 'gone', created_at: 1 }), null);
});

test('backfill brings stale threads up to their newest published message', () => {
  const { db, lastActivity } = setup();
  db.exec(`INSERT INTO messages VALUES ('m1', 'post', 150, NULL), ('m2', 'post', 250, NULL),
    ('later', 'post', 900, 900), ('old', 'side', 50, NULL)`);
  assert.equal(backfillThreadActivity(db), 1);
  assert.equal(lastActivity('post'), 250, 'a message still waiting to be published does not count');
  assert.equal(lastActivity('side'), 100, 'never moved backwards');
  assert.equal(backfillThreadActivity(db), 0, 'running it again changes nothing');
});
