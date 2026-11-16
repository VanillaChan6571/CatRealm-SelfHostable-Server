const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const policy = require('../src/channelPolicy');

function setup() {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE categories (id TEXT PRIMARY KEY, name TEXT);
    CREATE TABLE channels (id TEXT PRIMARY KEY, name TEXT, type TEXT DEFAULT 'basic', nsfw INTEGER DEFAULT 0, category_id TEXT);
    CREATE TABLE channel_settings (channel_id TEXT PRIMARY KEY, slowmode INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE threads (id TEXT PRIMARY KEY, channel_id TEXT, name TEXT);
    CREATE TABLE thread_settings (thread_id TEXT PRIMARY KEY, archived INTEGER NOT NULL DEFAULT 0,
      last_message_at INTEGER NOT NULL DEFAULT (unixepoch()));
    CREATE TABLE messages (id TEXT PRIMARY KEY);
    CREATE TABLE message_nsfw_tags (
      message_id TEXT NOT NULL, tag TEXT NOT NULL CHECK(tag IN ('blood', 'gore', 'violence', 'lewd', 'sexual', 'disturbing')),
      PRIMARY KEY (message_id, tag));
    INSERT INTO categories VALUES ('art', 'Art');
    INSERT INTO channels (id, name, nsfw, category_id) VALUES
      ('sketches', 'sketches', 0, 'art'), ('after-dark', 'after-dark', 1, 'art'), ('lobby', 'lobby', 0, NULL);
    INSERT INTO channel_settings (channel_id, slowmode) VALUES ('sketches', 30);
    INSERT INTO threads VALUES ('t1', 'sketches', 'Critique');
    INSERT INTO messages VALUES ('m1'), ('m2');
    INSERT INTO message_nsfw_tags VALUES ('m1', 'gore');
  `);
  policy.migrate(db);
  return db;
}

test('migration keeps existing tags and lets spoiler and nsfw be stored', () => {
  const db = setup();
  assert.deepEqual(db.prepare('SELECT tag FROM message_nsfw_tags').all().map((r) => r.tag), ['gore']);
  db.prepare("INSERT INTO message_nsfw_tags VALUES ('m1', 'spoiler'), ('m1', 'nsfw')").run();
  assert.throws(() => db.prepare("INSERT INTO message_nsfw_tags VALUES ('m1', 'made-up')").run());
  policy.migrate(db); // safe to run again
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM message_nsfw_tags').get().c, 3);
});

test('thread slowmode and auto-hide fall back thread → channel → category → default', () => {
  const db = setup();
  // Nothing set: slowmode follows the channel's own, auto-hide is 48 hours.
  assert.deepEqual(policy.threadPolicy(db, 't1').effective, { slowmode: 30, autoHideMinutes: 2880 });
  assert.deepEqual(policy.channelPolicy(db, 'lobby').effective.threadSlowmode, 0);

  policy.writeCategoryPolicy(db, 'art', { threadSlowmode: 10, threadAutoHideMinutes: 10080 });
  assert.deepEqual(policy.threadPolicy(db, 't1').effective, { slowmode: 10, autoHideMinutes: 10080 });

  policy.writeChannelPolicy(db, 'sketches', { threadSlowmode: policy.SYNC_WITH_CHANNEL, threadAutoHideMinutes: 60 });
  assert.deepEqual(policy.threadPolicy(db, 't1').effective, { slowmode: 30, autoHideMinutes: 60 }, 'synced with the channel again');

  policy.writeThreadSettings(db, 't1', { slowmode: 5, autoHideMinutes: 0 });
  assert.deepEqual(policy.threadPolicy(db, 't1').effective, { slowmode: 5, autoHideMinutes: 0 });
  policy.writeThreadSettings(db, 't1', { slowmode: null, autoHideMinutes: null });
  assert.deepEqual(policy.threadPolicy(db, 't1').effective, { slowmode: 30, autoHideMinutes: 60 });

  // Back to "use the category's".
  policy.writeChannelPolicy(db, 'sketches', { threadSlowmode: null, threadAutoHideMinutes: null });
  assert.deepEqual(policy.threadPolicy(db, 't1').effective, { slowmode: 10, autoHideMinutes: 10080 });
});

test('values are validated', () => {
  const db = setup();
  assert.throws(() => policy.writeChannelPolicy(db, 'sketches', { threadSlowmode: 99999 }), policy.PolicyError);
  assert.throws(() => policy.writeChannelPolicy(db, 'sketches', { threadAutoHideMinutes: -5 }), policy.PolicyError);
  assert.throws(() => policy.writeThreadSettings(db, 't1', { slowmode: -1 }), policy.PolicyError, 'a thread cannot "sync"; null means inherit');
  assert.throws(() => policy.writeChannelPolicy(db, 'nope', {}), policy.PolicyError);
});

test('hidden once quiet for longer than the setting; 0 never hides', () => {
  assert.equal(policy.isThreadHidden(1000, 60, 1000 + 3600), false);
  assert.equal(policy.isThreadHidden(1000, 60, 1000 + 3601), true);
  assert.equal(policy.isThreadHidden(1000, 0, 9_999_999), false);
});

test('media auto-marks: category is a floor, NSFW needs an NSFW channel, sub-marks need Auto NSFW', () => {
  const db = setup();
  const media = (id) => policy.channelPolicy(db, id).effective.media;

  // Sub-marks without Auto NSFW are cleared rather than stored.
  const saved = policy.writeCategoryPolicy(db, 'art', { media: { spoiler: true, lewd: true } });
  assert.deepEqual(saved.media, { spoiler: true, nsfw: false, lewd: false, blood: false, gore: false });
  assert.equal(media('sketches').spoiler, true, 'the category turns it on for its channels');
  assert.equal(media('lobby').spoiler, false);

  policy.writeCategoryPolicy(db, 'art', { media: { nsfw: true, lewd: true } });
  assert.deepEqual(media('after-dark'), { spoiler: true, nsfw: true, lewd: true, blood: false, gore: false });
  assert.deepEqual(media('sketches'), { spoiler: true, nsfw: false, lewd: false, blood: false, gore: false }, 'not marked NSFW, so no NSFW marks');

  // A channel can add to its category but not remove from it.
  policy.writeChannelPolicy(db, 'after-dark', { media: { nsfw: true, gore: true, spoiler: false } });
  assert.deepEqual(media('after-dark'), { spoiler: true, nsfw: true, lewd: true, blood: false, gore: true });

  assert.throws(() => policy.writeChannelPolicy(db, 'sketches', { media: { nsfw: true } }), /Mark the channel as NSFW/);
});

test('media messages get the automatic tags on top of the sender\'s own', () => {
  const db = setup();
  assert.deepEqual(policy.tagMediaMessage(db, 'm2', 'lobby', ['blood', 'bogus']), ['blood']);
  policy.writeCategoryPolicy(db, 'art', { media: { spoiler: true, nsfw: true, lewd: true } });
  db.exec("DELETE FROM message_nsfw_tags WHERE message_id = 'm2'");
  assert.deepEqual(policy.tagMediaMessage(db, 'm2', 'after-dark', ['blood']).sort(), ['blood', 'lewd', 'nsfw', 'spoiler']);
  assert.deepEqual(db.prepare("SELECT tag FROM message_nsfw_tags WHERE message_id = 'm2' ORDER BY tag").all().map((r) => r.tag),
    ['blood', 'lewd', 'nsfw', 'spoiler']);
});
