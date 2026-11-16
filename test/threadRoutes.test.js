const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModule, makeDatabase, getUser } = require('./helpers');

function setup() {
  const db = makeDatabase();
  db.exec(`
    DROP TABLE threads;
    CREATE TABLE threads (id TEXT PRIMARY KEY, channel_id TEXT, parent_message_id TEXT, name TEXT, created_by TEXT,
      created_at INTEGER NOT NULL DEFAULT (unixepoch()));
    CREATE TABLE thread_settings (thread_id TEXT PRIMARY KEY, archived INTEGER NOT NULL DEFAULT 0, archive_at INTEGER,
      last_message_at INTEGER NOT NULL DEFAULT (unixepoch()), cover_image TEXT);
    ALTER TABLE channel_settings ADD COLUMN thread_creation_cooldown INTEGER DEFAULT 0;
    INSERT INTO users (id, username, is_owner) VALUES ('owner', 'Owner', 1);
    INSERT INTO channels (id, name, type) VALUES ('help', 'Help', 'forum');
    INSERT INTO messages (id, channel_id, user_id, content) VALUES ('forum-body', 'help', 'bob', 'Forum body');
  `);
  db.exec('ALTER TABLE categories ADD COLUMN name TEXT');
  require('../src/channelPolicy').migrate(db);
  const events = [];
  const delivered = { webhooks: [], mentions: [] };
  const routes = {};
  const router = new Proxy({}, {
    get: (_target, method) => (path, ...handlers) => { routes[`${String(method)} ${path}`] = handlers.at(-1); },
  });
  loadModule('src/routes/threads.js', {
    express: { Router: () => router },
    '../db': db,
    '../messageCrypto': { decryptMessageRows: (rows) => rows, encryptMessageContent: (text) => `enc:${text}` },
    '../safety': {},
    '../reactions': {},
    '../socket/handler': {
      emitToChannel: (room, event, data) => events.push({ room, event, data }),
      emitMessage: (room, data) => events.push({ room, event: 'message:new', data }),
      // Per-member delivery, tried here against the three test users.
      emitToChannelEach: (room, event, build) => {
        for (const id of ['alice', 'bob', 'owner']) {
          const data = build(getUser(db, id));
          if (data) events.push({ room, event, data, to: id });
        }
      },
      messageAuthorFields: () => ({ display_name: 'Alice A.', role_color: '#ff8800', avatar: null }),
      relayMentions: (mention) => delivered.mentions.push(mention),
    },
    '../webhooks': { queueMessageCreatedEvent: (message) => delivered.webhooks.push(message) },
    '../threadActivity': require('../src/threadActivity'),
  });
  const call = (route, userId, { body = {}, query = {}, params = {}, bot = null, user = {} } = {}) => {
    const res = { statusCode: 200, body: undefined, status(code) { this.statusCode = code; return this; }, json(data) { this.body = JSON.parse(JSON.stringify(data)); return this; } };
    routes[route]({ user: { ...getUser(db, userId), ...user }, bot, body, query, params }, res);
    return res;
  };
  return { db, call, events, delivered };
}

test('creating a thread names it, posts the opening message and announces it', () => {
  const { db, call, events } = setup();
  const created = call('post /', 'alice', {
    body: { channelId: 'public', messageId: 'public-message', name: '  Release plan  ', firstMessage: 'Shall we ship Friday?' },
  });
  assert.equal(created.statusCode, 201);
  assert.equal(created.body.name, 'Release plan');
  assert.equal(created.body.reply_count, 1);

  const opening = db.prepare("SELECT * FROM messages WHERE thread_id = ?").get(created.body.id);
  assert.deepEqual([opening.user_id, opening.content, opening.message_type], ['alice', 'enc:Shall we ship Friday?', 'user']);

  const announcement = db.prepare("SELECT * FROM messages WHERE channel_id = 'public' AND message_type = 'system'").get();
  assert.equal(announcement.content, 'enc:🧶 Alice made a thread called Release plan');
  assert.equal(announcement.thread_id, null, 'the announcement is in the channel, not the thread');
  assert.equal(announcement.attachment_url, 'public-message', 'it points at the message the thread grew from');
  assert.equal(announcement.attachment_type, `thread:${created.body.id}`, 'and names the thread so clients can open it');

  const sent = (event) => events.filter((e) => e.event === event);
  assert.equal(sent('message:new').find((e) => e.room === 'public').data.content, '🧶 Alice made a thread called Release plan');
  assert.equal(sent('message:new').find((e) => e.room === `thread:${created.body.id}`).data.content, 'Shall we ship Friday?');
  assert.equal(sent('thread:created')[0].data.name, 'Release plan');
  assert.equal(sent('thread:created')[0].to, undefined, 'a thread with a message is announced to the whole channel');
  assert.equal(sent('thread:activity')[0].data.replyCount, 1);
});

test('the opening message is delivered like any other: styled, sent to webhooks, mentions relayed', () => {
  const { call, events, delivered } = setup();
  const created = call('post /', 'alice', {
    body: { channelId: 'public', messageId: 'public-message', name: 'Ping', firstMessage: 'hey @Bob' },
  }).body;
  const opening = events.find((e) => e.room === `thread:${created.id}`).data;
  assert.deepEqual([opening.display_name, opening.role_color], ['Alice A.', '#ff8800']);
  assert.deepEqual(delivered.webhooks.map((m) => m.id), [opening.id]);
  assert.deepEqual(JSON.parse(JSON.stringify(delivered.mentions)), [{
    authorId: 'alice', authorUsername: 'Alice', authorAvatar: null, bot: null, channelId: 'public',
    messageId: opening.id, createdAt: opening.created_at, content: 'hey @Bob',
  }]);
});

test('a bot opening message carries its consent context to the mention relay', () => {
  const { call, delivered } = setup();
  const bot = { id: 'bot-1' };
  call('post /', 'alice', {
    user: { is_bot: 1 }, bot,
    body: { channelId: 'public', messageId: 'public-message', name: 'Ping', firstMessage: 'hey @Bob' },
  });
  assert.equal(delivered.mentions[0].bot, bot);
});

test('an empty thread is announced only to its creator and staff', () => {
  const { db, call, events, delivered } = setup();
  const thread = call('post /', 'alice', { body: { channelId: 'public', messageId: 'public-message', name: 'Empty' } }).body;
  assert.deepEqual(events.filter((e) => e.event === 'thread:created').map((e) => e.to).sort(), ['alice', 'owner']);
  assert.equal(events.some((e) => e.event === 'message:new' && e.room === 'public'), false);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM messages WHERE channel_id = 'public' AND message_type = 'system'").get().count, 0);
  assert.deepEqual(delivered.webhooks, []);
  call('patch /:id', 'alice', { params: { id: thread.id }, body: { name: 'Renamed empty' } });
  assert.deepEqual(events.filter((e) => e.event === 'thread:updated').map((e) => e.to).sort(), ['alice', 'owner']);
});

test('thread names are capped and over-long opening messages are refused', () => {
  const { db, call } = setup();
  const long = call('post /', 'alice', { body: { channelId: 'public', messageId: 'public-message', name: 'x'.repeat(300) } });
  assert.equal(long.body.name.length, 100);
  const before = db.prepare('SELECT COUNT(*) AS c FROM threads').get().c;
  const refused = call('post /', 'alice', { body: { channelId: 'public', messageId: 'public-message', name: 'ok', firstMessage: 'y'.repeat(2001) } });
  assert.equal(refused.statusCode, 400);
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM threads').get().c, before, 'nothing is created');
});

test('empty threads are listed only for their creator and for staff', () => {
  const { call } = setup();
  const empty = call('post /', 'alice', { body: { channelId: 'public', messageId: 'public-message', name: 'Empty' } }).body;
  const busy = call('post /', 'alice', { body: { channelId: 'public', messageId: 'public-message', name: 'Busy', firstMessage: 'hi' } }).body;
  const list = (userId) => call('get /', userId, { query: { channelId: 'public' } }).body.map((t) => t.id).sort();
  assert.deepEqual(list('bob'), [busy.id]);
  assert.deepEqual(list('alice'), [busy.id, empty.id].sort());
  assert.deepEqual(list('owner'), [busy.id, empty.id].sort());
});

test('rename and delete are limited to the creator or staff, and are broadcast', () => {
  const { db, call, events } = setup();
  const thread = call('post /', 'alice', { body: { channelId: 'public', messageId: 'public-message', name: 'Mine', firstMessage: 'hi' } }).body;
  assert.equal(call('patch /:id', 'bob', { params: { id: thread.id }, body: { name: 'Hijacked' } }).statusCode, 403);
  assert.equal(call('delete /:id', 'bob', { params: { id: thread.id } }).statusCode, 403);

  assert.equal(call('patch /:id', 'owner', { params: { id: thread.id }, body: { name: 'Renamed by staff' } }).body.name, 'Renamed by staff');
  assert.equal(events.at(-1).event, 'thread:updated');
  assert.equal(call('delete /:id', 'owner', { params: { id: thread.id } }).statusCode, 200);
  assert.deepEqual(JSON.parse(JSON.stringify(events.at(-1))), { room: 'public', event: 'thread:deleted', data: { id: thread.id, channel_id: 'public' } });
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM threads WHERE id = ?').get(thread.id).c, 0);
});

test('quiet threads auto-hide from the list and return when someone writes in them', () => {
  const { db, call } = setup();
  const thread = call('post /', 'alice', { body: { channelId: 'public', messageId: 'public-message', name: 'Old news', firstMessage: 'hi' } }).body;
  const list = (userId, query = {}) => call('get /', userId, { query: { channelId: 'public', ...query } }).body;
  const quietFor = (hours) => db.prepare('UPDATE thread_settings SET last_message_at = unixepoch() - ? WHERE thread_id = ?').run(hours * 3600, thread.id);

  quietFor(47);
  assert.deepEqual(list('bob').map((t) => t.id), [thread.id], 'still listed inside the 48 hour default');
  quietFor(49);
  assert.deepEqual(list('bob'), []);
  assert.deepEqual(list('alice'), [], 'hidden for its creator too');
  assert.deepEqual(list('owner'), [], 'and for staff, unless they ask');
  assert.equal(list('owner', { includeHidden: '1' })[0].hidden, true);
  assert.deepEqual(list('bob', { includeHidden: '1' }), [], 'members cannot ask for hidden threads');
  assert.equal(call('get /:id', 'bob', { params: { id: thread.id } }).body.id, thread.id, 'a direct link still opens it');

  // The channel can lengthen it, and one thread can be set to never hide.
  db.prepare("INSERT INTO channel_settings (channel_id, slowmode, thread_auto_hide_minutes) VALUES ('public', 0, 10080)").run();
  assert.equal(list('bob').length, 1);
  quietFor(24 * 8);
  assert.equal(list('bob').length, 0);
  db.prepare('UPDATE thread_settings SET auto_hide_minutes = 0 WHERE thread_id = ?').run(thread.id);
  assert.equal(list('bob').length, 1);
});

test('forum posts are unaffected: no announcement and always listed', () => {
  const { db, call, events } = setup();
  const post = call('post /', 'alice', { body: { channelId: 'help', messageId: 'forum-body', name: 'Question' } });
  assert.equal(post.statusCode, 201);
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM messages WHERE message_type = 'system'").get().c, 0);
  assert.ok(!events.some((e) => e.event === 'thread:created'));
  assert.deepEqual(call('get /', 'bob', { query: { channelId: 'help' } }).body.map((t) => t.id), [post.body.id]);
});
