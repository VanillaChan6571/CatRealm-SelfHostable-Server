const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const { PERMISSIONS: P } = require('../src/permissions');
const { normalizeBotCommands, commandPermissionBits, canUseBotCommand, resolveOptionValue } = require('../src/bots/core');
const { loadModule, makeDatabase, getUser, makeSocketHarness } = require('./helpers');

// vm-sandboxed modules build objects with foreign prototypes; compare plain copies.
const plain = (value) => JSON.parse(JSON.stringify(value));

function routeHandlers(router, method, url) {
  return router.stack.find((l) => l.route?.path === url && l.route.methods[method]).route.stack.map((s) => s.handle);
}
function call(router, method, url, req) {
  const res = { statusCode: 200, status(c) { this.statusCode = c; return this; }, json(d) { this.data = d; return this; } };
  const handlers = routeHandlers(router, method, url);
  const run = (i) => handlers[i] && handlers[i]({ query: {}, body: {}, ...req }, res, () => run(i + 1));
  run(0);
  return res;
}

test('reaction toggles emit add/remove deltas next to the full summary', (t) => {
  const db = makeDatabase();
  t.after(() => db.close());
  db.exec('CREATE TABLE message_reactions (message_id TEXT, user_id TEXT, emoji TEXT, created_at INTEGER DEFAULT 1)');
  db.prepare('UPDATE roles SET permissions = permissions + ? WHERE id = ?').run(P.ADD_REACTIONS, 'member');
  const reactions = loadModule('src/reactions.js', { './db': db });
  const h = makeSocketHarness(db, { overrides: { '../reactions': reactions } });

  h.dispatch('message:react', { messageId: 'public-message', emoji: '👍' });
  h.dispatch('message:react', { messageId: 'public-message', emoji: '👍' });
  const deltas = h.events.filter((e) => e.event.startsWith('message:reaction:'));
  assert.deepEqual(deltas.map((e) => e.event), [
    'message:reaction:update', 'message:reaction:add', 'message:reaction:update', 'message:reaction:remove',
  ]);
  const expected = { messageId: 'public-message', channelId: 'public', threadId: null, userId: 'alice', emoji: '👍' };
  assert.deepEqual(plain(deltas[1].data), expected);
  assert.deepEqual(plain(deltas[3].data), expected);
  assert.equal(deltas[1].room, 'public');
});

test('commands validate defaultPermission names', () => {
  const ok = normalizeBotCommands([{ name: 'setup', defaultPermission: 'MANAGE_ROLES' }, { name: 'ping' }]);
  assert.equal(ok.commands[0].defaultPermission, 'MANAGE_ROLES');
  assert.equal(ok.commands[1].defaultPermission, null);
  assert.equal(normalizeBotCommands([{ name: 'x', default_permission: 'MANAGE_ROLES' }]).commands[0].defaultPermission, 'MANAGE_ROLES');
  assert.match(normalizeBotCommands([{ name: 'x', defaultPermission: 'NOPE' }]).error, /Unknown defaultPermission/);
  // Group objects (PERMISSIONS.ADMIN) are not single permissions.
  assert.match(normalizeBotCommands([{ name: 'x', defaultPermission: 'ADMIN' }]).error, /Unknown defaultPermission/);
  assert.equal(commandPermissionBits('MANAGE_ROLES'), P.MANAGE_ROLES);
  // A stale/unknown stored name fails closed instead of opening the command.
  assert.equal(canUseBotCommand({ permissions: 0 }, 'RENAMED_LATER', () => true), false);
  assert.equal(canUseBotCommand({ permissions: 0 }, null, () => false), true);
});

function setupInteraction(t) {
  const db = makeDatabase();
  t.after(() => db.close());
  db.exec(`
    ALTER TABLE users ADD COLUMN bio TEXT;
    ALTER TABLE users ADD COLUMN pronouns TEXT;
    CREATE TABLE bots (id TEXT PRIMARY KEY, user_id TEXT, enabled INTEGER DEFAULT 1, requested_scopes TEXT DEFAULT '[]');
    CREATE TABLE bot_commands (id TEXT, bot_id TEXT, name TEXT, description TEXT, options TEXT, default_permission TEXT);
    INSERT INTO users (id, username, is_bot) VALUES ('botuser', 'Bot', 1);
    INSERT INTO bots (id, user_id) VALUES ('b1', 'botuser');
    INSERT INTO bot_commands VALUES ('c1', 'b1', 'pick', '', '[]', NULL), ('c2', 'b1', 'setup', '', '[]', 'MANAGE_ROLES');
    INSERT INTO user_roles VALUES ('botuser', 'member');
  `);
  const { commands } = normalizeBotCommands([
    { name: 'mode', options: [{ name: 'mode', choices: [{ name: 'Normal', value: 'normal' }, { name: 'Unique', value: 'unique' }] }] },
    { name: 'give', options: [{ name: 'role', type: 'role' }] },
  ]);
  for (const cmd of commands) {
    db.prepare('INSERT INTO bot_commands VALUES (?, ?, ?, ?, ?, NULL)').run(cmd.name, 'b1', cmd.name, '', JSON.stringify(cmd.options));
  }
  const consent = { decision: 'allowed' };
  const h = makeSocketHarness(db, {
    extraUsers: ['botuser'],
    overrides: {
      '../bots/core': { isBotToken: () => false, canUseBotCommand, resolveOptionValue },
      '../bots/scopes': {
        BOT_SCOPES: { PROFILE: 'profile' },
        botHasScope: () => false,
        getBotConsent: () => ({ decision: consent.decision, scopes: { interactions: true } }),
      },
    },
  });
  const invoke = (payload) => {
    let ack;
    h.dispatch('interaction:invoke', { botId: 'b1', channelId: 'public', ...payload }, (a) => { ack = a; });
    return ack;
  };
  const created = () => h.events.filter((e) => e.socket === 'socket-botuser' && e.event === 'interaction:create').at(-1)?.data;
  h.extraSockets.botuser.bot = { id: 'b1' };
  const asBot = (event, payload) => {
    let ack;
    h.dispatchAs('botuser', event, payload, (a) => { ack = a; });
    return ack;
  };
  const ghosts = () => h.events.filter((e) => !e.socket && e.event === 'bot:ephemeral').map((e) => e.data);
  return { db, h, invoke, created, asBot, ghosts, consent };
}

test('interaction:create carries reply target and invoker permissions', (t) => {
  const { invoke, created } = setupInteraction(t);
  assert.equal(invoke({ command: 'pick', replyToId: 'public-message' }).status, 'ok');
  const interaction = created();
  assert.equal(interaction.replyToId, 'public-message');
  assert.deepEqual(plain(interaction.user.roleIds), ['member']);
  assert.equal(interaction.user.isOwner, false);
  assert.equal(BigInt(interaction.user.permissions) & BigInt(P.SEND_MESSAGES), BigInt(P.SEND_MESSAGES));

  // A reply target from another channel is dropped, not forwarded.
  assert.equal(invoke({ command: 'pick', replyToId: 'private-message' }).status, 'ok');
  assert.equal(created().replyToId, null);
});

test('permission-gated commands are refused for members without it', (t) => {
  const { db, invoke, h, created } = setupInteraction(t);
  assert.equal(invoke({ command: 'setup' }).status, 'missing_permission');
  assert.equal(created(), undefined);

  db.prepare('UPDATE roles SET permissions = permissions + ? WHERE id = ?').run(P.MANAGE_ROLES, 'member');
  h.socket.user = getUser(db);
  assert.equal(invoke({ command: 'setup' }).status, 'ok');
});

test('single-role add/remove keeps hierarchy and default-role rules', (t) => {
  const db = new Database(':memory:');
  t.after(() => db.close());
  db.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT, role TEXT, avatar TEXT, bio TEXT, is_owner INTEGER DEFAULT 0,
      is_bot INTEGER DEFAULT 0, is_member INTEGER DEFAULT 1);
    CREATE TABLE bans (user_id TEXT);
    CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT, permissions INTEGER, position INTEGER, is_default INTEGER DEFAULT 0);
    CREATE TABLE user_roles (user_id TEXT, role_id TEXT, UNIQUE (user_id, role_id));
    INSERT INTO users (id, username) VALUES ('modUser', 'Mod'), ('target', 'Target');
    INSERT INTO roles VALUES ('cats', 'Cats', 0, 0, 1), ('admin', 'Admin', 0, 3, 0), ('mod', 'Mod', 0, 2, 0), ('rebel', 'Rebel', 0, 1, 0);
    INSERT INTO user_roles VALUES ('modUser', 'cats'), ('modUser', 'mod'), ('target', 'cats');
  `);
  const audits = [];
  const router = loadModule('src/routes/admin.js', {
    '../db': db,
    '../middleware/auth': { SERVER_MODE: 'standalone' },
    '../settings': { getSetting: () => null, setSetting() {} },
    '../permissions': { PERMISSIONS: P, hasPermission: () => true },
    '../socket/handler': { emitServerInfoUpdate() {}, emitPermissionsChanged() {}, kickUserFromServer() {} },
    '../diagnosticCommands': {},
    '../theaterYouTubeCookies': {},
    '../webhooks': {},
    '../lib/theaterUploadLimits': {},
    '../lib/auditLog': { AUDIT_ACTIONS: {}, logAuditAction: (...a) => audits.push(a), diffFields: () => null },
  });
  const mod = { id: 'modUser', is_owner: 0 };
  const role = (method, roleId, userId = 'target') =>
    call(router, method, '/users/:id/roles/:roleId', { user: mod, params: { id: userId, roleId } });

  let res = role('put', 'rebel');
  assert.equal(res.statusCode, 200);
  assert.deepEqual(plain(res.data.roleIds).sort(), ['cats', 'rebel']);
  assert.equal(audits.length, 1);
  assert.equal(role('put', 'rebel').statusCode, 200); // idempotent
  assert.equal(audits.length, 1);

  assert.equal(role('put', 'admin').statusCode, 403); // above the actor
  assert.equal(role('put', 'missing').statusCode, 404);
  assert.equal(role('delete', 'cats').statusCode, 400); // default role
  assert.equal(role('put', 'rebel', 'nobody').statusCode, 404);

  res = role('delete', 'rebel');
  assert.equal(res.statusCode, 200);
  assert.deepEqual(plain(res.data.roleIds), ['cats']);

  res = call(router, 'get', '/users/:id', { user: mod, params: { id: 'target' } });
  assert.equal(res.data.id, 'target');
  assert.deepEqual(plain(res.data.roleIds), ['cats']);
  assert.equal(call(router, 'get', '/users/:id', { user: mod, params: { id: 'nobody' } }).statusCode, 404);
});

test('single message fetch covers threads and hides others’ scheduled messages', (t) => {
  const db = makeDatabase();
  t.after(() => db.close());
  db.prepare('INSERT INTO messages (id, channel_id, user_id, content, thread_id) VALUES (?, ?, ?, ?, ?)')
    .run('thread-message', 'public', 'bob', 'In thread', 'public-thread');
  db.prepare('INSERT INTO messages (id, channel_id, user_id, content, scheduled_at) VALUES (?, ?, ?, ?, ?)')
    .run('scheduled', 'public', 'bob', 'Later', 9999999999);
  const router = loadModule('src/routes/messages.js', {
    '../db': db, '../socket/handler': { emitToChannel() {} },
    '../middleware/rateLimits': { searchLimiter: (_req, _res, next) => next() },
    '../reactions': { attachReactionsToMessages: (rows) => rows },
  });
  const get = (channelId, messageId) =>
    call(router, 'get', '/:channelId/:messageId', { user: getUser(db), params: { channelId, messageId } });

  const res = get('public', 'thread-message');
  assert.equal(res.statusCode, 200);
  assert.equal(res.data.thread_id, 'public-thread');
  assert.deepEqual(plain(res.data.attachments), []);
  assert.equal(get('public', 'scheduled').statusCode, 404);
  assert.equal(get('public', 'private-message').statusCode, 404); // wrong channel
  // `search` is still routed to the search handler, not treated as a message id.
  assert.ok(router.stack.findIndex((l) => l.route?.path === '/:channelId/search')
    < router.stack.findIndex((l) => l.route?.path === '/:channelId/:messageId'));
});

test('message socket actions ack with status and ids', (t) => {
  const db = makeDatabase();
  t.after(() => db.close());
  db.exec('CREATE TABLE message_reactions (message_id TEXT, user_id TEXT, emoji TEXT, created_at INTEGER DEFAULT 1)');
  db.prepare('UPDATE roles SET permissions = permissions + ? WHERE id = ?').run(P.ADD_REACTIONS, 'member');
  const h = makeSocketHarness(db, { overrides: { '../reactions': loadModule('src/reactions.js', { './db': db }) } });
  const send = (event, payload) => { let ack; h.dispatch(event, payload, (a) => { ack = a; }); return plain(ack); };

  const sent = send('message:send', { channelId: 'public', content: 'hello' });
  assert.equal(sent.status, 'ok');
  assert.ok(db.prepare('SELECT 1 FROM messages WHERE id = ?').get(sent.messageId));
  assert.equal(send('message:send', { channelId: 'missing', content: 'x' }).status, 'not_found');
  assert.equal(send('message:send', { channelId: 'public', content: '' }).status, 'invalid');

  assert.deepEqual(send('message:react', { messageId: sent.messageId, emoji: '🐱' }), { status: 'ok', messageId: sent.messageId, reacted: true });
  assert.deepEqual(send('message:edit', { messageId: sent.messageId, content: 'edited' }), { status: 'ok', messageId: sent.messageId });
  assert.equal(send('message:edit', { messageId: 'public-message', content: 'not mine' }).status, 'denied');
  assert.equal(send('message:delete', { messageId: 'nope' }).status, 'not_found');
  assert.deepEqual(send('message:delete', { messageId: sent.messageId }), { status: 'ok', messageId: sent.messageId });
  // Legacy `error` strings are still emitted for clients that don't pass an ack.
  assert.ok(h.events.some((e) => e.event === 'error' && e.data === 'Channel not found'));
});

test('interactions accept follow-ups (public and ghost) after the first response', (t) => {
  const { invoke, created, asBot, ghosts } = setupInteraction(t);
  invoke({ command: 'pick' });
  const { id } = created();

  assert.equal(asBot('interaction:followup', { id, content: 'too early' }).status, 'unknown_interaction');
  assert.equal(asBot('interaction:respond', { id, content: '' }).status, 'invalid'); // stays open
  assert.equal(asBot('interaction:respond', { id, content: 'first' }).status, 'ok');
  assert.equal(asBot('interaction:respond', { id, content: 'again' }).status, 'unknown_interaction');

  const pub = asBot('interaction:followup', { id, content: 'public follow-up' });
  assert.equal(pub.status, 'ok');
  assert.ok(pub.messageId);
  assert.equal(asBot('interaction:followup', { id, content: 'just you', ephemeral: true }).status, 'ok');
  assert.equal(asBot('interaction:followup', { id, content: 'and again', ephemeral: true }).status, 'ok');
  const [first, second] = ghosts();
  assert.equal(first.content, 'just you');
  assert.equal(first.interactionId, id);
  assert.equal(first.interaction.command, 'pick');
  assert.notEqual(first.id, second.id); // unique keys for same-second ghosts
});

test('bots can ghost-message a user in a channel outside an interaction', (t) => {
  const { asBot, ghosts, consent } = setupInteraction(t);
  const ack = asBot('bot:ephemeral:send', { userId: 'alice', channelId: 'public', content: 'Role added' });
  assert.equal(ack.status, 'ok');
  const [ghost] = ghosts();
  assert.equal(ghost.content, 'Role added');
  assert.equal(ghost.channelId, 'public');
  assert.equal(ghost.interaction, null);

  assert.equal(asBot('bot:ephemeral:send', { userId: 'bob', channelId: 'public', content: 'x' }).status, 'user_offline');
  assert.equal(asBot('bot:ephemeral:send', { userId: 'alice', channelId: 'public', threadId: 'private-thread', content: 'x' }).status, 'not_found');
  assert.equal(asBot('bot:ephemeral:send', { userId: 'botuser', channelId: 'public', content: 'x' }).status, 'not_found');
  consent.decision = 'denied';
  assert.equal(asBot('bot:ephemeral:send', { userId: 'alice', channelId: 'public', content: 'x' }).status, 'denied');
  assert.equal(ghosts().length, 1);
});

test('option choices and role options are validated and resolved', (t) => {
  assert.match(normalizeBotCommands([{ name: 'x', options: [{ name: 'flag', type: 'boolean', choices: [{ name: 'a', value: 'a' }] }] }]).error, /only allowed/);
  assert.match(normalizeBotCommands([{ name: 'x', options: [{ name: 'n', type: 'integer', choices: [{ name: 'one', value: '1' }] }] }]).error, /invalid choice/);
  const many = Array.from({ length: 26 }, (_, i) => ({ name: `c${i}`, value: `c${i}` }));
  assert.match(normalizeBotCommands([{ name: 'x', options: [{ name: 'o', choices: many }] }]).error, /1-25/);

  const { invoke, created } = setupInteraction(t);
  assert.equal(invoke({ command: 'mode', options: { mode: 'Unique' } }).status, 'ok');
  assert.equal(created().options.mode, 'unique'); // choice name resolves to its value
  assert.match(invoke({ command: 'mode', options: { mode: 'bogus' } }).error, /must be one of: Normal, Unique/);

  assert.equal(invoke({ command: 'give', options: { role: '@Member' } }).status, 'ok');
  assert.equal(created().options.role, 'member'); // role name resolves to id
  assert.equal(invoke({ command: 'give', options: { role: 'member' } }).status, 'ok');
  assert.equal(invoke({ command: 'give', options: { role: 'Nope' } }).status, 'invalid');
  // Undeclared keys still pass through untouched.
  assert.equal(invoke({ command: 'pick', options: { extra: 'kept' } }).status, 'ok');
  assert.equal(created().options.extra, 'kept');
});
