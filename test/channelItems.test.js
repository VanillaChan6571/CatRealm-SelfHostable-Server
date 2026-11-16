const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const { loadModule } = require('./helpers');
const permissionModel = require('../src/permissionModel');
const channelItems = require('../src/channelItems');

const attachmentDir = fs.mkdtempSync(path.join(os.tmpdir(), 'catrealm-tracker-attachments-'));
test.after(() => fs.rmSync(attachmentDir, { recursive: true, force: true }));

function setup() {
  const db = new Database(':memory:');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT, role TEXT DEFAULT 'member', is_owner INTEGER DEFAULT 0,
      avatar TEXT, display_name TEXT, account_type TEXT DEFAULT 'local');
    CREATE TABLE display_name_overrides (user_id TEXT, display_name TEXT);
    CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT, color TEXT, position INTEGER DEFAULT 0, permissions INTEGER DEFAULT 0, is_default INTEGER DEFAULT 0);
    CREATE TABLE user_roles (user_id TEXT, role_id TEXT);
    CREATE TABLE channels (id TEXT PRIMARY KEY, name TEXT, type TEXT, category_id TEXT);
    CREATE TABLE channel_permission_overwrites (id TEXT PRIMARY KEY, channel_id TEXT, target_type TEXT, target_id TEXT, allow INTEGER DEFAULT 0, deny INTEGER DEFAULT 0);
    CREATE TABLE category_permission_overwrites (id TEXT PRIMARY KEY, category_id TEXT, target_type TEXT, target_id TEXT, allow INTEGER DEFAULT 0, deny INTEGER DEFAULT 0);
    INSERT INTO users (id, username, is_owner) VALUES ('owner', 'Owner', 1), ('alice', 'Alice', 0), ('bob', 'Bob', 0), ('hidden', 'Hidden', 0);
    INSERT INTO roles (id, name, is_default) VALUES ('member', 'Member', 1), ('triage', 'Triage', 0), ('blind', 'Blind', 0);
    INSERT INTO user_roles VALUES ('alice', 'member'), ('bob', 'member'), ('bob', 'triage'), ('hidden', 'blind');
    INSERT INTO channels (id, name, type) VALUES ('bugs', 'bugs', 'tracker'), ('plan', 'plan', 'board'), ('chat', 'chat', 'basic');
  `);
  permissionModel.migrate(db);
  permissionModel.writeRoleKeys(db, 'member', ['VIEW_CHANNELS', 'READ_CHAT_HISTORY']);
  channelItems.migrate(db); // grants CREATE_/COMMENT_ keys to the default role
  permissionModel.writeRoleKeys(db, 'triage', ['ASSIGN_ISSUES', 'MANAGE_ISSUES', 'ASSIGN_CARDS', 'MANAGE_BOARDS']);

  const events = [];
  const audits = [];
  const userFor = (id) => {
    const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    return { ...row, permission_keys: require('../src/permissions').computePermissionKeysForUser(id, row.role, row.is_owner, db) };
  };
  const overrides = {
    '../db': db,
    '../socket/handler': {
      emitToChannel: (channelId, event, data) => events.push({ channelId, event, data }),
      emitToUserSockets: (userId, event, data) => events.push({ to: userId, event, data }),
      // Per-member events are recorded once per user who would receive them, with `to`.
      emitToChannelEach: (channelId, event, build) => {
        for (const { id } of db.prepare('SELECT id FROM users ORDER BY id').all()) {
          const data = build(userFor(id));
          if (data !== null && data !== undefined) events.push({ channelId, event, data, to: id });
        }
      },
    },
    '../lib/auditLog': { logAuditAction: (...args) => audits.push(args) },
    '../channelItems': channelItems,
  };
  const routers = {
    tracker: loadModule('src/routes/tracker.js', overrides, { process: { env: { UGC_IMAGES_DIR: attachmentDir } } }),
    boards: loadModule('src/routes/boards.js', overrides),
  };
  // call('tracker', 'post', '/:channelId/issues', 'alice', { channelId: 'bugs' }, body, query)
  const call = (name, method, path, userId, params, body = {}, query = {}) => {
    const layer = routers[name].stack.find((l) => l.route?.path === path && l.route.methods[method]);
    assert.ok(layer, `route ${method} ${path}`);
    const handlers = layer.route.stack.map((s) => s.handle);
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
    const req = { params, body, query, user: userFor(userId) };
    const run = (i) => handlers[i] && handlers[i](req, res, () => run(i + 1));
    run(0);
    return res;
  };
  return { db, call, events, audits, routers, userFor };
}

test('default role gets create and comment keys once; manage and assign stay with staff', () => {
  const { db } = setup();
  const keys = permissionModel.roleKeys(db, 'member');
  for (const key of ['CREATE_ISSUES', 'COMMENT_ON_ISSUES', 'CREATE_CARDS', 'COMMENT_ON_CARDS']) assert.ok(keys.includes(key), key);
  assert.ok(!keys.includes('MANAGE_ISSUES') && !keys.includes('ASSIGN_CARDS'));
  permissionModel.writeRoleKeys(db, 'member', ['VIEW_CHANNELS']);
  channelItems.migrate(db);
  assert.deepEqual(permissionModel.roleKeys(db, 'member'), ['VIEW_CHANNELS'], 'a second migrate does not re-grant');
});

test('tracker: managers set a synced or custom title and background', () => {
  const { call, events } = setup();
  const at = { channelId: 'bugs' };
  const route = '/:channelId/settings';
  assert.deepEqual(JSON.parse(JSON.stringify(call('tracker', 'get', route, 'alice', at).body)), { title: null, background: null });
  assert.equal(call('tracker', 'patch', route, 'alice', at, { title: 'Changed' }).statusCode, 403);
  assert.equal(call('tracker', 'patch', route, 'bob', at, { background: { kind: 'pattern', colors: ['#112233'], pattern: 'mesh', scene: 'bad' } }).statusCode, 400);
  assert.equal(call('tracker', 'patch', route, 'bob', at, { background: { kind: 'image', image: '/ugc/images/bg.png', positionX: 150 } }).statusCode, 400);
  assert.equal(call('tracker', 'patch', route, 'bob', at, { background: { kind: 'image', image: '/ugc/images/bg.png', fit: true, stretch: true } }).statusCode, 400);
  const saved = call('tracker', 'patch', route, 'bob', at, {
    title: '  Bug queue  ',
    background: { kind: 'pattern', colors: ['#9BF00B', '#107c10'], pattern: 'mesh', animated: true, scene: 'rings' },
  }).body;
  assert.deepEqual(JSON.parse(JSON.stringify(saved)), {
    title: 'Bug queue',
    background: { kind: 'pattern', colors: ['#9bf00b', '#107c10'], pattern: 'mesh', animated: true, scene: 'rings' },
  });
  assert.equal(events.at(-1).event, 'tracker:settings-updated');
  assert.equal(call('tracker', 'get', '/:channelId/issues', 'alice', at).body.settings.title, 'Bug queue');
  const image = call('tracker', 'patch', route, 'bob', at, {
    background: { kind: 'image', image: '/ugc/images/bg.png', fit: true, positionX: 20, positionY: 70 },
  }).body.background;
  assert.deepEqual(JSON.parse(JSON.stringify(image)), { kind: 'image', image: '/ugc/images/bg.png', fit: true, positionX: 20, positionY: 70 });
  const stretched = call('tracker', 'patch', route, 'bob', at, {
    background: { kind: 'image', image: '/ugc/images/bg.png', stretch: true },
  }).body.background;
  assert.deepEqual(JSON.parse(JSON.stringify(stretched)), { kind: 'image', image: '/ugc/images/bg.png', stretch: true });
  const synced = call('tracker', 'patch', route, 'bob', at, { title: null, background: null }).body;
  assert.deepEqual(JSON.parse(JSON.stringify(synced)), { title: null, background: null });
});

test('tracker: numbering, filters, state changes and permissions', () => {
  const { db, call, events, audits } = setup();
  const issues = '/:channelId/issues';
  const one = '/:channelId/issues/:itemId';
  const at = { channelId: 'bugs' };

  assert.equal(call('tracker', 'post', issues, 'alice', { channelId: 'chat' }, { title: 'x' }).statusCode, 404, 'wrong channel type');
  assert.equal(call('tracker', 'post', issues, 'hidden', at, { title: 'x' }).statusCode, 403, 'cannot view');
  assert.equal(call('tracker', 'post', issues, 'alice', at, { title: '  ' }).statusCode, 400);

  const first = call('tracker', 'post', issues, 'alice', at, { title: 'Crash on start', body: 'It crashes' });
  assert.equal(first.statusCode, 201);
  assert.equal(first.body.number, 1);
  assert.equal(first.body.author.username, 'Alice');
  assert.equal(events.at(-1).event, 'tracker:issue-created');
  const second = call('tracker', 'post', issues, 'bob', at, { title: 'Typo' });
  assert.equal(second.body.number, 2);

  // Members cannot assign at creation, staff can; hidden users cannot be assigned.
  assert.equal(call('tracker', 'post', issues, 'alice', at, { title: 'a', assigneeIds: ['alice'] }).statusCode, 403);
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM channel_items WHERE title = 'a'").get().c, 0, 'failed create rolls back');
  const assign = '/:channelId/issues/:itemId/assignees';
  assert.equal(call('tracker', 'put', assign, 'alice', { ...at, itemId: '1' }, { userIds: ['alice'] }).statusCode, 403);
  assert.equal(call('tracker', 'put', assign, 'bob', { ...at, itemId: '1' }, { userIds: ['hidden'] }).statusCode, 400);
  assert.deepEqual(call('tracker', 'put', assign, 'bob', { ...at, itemId: '1' }, { userIds: ['alice'] }).body.assignees.map((u) => u.id), ['alice']);

  // Only the author or a manager edits and closes.
  assert.equal(call('tracker', 'patch', one, 'alice', { ...at, itemId: '2' }, { state: 'closed' }).statusCode, 403);
  const closed = call('tracker', 'patch', one, 'alice', { ...at, itemId: '1' }, { state: 'closed', title: 'Crash on launch' });
  assert.equal(closed.body.state, 'closed');
  assert.equal(closed.body.closed_by, 'alice');
  assert.equal(call('tracker', 'patch', one, 'alice', { ...at, itemId: '1' }, { state: 'bogus' }).statusCode, 400);

  const list = (query) => call('tracker', 'get', issues, 'alice', at, {}, query).body;
  assert.deepEqual(list({}).issues.map((i) => i.number), [2]);
  assert.deepEqual(list({ state: 'closed' }).issues.map((i) => i.number), [1]);
  assert.deepEqual(list({ state: 'all', assignee: 'alice' }).issues.map((i) => i.number), [1]);
  assert.deepEqual(list({ state: 'all', q: 'typ' }).issues.map((i) => i.number), [2]);
  assert.deepEqual(list({ state: 'all', q: '%' }).issues, [], 'LIKE wildcards are escaped');
  assert.deepEqual({ ...list({}).counts }, { open: 1, in_progress: 0, blocked: 0, closed: 1 });

  const detail = call('tracker', 'get', one, 'alice', { ...at, itemId: '1' }).body;
  assert.deepEqual(detail.events.map((e) => e.type), ['assignees', 'renamed', 'closed']);
  assert.equal(detail.body, 'It crashes');

  // Deleting needs MANAGE_ISSUES, is audited, and the number is not reused.
  assert.equal(call('tracker', 'delete', one, 'alice', { ...at, itemId: '2' }).statusCode, 403);
  assert.equal(call('tracker', 'delete', one, 'bob', { ...at, itemId: '2' }).statusCode, 200);
  assert.equal(audits.length, 1);
  assert.equal(call('tracker', 'post', issues, 'alice', at, { title: 'Next' }).body.number, 3);
});

test('labels and comments are shared by both channel types', () => {
  const { call, events } = setup();
  const at = { channelId: 'bugs' };
  const labels = '/:channelId/labels';
  assert.equal(call('tracker', 'post', labels, 'alice', at, { name: 'bug', color: '#ff0000' }).statusCode, 403);
  assert.equal(call('tracker', 'post', labels, 'bob', at, { name: 'bug', color: 'red' }).statusCode, 400);
  const label = call('tracker', 'post', labels, 'bob', at, { name: 'bug', color: '#FF0000' }).body;
  assert.equal(label.color, '#ff0000');
  assert.equal(call('tracker', 'post', labels, 'bob', at, { name: 'BUG', color: '#00ff00' }).statusCode, 409);
  assert.equal(events.at(-1).event, 'tracker:labels-updated');

  const issue = call('tracker', 'post', '/:channelId/issues', 'alice', at, { title: 'Labelled', labelIds: [label.id] }).body;
  assert.deepEqual(issue.label_ids, [label.id]);
  const item = { ...at, itemId: issue.id };
  assert.equal(call('tracker', 'patch', '/:channelId/issues/:itemId', 'alice', item, { labelIds: ['nope'] }).statusCode, 400);

  const comments = '/:channelId/issues/:itemId/comments';
  const comment = call('tracker', 'post', comments, 'bob', item, { body: 'Confirmed' });
  assert.equal(comment.statusCode, 201);
  assert.ok(events.some((event) => event.event === 'tracker:comment-created'));
  const one = '/:channelId/issues/:itemId/comments/:commentId';
  const ref = { ...item, commentId: comment.body.id };
  assert.equal(call('tracker', 'patch', one, 'alice', ref, { body: 'hijack' }).statusCode, 403, 'only the author edits');
  assert.ok(call('tracker', 'patch', one, 'bob', ref, { body: 'Confirmed on 1.9' }).body.edited_at);
  assert.equal(call('tracker', 'get', '/:channelId/issues/:itemId', 'alice', item).body.comment_count, 1);

  const mine = call('tracker', 'post', comments, 'alice', item, { body: 'Thanks' }).body;
  assert.equal(call('tracker', 'delete', one, 'bob', { ...item, commentId: mine.id }).statusCode, 200, 'managers delete any comment');
  assert.equal(call('tracker', 'delete', one, 'alice', ref).statusCode, 403);
});

test('boards: lists, card moves and archive', () => {
  const { db, call, events, audits } = setup();
  const at = { channelId: 'plan' };
  assert.equal(call('boards', 'post', '/:channelId/lists', 'alice', at, { name: 'Todo' }).statusCode, 403);
  const todo = call('boards', 'post', '/:channelId/lists', 'bob', at, { name: 'Todo' }).body;
  const done = call('boards', 'post', '/:channelId/lists', 'bob', at, { name: 'Done' }).body;
  assert.deepEqual([todo.position, done.position], [0, 1]);

  assert.equal(call('boards', 'put', '/:channelId/lists/order', 'bob', at, { listIds: [done.id] }).statusCode, 400);
  assert.deepEqual(call('boards', 'put', '/:channelId/lists/order', 'bob', at, { listIds: [done.id, todo.id] }).body.map((l) => l.name), ['Done', 'Todo']);

  const add = (title) => call('boards', 'post', '/:channelId/cards', 'alice', at, { listId: todo.id, title }).body;
  assert.equal(call('boards', 'post', '/:channelId/cards', 'alice', at, { listId: 'nope', title: 'x' }).statusCode, 404);
  const [a, b, c] = ['A', 'B', 'C'].map(add);
  assert.deepEqual([a.position, b.position, c.position], [0, 1, 2]);
  assert.equal(events.at(-1).event, 'board:card-created');

  const move = '/:channelId/cards/:itemId/position';
  const order = (listId) => db.prepare('SELECT title FROM channel_items WHERE list_id = ? AND archived = 0 ORDER BY position').all(listId).map((r) => r.title).join('');
  // Reorder within a list, including an index past the end.
  call('boards', 'put', move, 'alice', { ...at, itemId: c.id }, { listId: todo.id, index: 0 });
  assert.equal(order(todo.id), 'CAB');
  call('boards', 'put', move, 'alice', { ...at, itemId: c.id }, { listId: todo.id, index: 99 });
  assert.equal(order(todo.id), 'ABC');
  // Move across lists; both lists are renumbered and broadcast.
  const moved = call('boards', 'put', move, 'alice', { ...at, itemId: a.id }, { listId: done.id, index: 0 });
  assert.equal(order(todo.id), 'BC');
  assert.equal(order(done.id), 'A');
  assert.equal(moved.body.lists.length, 2);
  assert.equal(events.at(-1).event, 'board:cards-moved');
  assert.deepEqual(db.prepare('SELECT position FROM channel_items WHERE list_id = ? ORDER BY position').all(todo.id).map((r) => r.position), [0, 1]);
  assert.equal(call('boards', 'put', move, 'hidden', { ...at, itemId: a.id }, { listId: todo.id, index: 0 }).statusCode, 403);
  assert.equal(call('boards', 'put', move, 'alice', { ...at, itemId: a.id }, { listId: todo.id, index: -1 }).statusCode, 400);

  // Archive hides the card from the board; restoring appends it.
  const card = '/:channelId/cards/:itemId';
  assert.equal(call('boards', 'patch', card, 'alice', { ...at, itemId: b.id }, { archived: true, dueAt: 1800000000 }).body.archived, true);
  assert.deepEqual(call('boards', 'get', '/:channelId', 'alice', at).body.cards.map((x) => x.title).sort(), ['A', 'C']);
  assert.deepEqual(call('boards', 'get', '/:channelId', 'alice', at, {}, { archived: '1' }).body.cards.map((x) => x.title), ['B']);
  assert.equal(call('boards', 'put', move, 'alice', { ...at, itemId: b.id }, { listId: todo.id, index: 0 }).statusCode, 400);
  call('boards', 'patch', card, 'alice', { ...at, itemId: b.id }, { archived: false });
  assert.equal(order(todo.id), 'CB');
  assert.equal(call('boards', 'patch', card, 'alice', { ...at, itemId: b.id }, { dueAt: 'soon' }).statusCode, 400);

  // Deleting a list removes its cards and is audited.
  assert.equal(call('boards', 'delete', '/:channelId/lists/:listId', 'bob', { ...at, listId: todo.id }).statusCode, 200);
  assert.deepEqual(db.prepare("SELECT title FROM channel_items WHERE kind = 'card'").all().map((r) => r.title), ['A']);
  assert.equal(audits[0][2].details.cards, 2);
  assert.deepEqual(call('boards', 'get', '/:channelId', 'alice', at).body.lists.map((l) => [l.name, l.position]), [['Done', 0]]);
});

test('a channel overwrite can deny creating in one tracker', () => {
  const { db, call } = setup();
  db.prepare("INSERT INTO channel_permission_overwrites (id, channel_id, target_type, target_id) VALUES ('ow', 'bugs', 'role', 'member')").run();
  permissionModel.writeOverwriteKeys(db, 'channel', 'ow', [], ['CREATE_ISSUES']);
  assert.equal(call('tracker', 'post', '/:channelId/issues', 'alice', { channelId: 'bugs' }, { title: 'x' }).statusCode, 403);
  assert.equal(call('tracker', 'post', '/:channelId/issues', 'owner', { channelId: 'bugs' }, { title: 'x' }).statusCode, 201);
});

test('boards: staff-only lists are hidden from everyone but managers and chosen roles', () => {
  const { db, call, events } = setup();
  db.exec(`
    INSERT INTO users (id, username) VALUES ('carol', 'Carol');
    INSERT INTO roles (id, name) VALUES ('qa', 'QA');
    INSERT INTO user_roles VALUES ('carol', 'member'), ('carol', 'qa');
  `);
  const at = { channelId: 'plan' };
  const open = call('boards', 'post', '/:channelId/lists', 'bob', at, { name: 'Open' }).body;
  const secret = call('boards', 'post', '/:channelId/lists', 'bob', at, { name: 'Secret' }).body;
  assert.deepEqual([open.staff_only, open.cover_image, open.icon, open.role_ids], [false, null, null, []]);
  const list = '/:channelId/lists/:listId';
  const card = call('boards', 'post', '/:channelId/cards', 'alice', at, { listId: secret.id, title: 'Plan' }).body;

  // Appearance: only managers, only image references.
  assert.equal(call('boards', 'patch', list, 'alice', { ...at, listId: open.id }, { icon: '/ugc/images/a.png' }).statusCode, 403);
  assert.equal(call('boards', 'patch', list, 'bob', { ...at, listId: open.id }, { coverImage: 'javascript:alert(1)' }).statusCode, 400);
  assert.equal(call('boards', 'patch', list, 'bob', { ...at, listId: open.id }, { icon: 'https://elsewhere.example/i.png' }).statusCode, 400, 'only this realm\'s uploads');
  const styled = call('boards', 'patch', list, 'bob', { ...at, listId: open.id }, { coverImage: '/ugc/images/c.png', icon: '/ugc/images/i.png' }).body;
  assert.deepEqual([styled.name, styled.cover_image, styled.icon], ['Open', '/ugc/images/c.png', '/ugc/images/i.png']);
  assert.equal(call('boards', 'patch', list, 'bob', { ...at, listId: open.id }, { icon: null }).body.icon, null);
  assert.equal(styled.cover_size, null, 'covers fit the list unless a size is chosen');
  assert.equal(call('boards', 'patch', list, 'bob', { ...at, listId: open.id }, { coverSize: 300 }).statusCode, 400);
  assert.equal(call('boards', 'patch', list, 'bob', { ...at, listId: open.id }, { coverSize: 256 }).body.cover_size, 256);
  assert.equal(call('boards', 'patch', list, 'bob', { ...at, listId: open.id }, { coverSize: null }).body.cover_size, null);

  // Hide the list, sharing it with the QA role.
  assert.equal(call('boards', 'patch', list, 'bob', { ...at, listId: secret.id }, { roleIds: ['nope'] }).statusCode, 400);
  events.length = 0;
  const hidden = call('boards', 'patch', list, 'bob', { ...at, listId: secret.id }, { staffOnly: true, roleIds: ['qa'] }).body;
  assert.deepEqual([hidden.staff_only, hidden.role_ids], [true, ['qa']]);
  const listsSentTo = (id) => events.find((e) => e.event === 'board:lists-updated' && e.to === id).data.lists;
  assert.deepEqual(listsSentTo('alice').map((l) => l.name), ['Open']);
  assert.deepEqual(listsSentTo('carol').map((l) => l.name), ['Open', 'Secret']);
  assert.equal(listsSentTo('carol')[1].role_ids, undefined, 'only managers learn the roles');
  assert.deepEqual(listsSentTo('bob')[1].role_ids, ['qa']);

  const board = (userId) => call('boards', 'get', '/:channelId', userId, at).body;
  assert.deepEqual(board('alice').lists.map((l) => l.name), ['Open']);
  assert.deepEqual(board('alice').cards, [], 'her own card is hidden with its list');
  assert.deepEqual(board('carol').cards.map((c) => c.title), ['Plan']);
  assert.deepEqual(board('owner').lists.map((l) => l.name), ['Open', 'Secret']);

  // To someone who cannot see the list, it and its cards do not exist.
  const one = { ...at, itemId: card.id };
  assert.equal(call('boards', 'get', '/:channelId/cards/:itemId', 'alice', one).statusCode, 404);
  assert.equal(call('boards', 'patch', '/:channelId/cards/:itemId', 'alice', one, { title: 'x' }).statusCode, 404);
  assert.equal(call('boards', 'post', '/:channelId/cards/:itemId/comments', 'alice', one, { body: 'hi' }).statusCode, 404);
  assert.equal(call('boards', 'post', '/:channelId/cards', 'alice', at, { listId: secret.id, title: 'x' }).statusCode, 404);
  const visible = call('boards', 'post', '/:channelId/cards', 'alice', at, { listId: open.id, title: 'Public' }).body;
  const move = '/:channelId/cards/:itemId/position';
  assert.equal(call('boards', 'put', move, 'alice', { ...at, itemId: visible.id }, { listId: secret.id, index: 0 }).statusCode, 404);
  assert.equal(call('boards', 'get', '/:channelId/roles', 'alice', at).statusCode, 403);
  assert.deepEqual(call('boards', 'get', '/:channelId/roles', 'bob', at).body.map((r) => r.id).sort(), ['blind', 'qa', 'triage']);

  // Events about a hidden card reach only those who can see it.
  events.length = 0;
  assert.equal(call('boards', 'post', '/:channelId/cards/:itemId/comments', 'carol', one, { body: 'noted' }).statusCode, 201);
  call('boards', 'patch', '/:channelId/cards/:itemId', 'bob', one, { title: 'Plan B' });
  assert.deepEqual([...new Set(events.map((e) => e.to))].sort(), ['bob', 'carol', 'owner']);

  // Moving a card out of the hidden list: Alice only hears about the list she can see.
  events.length = 0;
  call('boards', 'put', move, 'carol', one, { listId: open.id, index: 0 });
  const moved = (id) => [...events.find((e) => e.event === 'board:cards-moved' && e.to === id).data.lists].map((l) => l.listId);
  assert.deepEqual(moved('alice'), [open.id]);
  assert.deepEqual(moved('bob').sort(), [open.id, secret.id].sort());

  // Board settings: managers only, validated, broadcast, and returned with the board.
  const settingsRoute = '/:channelId/settings';
  assert.deepEqual(JSON.parse(JSON.stringify(board('alice').settings)), { title: null, background: null });
  assert.equal(call('boards', 'patch', settingsRoute, 'alice', at, { title: 'Mine' }).statusCode, 403);
  assert.equal(call('boards', 'patch', settingsRoute, 'bob', at, { background: { kind: 'pattern', colors: ['red'], pattern: 'mesh' } }).statusCode, 400);
  assert.equal(call('boards', 'patch', settingsRoute, 'bob', at, { background: { kind: 'pattern', colors: ['#112233'], pattern: 'zigzag' } }).statusCode, 400);
  assert.equal(call('boards', 'patch', settingsRoute, 'bob', at, { background: { kind: 'pattern', colors: ['#112233'], pattern: 'mesh', scene: 'unknown' } }).statusCode, 400);
  assert.equal(call('boards', 'patch', settingsRoute, 'bob', at, { background: { kind: 'image', image: 'javascript:alert(1)' } }).statusCode, 400);
  assert.equal(call('boards', 'patch', settingsRoute, 'bob', at, { background: { kind: 'image', image: 'https://elsewhere.example/bg.png' } }).statusCode, 400);
  const saved = call('boards', 'patch', settingsRoute, 'bob', at, {
    title: '  Commissions  ', background: { kind: 'pattern', colors: ['#7C3AED', '#1e1b4b'], pattern: 'mesh', animated: 1, scene: 'particles' },
  }).body;
  assert.deepEqual(JSON.parse(JSON.stringify(saved)),
    { title: 'Commissions', background: { kind: 'pattern', colors: ['#7c3aed', '#1e1b4b'], pattern: 'mesh', animated: true, scene: 'particles' } });
  assert.equal(events.at(-1).event, 'board:settings-updated');
  assert.equal(board('alice').settings.title, 'Commissions');
  // A title on its own leaves the background alone; null goes back to the channel's name.
  const imaged = call('boards', 'patch', settingsRoute, 'bob', at, { background: { kind: 'image', image: '/ugc/images/bg.png' } }).body;
  assert.deepEqual([imaged.title, imaged.background.kind], ['Commissions', 'image']);
  const positioned = call('boards', 'patch', settingsRoute, 'bob', at, {
    background: { kind: 'image', image: '/ugc/images/bg.png', fit: true, positionX: 25, positionY: 80 },
  }).body.background;
  assert.deepEqual(JSON.parse(JSON.stringify(positioned)), { kind: 'image', image: '/ugc/images/bg.png', fit: true, positionX: 25, positionY: 80 });
  const cleared = call('boards', 'patch', settingsRoute, 'bob', at, { title: null, background: null }).body;
  assert.deepEqual(JSON.parse(JSON.stringify(cleared)), { title: null, background: null });

  // Making it public again shows it to everyone.
  call('boards', 'patch', list, 'bob', { ...at, listId: secret.id }, { staffOnly: false });
  assert.deepEqual(board('alice').lists.map((l) => l.name), ['Open', 'Secret']);
});

test('tracker: active workflow, priority and due date validate and round-trip', () => {
  const { db, call } = setup();
  const at = { channelId: 'bugs' };
  const created = call('tracker', 'post', '/:channelId/issues', 'alice', at, {
    title: 'Ship release', priority: 'high', dueAt: 1893455999,
  }).body;
  assert.equal(created.priority, 'high');
  assert.equal(created.due_at, 1893455999);
  const one = { ...at, itemId: created.id };
  assert.equal(call('tracker', 'patch', '/:channelId/issues/:itemId', 'alice', one, { state: 'in_progress' }).body.state, 'in_progress');
  assert.equal(call('tracker', 'patch', '/:channelId/issues/:itemId', 'alice', one, { state: 'blocked', priority: 'urgent', dueAt: null }).body.priority, 'urgent');
  assert.equal(call('tracker', 'get', '/:channelId/issues', 'alice', at, {}, { state: 'active' }).body.issues.length, 1);
  assert.equal(call('tracker', 'get', '/:channelId/issues', 'alice', at, {}, { state: 'blocked' }).body.issues.length, 1);
  assert.equal(call('tracker', 'get', '/:channelId/issues', 'alice', at, {}, { state: 'open' }).body.issues.length, 0);
  assert.deepEqual({ ...call('tracker', 'get', '/:channelId/issues', 'alice', at).body.counts },
    { open: 0, in_progress: 0, blocked: 1, closed: 0 });
  // An assignee who is neither author nor manager may change the state, and nothing else.
  const patch = '/:channelId/issues/:itemId';
  db.exec("INSERT INTO users (id, username) VALUES ('carol', 'Carol'); INSERT INTO user_roles VALUES ('carol', 'member');");
  assert.equal(call('tracker', 'patch', patch, 'carol', one, { state: 'closed' }).statusCode, 403);
  call('tracker', 'put', '/:channelId/issues/:itemId/assignees', 'bob', one, { userIds: ['carol'] });
  assert.equal(call('tracker', 'patch', patch, 'carol', one, { state: 'in_progress' }).body.state, 'in_progress');
  assert.equal(call('tracker', 'patch', patch, 'carol', one, { state: 'blocked', title: 'Mine now' }).statusCode, 403);
  assert.equal(call('tracker', 'patch', patch, 'carol', one, {}).statusCode, 403);
  assert.equal(call('tracker', 'patch', patch, 'carol', one, { state: 'blocked' }).body.state, 'blocked');
  assert.equal(call('tracker', 'patch', '/:channelId/issues/:itemId', 'alice', one, { priority: 'critical' }).statusCode, 400);
  assert.equal(call('tracker', 'patch', '/:channelId/issues/:itemId', 'alice', one, { dueAt: 'tomorrow' }).statusCode, 400);
  assert.equal(call('tracker', 'post', '/:channelId/issues', 'alice', at, { title: 'Bad', dueAt: -1 }).statusCode, 400);
  const detail = call('tracker', 'get', '/:channelId/issues/:itemId', 'alice', one).body;
  assert.deepEqual(detail.events.filter((event) => ['state', 'priority', 'due_date'].includes(event.type)).map((event) => event.type),
    ['state', 'state', 'priority', 'due_date', 'state', 'state']);
  assert.equal(detail.due_at, null);
  assert.equal(call('tracker', 'patch', '/:channelId/issues/:itemId', 'alice', one, { state: 'closed' }).body.state, 'closed');
  assert.equal(call('tracker', 'get', '/:channelId/issues', 'alice', at, {}, { state: 'active' }).body.issues.length, 0);
});

test('tracker: watching delivers changes only to other visible watchers', () => {
  const { call, events, db } = setup();
  const at = { channelId: 'bugs' };
  const issue = call('tracker', 'post', '/:channelId/issues', 'alice', at, { title: 'Watch me' }).body;
  const one = { ...at, itemId: issue.id };
  const detail = '/:channelId/issues/:itemId';
  assert.deepEqual({ watching: call('tracker', 'get', detail, 'alice', one).body.watching,
    count: call('tracker', 'get', detail, 'alice', one).body.watcher_count }, { watching: true, count: 1 });
  assert.equal(call('tracker', 'get', detail, 'bob', one).body.watching, false);
  assert.deepEqual(JSON.parse(JSON.stringify(call('tracker', 'put', '/:channelId/issues/:itemId/watch', 'bob', one).body)),
    { watching: true, watcher_count: 2 });
  events.length = 0;
  call('tracker', 'patch', detail, 'alice', one, { priority: 'urgent' });
  assert.deepEqual(events.filter((event) => event.event === 'tracker:watch-notification').map((event) => event.to), ['bob']);
  assert.equal(events.find((event) => event.event === 'tracker:watch-notification').data.issueId, issue.id);
  // A user who loses channel access stops receiving notifications.
  permissionModel.writeRoleKeys(db, 'triage', ['MANAGE_ISSUES', 'ASSIGN_ISSUES']);
  permissionModel.writeRoleKeys(db, 'member', ['VIEW_CHANNELS', 'READ_CHAT_HISTORY', 'CREATE_ISSUES', 'COMMENT_ON_ISSUES']);
  db.prepare('INSERT INTO channel_permission_overwrites (id, channel_id, target_type, target_id, deny) VALUES (?, ?, ?, ?, ?)')
    .run('hide-bob', 'bugs', 'user', 'bob', require('../src/permissions').PERMISSIONS.VIEW_CHANNELS);
  events.length = 0;
  call('tracker', 'patch', detail, 'alice', one, { priority: 'high' });
  assert.equal(events.some((event) => event.event === 'tracker:watch-notification'), false);
  assert.deepEqual(JSON.parse(JSON.stringify(call('tracker', 'delete', '/:channelId/issues/:itemId/watch', 'alice', one).body)),
    { watching: false, watcher_count: 1 });
});

test('tracker migration expands old state constraint without losing child rows', () => {
  const db = new Database(':memory:');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY);
    CREATE TABLE channels (id TEXT PRIMARY KEY);
    CREATE TABLE roles (id TEXT PRIMARY KEY, is_default INTEGER);
    CREATE TABLE role_permission_grants (role_id TEXT, permission_key TEXT, PRIMARY KEY(role_id, permission_key));
    INSERT INTO users VALUES ('alice');
    INSERT INTO channels VALUES ('bugs');
    CREATE TABLE board_lists (id TEXT PRIMARY KEY, channel_id TEXT, name TEXT, position INTEGER);
    CREATE TABLE channel_items (
      id TEXT PRIMARY KEY, channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK(kind IN ('issue', 'card')), title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '',
      created_by TEXT REFERENCES users(id) ON DELETE SET NULL, created_at INTEGER NOT NULL DEFAULT (unixepoch()),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch()), number INTEGER,
      state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open', 'closed')),
      closed_at INTEGER, closed_by TEXT, list_id TEXT REFERENCES board_lists(id) ON DELETE CASCADE,
      position INTEGER NOT NULL DEFAULT 0, due_at INTEGER, archived INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE channel_item_comments (id TEXT PRIMARY KEY, item_id TEXT NOT NULL REFERENCES channel_items(id) ON DELETE CASCADE,
      body TEXT, created_at INTEGER NOT NULL DEFAULT (unixepoch()));
    INSERT INTO channel_items (id, channel_id, kind, title) VALUES ('old', 'bugs', 'issue', 'Old issue');
    INSERT INTO channel_item_comments (id, item_id, body) VALUES ('comment', 'old', 'Still attached');
  `);
  channelItems.migrate(db);
  db.prepare("UPDATE channel_items SET state = 'blocked', priority = 'urgent' WHERE id = 'old'").run();
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM channel_item_comments WHERE item_id = 'old'").get().count, 1);
  assert.deepEqual(db.pragma('foreign_key_check'), []);
  db.close();
});

test('tracker attachments require permission, validate content and can be removed', async () => {
  const { db, call, routers, userFor } = setup();
  const issue = call('tracker', 'post', '/:channelId/issues', 'alice', { channelId: 'bugs' }, { title: 'Screenshot' }).body;
  const app = express();
  app.use((req, _res, next) => { req.user = userFor(req.headers['x-test-user'] || 'alice'); next(); });
  app.use('/api/tracker', routers.tracker);
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
  });
  const base = `http://127.0.0.1:${server.address().port}/api/tracker/bugs/issues/${issue.id}/attachments`;
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScL/nwAAAABJRU5ErkJggg==', 'base64');
  const upload = async (name, mime, bytes) => {
    const form = new FormData();
    form.append('file', new Blob([bytes], { type: mime }), name);
    return fetch(base, { method: 'POST', headers: { 'x-test-user': 'alice' }, body: form });
  };
  try {
    assert.equal((await upload('screenshot.png', 'image/png', png)).status, 403);
    permissionModel.writeRoleKeys(db, 'member', [...permissionModel.roleKeys(db, 'member'), 'ATTACH_FILES']);
    assert.equal((await upload('page.html', 'text/html', Buffer.from('<script>x</script>'))).status, 400);
    assert.equal((await upload('fake.png', 'image/png', Buffer.from('not an image'))).status, 400);
    const response = await upload('screenshot.png', 'image/png', png);
    assert.equal(response.status, 201);
    const attachment = await response.json();
    assert.deepEqual(Object.keys(attachment).sort(), ['created_at', 'id', 'mime', 'name', 'size', 'uploaded_by', 'url']);
    assert.equal(attachment.name, 'screenshot.png');
    assert.equal(fs.existsSync(path.join(attachmentDir, path.posix.basename(attachment.url))), true);
    const one = { channelId: 'bugs', itemId: issue.id };
    assert.equal(call('tracker', 'get', '/:channelId/issues/:itemId', 'alice', one).body.attachments.length, 1);
    const removeUrl = `${base}/${attachment.id}`;
    assert.equal((await fetch(removeUrl, { method: 'DELETE', headers: { 'x-test-user': 'hidden' } })).status, 403);
    assert.equal((await fetch(removeUrl, { method: 'DELETE', headers: { 'x-test-user': 'alice' } })).status, 200);
    assert.equal(call('tracker', 'get', '/:channelId/issues/:itemId', 'alice', one).body.attachments.length, 0);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('deleting a tracker issue or channel removes its attachment files', async () => {
  const { db, call, userFor } = setup();
  const addAttachment = (issueId, name) => {
    const file = path.join(attachmentDir, name);
    fs.writeFileSync(file, 'test attachment');
    db.prepare('INSERT INTO tracker_issue_attachments (id, item_id, name, url, mime, size, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(name, issueId, name, `/ugc/images/${name}`, 'text/plain', 15, 'alice');
    return file;
  };
  const waitForRemoval = async (file) => {
    for (let attempt = 0; attempt < 50 && fs.existsSync(file); attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(fs.existsSync(file), false);
  };

  const first = call('tracker', 'post', '/:channelId/issues', 'alice', { channelId: 'bugs' }, { title: 'Delete issue' }).body;
  const issueFile = addAttachment(first.id, 'cleanup-issue.txt');
  assert.equal(call('tracker', 'delete', '/:channelId/issues/:itemId', 'bob', { channelId: 'bugs', itemId: first.id }).statusCode, 200);
  await waitForRemoval(issueFile);

  const second = call('tracker', 'post', '/:channelId/issues', 'alice', { channelId: 'bugs' }, { title: 'Delete channel' }).body;
  const channelFile = addAttachment(second.id, 'cleanup-channel.txt');
  const channels = loadModule('src/routes/channels.js', {
    '../db': db,
    '../socket/handler': { broadcastChannelUpdate() {} },
    '../settings': {},
    '../messageCrypto': {},
    '../webhooks': { queueChannelDeletedEvent() {} },
    '../lib/auditLog': { AUDIT_ACTIONS: { CHANNEL_DELETE: 'CHANNEL_DELETE' }, logAuditAction() {} },
  }, { process: { env: { UGC_IMAGES_DIR: attachmentDir } } });
  const route = channels.stack.find((layer) => layer.route?.path === '/:id' && layer.route.methods.delete);
  const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
  route.route.stack[0].handle({ params: { id: 'bugs' }, user: userFor('owner') }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(db.prepare('SELECT 1 FROM channels WHERE id = ?').get('bugs'), undefined);
  await waitForRemoval(channelFile);
});
