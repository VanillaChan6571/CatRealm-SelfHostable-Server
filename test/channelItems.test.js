const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const { loadModule } = require('./helpers');
const permissionModel = require('../src/permissionModel');
const channelItems = require('../src/channelItems');

function setup() {
  const db = new Database(':memory:');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT, role TEXT DEFAULT 'member', is_owner INTEGER DEFAULT 0,
      avatar TEXT, display_name TEXT, account_type TEXT DEFAULT 'local');
    CREATE TABLE display_name_overrides (user_id TEXT, display_name TEXT);
    CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT, permissions INTEGER DEFAULT 0, is_default INTEGER DEFAULT 0);
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
  const overrides = {
    '../db': db,
    '../socket/handler': { emitToChannel: (channelId, event, data) => events.push({ channelId, event, data }) },
    '../lib/auditLog': { logAuditAction: (...args) => audits.push(args) },
    '../channelItems': channelItems,
  };
  const routers = { tracker: loadModule('src/routes/tracker.js', overrides), boards: loadModule('src/routes/boards.js', overrides) };
  const userFor = (id) => {
    const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
    return { ...row, permission_keys: require('../src/permissions').computePermissionKeysForUser(id, row.role, row.is_owner, db) };
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
  return { db, call, events, audits };
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
  assert.deepEqual({ ...list({}).counts }, { open: 1, closed: 1 });

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
  assert.equal(events.at(-1).event, 'tracker:comment-created');
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
