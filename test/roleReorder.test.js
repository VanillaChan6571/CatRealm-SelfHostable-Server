const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const { loadModule } = require('./helpers');
const { PERMISSIONS } = require('../src/permissions');

function setup() {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT, permissions INTEGER, position INTEGER, is_default INTEGER DEFAULT 0, category_id TEXT);
    CREATE TABLE role_categories (id TEXT PRIMARY KEY, name TEXT, position INTEGER);
    CREATE TABLE user_roles (user_id TEXT, role_id TEXT);
    INSERT INTO roles VALUES ('cats', 'Cats', 0, 0, 1, NULL), ('admin', 'Admin', 0, 3, 0, NULL),
      ('mod', 'Mod', 0, 2, 0, NULL), ('rebel', 'Rebel', 0, 1, 0, NULL);
    INSERT INTO role_categories VALUES ('a', 'A', 0), ('b', 'B', 1);
    INSERT INTO user_roles VALUES ('modUser', 'cats'), ('modUser', 'mod');
  `);
  const audits = [];
  const router = loadModule('src/routes/admin.js', {
    '../db': db,
    '../middleware/auth': { SERVER_MODE: 'standalone' },
    '../settings': { getSetting: () => null, setSetting() {} },
    '../permissions': { PERMISSIONS, hasPermission: () => true },
    '../socket/handler': { emitServerInfoUpdate() {}, emitPermissionsChanged() {}, kickUserFromServer() {} },
    '../diagnosticCommands': {},
    '../theaterYouTubeCookies': {},
    '../webhooks': {},
    '../lib/theaterUploadLimits': {},
    '../lib/auditLog': { AUDIT_ACTIONS: { ROLE_UPDATE: 'ROLE_UPDATE' }, logAuditAction: (...a) => audits.push(a), diffFields: () => null },
  });
  const call = (path, user, body, params = {}) => {
    const layer = router.stack.find((l) => l.route?.path === path && l.route.methods.put);
    const handlers = layer.route.stack.map((s) => s.handle);
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
    const req = { params, body, user };
    const run = (i) => handlers[i] && handlers[i](req, res, () => run(i + 1));
    run(0);
    return res;
  };
  const order = () => db.prepare('SELECT id FROM roles ORDER BY position DESC').all().map((r) => r.id);
  return { db, call, order, audits };
}

const owner = { id: 'owner', is_owner: 1 };
const mod = { id: 'modUser', is_owner: 0 };

test('owner can reorder any role; default role stays lowest', () => {
  const { call, order, audits } = setup();
  const res = call('/roles/reorder', owner, { roleIds: ['rebel', 'admin', 'mod'] });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(order(), ['rebel', 'admin', 'mod', 'cats']);
  assert.equal(audits.length, 1);
});

test('reorder must list every non-default role exactly once', () => {
  const { call } = setup();
  assert.equal(call('/roles/reorder', owner, { roleIds: ['admin', 'mod'] }).statusCode, 400);
  assert.equal(call('/roles/reorder', owner, { roleIds: ['admin', 'mod', 'mod'] }).statusCode, 400);
  assert.equal(call('/roles/reorder', owner, { roleIds: ['admin', 'mod', 'cats'] }).statusCode, 400);
});

test('non-owner can only rearrange roles below their highest role', () => {
  const { call, order } = setup();
  // modUser's top role is Mod (2): Admin and Mod are locked at the top.
  assert.equal(call('/roles/reorder', mod, { roleIds: ['rebel', 'admin', 'mod'] }).statusCode, 403);
  assert.equal(call('/roles/reorder', mod, { roleIds: ['mod', 'admin', 'rebel'] }).statusCode, 403);
  assert.deepEqual(order(), ['admin', 'mod', 'rebel', 'cats']);
  assert.equal(call('/roles/reorder', mod, { roleIds: ['admin', 'mod', 'rebel'] }).statusCode, 200);
});

test('PUT /roles/:id rejects position changes at or above the actor', () => {
  const { call, db } = setup();
  const pos = (id) => db.prepare('SELECT position FROM roles WHERE id = ?').get(id).position;
  assert.equal(call('/roles/:id', mod, { position: 1 }, { id: 'admin' }).statusCode, 403);
  assert.equal(call('/roles/:id', mod, { position: 5 }, { id: 'rebel' }).statusCode, 403);
  assert.equal(pos('admin'), 3);
  assert.equal(pos('rebel'), 1);
  assert.equal(call('/roles/:id', owner, { position: 9 }, { id: 'rebel' }).statusCode, 200);
  assert.equal(pos('rebel'), 9);
});

test('role categories reorder', () => {
  const { call, db } = setup();
  assert.equal(call('/role-categories/reorder', mod, { categoryIds: ['b'] }).statusCode, 400);
  const res = call('/role-categories/reorder', mod, { categoryIds: ['b', 'a'] });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(db.prepare('SELECT id FROM role_categories ORDER BY position').all().map((c) => c.id), ['b', 'a']);
});
