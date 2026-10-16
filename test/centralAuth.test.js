const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { loadModule, makeDatabase } = require('./helpers');

test('new local account usernames require four characters while existing short accounts can log in', async t => {
  const db = makeDatabase();
  t.after(() => db.close());
  db.exec('ALTER TABLE users ADD COLUMN password TEXT; ALTER TABLE users ADD COLUMN onboarding_completed INTEGER DEFAULT 1');
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(bcrypt.hashSync('password123', 4), 'bob');
  const router = loadModule('src/routes/auth.js', {
    '../db': db,
    '../middleware/auth': {
      JWT_SECRET: 'synthetic-realm-secret', SERVER_MODE: 'decentral_only',
      checkUsernameConflict: async () => false, authenticateToken: (_req, _res, next) => next(),
    },
    '../permissions': { computePermissionsForUser: () => 0 },
    '../logger': () => {},
    '../usernameBlocklist': { isBlockedUsername: () => false },
    '../settings': { getSetting: (_key, fallback) => fallback },
    '../lib/auditLog': { AUDIT_ACTIONS: { MEMBER_JOIN: 'member_join' }, logAuditAction: () => {} },
  });
  const app = express();
  app.use(express.json());
  app.use('/api/auth', router);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const post = async (path, username) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/auth/${path}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: 'password123' }),
    });
    return { status: response.status, body: await response.json() };
  };

  const short = await post('register', 'Nya');
  assert.equal(short.status, 400);
  assert.match(short.body.error, /4-32 characters/);
  const accepted = await post('register', 'Nya4');
  assert.equal(accepted.status, 201);
  assert.equal(accepted.body.user.username, 'Nya4');
  assert.equal((await post('login', 'Bob')).status, 200);
});

test('a new realm exchanges an audience-bound assertion with central before issuing its local token', async t => {
  const db = makeDatabase();
  t.after(() => db.close());
  db.exec("ALTER TABLE users ADD COLUMN central_id TEXT; UPDATE users SET central_id = 'central-alice' WHERE id = 'alice'");

  const realmOrigin = 'https://realm.example';
  const assertion = jwt.sign({ type: 'realm_assertion', aud: realmOrigin, sub: 'central-alice' }, 'synthetic-central-secret');
  const verifyCalls = [];
  const axios = {
    get: async (url, config) => {
      verifyCalls.push({ url, config });
      const valid = url === 'https://auth.catrealm.app/api/verify'
        && config.headers.Authorization === `Bearer ${assertion}`
        && config.headers['X-CatRealm-Realm-Origin'] === realmOrigin;
      return { data: { valid, audience: realmOrigin, user: { id: 'central-alice', username: 'Alice', verified: true } } };
    },
    isAxiosError: () => false,
  };
  const router = loadModule('src/routes/auth.js', {
    '../db': db,
    axios,
    '../middleware/auth': {
      JWT_SECRET: 'synthetic-realm-secret', SERVER_MODE: 'mixed',
      checkUsernameConflict: async () => false, authenticateToken: (_req, _res, next) => next(),
    },
    '../permissions': { computePermissionsForUser: () => 0 },
    '../logger': () => {},
    '../usernameBlocklist': { isBlockedUsername: () => false },
    '../settings': { getSetting: (_key, fallback) => fallback },
    '../lib/auditLog': { AUDIT_ACTIONS: {}, logAuditAction: () => {} },
  }, {
    process: { env: {
      AUTH_SERVER_URL: 'https://auth.catrealm.app',
      PUBLIC_SERVER_URL: realmOrigin,
      SERVER_URL: 'http://0.0.0.0:40500',
    } },
  });
  const app = express();
  app.use(express.json());
  app.use('/api/auth', router);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const post = async token => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/auth/central`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }),
    });
    return { status: response.status, body: await response.json() };
  };

  const accepted = await post(assertion);
  assert.equal(accepted.status, 200);
  assert.equal(jwt.verify(accepted.body.token, 'synthetic-realm-secret').account_type, 'central');
  assert.equal(verifyCalls.length, 1);

  const legacy = jwt.sign({ type: 'central', sub: 'central-alice' }, 'synthetic-central-secret');
  assert.equal((await post(legacy)).status, 401);
  assert.equal((await post(jwt.sign({ type: 'realm_assertion', aud: 'https://other.example' }, 'synthetic-central-secret'))).status, 401);
  assert.equal(verifyCalls.length, 1, 'wrong-purpose or wrong-audience tokens must not reach central');
});
