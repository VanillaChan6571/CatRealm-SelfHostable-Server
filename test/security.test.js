const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { PERMISSIONS: P } = require('../src/permissions');
const { localUploadSuffix, resolveUploadForDeletion } = require('../src/lib/uploadPaths');
const { loadModule, makeDatabase, getUser, makeSocketHarness } = require('./helpers');

test('upload deletion rejects traversal, escaped paths, and symlinks outside uploads', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catrealm-files-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const uploads = path.join(root, 'uploads');
  fs.mkdirSync(path.join(uploads, 'thumbs'), { recursive: true });
  fs.writeFileSync(path.join(root, 'outside.txt'), 'keep');
  fs.writeFileSync(path.join(uploads, 'image.png'), 'synthetic');
  fs.writeFileSync(path.join(uploads, 'thumbs', 'image.webp'), 'synthetic');
  for (const suffix of ['../outside.txt', 'thumbs/../../outside.txt', '%2e%2e/outside.txt', '..\\outside.txt', '/outside.txt', 'image.png?x=1']) {
    assert.equal(localUploadSuffix(`/ugc/images/${suffix}`), null, suffix);
    assert.equal(resolveUploadForDeletion(uploads, `/ugc/images/${suffix}`), null, suffix);
  }
  assert.equal(resolveUploadForDeletion(uploads, '/ugc/images/image.png'), path.join(uploads, 'image.png'));
  assert.equal(resolveUploadForDeletion(uploads, '/ugc/images/thumbs/image.webp'), path.join(uploads, 'thumbs', 'image.webp'));
  fs.symlinkSync(path.join(root, 'outside.txt'), path.join(uploads, 'link.png'));
  assert.equal(resolveUploadForDeletion(uploads, '/ugc/images/link.png'), null);
  const db = makeDatabase();
  t.after(() => db.close());
  const h = makeSocketHarness(db, { directory: uploads });
  h.dispatch('message:send', { channelId: 'public', content: 'test', attachments: [{ url: '/ugc/images/../outside.txt' }] });
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM messages').get().n, 2);
  // Legacy malicious metadata must also be safe when deleting or expiring it.
  db.prepare('INSERT INTO messages (id, channel_id, user_id, attachment_url) VALUES (?, ?, ?, ?)')
    .run('malicious-old', 'public', 'alice', '/ugc/images/../outside.txt');
  h.dispatch('message:delete', { messageId: 'malicious-old' });
  assert.equal(fs.readFileSync(path.join(root, 'outside.txt'), 'utf8'), 'keep');
  db.prepare('INSERT INTO messages (id, channel_id, user_id, attachment_url, voice_expires_at) VALUES (?, ?, ?, ?, 1)')
    .run('expired-old', 'public', 'alice', '/ugc/images/../outside.txt');
  h.intervalCallbacks.find(item => item.delay === 60 * 60 * 1000).callback();
  assert.equal(fs.readFileSync(path.join(root, 'outside.txt'), 'utf8'), 'keep');
  // Legitimate, unreferenced uploads still get removed.
  h.dispatch('message:send', { channelId: 'public', content: 'test', attachments: [{ url: '/ugc/images/image.png' }] });
  const sent = h.events.findLast(event => event.event === 'message:new').data;
  h.dispatch('message:delete', { messageId: sent.id });
  assert.equal(fs.existsSync(path.join(uploads, 'image.png')), false);
});

test('expired attacker messages must not delete attachments still used by another member', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catrealm-expiry-security-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, 'victim.png');
  const url = '/ugc/images/victim.png';
  fs.writeFileSync(file, 'Synthetic attachment belonging to Bob');
  const db = makeDatabase();
  t.after(() => db.close());
  db.prepare('UPDATE messages SET attachment_url = ?, attachments = ? WHERE id = ?')
    .run(url, JSON.stringify([{ url, mime: 'image/png' }]), 'public-message');
  let completeUnlink;
  const unlinks = [];
  const h = makeSocketHarness(db, {
    directory: root,
    fakeFs: { ...fs, unlink(target, callback) {
      // Real unlink on synthetic data, with completion observed deterministically.
      unlinks.push(target);
      completeUnlink = new Promise(resolve => fs.unlink(target, error => { callback(error); resolve(); }));
    } },
  });
  h.dispatch('message:send', {
    channelId: 'public', content: 'Attacker references a known attachment',
    attachments: [{ url, mime: 'image/png' }], voice_expires_at: 1,
  });
  h.intervalCallbacks.find(item => item.delay === 60 * 60 * 1000).callback();
  if (completeUnlink) await completeUnlink;
  assert(db.prepare('SELECT id FROM messages WHERE id = ?').get('public-message'));
  assert.equal(unlinks.length, 0, 'Expiry must check surviving attachment references before unlinking');
  assert.equal(fs.existsSync(file), true);
});

test('expiry removes unreferenced batch attachments and thumbnails but preserves shared thumbnails', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catrealm-expiry-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of ['voice.mp3', 'unused.webp', 'shared.webp']) fs.writeFileSync(path.join(root, name), 'fixture');
  const db = makeDatabase();
  t.after(() => db.close());
  db.prepare('UPDATE messages SET attachments = ? WHERE id = ?')
    .run(JSON.stringify([{ thumbnailUrl: '/ugc/images/shared.webp' }]), 'public-message');
  const insert = db.prepare('INSERT INTO messages (id, channel_id, user_id, attachments, voice_expires_at) VALUES (?, ?, ?, ?, 1)');
  insert.run('expired-1', 'public', 'alice', JSON.stringify([{ url: '/ugc/images/voice.mp3', thumbnailUrl: '/ugc/images/unused.webp' }]));
  insert.run('expired-2', 'public', 'alice', JSON.stringify([{ url: '/ugc/images/voice.mp3', thumbnail_url: '/ugc/images/shared.webp' }]));
  const h = makeSocketHarness(db, { directory: root });
  h.intervalCallbacks.find(item => item.delay === 60 * 60 * 1000).callback();
  assert.equal(fs.existsSync(path.join(root, 'voice.mp3')), false);
  assert.equal(fs.existsSync(path.join(root, 'unused.webp')), false);
  assert.equal(fs.existsSync(path.join(root, 'shared.webp')), true);
});

test('manual deletion preserves another members shared attachment', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catrealm-shared-security-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, 'shared.png');
  const url = '/ugc/images/shared.png';
  fs.writeFileSync(file, 'Synthetic shared attachment');
  const db = makeDatabase();
  t.after(() => db.close());
  db.prepare('UPDATE messages SET attachments = ? WHERE id = ?')
    .run(JSON.stringify([{ url }]), 'public-message');
  const h = makeSocketHarness(db, { directory: root });
  h.dispatch('message:send', { channelId: 'public', attachments: [{ url }] });
  const sent = h.events.findLast(event => event.event === 'message:new').data;
  h.dispatch('message:delete', { messageId: sent.id });
  assert.equal(fs.existsSync(file), true);
});

test('permission revocation removes channel/thread subscriptions and affects existing handlers', (t) => {
  const db = makeDatabase();
  t.after(() => db.close());
  const h = makeSocketHarness(db);
  h.dispatch('thread:join', 'private-thread');
  assert(h.socket.rooms.has('private'));
  assert(h.socket.rooms.has('thread:private-thread'));
  db.prepare('INSERT INTO channel_permission_overwrites (channel_id, target_type, target_id, deny) VALUES (?, ?, ?, ?)')
    .run('private', 'user', 'alice', P.VIEW_CHANNELS);
  db.prepare('UPDATE roles SET permissions = permissions - ? WHERE id = ?').run(P.SEND_MESSAGES, 'member');
  h.api.emitPermissionsChanged();
  assert(!h.socket.rooms.has('private'));
  assert(!h.socket.rooms.has('thread:private-thread'));
  assert(h.socket.rooms.has(h.socket.id));
  h.dispatch('message:send', { channelId: 'public', content: 'must fail' });
  assert.equal(h.events.at(-1).event, 'error');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM messages').get().n, 2);
  db.prepare('UPDATE roles SET permissions = permissions + ? WHERE id = ?').run(P.SEND_MESSAGES, 'member');
  h.api.emitPermissionsChanged();
  h.dispatch('message:send', { channelId: 'public', content: 'allowed again' });
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM messages').get().n, 3);
});

test('losing read-history permission removes message rooms and blocks thread rejoin', (t) => {
  const db = makeDatabase();
  t.after(() => db.close());
  const h = makeSocketHarness(db);
  db.prepare('UPDATE roles SET permissions = permissions - ? WHERE id = ?').run(P.READ_CHAT_HISTORY, 'member');
  h.api.emitPermissionsChanged();
  assert(!h.socket.rooms.has('public'));
  h.dispatch('thread:join', 'public-thread');
  assert(!h.socket.rooms.has('thread:public-thread'));
});

test('replies and forwards check source access before disclosing content', (t) => {
  const db = makeDatabase();
  t.after(() => db.close());
  db.prepare('INSERT INTO channel_permission_overwrites (channel_id, target_type, target_id, deny) VALUES (?, ?, ?, ?)')
    .run('private', 'user', 'alice', P.VIEW_CHANNELS);
  const h = makeSocketHarness(db);
  for (const source of [{ replyToId: 'private-message' }, { forwardFromId: 'private-message' }]) {
    h.dispatch('message:send', { channelId: 'public', content: 'test', ...source });
    assert.equal(h.events.at(-1).event, 'error');
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM messages').get().n, 2);
  }
  h.dispatch('message:send', { channelId: 'public', content: 'valid reply', replyToId: 'public-message' });
  assert.equal(h.events.findLast(event => event.event === 'message:new').data.reply_to.content, 'Public content');
  db.prepare('UPDATE messages SET scheduled_at = 9999999999 WHERE id = ?').run('public-message');
  h.dispatch('message:send', { channelId: 'public', content: 'unpublished reply', replyToId: 'public-message' });
  assert.equal(h.events.at(-1).event, 'error');
});

test('forwarding rejects unreadable and scheduled sources even when their channel is visible', t => {
  const db = makeDatabase();
  t.after(() => db.close());
  db.prepare('INSERT INTO channel_permission_overwrites (channel_id, target_type, target_id, deny) VALUES (?, ?, ?, ?)')
    .run('private', 'user', 'alice', P.READ_CHAT_HISTORY);
  const h = makeSocketHarness(db);
  h.dispatch('message:send', { channelId: 'public', content: 'forward', forwardFromId: 'private-message' });
  assert.equal(h.events.at(-1).event, 'error');
  db.prepare('DELETE FROM channel_permission_overwrites').run();
  db.prepare('UPDATE messages SET scheduled_at = ? WHERE id = ?').run(9999999999, 'private-message');
  h.dispatch('message:send', { channelId: 'public', content: 'forward', forwardFromId: 'private-message' });
  assert.equal(h.events.at(-1).event, 'error');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM messages').get().n, 2);
});

function routeHandler(router, method, url) {
  return router.stack.find(layer => layer.route?.path === url && layer.route.methods[method]).route.stack.at(-1).handle;
}
function response() {
  return { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(data) { this.data = data; return this; } };
}

test('thread mutations require channel access and authorship or moderation permission', (t) => {
  const db = makeDatabase();
  t.after(() => db.close());
  const router = loadModule('src/routes/threads.js', {
    '../db': db, '../socket/handler': { emitToChannel() {} },
    '../reactions': { attachReactionsToMessages: rows => rows },
  });
  for (const method of ['patch', 'delete']) {
    const handler = routeHandler(router, method, '/:id');
    const denied = response();
    handler({ user: getUser(db), params: { id: 'public-thread' }, body: { name: 'Changed' } }, denied);
    assert.equal(denied.statusCode, 403);
  }
  const patch = routeHandler(router, 'patch', '/:id');
  const own = response();
  patch({ user: getUser(db, 'bob'), params: { id: 'public-thread' }, body: { name: 'Own edit' } }, own);
  assert.equal(own.statusCode, 200);
  const moderator = { ...getUser(db), permissions: getUser(db).permissions + P.MANAGE_POSTS };
  const moderated = response();
  patch({ user: moderator, params: { id: 'public-thread' }, body: { name: 'Moderated' } }, moderated);
  assert.equal(moderated.statusCode, 200);
  db.prepare('INSERT INTO channel_permission_overwrites (channel_id, target_type, target_id, deny) VALUES (?, ?, ?, ?)')
    .run('private', 'user', 'alice', P.VIEW_CHANNELS);
  const inaccessible = response();
  patch({ user: moderator, params: { id: 'private-thread' }, body: { name: 'Hidden' } }, inaccessible);
  assert.equal(inaccessible.statusCode, 403);
  const deleted = response();
  routeHandler(router, 'delete', '/:id')({ user: moderator, params: { id: 'public-thread' } }, deleted);
  assert.equal(deleted.statusCode, 200);
});

test('history omits legacy cross-channel and unpublished reply content', (t) => {
  const db = makeDatabase();
  t.after(() => db.close());
  const dependencies = { '../db': db, '../socket/handler': { emitToChannel() {} },
    '../middleware/rateLimits': { searchLimiter: (_req, _res, next) => next() },
    '../reactions': { attachReactionsToMessages: rows => rows } };
  const channels = loadModule('src/routes/messages.js', dependencies);
  const threads = loadModule('src/routes/threads.js', dependencies);
  for (const threadId of [null, 'public-thread']) {
    db.prepare('INSERT OR REPLACE INTO messages (id, channel_id, user_id, content, reply_to_id, thread_id) VALUES (?, ?, ?, ?, ?, ?)')
      .run('legacy-reply', 'public', 'alice', 'Public reply', 'private-message', threadId);
    const res = response();
    const router = threadId ? threads : channels;
    routeHandler(router, 'get', threadId ? '/:id/messages' : '/:channelId')({
      user: getUser(db), params: threadId ? { id: threadId } : { channelId: 'public' }, query: {},
    }, res);
    assert.equal(res.data.find(message => message.id === 'legacy-reply').reply_to, null);
    assert(!JSON.stringify(res.data).includes('Private content'));
  }
  db.prepare('UPDATE messages SET scheduled_at = ? WHERE id = ?').run(9999999999, 'public-message');
  for (const threadId of [null, 'public-thread']) {
    db.prepare('UPDATE messages SET reply_to_id = ?, thread_id = ? WHERE id = ?')
      .run('public-message', threadId, 'legacy-reply');
    const res = response();
    routeHandler(threadId ? threads : channels, 'get', threadId ? '/:id/messages' : '/:channelId')({
      user: getUser(db), params: threadId ? { id: threadId } : { channelId: 'public' }, query: {},
    }, res);
    assert.equal(res.data.find(message => message.id === 'legacy-reply').reply_to, null);
    assert(!JSON.stringify(res.data).includes('Public content'));
  }
});
