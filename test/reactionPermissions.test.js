const test = require('node:test');
const assert = require('node:assert/strict');
const { PERMISSIONS } = require('../src/permissions');
const { loadModule, makeDatabase, makeSocketHarness } = require('./helpers');

test('external reactions require permission, while existing reactions can be removed', (t) => {
  const db = makeDatabase();
  t.after(() => db.close());
  db.exec('CREATE TABLE message_reactions (message_id TEXT, user_id TEXT, emoji TEXT, created_at INTEGER DEFAULT 1)');
  db.prepare('UPDATE roles SET permissions = permissions + ? WHERE id = ?').run(PERMISSIONS.ADD_REACTIONS, 'member');
  const reactions = loadModule('src/reactions.js', { './db': db });
  const h = makeSocketHarness(db, { overrides: { '../reactions': reactions } });
  const emoji = ':https://other.example:cat:';
  const react = () => {
    let result;
    h.dispatch('message:react', { messageId: 'public-message', emoji }, (ack) => { result = ack; });
    return result;
  };

  assert.match(react().error, /use_external_emotes/);
  assert.equal(db.prepare('SELECT count(*) AS n FROM message_reactions').get().n, 0);

  let personalAck;
  h.dispatch('message:react', { messageId: 'public-message', emoji: ':cat:alice:' }, (ack) => { personalAck = ack; });
  assert.match(personalAck.error, /use_external_emotes/);
  assert.equal(db.prepare('SELECT count(*) AS n FROM message_reactions').get().n, 0);

  db.prepare('INSERT INTO message_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)')
    .run('public-message', 'alice', emoji);
  assert.equal(react().reacted, false);
  assert.equal(db.prepare('SELECT count(*) AS n FROM message_reactions').get().n, 0);
});
