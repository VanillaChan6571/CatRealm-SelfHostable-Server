const test = require('node:test');
const assert = require('node:assert/strict');
const { makeDatabase, makeSocketHarness } = require('./helpers');

function setup(t, clientType = 'mobile') {
  const db = makeDatabase();
  t.after(() => db.close());
  db.exec(`
    INSERT INTO channels (id, name, type) VALUES ('theater', 'Movies', 'theater');
    CREATE TABLE theater_state (channel_id TEXT PRIMARY KEY, current_item_id TEXT,
      position_ms INTEGER DEFAULT 0, duration_ms INTEGER DEFAULT 0, playing INTEGER DEFAULT 0,
      host_user_id TEXT, updated_at INTEGER DEFAULT (unixepoch()));
    CREATE TABLE theater_queue (id TEXT PRIMARY KEY, channel_id TEXT, added_by TEXT,
      position INTEGER, created_at INTEGER, cached_path TEXT);
  `);
  return makeSocketHarness(db, { clientType });
}
const member = h => h.events.findLast(e => e.event === 'theater:room-users').data.users[0];

test('mobile video-only presence reaches join replies, sidebar broadcasts, and room snapshots', t => {
  const h = setup(t);
  let reply;
  h.dispatch('theater:join', { channelId: 'theater', voiceConnected: false, clientType: 'desktop' }, data => { reply = data; });
  assert.equal(reply.ok, true);
  assert.equal(reply.users[0].clientType, 'mobile', 'Device type comes from the session, not a join payload');
  assert.equal(reply.users[0].voiceConnected, false);
  assert.equal(member(h).voiceConnected, false);
  h.dispatch('theater:rooms:get', data => { reply = data; });
  assert.equal(reply.rooms[0].users[0].voiceConnected, false);
});

test('voice joins and leaves update presence without removing the theater viewer', t => {
  const h = setup(t);
  h.dispatch('theater:join', { channelId: 'theater', voiceConnected: false });
  h.dispatch('theater:voice-state', { channelId: 'theater', voiceConnected: true });
  assert.equal(member(h).voiceConnected, true);
  assert.equal(member(h).micEnabled, false, 'Joining a call does not unmute');
  h.dispatch('theater:mic-state', { channelId: 'theater', micEnabled: true });
  assert.equal(member(h).micEnabled, true);
  h.dispatch('theater:voice-state', { channelId: 'theater', voiceConnected: false });
  assert.equal(member(h).voiceConnected, false);
  assert.equal(member(h).muted, true);
  assert.equal(member(h).micEnabled, false);
  assert.equal(h.socket.currentTheaterChannel, 'theater');
  assert(h.socket.rooms.has('theater:theater'));
  const update = h.events.findLast(e => e.event === 'theater:user-state');
  assert.equal(update.data.voiceConnected, false);
  assert.equal(update.data.userId, 'alice');
  h.dispatch('theater:mic-state', { channelId: 'theater', micEnabled: true });
  assert.equal(member(h).micEnabled, false, 'Video-only presence cannot claim an enabled mic');
});

test('malformed, out-of-room, and stale-socket voice updates are ignored', t => {
  const h = setup(t);
  h.dispatch('theater:join', { channelId: 'theater', voiceConnected: false });
  const before = h.events.length;
  h.dispatch('theater:voice-state', { channelId: 'theater', voiceConnected: 'true' });
  h.dispatch('theater:voice-state', { channelId: 'public', voiceConnected: true });
  h.dispatch('theater:voice-state', undefined);
  h.dispatch('theater:voice-state', null);
  h.socket.id = 'replaced-socket';
  h.dispatch('theater:voice-state', { channelId: 'theater', voiceConnected: true });
  h.dispatch('theater:mic-state', { channelId: 'theater', micEnabled: true });
  h.dispatch('theater:camera-state', { channelId: 'theater', cameraEnabled: true });
  h.dispatch('theater:deafen-state', { channelId: 'theater', deafened: true });
  assert.equal(h.events.length, before);
  assert.equal(member(h).voiceConnected, false);
});

for (const clientType of ['mobile', 'desktop']) {
  test(`legacy ${clientType} clients keep unknown voice presence and existing mic controls`, t => {
    const h = setup(t, clientType);
    h.dispatch('theater:join', { channelId: 'theater' });
    assert.equal(member(h).clientType, clientType);
    assert.equal(member(h).voiceConnected, undefined);
    h.dispatch('theater:mic-state', { channelId: 'theater', micEnabled: true });
    assert.equal(member(h).micEnabled, true);
  });
}
