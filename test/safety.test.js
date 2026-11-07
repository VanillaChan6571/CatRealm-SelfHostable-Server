const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const { loadModule } = require('./helpers');

function setup() {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE users (id TEXT PRIMARY KEY, created_at INTEGER, central_id TEXT);
    CREATE TABLE channels (id TEXT PRIMARY KEY);
    CREATE TABLE messages (id TEXT PRIMARY KEY, channel_id TEXT, user_id TEXT, content TEXT, attachments TEXT, attachment_url TEXT, attachment_type TEXT);
    CREATE TABLE safety_reports (id TEXT PRIMARY KEY, reporter_user_id TEXT, subject_user_id TEXT, channel_id TEXT, message_id TEXT, artifact_kind TEXT, artifact_key TEXT, reason TEXT, evidence_encrypted TEXT, status TEXT DEFAULT 'pending', reviewed_by TEXT, reviewed_at INTEGER, review_note_encrypted TEXT, created_at INTEGER, updated_at INTEGER, UNIQUE(reporter_user_id, channel_id, message_id, artifact_key));
    CREATE TABLE safety_artifact_visibility (channel_id TEXT, message_id TEXT, artifact_key TEXT, viewer_user_id TEXT, state TEXT, created_at INTEGER, PRIMARY KEY(channel_id, message_id, artifact_key, viewer_user_id));
    CREATE TABLE safety_restrictions (subject_user_id TEXT PRIMARY KEY, status TEXT, reason TEXT, expires_at INTEGER, created_at INTEGER, lifted_at INTEGER, lifted_by TEXT);
    CREATE TABLE safety_report_events (id TEXT PRIMARY KEY, report_id TEXT, actor_user_id TEXT, event_type TEXT, metadata_encrypted TEXT, created_at INTEGER);
    CREATE TABLE safety_quarantined_uploads (upload_path TEXT PRIMARY KEY, report_id TEXT, channel_id TEXT, message_id TEXT, artifact_key TEXT, status TEXT, created_at INTEGER, cleared_at INTEGER);
  `);
  for (const id of ['sender', 'reporter-a', 'reporter-b', 'viewer']) db.prepare('INSERT INTO users (id, created_at) VALUES (?, 1)').run(id);
  db.prepare('INSERT INTO channels (id) VALUES (?)').run('general');
  db.prepare('INSERT INTO messages VALUES (?, ?, ?, ?, ?, NULL, NULL)').run(
    'message-1', 'general', 'sender', 'look https://unsafe.example/path',
    JSON.stringify([{ url: '/ugc/images/evidence.png', mime: 'image/png' }]),
  );
  const safety = loadModule('src/safety.js', {
    './db': db,
    './messageCrypto': {
      encryptMessageContent: (value) => value,
      decryptMessageContent: (value) => value,
    },
  });
  return { db, safety };
}

test('realm reports hide privately, quarantine at quorum, and restrict the sender', () => {
  const { db, safety } = setup();
  const body = { channelId: 'general', messageId: 'message-1', artifactKind: 'image', artifactKey: 'attachment:0', reason: 'suspected_csam' };
  const first = safety.submitReport('reporter-a', body);
  assert.equal(first.quarantined, false);
  assert.equal(safety.isMediaLinkRestricted('sender'), true);
  const second = safety.submitReport('reporter-b', body);
  assert.equal(second.quarantined, true);
  assert.equal(db.prepare(`SELECT COUNT(*) AS count FROM safety_artifact_visibility WHERE state = 'quarantined'`).get().count, 2);
  assert.equal(safety.isUploadQuarantined('/ugc/images/evidence.png'), true);
  const [visible] = safety.attachSafetyArtifacts([db.prepare(`SELECT * FROM messages WHERE id = 'message-1'`).get()], 'viewer');
  assert.equal(visible.safety_artifacts.length, 1);
  assert.equal(visible.safety_artifacts[0].artifactKey, 'attachment:0');
  assert.equal(visible.safety_artifacts[0].state, 'quarantined');
  assert.equal(visible.safety_artifacts[0].hiddenForUser, true);
});

test('new Realm accounts do not satisfy quarantine quorum', () => {
  const { db, safety } = setup();
  db.prepare(`UPDATE users SET created_at = unixepoch() WHERE id = 'reporter-b'`).run();
  const body = { channelId: 'general', messageId: 'message-1', artifactKind: 'image', artifactKey: 'attachment:0', reason: 'suspected_csam' };
  safety.submitReport('reporter-a', body);
  const second = safety.submitReport('reporter-b', body);
  assert.equal(second.quarantined, false);
});

test('dismissing a duplicate Realm report preserves a confirmed removal', () => {
  const { db, safety } = setup();
  const body = { channelId: 'general', messageId: 'message-1', artifactKind: 'image', artifactKey: 'attachment:0', reason: 'suspected_csam' };
  const first = safety.submitReport('reporter-a', body);
  const second = safety.submitReport('reporter-b', body);
  safety.reviewReport('viewer', first.id, 'confirmed', 'confirmed');
  safety.reviewReport('viewer', second.id, 'dismissed', 'duplicate');
  assert.equal(db.prepare(`SELECT state FROM safety_artifact_visibility WHERE message_id = 'message-1' LIMIT 1`).get().state, 'removed');
  assert.equal(safety.isUploadQuarantined('/ugc/images/evidence.png'), true);
});

test('realm review removes confirmed artifacts and dismissing the only report lifts restriction', () => {
  const { db, safety } = setup();
  const image = safety.submitReport('reporter-a', { channelId: 'general', messageId: 'message-1', artifactKind: 'image', artifactKey: 'attachment:0', reason: 'suspected_csam' });
  safety.reviewReport('reporter-b', image.id, 'confirmed', 'confirmed by reviewer');
  assert.equal(db.prepare(`SELECT state FROM safety_artifact_visibility WHERE message_id = 'message-1'`).get().state, 'removed');

  db.prepare(`DELETE FROM safety_reports`).run();
  db.prepare(`DELETE FROM safety_artifact_visibility`).run();
  db.prepare(`UPDATE safety_restrictions SET status = 'lifted'`).run();
  const link = safety.submitReport('reporter-a', { channelId: 'general', messageId: 'message-1', artifactKind: 'link', artifactKey: 'link:https://unsafe.example/path', reason: 'grooming_or_exploitation' });
  safety.reviewReport('reporter-b', link.id, 'dismissed', 'false positive');
  assert.equal(safety.isMediaLinkRestricted('sender'), false);
});
