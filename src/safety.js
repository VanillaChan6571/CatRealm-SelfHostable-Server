const { randomUUID } = require('crypto');
const db = require('./db');
const { encryptMessageContent, decryptMessageContent } = require('./messageCrypto');

const REPORT_REASONS = new Set(['suspected_csam', 'grooming_or_exploitation', 'child_sexual_abuse', 'other_child_safety']);
const URL_RE = /https?:\/\/[^\s<>"'`]+/gi;

function isMediaLinkRestricted(userId) {
  const row = db.prepare(`SELECT 1 FROM safety_restrictions WHERE subject_user_id = ? AND status = 'active' AND expires_at > unixepoch()`).get(userId);
  return !!row;
}

function contentHasLink(content) {
  return /https?:\/\/[^\s<>"'`]+/i.test(String(content || ''));
}

function normalizeUrl(value) {
  try {
    const parsed = new URL(String(value).replace(/[),.!?\]}]+$/g, ''));
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    parsed.hostname = parsed.hostname.toLowerCase();
    return parsed.toString();
  } catch { return null; }
}

function validateArtifact(message, kind, key) {
  if (kind === 'image') {
    let attachments = [];
    try { attachments = message.attachments ? JSON.parse(message.attachments) : []; } catch {}
    if (!attachments.length && message.attachment_url) attachments = [{ url: message.attachment_url, mime: message.attachment_type }];
    const match = /^attachment:(\d+)$/.exec(key);
    const attachment = match ? attachments[Number(match[1])] : null;
    const mime = attachment?.mime || attachment?.type || '';
    if (!attachment || !String(mime).startsWith('image/')) throw Object.assign(new Error('Reported image was not found'), { status: 400 });
    return { attachmentIndex: Number(match[1]), attachmentUrl: attachment.url, thumbnailUrl: attachment.thumbnailUrl || attachment.thumbnail_url || null, attachmentType: mime };
  }
  if (kind === 'link') {
    const selected = key.startsWith('link:') ? key.slice(5) : '';
    const links = String(decryptMessageContent(message.content) || '').match(URL_RE) || [];
    const normalizedSelected = normalizeUrl(selected);
    if (!normalizedSelected || !links.some((link) => normalizeUrl(link) === normalizedSelected)) throw Object.assign(new Error('Reported link was not found'), { status: 400 });
    return { selectedUrl: normalizedSelected };
  }
  throw Object.assign(new Error('Invalid artifact kind'), { status: 400 });
}

function submitReport(userId, body) {
  const channelId = typeof body?.channelId === 'string' ? body.channelId : '';
  const messageId = typeof body?.messageId === 'string' ? body.messageId : '';
  const artifactKind = body?.artifactKind;
  const artifactKey = typeof body?.artifactKey === 'string' ? body.artifactKey.slice(0, 512) : '';
  if (!channelId || !messageId || !artifactKey || !REPORT_REASONS.has(body?.reason)) throw Object.assign(new Error('Invalid safety report'), { status: 400 });
  const message = db.prepare('SELECT * FROM messages WHERE id = ? AND channel_id = ?').get(messageId, channelId);
  if (!message) throw Object.assign(new Error('Message not found'), { status: 404 });
  if (message.user_id === userId) throw Object.assign(new Error('You cannot report your own message'), { status: 400 });
  const verifiedEvidence = validateArtifact(message, artifactKind, artifactKey);
  const now = Math.floor(Date.now() / 1000);
  const id = randomUUID();
  return db.transaction(() => {
    try {
      db.prepare(`INSERT INTO safety_reports (id, reporter_user_id, subject_user_id, channel_id, message_id, artifact_kind, artifact_key, reason, evidence_encrypted, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(id, userId, message.user_id, channelId, messageId, artifactKind, artifactKey, body.reason, encryptMessageContent(JSON.stringify({ ...verifiedEvidence, details: String(body?.details || '').slice(0, 4000) })), now, now);
    } catch (error) {
      if (String(error?.message).includes('UNIQUE')) throw Object.assign(new Error('You already reported this item'), { status: 409 });
      throw error;
    }
    db.prepare(`INSERT OR REPLACE INTO safety_artifact_visibility (channel_id, message_id, artifact_key, viewer_user_id, state, created_at) VALUES (?, ?, ?, ?, 'reported', ?)`)
      .run(channelId, messageId, artifactKey, userId, now);
    const count = Number(db.prepare(`SELECT COUNT(DISTINCT r.reporter_user_id) AS count FROM safety_reports r JOIN users u ON u.id = r.reporter_user_id WHERE r.channel_id = ? AND r.message_id = ? AND r.artifact_key = ? AND r.status IN ('pending','confirmed','escalated') AND u.created_at <= ?`).get(channelId, messageId, artifactKey, now - 86400)?.count || 0);
    if (count >= 2) {
      db.prepare(`UPDATE safety_artifact_visibility SET state = 'quarantined' WHERE channel_id = ? AND message_id = ? AND artifact_key = ?`).run(channelId, messageId, artifactKey);
      quarantineEvidenceUploads(id, channelId, messageId, artifactKey, verifiedEvidence, now);
    }
    db.prepare(`INSERT INTO safety_restrictions (subject_user_id, status, reason, expires_at, created_at) VALUES (?, 'active', 'child_safety_report_review', ?, ?) ON CONFLICT(subject_user_id) DO UPDATE SET status = 'active', reason = excluded.reason, expires_at = MAX(safety_restrictions.expires_at, excluded.expires_at), lifted_at = NULL, lifted_by = NULL`)
      .run(message.user_id, now + 72 * 60 * 60, now);
    db.prepare(`INSERT INTO safety_report_events (id, report_id, actor_user_id, event_type, metadata_encrypted, created_at) VALUES (?, ?, ?, 'submitted', ?, ?)`)
      .run(randomUUID(), id, userId, encryptMessageContent(JSON.stringify({ quarantined: count >= 2 })), now);
    return { id, status: 'pending', quarantined: count >= 2 };
  })();
}

function reviewReport(reviewerId, reportId, status, note) {
  if (!['confirmed', 'dismissed', 'escalated'].includes(status)) throw Object.assign(new Error('Invalid review status'), { status: 400 });
  const report = db.prepare('SELECT * FROM safety_reports WHERE id = ?').get(reportId);
  if (!report) throw Object.assign(new Error('Report not found'), { status: 404 });
  const now = Math.floor(Date.now() / 1000);
  return db.transaction(() => {
    db.prepare('UPDATE safety_reports SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note_encrypted = ?, updated_at = ? WHERE id = ?')
      .run(status, reviewerId, now, note ? encryptMessageContent(String(note).slice(0, 4000)) : null, now, reportId);
    db.prepare(`INSERT INTO safety_report_events (id, report_id, actor_user_id, event_type, metadata_encrypted, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(randomUUID(), reportId, reviewerId, `review_${status}`, note ? encryptMessageContent(JSON.stringify({ note: String(note).slice(0, 4000) })) : null, now);
    if (status === 'confirmed' || status === 'escalated') {
      db.prepare(`UPDATE safety_artifact_visibility SET state = 'removed' WHERE channel_id = ? AND message_id = ? AND artifact_key = ?`).run(report.channel_id, report.message_id, report.artifact_key);
      db.prepare(`UPDATE safety_restrictions SET status = 'active', expires_at = MAX(expires_at, ?) WHERE subject_user_id = ?`).run(now + 30 * 86400, report.subject_user_id);
      let evidence = null;
      try { evidence = JSON.parse(decryptMessageContent(report.evidence_encrypted) || '{}'); } catch {}
      quarantineEvidenceUploads(report.id, report.channel_id, report.message_id, report.artifact_key, evidence, now);
    } else {
      const remainingRow = db.prepare(`SELECT COUNT(DISTINCT r.reporter_user_id) AS count, MAX(CASE WHEN r.status IN ('confirmed','escalated') THEN 1 ELSE 0 END) AS upheld FROM safety_reports r JOIN users u ON u.id = r.reporter_user_id WHERE r.channel_id = ? AND r.message_id = ? AND r.artifact_key = ? AND r.status IN ('pending','confirmed','escalated') AND u.created_at <= ?`).get(report.channel_id, report.message_id, report.artifact_key, now - 86400);
      const remaining = Number(remainingRow?.count || 0);
      const upheld = Number(remainingRow?.upheld || 0) === 1;
      if (!remaining) db.prepare('DELETE FROM safety_artifact_visibility WHERE channel_id = ? AND message_id = ? AND artifact_key = ?').run(report.channel_id, report.message_id, report.artifact_key);
      else if (upheld) db.prepare(`UPDATE safety_artifact_visibility SET state = 'removed' WHERE channel_id = ? AND message_id = ? AND artifact_key = ?`).run(report.channel_id, report.message_id, report.artifact_key);
      else if (remaining < 2) db.prepare(`UPDATE safety_artifact_visibility SET state = 'reported' WHERE channel_id = ? AND message_id = ? AND artifact_key = ?`).run(report.channel_id, report.message_id, report.artifact_key);
      if (remaining < 2 && !upheld) db.prepare(`UPDATE safety_quarantined_uploads SET status = 'cleared', cleared_at = ? WHERE channel_id = ? AND message_id = ? AND artifact_key = ? AND status = 'active'`).run(now, report.channel_id, report.message_id, report.artifact_key);
      const pending = Number(db.prepare(`SELECT COUNT(*) AS count FROM safety_reports WHERE subject_user_id = ? AND status IN ('pending','confirmed','escalated')`).get(report.subject_user_id)?.count || 0);
      if (!pending) db.prepare(`UPDATE safety_restrictions SET status = 'lifted', lifted_at = ?, lifted_by = ? WHERE subject_user_id = ? AND status = 'active'`).run(now, reviewerId, report.subject_user_id);
    }
    return { reportId, status };
  })();
}

function normalizedLocalUploadPath(value) {
  if (typeof value !== 'string') return null;
  const path = value.split('?')[0];
  return /^\/ugc\/images\/(?:thumbs\/)?[A-Za-z0-9._-]+$/.test(path) ? path : null;
}

function quarantineEvidenceUploads(reportId, channelId, messageId, artifactKey, evidence, now) {
  const paths = [evidence?.attachmentUrl, evidence?.thumbnailUrl].map(normalizedLocalUploadPath).filter(Boolean);
  const insert = db.prepare(`INSERT INTO safety_quarantined_uploads (upload_path, report_id, channel_id, message_id, artifact_key, status, created_at, cleared_at) VALUES (?, ?, ?, ?, ?, 'active', ?, NULL) ON CONFLICT(upload_path) DO UPDATE SET report_id = excluded.report_id, status = 'active', created_at = excluded.created_at, cleared_at = NULL`);
  for (const path of paths) insert.run(path, reportId, channelId, messageId, artifactKey, now);
}

function isUploadQuarantined(requestPath) {
  const path = normalizedLocalUploadPath(requestPath);
  if (!path) return false;
  return !!db.prepare(`SELECT 1 FROM safety_quarantined_uploads WHERE upload_path = ? AND status = 'active'`).get(path);
}

function attachSafetyArtifacts(messages, viewerUserId) {
  if (!Array.isArray(messages) || messages.length === 0) return messages;
  const ids = messages.map((message) => message.id).filter(Boolean);
  if (!ids.length) return messages;
  const placeholders = ids.map(() => '?').join(', ');
  const now = Math.floor(Date.now() / 1000);
  const rows = db.prepare(`
    SELECT r.message_id, r.artifact_key,
      MAX(CASE WHEN r.status IN ('confirmed','escalated') THEN 1 ELSE 0 END) AS removed,
      COUNT(DISTINCT CASE WHEN r.status IN ('pending','confirmed','escalated') AND u.created_at <= ? THEN r.reporter_user_id END) AS trusted_reporters,
      MAX(CASE WHEN r.reporter_user_id = ? AND r.status IN ('pending','confirmed','escalated') THEN 1 ELSE 0 END) AS reported_by_viewer
    FROM safety_reports r
    JOIN users u ON u.id = r.reporter_user_id
    WHERE r.message_id IN (${placeholders})
    GROUP BY r.message_id, r.artifact_key
  `).all(now - 86400, viewerUserId, ...ids);
  const byMessage = new Map();
  for (const row of rows) {
    const globallyHidden = Number(row.removed) === 1 || Number(row.trusted_reporters) >= 2;
    const hiddenForUser = globallyHidden || Number(row.reported_by_viewer) === 1;
    if (!hiddenForUser) continue;
    const list = byMessage.get(row.message_id) || [];
    list.push({
      artifactKey: row.artifact_key,
      state: Number(row.removed) === 1 ? 'removed' : (globallyHidden ? 'quarantined' : 'reported'),
      hiddenForUser,
    });
    byMessage.set(row.message_id, list);
  }
  return messages.map((message) => ({ ...message, safety_artifacts: byMessage.get(message.id) || [] }));
}

function serializeReport(row, includeEvidence = false) {
  const result = { id: row.id, reporterUserId: row.reporter_user_id, subjectUserId: row.subject_user_id, channelId: row.channel_id, messageId: row.message_id, artifactKind: row.artifact_kind, artifactKey: row.artifact_key, reason: row.reason, status: row.status, createdAt: row.created_at, reviewedAt: row.reviewed_at };
  if (includeEvidence) {
    try { result.evidence = JSON.parse(decryptMessageContent(row.evidence_encrypted) || '{}'); } catch { result.evidence = null; }
    result.reviewNote = row.review_note_encrypted ? decryptMessageContent(row.review_note_encrypted) : null;
  }
  return result;
}

module.exports = { attachSafetyArtifacts, contentHasLink, isMediaLinkRestricted, isUploadQuarantined, reviewReport, serializeReport, submitReport };
