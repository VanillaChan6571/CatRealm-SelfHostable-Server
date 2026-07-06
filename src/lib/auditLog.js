const { randomUUID } = require('crypto');
const db = require('../db');
const pteroLog = require('../logger');

const RETENTION_KEY = 'audit_log_retention_days';
const VALID_RETENTION_DAYS = [30, 90, 365];
const PRUNE_INTERVAL_MS = 60 * 60 * 1000;

const AUDIT_ACTIONS = Object.freeze({
  // Member
  MEMBER_KICK: 'MEMBER_KICK',
  MEMBER_BAN: 'MEMBER_BAN',
  MEMBER_UNBAN: 'MEMBER_UNBAN',
  MEMBER_TIMEOUT: 'MEMBER_TIMEOUT',
  MEMBER_TIMEOUT_REMOVE: 'MEMBER_TIMEOUT_REMOVE',
  MEMBER_JOIN: 'MEMBER_JOIN',
  MEMBER_LEAVE: 'MEMBER_LEAVE',
  MEMBER_NICKNAME_UPDATE: 'MEMBER_NICKNAME_UPDATE',
  MEMBER_ROLES_UPDATE: 'MEMBER_ROLES_UPDATE',
  MEMBER_BASE_ROLE_UPDATE: 'MEMBER_BASE_ROLE_UPDATE',
  MEMBER_VOICE_MUTE: 'MEMBER_VOICE_MUTE',
  MEMBER_VOICE_DISCONNECT: 'MEMBER_VOICE_DISCONNECT',
  MEMBER_VOICE_MOVE: 'MEMBER_VOICE_MOVE',
  // Message
  MESSAGE_DELETE: 'MESSAGE_DELETE',
  // Channel / category
  CHANNEL_CREATE: 'CHANNEL_CREATE',
  CHANNEL_UPDATE: 'CHANNEL_UPDATE',
  CHANNEL_DELETE: 'CHANNEL_DELETE',
  CHANNEL_OVERWRITE_CREATE: 'CHANNEL_OVERWRITE_CREATE',
  CHANNEL_OVERWRITE_UPDATE: 'CHANNEL_OVERWRITE_UPDATE',
  CHANNEL_OVERWRITE_DELETE: 'CHANNEL_OVERWRITE_DELETE',
  CATEGORY_CREATE: 'CATEGORY_CREATE',
  CATEGORY_UPDATE: 'CATEGORY_UPDATE',
  CATEGORY_DELETE: 'CATEGORY_DELETE',
  CATEGORY_OVERWRITE_CREATE: 'CATEGORY_OVERWRITE_CREATE',
  CATEGORY_OVERWRITE_UPDATE: 'CATEGORY_OVERWRITE_UPDATE',
  CATEGORY_OVERWRITE_DELETE: 'CATEGORY_OVERWRITE_DELETE',
  // Role
  ROLE_CREATE: 'ROLE_CREATE',
  ROLE_UPDATE: 'ROLE_UPDATE',
  ROLE_DELETE: 'ROLE_DELETE',
  // Server
  SERVER_UPDATE: 'SERVER_UPDATE',
  SERVER_ICON_UPDATE: 'SERVER_ICON_UPDATE',
  SERVER_BANNER_UPDATE: 'SERVER_BANNER_UPDATE',
  MODERATION_SETTINGS_UPDATE: 'MODERATION_SETTINGS_UPDATE',
  TEMPLATE_IMPORT: 'TEMPLATE_IMPORT',
  AUDIT_RETENTION_UPDATE: 'AUDIT_RETENTION_UPDATE',
  // Invite
  INVITE_CREATE: 'INVITE_CREATE',
  INVITE_DELETE: 'INVITE_DELETE',
  // Webhook
  WEBHOOK_CREATE: 'WEBHOOK_CREATE',
  WEBHOOK_UPDATE: 'WEBHOOK_UPDATE',
  WEBHOOK_DELETE: 'WEBHOOK_DELETE',
  // Bot
  BOT_CREATE: 'BOT_CREATE',
  BOT_UPDATE: 'BOT_UPDATE',
  BOT_DELETE: 'BOT_DELETE',
  BOT_TOKEN_REGENERATE: 'BOT_TOKEN_REGENERATE',
  BOT_ENABLE: 'BOT_ENABLE',
  BOT_DISABLE: 'BOT_DISABLE',
  // Expression
  EXPRESSION_CREATE: 'EXPRESSION_CREATE',
  EXPRESSION_UPDATE: 'EXPRESSION_UPDATE',
  EXPRESSION_DELETE: 'EXPRESSION_DELETE',
});

const insertStmt = db.prepare(`
  INSERT INTO audit_log (id, action_type, moderator_id, target_id, target_type, channel_id, details, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, unixepoch())
`);

/**
 * Record an audit log entry. Never throws — audit logging must not break the
 * action it records. actorId may be null for system-initiated events.
 */
function logAuditAction(actionType, actorId, { targetType = null, targetId = null, channelId = null, details = null } = {}) {
  try {
    insertStmt.run(
      randomUUID(),
      actionType,
      actorId || null,
      targetId,
      targetType,
      channelId,
      details ? JSON.stringify(details) : null
    );
  } catch (err) {
    pteroLog(`[CatRealm] Failed to write audit log entry (${actionType}): ${err.message}`);
  }
}

/**
 * Build a { field: { before, after } } map of changed fields between two rows.
 * Returns null when nothing changed. Values compared with !== after String()
 * normalization of BigInts so details stay JSON-serializable.
 */
function diffFields(before, after, keys) {
  const changes = {};
  for (const key of keys) {
    const prev = typeof before?.[key] === 'bigint' ? before[key].toString() : before?.[key];
    const next = typeof after?.[key] === 'bigint' ? after[key].toString() : after?.[key];
    if (prev !== next) changes[key] = { before: prev ?? null, after: next ?? null };
  }
  return Object.keys(changes).length > 0 ? changes : null;
}

function getRetentionDays() {
  const row = db.prepare('SELECT value FROM server_settings WHERE key = ?').get(RETENTION_KEY);
  if (!row) return null;
  const days = parseInt(row.value, 10);
  return Number.isFinite(days) && days > 0 ? days : null;
}

function setRetentionDays(days) {
  if (days === null) {
    db.prepare('DELETE FROM server_settings WHERE key = ?').run(RETENTION_KEY);
    return;
  }
  db.prepare(`
    INSERT INTO server_settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(RETENTION_KEY, String(days));
}

function pruneExpiredAuditLogs() {
  const days = getRetentionDays();
  if (!days) return 0;
  try {
    const result = db
      .prepare('DELETE FROM audit_log WHERE created_at < unixepoch() - ?')
      .run(days * 86400);
    if (result.changes > 0) {
      pteroLog(`[CatRealm] Pruned ${result.changes} audit log entries older than ${days} days`);
    }
    return result.changes;
  } catch (err) {
    pteroLog(`[CatRealm] Audit log prune failed: ${err.message}`);
    return 0;
  }
}

let prunerInterval = null;

function startAuditLogPruner() {
  if (prunerInterval) return;
  pruneExpiredAuditLogs();
  prunerInterval = setInterval(pruneExpiredAuditLogs, PRUNE_INTERVAL_MS);
  prunerInterval.unref();
}

function stopAuditLogPruner() {
  if (prunerInterval) {
    clearInterval(prunerInterval);
    prunerInterval = null;
  }
}

module.exports = {
  AUDIT_ACTIONS,
  VALID_RETENTION_DAYS,
  logAuditAction,
  diffFields,
  getRetentionDays,
  setRetentionDays,
  pruneExpiredAuditLogs,
  startAuditLogPruner,
  stopAuditLogPruner,
};
