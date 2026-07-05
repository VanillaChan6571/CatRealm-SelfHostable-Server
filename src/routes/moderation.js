const express = require('express');
const router = express.Router();
const db = require('../db');
const { PERMISSIONS, hasPermission } = require('../permissions');
const {
  AUDIT_ACTIONS,
  VALID_RETENTION_DAYS,
  logAuditAction,
  getRetentionDays,
  setRetentionDays,
} = require('../lib/auditLog');

// GET /api/moderation/settings - Get moderation settings
router.get('/settings', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

  if (!hasPermission(req.user, PERMISSIONS.MANAGE_SERVER)) {
    return res.status(403).json({ error: 'Missing MANAGE_SERVER permission' });
  }

  const settings = db.prepare('SELECT * FROM moderation_settings WHERE id = 1').get();

  if (!settings) {
    return res.json({
      banned_words: [],
      default_slowmode: 0,
      timeout_defaults: {}
    });
  }

  res.json({
    banned_words: settings.banned_words ? JSON.parse(settings.banned_words) : [],
    default_slowmode: settings.default_slowmode || 0,
    timeout_defaults: settings.timeout_defaults ? JSON.parse(settings.timeout_defaults) : {}
  });
});

// PUT /api/moderation/settings - Update moderation settings
router.put('/settings', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

  if (!hasPermission(req.user, PERMISSIONS.MANAGE_SERVER)) {
    return res.status(403).json({ error: 'Missing MANAGE_SERVER permission' });
  }

  const { banned_words, default_slowmode, timeout_defaults } = req.body;

  db.prepare(`
    INSERT OR REPLACE INTO moderation_settings (id, banned_words, default_slowmode, timeout_defaults)
    VALUES (1, ?, ?, ?)
  `).run(
    banned_words ? JSON.stringify(banned_words) : '[]',
    default_slowmode || 0,
    timeout_defaults ? JSON.stringify(timeout_defaults) : '{}'
  );

  logAuditAction(AUDIT_ACTIONS.MODERATION_SETTINGS_UPDATE, req.user.id, {
    targetType: 'server',
    details: { banned_words, default_slowmode, timeout_defaults },
  });

  res.json({ success: true });
});

// POST /api/moderation/timeout/:userId - Timeout a member
router.post('/timeout/:userId', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

  if (!hasPermission(req.user, PERMISSIONS.TIMEOUT_USER)) {
    return res.status(403).json({ error: 'Missing TIMEOUT_MEMBERS permission' });
  }

  const { userId } = req.params;
  const { duration, reason } = req.body; // duration in seconds

  if (!duration || duration <= 0) {
    return res.status(400).json({ error: 'Invalid timeout duration' });
  }

  const targetUser = db.prepare('SELECT id, username FROM users WHERE id = ?').get(userId);
  if (!targetUser) {
    return res.status(404).json({ error: 'User not found' });
  }

  const expiresAt = Math.floor(Date.now() / 1000) + duration;

  db.prepare(`
    INSERT OR REPLACE INTO timeouts (user_id, expires_at, reason, created_by, created_at)
    VALUES (?, ?, ?, ?, unixepoch())
  `).run(userId, expiresAt, reason || null, req.user.id);

  logAuditAction(AUDIT_ACTIONS.MEMBER_TIMEOUT, req.user.id, {
    targetType: 'user',
    targetId: userId,
    details: {
      username: targetUser.username,
      duration,
      reason,
      expires_at: expiresAt,
    },
  });

  res.json({
    success: true,
    timeout: {
      user_id: userId,
      expires_at: expiresAt,
      reason,
      created_by: req.user.id
    }
  });
});

// DELETE /api/moderation/timeout/:userId - Remove timeout
router.delete('/timeout/:userId', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

  if (!hasPermission(req.user, PERMISSIONS.TIMEOUT_USER)) {
    return res.status(403).json({ error: 'Missing TIMEOUT_MEMBERS permission' });
  }

  const { userId } = req.params;

  const timeout = db.prepare('SELECT * FROM timeouts WHERE user_id = ?').get(userId);
  if (!timeout) {
    return res.status(404).json({ error: 'No timeout found for this user' });
  }

  db.prepare('DELETE FROM timeouts WHERE user_id = ?').run(userId);

  logAuditAction(AUDIT_ACTIONS.MEMBER_TIMEOUT_REMOVE, req.user.id, {
    targetType: 'user',
    targetId: userId,
    details: { previous_timeout: timeout },
  });

  res.json({ success: true });
});

// GET /api/moderation/audit-log - Get audit log (filterable, keyset-paginated)
router.get('/audit-log', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

  if (!hasPermission(req.user, PERMISSIONS.VIEW_AUDIT_LOG)) {
    return res.status(403).json({ error: 'Missing VIEW_AUDIT_LOG permission' });
  }

  const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 100);

  const where = [];
  const params = [];

  if (req.query.action_types) {
    const types = String(req.query.action_types)
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);
    if (types.length > 0) {
      where.push(`al.action_type IN (${types.map(() => '?').join(',')})`);
      params.push(...types);
    }
  }
  if (req.query.actor_id) {
    where.push('al.moderator_id = ?');
    params.push(String(req.query.actor_id));
  }
  if (req.query.target_id) {
    where.push('al.target_id = ?');
    params.push(String(req.query.target_id));
  }
  const after = parseInt(req.query.after);
  if (Number.isFinite(after)) {
    where.push('al.created_at >= ?');
    params.push(after);
  }
  const before = parseInt(req.query.before);
  if (Number.isFinite(before)) {
    where.push('al.created_at <= ?');
    params.push(before);
  }

  const countWhere = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const total = db
    .prepare(`SELECT COUNT(*) as count FROM audit_log al ${countWhere}`)
    .get(...params).count;

  // Keyset cursor: "<created_at>:<id>" of the last entry from the previous page
  if (req.query.cursor) {
    const sep = String(req.query.cursor).indexOf(':');
    const cursorTs = parseInt(String(req.query.cursor).slice(0, sep));
    const cursorId = String(req.query.cursor).slice(sep + 1);
    if (Number.isFinite(cursorTs) && cursorId) {
      where.push('(al.created_at, al.id) < (?, ?)');
      params.push(cursorTs, cursorId);
    }
  }

  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const logs = db.prepare(`
    SELECT
      al.id,
      al.action_type,
      al.moderator_id,
      al.target_id,
      al.target_type,
      al.channel_id,
      al.details,
      al.created_at
    FROM audit_log al
    ${whereSql}
    ORDER BY al.created_at DESC, al.id DESC
    LIMIT ?
  `).all(...params, limit);

  // Resolve actor + user-targets into a users map for the client
  const userIds = new Set();
  for (const log of logs) {
    if (log.moderator_id) userIds.add(log.moderator_id);
    if (log.target_type === 'user' && log.target_id) userIds.add(log.target_id);
  }
  let users = {};
  if (userIds.size > 0) {
    const ids = [...userIds];
    const rows = db.prepare(`
      SELECT u.id, u.username, u.avatar,
        COALESCE(dno.display_name, u.display_name) as display_name
      FROM users u
      LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
      WHERE u.id IN (${ids.map(() => '?').join(',')})
    `).all(...ids);
    users = Object.fromEntries(
      rows.map((u) => [u.id, { username: u.username, display_name: u.display_name, avatar: u.avatar }])
    );
  }

  const last = logs[logs.length - 1];
  res.json({
    logs: logs.map((log) => ({
      ...log,
      details: log.details ? JSON.parse(log.details) : null,
    })),
    users,
    total,
    limit,
    cursor: logs.length === limit && last ? `${last.created_at}:${last.id}` : null,
  });
});

// GET /api/moderation/audit-log/retention - Get retention setting
router.get('/audit-log/retention', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

  if (!hasPermission(req.user, PERMISSIONS.VIEW_AUDIT_LOG)) {
    return res.status(403).json({ error: 'Missing VIEW_AUDIT_LOG permission' });
  }

  res.json({ retention_days: getRetentionDays() });
});

// PUT /api/moderation/audit-log/retention - Set retention (owner only)
router.put('/audit-log/retention', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

  if (!req.user.is_owner) {
    return res.status(403).json({ error: 'Only the server owner can change audit log retention' });
  }

  const { retention_days } = req.body;
  if (retention_days !== null && !VALID_RETENTION_DAYS.includes(retention_days)) {
    return res.status(400).json({
      error: `retention_days must be null (forever) or one of: ${VALID_RETENTION_DAYS.join(', ')}`,
    });
  }

  const previous = getRetentionDays();
  setRetentionDays(retention_days);

  logAuditAction(AUDIT_ACTIONS.AUDIT_RETENTION_UPDATE, req.user.id, {
    targetType: 'server',
    details: { before: previous, after: retention_days },
  });

  res.json({ retention_days });
});

module.exports = router;

