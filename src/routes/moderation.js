const express = require('express');
const router = express.Router();
const db = require('../db');
const { PERMISSIONS, hasPermission } = require('../permissions');
const { randomUUID } = require('crypto');

// Helper function to log audit actions
function logAuditAction(actionType, moderatorId, targetId = null, details = null) {
  const id = randomUUID();
  db.prepare(`
    INSERT INTO audit_log (id, action_type, moderator_id, target_id, details, created_at)
    VALUES (?, ?, ?, ?, ?, unixepoch())
  `).run(id, actionType, moderatorId, targetId, details ? JSON.stringify(details) : null);
}

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

  logAuditAction('MODERATION_SETTINGS_UPDATE', req.user.id, null, {
    banned_words,
    default_slowmode,
    timeout_defaults
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

  logAuditAction('MEMBER_TIMEOUT', req.user.id, userId, {
    username: targetUser.username,
    duration,
    reason,
    expires_at: expiresAt
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

  logAuditAction('MEMBER_TIMEOUT_REMOVE', req.user.id, userId, {
    previous_timeout: timeout
  });

  res.json({ success: true });
});

// GET /api/moderation/audit-log - Get audit log
router.get('/audit-log', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });

  if (!hasPermission(req.user, PERMISSIONS.VIEW_AUDIT_LOG)) {
    return res.status(403).json({ error: 'Missing VIEW_AUDIT_LOG permission' });
  }

  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;

  const logs = db.prepare(`
    SELECT
      al.id,
      al.action_type,
      al.moderator_id,
      al.target_id,
      al.details,
      al.created_at,
      u.username as moderator_username
    FROM audit_log al
    LEFT JOIN users u ON u.id = al.moderator_id
    ORDER BY al.created_at DESC
    LIMIT ? OFFSET ?
  `).all(limit, offset);

  const total = db.prepare('SELECT COUNT(*) as count FROM audit_log').get().count;

  res.json({
    logs: logs.map(log => ({
      ...log,
      details: log.details ? JSON.parse(log.details) : null
    })),
    total,
    limit,
    offset
  });
});

module.exports = router;

