const router = require('express').Router();
const db = require('../db');
const {
  PERMISSIONS,
  computePermissionsForUser,
  hasChannelPermission,
} = require('../permissions');

function userCanViewChannel(user, channelId) {
  if (!channelId) return true;
  if (user.is_owner || user.role === 'owner') return true;
  const permissions = computePermissionsForUser(user.id, user.role, user.is_owner, db);
  return hasChannelPermission(
    {
      id: user.id,
      role: user.role,
      is_owner: user.is_owner,
      permissions,
    },
    channelId,
    PERMISSIONS.VIEW_CHANNELS,
    db,
  );
}

// GET /api/users
router.get('/', (req, res) => {
  const channelId = typeof req.query.channelId === 'string' && req.query.channelId.trim()
    ? req.query.channelId.trim()
    : null;
  if (channelId) {
    const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(channelId);
    if (!channel) return res.status(404).json({ error: 'Channel not found' });
    if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
      return res.status(403).json({ error: 'Missing permission: view_channels' });
    }
  }

  const users = db.prepare(`
    SELECT u.id, u.username, u.role, u.avatar, u.is_owner, u.status, u.custom_status_text, u.activity_type, u.activity_text, u.activity_started_at
    FROM users u
    WHERE COALESCE(u.is_member, 1) = 1
      AND NOT EXISTS (SELECT 1 FROM bans b WHERE b.user_id = u.id)
    ORDER BY u.username COLLATE NOCASE
  `).all();
  res.json(users.filter((u) => userCanViewChannel(u, channelId)).map((u) => {
    const topRole = db.prepare(`
      SELECT r.color FROM roles r
      JOIN user_roles ur ON ur.role_id = r.id
      WHERE ur.user_id = ?
      ORDER BY r.position DESC
      LIMIT 1
    `).get(u.id);
    return {
      id: u.id,
      username: u.username,
      role: u.role,
      isOwner: !!u.is_owner,
      avatar: u.avatar || null,
      status: u.status || 'online',
      customStatusText: u.custom_status_text || null,
      activityType: u.activity_type || null,
      activityText: u.activity_text || null,
      activityStartedAt: u.activity_started_at || null,
      roleColor: topRole?.color || null,
    };
  }));
});

module.exports = router;
