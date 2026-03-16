const router = require('express').Router();
const db = require('../db');
const { PERMISSIONS, hasPermission } = require('../permissions');
const { emitPermissionsChanged } = require('../socket/handler');
const { startRoleViewSession, clearRoleViewSession } = require('../viewAsRole');

// GET /api/roles
router.get('/', (req, res) => {
  const includeAll = req.query?.all === '1' && hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS);
  const roles = includeAll
    ? db.prepare('SELECT id, name, color, permissions, position, is_default, mentionable FROM roles ORDER BY position DESC, name COLLATE NOCASE').all()
    : db.prepare('SELECT id, name, color, permissions, position, is_default, mentionable FROM roles WHERE mentionable = 1 ORDER BY position DESC, name COLLATE NOCASE').all();
  res.json(roles);
});

router.get('/view-as', (req, res) => {
  res.json({ active: !!req.viewAsRole, viewAsRole: req.viewAsRole || null });
});

router.post('/view-as', (req, res) => {
  if (!hasPermission(req.authUser, PERMISSIONS.MANAGE_ROLES)) {
    return res.status(403).json({ error: 'Missing permission: manage_roles' });
  }

  const roleId = typeof req.body?.roleId === 'string' ? req.body.roleId.trim() : '';
  if (!roleId) {
    return res.status(400).json({ error: 'roleId is required' });
  }

  const role = db.prepare(`
    SELECT id, name
    FROM roles
    WHERE id = ?
  `).get(roleId);
  if (!role) {
    return res.status(404).json({ error: 'Role not found' });
  }

  const session = startRoleViewSession(req.authUser.id, role.id);
  emitPermissionsChanged();
  res.json({
    success: true,
    viewAsRole: {
      roleId: role.id,
      roleName: role.name,
      startedAt: session.startedAt,
    },
  });
});

router.delete('/view-as', (req, res) => {
  clearRoleViewSession(req.authUser.id);
  emitPermissionsChanged();
  res.json({ success: true, viewAsRole: null });
});

module.exports = router;
