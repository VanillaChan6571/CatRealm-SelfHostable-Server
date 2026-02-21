const router = require('express').Router();
const db = require('../db');
const { PERMISSIONS, hasPermission } = require('../permissions');

// GET /api/roles
router.get('/', (req, res) => {
  const includeAll = req.query?.all === '1' && hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS);
  const roles = includeAll
    ? db.prepare('SELECT id, name, color, position, is_default, mentionable FROM roles ORDER BY position DESC, name COLLATE NOCASE').all()
    : db.prepare('SELECT id, name, color, position, is_default, mentionable FROM roles WHERE mentionable = 1 ORDER BY position DESC, name COLLATE NOCASE').all();
  res.json(roles);
});

module.exports = router;
