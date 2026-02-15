const router = require('express').Router();
const db = require('../db');

// GET /api/roles
router.get('/', (_req, res) => {
  const roles = db.prepare('SELECT id, name, color, position, is_default, mentionable FROM roles WHERE mentionable = 1 ORDER BY position DESC, name COLLATE NOCASE').all();
  res.json(roles);
});

module.exports = router;
