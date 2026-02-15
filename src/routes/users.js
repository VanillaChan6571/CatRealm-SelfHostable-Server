const router = require('express').Router();
const db = require('../db');

// GET /api/users
router.get('/', (_req, res) => {
  const users = db.prepare('SELECT id, username, role, avatar, is_owner FROM users ORDER BY username COLLATE NOCASE').all();
  res.json(users.map((u) => {
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
      roleColor: topRole?.color || null,
    };
  }));
});

module.exports = router;
