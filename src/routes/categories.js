const router = require('express').Router();
const { randomUUID } = require('crypto');
const db = require('../db');
const { PERMISSIONS, hasPermission } = require('../permissions');

// GET /api/categories
router.get('/', (_req, res) => {
  const categories = db.prepare('SELECT * FROM categories ORDER BY position ASC').all();
  res.json(categories);
});

// POST /api/categories
router.post('/', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  const { name } = req.body ?? {};
  if (typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: 'Category name required' });
  }
  const maxPos = db.prepare('SELECT MAX(position) as m FROM categories').get().m || 0;
  const id = randomUUID();
  db.prepare('INSERT INTO categories (id, name, position) VALUES (?, ?, ?)')
    .run(id, name.trim(), maxPos + 1);
  const category = db.prepare('SELECT * FROM categories WHERE id = ?').get(id);
  res.status(201).json(category);
});

// PATCH /api/categories/:id
router.patch('/:id', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  const { name, position } = req.body ?? {};
  const category = db.prepare('SELECT * FROM categories WHERE id = ?').get(req.params.id);
  if (!category) return res.status(404).json({ error: 'Category not found' });
  if (typeof name === 'string' && name.trim().length >= 2) {
    db.prepare('UPDATE categories SET name = ? WHERE id = ?').run(name.trim(), req.params.id);
  }
  if (typeof position === 'number') {
    db.prepare('UPDATE categories SET position = ? WHERE id = ?').run(position, req.params.id);
  }
  const updated = db.prepare('SELECT * FROM categories WHERE id = ?').get(req.params.id);
  res.json(updated);
});

// DELETE /api/categories/:id
router.delete('/:id', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  db.prepare('UPDATE channels SET category_id = NULL WHERE category_id = ?').run(req.params.id);
  db.prepare('DELETE FROM categories WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

module.exports = router;

