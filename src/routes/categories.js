const router = require('express').Router();
const { randomUUID } = require('crypto');
const db = require('../db');
const { PERMISSIONS, hasPermission } = require('../permissions');
const { broadcastChannelUpdate, emitPermissionsChanged } = require('../socket/handler');
const {
  WEBHOOK_SCOPE_CATEGORY,
  listWebhooks,
  createWebhook,
  updateWebhook,
  regenerateWebhookSecret,
  deleteWebhook,
} = require('../webhooks');

function normalizeOverwriteBits(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0;
  return Math.trunc(value);
}

function validateOverwriteTarget(targetType, targetId) {
  if (!['role', 'user'].includes(targetType)) {
    return 'targetType must be role or user';
  }
  if (typeof targetId !== 'string' || !targetId.trim()) {
    return 'targetId required';
  }
  if (targetType === 'role') {
    const role = db.prepare('SELECT id FROM roles WHERE id = ?').get(targetId);
    if (!role) return 'Role not found';
    return null;
  }
  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(targetId);
  if (!user) return 'User not found';
  return null;
}

function listCategoryOverwrites(categoryId) {
  return db.prepare(`
    SELECT * FROM category_permission_overwrites
    WHERE category_id = ?
    ORDER BY created_at, target_type, target_id
  `).all(categoryId);
}

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
  broadcastChannelUpdate();
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
  broadcastChannelUpdate();
  res.json(updated);
});

// DELETE /api/categories/:id
router.delete('/:id', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  db.prepare('UPDATE channels SET category_id = NULL WHERE category_id = ?').run(req.params.id);
  db.prepare('DELETE FROM categories WHERE id = ?').run(req.params.id);
  emitPermissionsChanged();
  res.json({ success: true });
});

// GET /api/categories/:id/webhooks
router.get('/:id/webhooks', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_WEBHOOKS)) {
    return res.status(403).json({ error: 'Missing permission: manage_webhooks' });
  }
  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(req.params.id);
  if (!category) return res.status(404).json({ error: 'Category not found' });
  res.json(listWebhooks(WEBHOOK_SCOPE_CATEGORY, req.params.id, req));
});

// POST /api/categories/:id/webhooks
router.post('/:id/webhooks', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_WEBHOOKS)) {
    return res.status(403).json({ error: 'Missing permission: manage_webhooks' });
  }
  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(req.params.id);
  if (!category) return res.status(404).json({ error: 'Category not found' });
  try {
    const created = createWebhook({
      req,
      scopeType: WEBHOOK_SCOPE_CATEGORY,
      scopeId: req.params.id,
      authMode: req.body?.authMode,
      name: req.body?.name,
      inboundEnabled: !!req.body?.inboundEnabled,
      outboundEnabled: !!req.body?.outboundEnabled,
      actionFlags: req.body?.actionFlags,
      ipLockEnabled: req.body?.ipLockEnabled,
      callbackUrl: req.body?.callbackUrl,
      createdBy: req.user.id,
    });
    res.status(201).json(created);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Failed to create webhook' });
  }
});

// PATCH /api/categories/:id/webhooks/:webhookId
router.patch('/:id/webhooks/:webhookId', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_WEBHOOKS)) {
    return res.status(403).json({ error: 'Missing permission: manage_webhooks' });
  }
  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(req.params.id);
  if (!category) return res.status(404).json({ error: 'Category not found' });
  try {
    res.json(updateWebhook({
      req,
      scopeType: WEBHOOK_SCOPE_CATEGORY,
      scopeId: req.params.id,
      webhookId: req.params.webhookId,
      body: req.body ?? {},
    }));
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Failed to update webhook' });
  }
});

// POST /api/categories/:id/webhooks/:webhookId/regenerate-secret
router.post('/:id/webhooks/:webhookId/regenerate-secret', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_WEBHOOKS)) {
    return res.status(403).json({ error: 'Missing permission: manage_webhooks' });
  }
  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(req.params.id);
  if (!category) return res.status(404).json({ error: 'Category not found' });
  try {
    res.json(regenerateWebhookSecret({
      req,
      scopeType: WEBHOOK_SCOPE_CATEGORY,
      scopeId: req.params.id,
      webhookId: req.params.webhookId,
    }));
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Failed to regenerate webhook secret' });
  }
});

// DELETE /api/categories/:id/webhooks/:webhookId
router.delete('/:id/webhooks/:webhookId', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_WEBHOOKS)) {
    return res.status(403).json({ error: 'Missing permission: manage_webhooks' });
  }
  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(req.params.id);
  if (!category) return res.status(404).json({ error: 'Category not found' });
  const deleted = deleteWebhook(WEBHOOK_SCOPE_CATEGORY, req.params.id, req.params.webhookId);
  if (!deleted) return res.status(404).json({ error: 'Webhook not found' });
  res.json({ success: true });
});

// GET /api/categories/:id/permissions - List category permission overwrites
router.get('/:id/permissions', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(req.params.id);
  if (!category) return res.status(404).json({ error: 'Category not found' });

  res.json(listCategoryOverwrites(req.params.id));
});

// POST /api/categories/:id/permissions - Create category permission overwrite
router.post('/:id/permissions', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  const { targetType, targetId, allow, deny } = req.body ?? {};
  if (!targetType || !targetId) {
    return res.status(400).json({ error: 'targetType and targetId required' });
  }
  if (!['role', 'user'].includes(targetType)) {
    return res.status(400).json({ error: 'targetType must be role or user' });
  }

  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(req.params.id);
  if (!category) return res.status(404).json({ error: 'Category not found' });

  if (targetType === 'role') {
    const role = db.prepare('SELECT id FROM roles WHERE id = ?').get(targetId);
    if (!role) return res.status(404).json({ error: 'Role not found' });
  } else {
    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(targetId);
    if (!user) return res.status(404).json({ error: 'User not found' });
  }

  const allowBits = typeof allow === 'number' ? allow : 0;
  const denyBits = typeof deny === 'number' ? deny : 0;
  const existing = db.prepare(`
    SELECT * FROM category_permission_overwrites
    WHERE category_id = ? AND target_type = ? AND target_id = ?
    LIMIT 1
  `).get(req.params.id, targetType, targetId);

  if (existing) {
    db.prepare('UPDATE category_permission_overwrites SET allow = ?, deny = ? WHERE id = ?')
      .run(allowBits, denyBits, existing.id);
    const updated = db.prepare('SELECT * FROM category_permission_overwrites WHERE id = ?').get(existing.id);
    emitPermissionsChanged();
    return res.json(updated);
  }

  const id = randomUUID();
  db.prepare(`
    INSERT INTO category_permission_overwrites (id, category_id, target_type, target_id, allow, deny)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, req.params.id, targetType, targetId, allowBits, denyBits);
  const overwrite = db.prepare('SELECT * FROM category_permission_overwrites WHERE id = ?').get(id);
  emitPermissionsChanged();
  res.status(201).json(overwrite);
});

// PUT /api/categories/:id/permissions - Replace category permission overwrites
router.put('/:id/permissions', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  const categoryId = req.params.id;
  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(categoryId);
  if (!category) return res.status(404).json({ error: 'Category not found' });

  const overwrites = Array.isArray(req.body?.overwrites) ? req.body.overwrites : null;
  if (!overwrites) {
    return res.status(400).json({ error: 'overwrites array required' });
  }

  for (const overwrite of overwrites) {
    const targetType = overwrite.targetType ?? overwrite.target_type;
    const targetId = overwrite.targetId ?? overwrite.target_id;
    const error = validateOverwriteTarget(targetType, targetId);
    if (error) return res.status(400).json({ error });
  }

  const insertOverwrite = db.prepare(`
    INSERT INTO category_permission_overwrites (id, category_id, target_type, target_id, allow, deny)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const transaction = db.transaction((items) => {
    db.prepare('DELETE FROM category_permission_overwrites WHERE category_id = ?').run(categoryId);
    for (const overwrite of items) {
      const targetType = overwrite.targetType ?? overwrite.target_type;
      const targetId = overwrite.targetId ?? overwrite.target_id;
      const allow = normalizeOverwriteBits(overwrite.allow);
      const deny = normalizeOverwriteBits(overwrite.deny);
      if (allow === 0 && deny === 0) continue;
      insertOverwrite.run(randomUUID(), categoryId, targetType, targetId, allow, deny);
    }
  });

  transaction(overwrites);
  emitPermissionsChanged();
  res.json(listCategoryOverwrites(categoryId));
});

// PATCH /api/categories/:id/permissions/:overwriteId - Update category permission overwrite
router.patch('/:id/permissions/:overwriteId', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  const { allow, deny } = req.body ?? {};
  const overwrite = db.prepare(`
    SELECT * FROM category_permission_overwrites
    WHERE id = ? AND category_id = ?
  `).get(req.params.overwriteId, req.params.id);
  if (!overwrite) return res.status(404).json({ error: 'Overwrite not found' });

  if (typeof allow === 'number') {
    db.prepare('UPDATE category_permission_overwrites SET allow = ? WHERE id = ?')
      .run(allow, req.params.overwriteId);
  }
  if (typeof deny === 'number') {
    db.prepare('UPDATE category_permission_overwrites SET deny = ? WHERE id = ?')
      .run(deny, req.params.overwriteId);
  }

  const updated = db.prepare('SELECT * FROM category_permission_overwrites WHERE id = ?').get(req.params.overwriteId);
  emitPermissionsChanged();
  res.json(updated);
});

// DELETE /api/categories/:id/permissions/:overwriteId - Remove category permission overwrite
router.delete('/:id/permissions/:overwriteId', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  db.prepare(`
    DELETE FROM category_permission_overwrites
    WHERE id = ? AND category_id = ?
  `).run(req.params.overwriteId, req.params.id);
  emitPermissionsChanged();
  res.json({ success: true });
});

module.exports = router;
