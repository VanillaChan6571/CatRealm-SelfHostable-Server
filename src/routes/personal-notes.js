const router = require('express').Router();
const { v4: uuidv4 } = require('uuid');
const db = require('../db');

const NOTES_LIMIT_BYTES = 10 * 1024 * 1024; // 10 MB

// ── Helpers ────────────────────────────────────────────────────────────────────

function getUserStorageUsed(userId) {
  const row = db.prepare(
    'SELECT COALESCE(SUM(content_size), 0) AS used FROM personal_notes WHERE user_id = ?'
  ).get(userId);
  return row.used;
}

// ── Routes ─────────────────────────────────────────────────────────────────────

// GET /api/personal-notes/storage
// Must be registered before /:id so Express doesn't treat "storage" as an id
router.get('/storage', (req, res) => {
  const used = getUserStorageUsed(req.user.id);
  res.json({ used, limit: NOTES_LIMIT_BYTES });
});

// GET /api/personal-notes
// Returns metadata list — no encrypted_content
router.get('/', (req, res) => {
  const notes = db.prepare(`
    SELECT id, title, lock_type AS lockType, content_size AS contentSize,
           created_at AS createdAt, updated_at AS updatedAt
    FROM personal_notes
    WHERE user_id = ?
    ORDER BY updated_at DESC
  `).all(req.user.id);
  res.json({ notes });
});

// GET /api/personal-notes/:id
// Returns full note; 2FA lock is not supported for local accounts
router.get('/:id', (req, res) => {
  const note = db.prepare(
    'SELECT * FROM personal_notes WHERE id = ? AND user_id = ?'
  ).get(req.params.id, req.user.id);
  if (!note) return res.status(404).json({ error: 'Note not found' });

  if (note.lock_type === '2fa') {
    return res.status(501).json({ error: '2FA note lock is only available for central accounts' });
  }

  res.json({
    id: note.id,
    title: note.title,
    encryptedContent: note.encrypted_content,
    lockType: note.lock_type,
    lockSalt: note.lock_salt,
    contentSize: note.content_size,
    createdAt: note.created_at,
    updatedAt: note.updated_at,
  });
});

// POST /api/personal-notes
// Body: { title, encryptedContent, lockType?, lockSalt? }
router.post('/', (req, res) => {
  const { title = '', encryptedContent, lockType = null, lockSalt = null } = req.body;
  if (!encryptedContent) return res.status(400).json({ error: 'encryptedContent is required' });
  if (lockType === '2fa') {
    return res.status(501).json({ error: '2FA note lock is only available for central accounts' });
  }
  if (lockType && lockType !== 'pin') {
    return res.status(400).json({ error: 'Invalid lockType' });
  }

  const contentSize = Buffer.byteLength(encryptedContent, 'utf8');
  const used = getUserStorageUsed(req.user.id);
  if (used + contentSize > NOTES_LIMIT_BYTES) {
    return res.status(413).json({ error: 'Storage quota exceeded', used, limit: NOTES_LIMIT_BYTES });
  }

  const id = uuidv4();
  const now = Math.floor(Date.now() / 1000);
  db.prepare(`
    INSERT INTO personal_notes (id, user_id, title, encrypted_content, lock_type, lock_salt, content_size, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, req.user.id, title, encryptedContent, lockType, lockSalt, contentSize, now, now);

  res.status(201).json({ id, createdAt: now, updatedAt: now });
});

// PUT /api/personal-notes/:id
// Body: { title?, encryptedContent?, lockType?, lockSalt? }
router.put('/:id', (req, res) => {
  const note = db.prepare(
    'SELECT * FROM personal_notes WHERE id = ? AND user_id = ?'
  ).get(req.params.id, req.user.id);
  if (!note) return res.status(404).json({ error: 'Note not found' });

  if (req.body.lockType === '2fa') {
    return res.status(501).json({ error: '2FA note lock is only available for central accounts' });
  }

  const title = req.body.title !== undefined ? req.body.title : note.title;
  const encryptedContent = req.body.encryptedContent !== undefined ? req.body.encryptedContent : note.encrypted_content;
  const lockType = 'lockType' in req.body ? (req.body.lockType || null) : note.lock_type;
  const lockSalt = 'lockSalt' in req.body ? (req.body.lockSalt || null) : note.lock_salt;

  if (lockType && lockType !== 'pin') {
    return res.status(400).json({ error: 'Invalid lockType' });
  }

  const contentSize = Buffer.byteLength(encryptedContent, 'utf8');
  const usedExcludingThis = getUserStorageUsed(req.user.id) - note.content_size;
  if (usedExcludingThis + contentSize > NOTES_LIMIT_BYTES) {
    return res.status(413).json({ error: 'Storage quota exceeded', used: usedExcludingThis + note.content_size, limit: NOTES_LIMIT_BYTES });
  }

  const now = Math.floor(Date.now() / 1000);
  db.prepare(`
    UPDATE personal_notes
    SET title = ?, encrypted_content = ?, lock_type = ?, lock_salt = ?, content_size = ?, updated_at = ?
    WHERE id = ? AND user_id = ?
  `).run(title, encryptedContent, lockType, lockSalt, contentSize, now, req.params.id, req.user.id);

  res.json({ updatedAt: now });
});

// DELETE /api/personal-notes/:id
router.delete('/:id', (req, res) => {
  const result = db.prepare(
    'DELETE FROM personal_notes WHERE id = ? AND user_id = ?'
  ).run(req.params.id, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Note not found' });
  res.json({ ok: true });
});

module.exports = router;
