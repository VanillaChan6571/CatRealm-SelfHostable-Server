const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { randomUUID } = require('crypto');
const db = require('../db');
const { authenticateToken } = require('../middleware/auth');
const { PERMISSIONS, hasPermission } = require('../permissions');
const { getSetting } = require('../settings');

const UGC_EXPRESSIONS_DIR = process.env.UGC_EXPRESSIONS_DIR || path.join(__dirname, '../../data/ugc/expressions');
const EXPRESSION_TYPES = ['emotes', 'anim-emotes', 'stickers', 'anim-stickers'];

const MIME_TO_EXT = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/jpg': '.jpg',
  'image/webp': '.webp',
  'image/gif': '.gif',
  'image/apng': '.apng',
};

const TYPE_ALLOWED_MIMES = {
  emotes: new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp']),
  'anim-emotes': new Set(['image/gif', 'image/apng']),
  stickers: new Set(['image/png', 'image/jpeg', 'image/jpg', 'image/webp']),
  'anim-stickers': new Set(['image/gif', 'image/apng']),
};

const TYPE_SETTING_KEYS = {
  emotes: 'max_emotes',
  'anim-emotes': 'max_animated_emotes',
  stickers: 'max_stickers',
  'anim-stickers': 'max_animated_stickers',
};

const TYPE_DEFAULT_LIMITS = {
  emotes: 100,
  'anim-emotes': 50,
  stickers: 100,
  'anim-stickers': 50,
};

if (!fs.existsSync(UGC_EXPRESSIONS_DIR)) fs.mkdirSync(UGC_EXPRESSIONS_DIR, { recursive: true });
for (const type of EXPRESSION_TYPES) {
  const dir = path.join(UGC_EXPRESSIONS_DIR, type);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function sanitizeName(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9_-]/g, '')
    .slice(0, 64);
}

function withAbsoluteUrl(req, row) {
  if (!row) return row;
  const base = `${req.protocol}://${req.get('host')}`;
  return {
    ...row,
    absolute_url: `${base}${row.file_url}`,
  };
}

function canManageType(user, type) {
  if (!user) return false;
  if (type === 'emotes' || type === 'anim-emotes') {
    return hasPermission(user, PERMISSIONS.MANAGE_CUSTOM_EMOTES);
  }
  return hasPermission(user, PERMISSIONS.MANAGE_CUSTOM_STICKERS);
}

function ensureValidType(type) {
  return EXPRESSION_TYPES.includes(type);
}

function expressionStorage(type) {
  return multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, path.join(UGC_EXPRESSIONS_DIR, type)),
    filename: (req, file, cb) => {
      const ext = MIME_TO_EXT[file.mimetype];
      if (!ext) return cb(new Error('Invalid file type'));
      const desiredName = sanitizeName(req.body?.name || path.parse(file.originalname).name);
      if (!desiredName) return cb(new Error('Expression name is required (letters/numbers/-/_)'));
      const id = randomUUID();
      req.expressionMeta = { id, name: desiredName, ext };
      cb(null, `${desiredName}-${id}${ext}`);
    },
  });
}

function buildUploadMiddleware(type) {
  return multer({
    storage: expressionStorage(type),
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (_req, file, cb) => {
      if (!TYPE_ALLOWED_MIMES[type].has(file.mimetype)) {
        return cb(new Error(`Invalid file type for ${type}`));
      }
      cb(null, true);
    },
  }).single('file');
}

// Public list endpoint for server expressions (usable outside the server context).
router.get('/', (req, res) => {
  const { type } = req.query;
  if (type && !ensureValidType(type)) {
    return res.status(400).json({ error: 'Invalid expression type' });
  }

  const rows = type
    ? db.prepare(`
      SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at
      FROM expressions
      WHERE type = ?
      ORDER BY created_at DESC
    `).all(type)
    : db.prepare(`
      SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at
      FROM expressions
      ORDER BY type ASC, created_at DESC
    `).all();

  res.json(rows.map((row) => withAbsoluteUrl(req, row)));
});

router.get('/manifest', (req, res) => {
  const rows = db.prepare(`
    SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at
    FROM expressions
    ORDER BY created_at DESC
  `).all();

  const grouped = {
    emotes: [],
    'anim-emotes': [],
    stickers: [],
    'anim-stickers': [],
  };

  for (const row of rows) {
    grouped[row.type].push(withAbsoluteUrl(req, row));
  }

  res.json(grouped);
});

router.get('/limits', (_req, res) => {
  res.json({
    maxEmotes: Number(getSetting('max_emotes', String(TYPE_DEFAULT_LIMITS.emotes))),
    maxAnimatedEmotes: Number(getSetting('max_animated_emotes', String(TYPE_DEFAULT_LIMITS['anim-emotes']))),
    maxStickers: Number(getSetting('max_stickers', String(TYPE_DEFAULT_LIMITS.stickers))),
    maxAnimatedStickers: Number(getSetting('max_animated_stickers', String(TYPE_DEFAULT_LIMITS['anim-stickers']))),
  });
});

router.get('/:id', (req, res) => {
  const row = db.prepare(`
    SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at
    FROM expressions
    WHERE id = ?
  `).get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Expression not found' });
  res.json(withAbsoluteUrl(req, row));
});

router.post('/:type', authenticateToken, (req, res) => {
  const { type } = req.params;
  if (!ensureValidType(type)) {
    return res.status(400).json({ error: 'Invalid expression type' });
  }
  if (!canManageType(req.user, type)) {
    return res.status(403).json({ error: 'Missing permission to manage this expression type' });
  }

  const limitKey = TYPE_SETTING_KEYS[type];
  const maxCount = Number(getSetting(limitKey, String(TYPE_DEFAULT_LIMITS[type])));
  const currentCount = db.prepare('SELECT COUNT(*) as c FROM expressions WHERE type = ?').get(type).c;
  if (currentCount >= maxCount) {
    return res.status(400).json({ error: `Limit reached for ${type} (${maxCount})` });
  }

  const upload = buildUploadMiddleware(type);
  upload(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file || !req.expressionMeta) return res.status(400).json({ error: 'File and name are required' });

    const relativeUrl = `/ugc/expressions/${type}/${req.file.filename}`;

    try {
      db.prepare(`
        INSERT INTO expressions (id, name, type, file_url, mime_type, file_size, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.expressionMeta.id,
        req.expressionMeta.name,
        type,
        relativeUrl,
        req.file.mimetype,
        req.file.size,
        req.user.id
      );
    } catch (insertErr) {
      fs.unlink(req.file.path, () => {});
      if (String(insertErr.message || '').includes('idx_expressions_name_type')) {
        return res.status(409).json({ error: `An expression named "${req.expressionMeta.name}" already exists in ${type}` });
      }
      return res.status(500).json({ error: 'Failed to save expression' });
    }

    const created = db.prepare(`
      SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at
      FROM expressions WHERE id = ?
    `).get(req.expressionMeta.id);

    return res.status(201).json(withAbsoluteUrl(req, created));
  });
});

router.patch('/:id', authenticateToken, (req, res) => {
  const row = db.prepare('SELECT id, name, type FROM expressions WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Expression not found' });
  if (!canManageType(req.user, row.type)) {
    return res.status(403).json({ error: 'Missing permission to manage this expression type' });
  }

  const nextName = sanitizeName(req.body?.name);
  if (!nextName) return res.status(400).json({ error: 'Name is required' });

  try {
    db.prepare('UPDATE expressions SET name = ? WHERE id = ?').run(nextName, req.params.id);
  } catch (err) {
    if (String(err.message || '').includes('idx_expressions_name_type')) {
      return res.status(409).json({ error: `An expression named "${nextName}" already exists in ${row.type}` });
    }
    return res.status(500).json({ error: 'Failed to rename expression' });
  }

  const updated = db.prepare(`
    SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at
    FROM expressions
    WHERE id = ?
  `).get(req.params.id);

  res.json(withAbsoluteUrl(req, updated));
});

router.delete('/:id', authenticateToken, (req, res) => {
  const row = db.prepare('SELECT id, type, file_url FROM expressions WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Expression not found' });
  if (!canManageType(req.user, row.type)) {
    return res.status(403).json({ error: 'Missing permission to manage this expression type' });
  }

  db.prepare('DELETE FROM expressions WHERE id = ?').run(req.params.id);

  if (row.file_url && row.file_url.startsWith('/ugc/expressions/')) {
    const localPath = path.join(UGC_EXPRESSIONS_DIR, row.file_url.replace('/ugc/expressions/', ''));
    fs.unlink(localPath, () => {});
  }

  res.json({ success: true });
});

module.exports = router;
