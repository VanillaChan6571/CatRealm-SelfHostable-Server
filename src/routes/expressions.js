const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const { randomUUID } = require('crypto');
const db = require('../db');
const { authenticateToken } = require('../middleware/auth');
const { PERMISSIONS, hasPermission } = require('../permissions');
const { getSetting } = require('../settings');
let sharp = null;
try {
  sharp = require('sharp');
} catch {}

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

const EMOTE_VARIANT_SIZES = [512, 256, 128, 96, 64, 32, 16];
const STICKER_VARIANT_SIZES = [320];

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

function getVariantSizesForType(type) {
  return (type === 'stickers' || type === 'anim-stickers')
    ? STICKER_VARIANT_SIZES
    : EMOTE_VARIANT_SIZES;
}

function parseVariantsJson(value) {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') return {};
    const variants = {};
    for (const [sizeKey, url] of Object.entries(parsed)) {
      if (!/^\d+$/.test(sizeKey)) continue;
      if (typeof url !== 'string' || !url.startsWith('/ugc/expressions/')) continue;
      variants[sizeKey] = url;
    }
    return variants;
  } catch {
    return {};
  }
}

function buildFallbackVariants(type, primaryUrl) {
  const sizes = getVariantSizesForType(type);
  const variants = {};
  for (const size of sizes) {
    variants[String(size)] = primaryUrl;
  }
  return variants;
}

function toLocalExpressionPath(fileUrl) {
  if (typeof fileUrl !== 'string') return null;
  const cleaned = fileUrl.split('?')[0];
  if (!cleaned.startsWith('/ugc/expressions/')) return null;
  const relativePart = cleaned.replace('/ugc/expressions/', '');
  if (!relativePart || relativePart.includes('..')) return null;
  return path.join(UGC_EXPRESSIONS_DIR, relativePart);
}

async function processExpressionUpload(type, file) {
  const relativeOriginalUrl = `/ugc/expressions/${type}/${file.filename}`;
  const shouldResizeStatic =
    !!sharp &&
    (type === 'emotes' || type === 'stickers') &&
    ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'].includes(file.mimetype);

  if (!shouldResizeStatic) {
    return {
      fileUrl: relativeOriginalUrl,
      mimeType: file.mimetype,
      fileSize: file.size,
      variants: buildFallbackVariants(type, relativeOriginalUrl),
      cleanupPaths: [file.path],
    };
  }

  const variantSizes = getVariantSizesForType(type);
  const parsed = path.parse(file.filename);
  const variantPaths = [];
  const variants = {};

  try {
    for (const size of variantSizes) {
      const variantFilename = `${parsed.name}-${size}.png`;
      const variantPath = path.join(path.dirname(file.path), variantFilename);
      await sharp(file.path)
        .resize(size, size, {
          fit: 'contain',
          background: { r: 0, g: 0, b: 0, alpha: 0 },
          withoutEnlargement: false,
        })
        .png({ compressionLevel: 9, quality: 100 })
        .toFile(variantPath);
      variantPaths.push(variantPath);
      variants[String(size)] = `/ugc/expressions/${type}/${variantFilename}`;
    }

    fs.unlink(file.path, () => {});
    const primarySize = variantSizes[0];
    const primaryVariantPath = variantPaths[0];
    const primarySizeBytes = fs.existsSync(primaryVariantPath) ? fs.statSync(primaryVariantPath).size : file.size;
    return {
      fileUrl: variants[String(primarySize)],
      mimeType: 'image/png',
      fileSize: primarySizeBytes,
      variants,
      cleanupPaths: variantPaths,
    };
  } catch {
    for (const variantPath of variantPaths) {
      fs.unlink(variantPath, () => {});
    }
    return {
      fileUrl: relativeOriginalUrl,
      mimeType: file.mimetype,
      fileSize: file.size,
      variants: buildFallbackVariants(type, relativeOriginalUrl),
      cleanupPaths: [file.path],
    };
  }
}

function withAbsoluteUrl(req, row) {
  if (!row) return row;
  const base = `${req.protocol}://${req.get('host')}`;
  const variants = parseVariantsJson(row.variants_json);
  const absoluteVariants = {};
  for (const [size, url] of Object.entries(variants)) {
    absoluteVariants[size] = `${base}${url}`;
  }
  return {
    ...row,
    variants,
    absolute_variants: absoluteVariants,
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

function isAllowedMimeForType(type, file) {
  if (TYPE_ALLOWED_MIMES[type].has(file.mimetype)) return true;
  const lowerName = String(file.originalname || '').toLowerCase();
  // APNG files are often reported as image/png by browsers.
  if ((type === 'anim-emotes' || type === 'anim-stickers') && file.mimetype === 'image/png' && lowerName.endsWith('.apng')) {
    return true;
  }
  return false;
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
      if (!isAllowedMimeForType(type, file)) {
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
      , variants_json
      FROM expressions
      WHERE type = ?
      ORDER BY created_at DESC
    `).all(type)
    : db.prepare(`
      SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at
      , variants_json
      FROM expressions
      ORDER BY type ASC, created_at DESC
    `).all();

  res.json(rows.map((row) => withAbsoluteUrl(req, row)));
});

router.get('/manifest', (req, res) => {
  const rows = db.prepare(`
    SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at, variants_json
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
    SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at, variants_json
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
  upload(req, res, async (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file || !req.expressionMeta) return res.status(400).json({ error: 'File and name are required' });

    const processed = await processExpressionUpload(type, req.file);

    try {
      db.prepare(`
        INSERT INTO expressions (id, name, type, file_url, variants_json, mime_type, file_size, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.expressionMeta.id,
        req.expressionMeta.name,
        type,
        processed.fileUrl,
        JSON.stringify(processed.variants),
        processed.mimeType,
        processed.fileSize,
        req.user.id
      );
    } catch (insertErr) {
      for (const localPath of processed.cleanupPaths || []) {
        fs.unlink(localPath, () => {});
      }
      if (String(insertErr.message || '').includes('idx_expressions_name_type')) {
        return res.status(409).json({ error: `An expression named "${req.expressionMeta.name}" already exists in ${type}` });
      }
      return res.status(500).json({ error: 'Failed to save expression' });
    }

    const created = db.prepare(`
      SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at, variants_json
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
    SELECT id, name, type, file_url, mime_type, file_size, created_by, created_at, variants_json
    FROM expressions
    WHERE id = ?
  `).get(req.params.id);

  res.json(withAbsoluteUrl(req, updated));
});

router.delete('/:id', authenticateToken, (req, res) => {
  const row = db.prepare('SELECT id, type, file_url, variants_json FROM expressions WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Expression not found' });
  if (!canManageType(req.user, row.type)) {
    return res.status(403).json({ error: 'Missing permission to manage this expression type' });
  }

  db.prepare('DELETE FROM expressions WHERE id = ?').run(req.params.id);

  const variants = parseVariantsJson(row.variants_json);
  const urls = new Set([row.file_url, ...Object.values(variants)]);
  for (const url of urls) {
    const localPath = toLocalExpressionPath(url);
    if (!localPath) continue;
    fs.unlink(localPath, () => {});
  }

  res.json({ success: true });
});

module.exports = router;
