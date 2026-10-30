const router = require('express').Router();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const db = require('../db');
const { PERMISSIONS, hasPermission, hasChannelPermission } = require('../permissions');
const { getSetting } = require('../settings');
const {
  classifyChatUploadForCompression,
  compressChatImageInline,
  enqueueChatVideoCompression,
} = require('../mediaCompression');

let sharp = null;
try {
  sharp = require('sharp');
} catch (_err) {
  sharp = null;
}

const UGC_IMAGES_DIR = process.env.UGC_IMAGES_DIR || path.join(__dirname, '../../data/ugc/images');
if (!fs.existsSync(UGC_IMAGES_DIR)) fs.mkdirSync(UGC_IMAGES_DIR, { recursive: true });
const UGC_THUMBS_DIR = path.join(UGC_IMAGES_DIR, 'thumbs');
if (!fs.existsSync(UGC_THUMBS_DIR)) fs.mkdirSync(UGC_THUMBS_DIR, { recursive: true });

const MEDIA_REMOVE_LIMITS = (() => {
  const value = String(process.env.MEDIA_REMOVE_LIMITS || '').trim().toLowerCase();
  return value === '1' || value === 'true' || value === 'yes' || value === 'on';
})();

const MIME_TO_EXT = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/webp': '.webp',
  'image/gif': '.gif',
  'video/mp4': '.mp4',
  'audio/webm': '.webm',
  'audio/ogg': '.ogg',
  'audio/mpeg': '.mp3',
  'audio/wav': '.wav',
};

// Archives are stored and served as downloads only. Browsers report them under several MIME
// names (Windows often sends application/octet-stream for .rar), so they are also recognised
// by file extension, then checked against their signature bytes before being kept.
const ARCHIVES = {
  '.zip': { mime: 'application/zip', magic: [Buffer.from('PK\x03\x04', 'latin1'), Buffer.from('PK\x05\x06', 'latin1')] },
  '.rar': { mime: 'application/vnd.rar', magic: [Buffer.from('Rar!\x1a\x07', 'latin1')] },
  '.7z': { mime: 'application/x-7z-compressed', magic: [Buffer.from('7z\xbc\xaf\x27\x1c', 'latin1')] },
};
const ARCHIVE_EXT_BY_MIME = {
  'application/zip': '.zip',
  'application/x-zip-compressed': '.zip',
  'application/vnd.rar': '.rar',
  'application/x-rar-compressed': '.rar',
  'application/x-rar': '.rar',
  'application/x-7z-compressed': '.7z',
};
const GENERIC_MIME_TYPES = new Set(['application/octet-stream', 'binary/octet-stream', '']);

function uploadExtension(file) {
  const byMime = MIME_TO_EXT[file.mimetype] ?? ARCHIVE_EXT_BY_MIME[file.mimetype];
  if (byMime) return byMime;
  if (!GENERIC_MIME_TYPES.has(file.mimetype ?? '')) return null;
  const ext = path.extname(String(file.originalname || '')).toLowerCase();
  return ARCHIVES[ext] ? ext : null;
}

function hasArchiveSignature(filePath, ext) {
  const { magic } = ARCHIVES[ext];
  const head = Buffer.alloc(Math.max(...magic.map((m) => m.length)));
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const read = fs.readSync(fd, head, 0, head.length, 0);
    return magic.some((m) => read >= m.length && head.subarray(0, m.length).equals(m));
  } catch (_err) {
    return false;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** Display name for a download: the original base name, stripped to safe characters. */
function safeDisplayName(originalname, ext) {
  const base = path.basename(String(originalname || '')).replace(/[^\p{L}\p{N} ._()-]/gu, '').trim().slice(0, 120);
  return base.toLowerCase().endsWith(ext) ? base : `${base || 'archive'}${ext}`;
}

const THUMBNAIL_IMAGE_MIME_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
  'image/avif',
]);

async function generateChatThumbnail(file) {
  if (!sharp || !file?.path || !THUMBNAIL_IMAGE_MIME_TYPES.has(file.mimetype)) return null;
  const base = path.basename(file.filename, path.extname(file.filename));
  const thumbFilename = `${base}.webp`;
  const thumbPath = path.join(UGC_THUMBS_DIR, thumbFilename);
  try {
    await sharp(file.path, { animated: false })
      .rotate()
      .resize({ width: 1024, height: 1024, fit: 'inside', withoutEnlargement: true })
      .webp({ quality: 72 })
      .toFile(thumbPath);
    return `/ugc/images/thumbs/${thumbFilename}`;
  } catch (_err) {
    try { fs.unlinkSync(thumbPath); } catch {}
    return null;
  }
}

// Multi-realm mode shares this directory across all realms: filenames are
// UUIDs so realms never collide, but any future orphan-sweep/GC must check
// every realm's database before deleting a file, not just this process's DB.
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UGC_IMAGES_DIR),
  filename: (_req, file, cb) => {
    const ext = uploadExtension(file);
    if (!ext) return cb(new Error('Invalid file type'));
    // Unguessable name: served files have no auth, so the URL must not be enumerable.
    cb(null, `${crypto.randomUUID()}${ext}`);
  },
});

const upload = multer({
  storage,
  ...(MEDIA_REMOVE_LIMITS
    ? {}
    : {
        limits: {
          // Hard ceiling matches owner-configurable media_max_mb upper bound.
          fileSize: 980 * 1024 * 1024,
        },
      }),
  fileFilter: (_req, file, cb) => {
    if (!uploadExtension(file)) return cb(new Error('Invalid file type'));
    cb(null, true);
  },
});

// POST /api/uploads/chat
router.post('/chat', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File required' });

  const cleanupUploadedFile = () => {
    if (req.file?.path) fs.unlink(req.file.path, () => {});
  };

  const channelId = typeof req.body?.channelId === 'string' ? req.body.channelId.trim() : '';
  if (channelId) {
    if (!hasChannelPermission(req.user, channelId, PERMISSIONS.ATTACH_FILES, db)) {
      cleanupUploadedFile();
      return res.status(403).json({ error: 'Missing permission: send_media' });
    }
  } else if (!hasPermission(req.user, PERMISSIONS.SEND_MEDIA)) {
    // Backward-compatible fallback for older clients that do not send channelId.
    cleanupUploadedFile();
    return res.status(403).json({ error: 'Missing permission: send_media' });
  }

  const mediaMaxMb = Number(getSetting('media_max_mb', '50'));
  const maxBytes = mediaMaxMb * 1024 * 1024;
  if (req.file.size > maxBytes) {
    cleanupUploadedFile();
    return res.status(400).json({ error: `File exceeds ${mediaMaxMb}MB limit` });
  }

  const archiveExt = path.extname(req.file.filename).toLowerCase();
  if (ARCHIVES[archiveExt]) {
    // The declared type is the client's word; only keep files that really are archives.
    if (!hasArchiveSignature(req.file.path, archiveExt)) {
      cleanupUploadedFile();
      return res.status(400).json({ error: 'Invalid file type' });
    }
    return res.json({
      url: `/ugc/images/${req.file.filename}`,
      mime: ARCHIVES[archiveExt].mime,
      size: req.file.size,
      name: safeDisplayName(req.file.originalname, archiveExt),
    });
  }

  let finalSize = req.file.size;
  const isAudio = req.file.mimetype.startsWith('audio/');
  const compressionType = isAudio ? { kind: 'none' } : classifyChatUploadForCompression(req.file);
  if (compressionType.kind === 'image') {
    const result = await compressChatImageInline(req.file);
    if (typeof result?.sizeAfter === 'number' && Number.isFinite(result.sizeAfter) && result.sizeAfter > 0) {
      finalSize = result.sizeAfter;
    }
  } else if (compressionType.kind === 'video') {
    enqueueChatVideoCompression(req.file);
  }

  const thumbnailUrl = await generateChatThumbnail(req.file);

  res.json({
    url: `/ugc/images/${req.file.filename}`,
    mime: req.file.mimetype,
    size: finalSize,
    ...(thumbnailUrl ? { thumbnailUrl } : {}),
  });
});

module.exports = router;
