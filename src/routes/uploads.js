const router = require('express').Router();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const db = require('../db');
const { PERMISSIONS, hasPermission, hasChannelPermission } = require('../permissions');
const { getSetting } = require('../settings');
const {
  classifyChatUploadForCompression,
  compressChatImageInline,
  enqueueChatVideoCompression,
} = require('../mediaCompression');

const UGC_IMAGES_DIR = process.env.UGC_IMAGES_DIR || path.join(__dirname, '../../data/ugc/images');
if (!fs.existsSync(UGC_IMAGES_DIR)) fs.mkdirSync(UGC_IMAGES_DIR, { recursive: true });

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

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UGC_IMAGES_DIR),
  filename: (req, file, cb) => {
    const ext = MIME_TO_EXT[file.mimetype];
    if (!ext) return cb(new Error('Invalid file type'));
    const safeId = String(req.user.id).replace(/[^a-zA-Z0-9_-]/g, '');
    const filename = `${safeId}-${Date.now()}${ext}`;
    cb(null, filename);
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
    if (!MIME_TO_EXT[file.mimetype]) return cb(new Error('Invalid file type'));
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

  res.json({
    url: `/ugc/images/${req.file.filename}`,
    mime: req.file.mimetype,
    size: finalSize,
  });
});

module.exports = router;
