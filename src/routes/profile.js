const router = require('express').Router();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const db = require('../db');
const { SERVER_MODE } = require('../middleware/auth');
const { updateOnlineUserAvatar, updateOnlineUserStatus, updateOnlineUserDisplayName, updateOnlineUserActivity } = require('../socket/handler');
const { getSetting } = require('../settings');

const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, '../../data/uploads');
const AVATAR_DIR = path.join(UPLOADS_DIR, 'avatars');
const BANNER_DIR = path.join(UPLOADS_DIR, 'banners');
if (!fs.existsSync(AVATAR_DIR)) fs.mkdirSync(AVATAR_DIR, { recursive: true });
if (!fs.existsSync(BANNER_DIR)) fs.mkdirSync(BANNER_DIR, { recursive: true });

const MAX_AVATAR_BYTES = 50 * 1024 * 1024;
const MIME_TO_EXT = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/webp': '.webp',
  'image/gif': '.gif',
};

const storage = multer.diskStorage({
  destination: (req, _file, cb) => cb(null, req.uploadType === 'banner' ? BANNER_DIR : AVATAR_DIR),
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
  limits: { fileSize: MAX_AVATAR_BYTES },
  fileFilter: (_req, file, cb) => {
    if (!MIME_TO_EXT[file.mimetype]) {
      return cb(new Error('Invalid file type'));
    }
    cb(null, true);
  },
});

function ensureProfileAllowed(req, res, next) {
  if (SERVER_MODE === 'decentral_only' && req.user?.accountType !== 'local') {
    return res.status(403).json({ error: 'Profiles are only available for local accounts on this server' });
  }
  if (SERVER_MODE === 'central_only' && req.user?.accountType !== 'central') {
    return res.status(403).json({ error: 'Profiles are only available for central accounts on this server' });
  }
  next();
}

// GET /api/profile/me
router.get('/me', (req, res) => {
  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // For central accounts, check if there's a server-specific display name override
  let displayName = user.display_name;
  if (req.user.accountType === 'central') {
    const override = db.prepare('SELECT display_name FROM display_name_overrides WHERE user_id = ?').get(req.user.id);
    if (override) {
      displayName = override.display_name;
    }
  }

  res.json({
    ...user,
    display_name: displayName,
    isOwner: !!user.is_owner,
    accountType: req.user.accountType || 'local'
  });
});

// PUT /api/profile/me  { bio }
router.put('/me', ensureProfileAllowed, (req, res) => {
  const bio = typeof req.body.bio === 'string' ? req.body.bio.trim() : '';
  if (bio.length > 500) return res.status(400).json({ error: 'Bio must be 500 characters or less' });
  db.prepare('UPDATE users SET bio = ? WHERE id = ?').run(bio, req.user.id);
  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...user, isOwner: !!user.is_owner, accountType: req.user.accountType || 'local' });
});

// POST /api/profile/me/avatar-url  (central accounts only)
router.post('/me/avatar-url', (req, res) => {
  if (req.user?.accountType !== 'central') {
    return res.status(403).json({ error: 'Avatar URL updates are only available for central accounts' });
  }
  const url = typeof req.body?.url === 'string' ? req.body.url.trim() : '';
  if (!/^https?:\/\//i.test(url)) {
    return res.status(400).json({ error: 'Invalid avatar URL' });
  }

  const existing = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.user.id);
  const existingAvatar = existing?.avatar || null;
  const isLocalUpload = !!existingAvatar && existingAvatar.startsWith('/uploads/avatars/');
  if (isLocalUpload) {
    return res.status(409).json({ error: 'Server-specific avatar is set. Remove it to sync from central.' });
  }

  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(url, req.user.id);
  updateOnlineUserAvatar(req.user.id, url);
  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...user, isOwner: !!user.is_owner, accountType: req.user.accountType || 'central' });
});

// POST /api/profile/me/avatar  (multipart/form-data, field "avatar")
router.post('/me/avatar', upload.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Avatar file required' });
  const maxBytes = Number(getSetting('avatar_max_mb', '10')) * 1024 * 1024;
  if (req.file.size > maxBytes) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: `Avatar exceeds ${getSetting('avatar_max_mb', '10')}MB limit` });
  }

  const existing = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.user.id);
  const avatarPath = `/uploads/avatars/${req.file.filename}`;
  db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(avatarPath, req.user.id);
  updateOnlineUserAvatar(req.user.id, avatarPath);

  if (existing?.avatar && existing.avatar.startsWith('/uploads/avatars/')) {
    const oldPath = path.join(UPLOADS_DIR, existing.avatar.replace('/uploads/', ''));
    fs.unlink(oldPath, () => {});
  }

  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...user, isOwner: !!user.is_owner, accountType: req.user.accountType || 'local' });
});

// POST /api/profile/me/banner  (multipart/form-data, field "banner")
router.post('/me/banner', (req, _res, next) => {
  req.uploadType = 'banner';
  next();
}, upload.single('banner'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Banner file required' });
  const maxBytes = Number(getSetting('avatar_max_mb', '10')) * 1024 * 1024;
  if (req.file.size > maxBytes) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: `Banner exceeds ${getSetting('avatar_max_mb', '10')}MB limit` });
  }

  const existing = db.prepare('SELECT banner FROM users WHERE id = ?').get(req.user.id);
  const bannerPath = `/uploads/banners/${req.file.filename}`;
  db.prepare('UPDATE users SET banner = ? WHERE id = ?').run(bannerPath, req.user.id);

  if (existing?.banner && existing.banner.startsWith('/uploads/banners/')) {
    const oldPath = path.join(UPLOADS_DIR, existing.banner.replace('/uploads/', ''));
    fs.unlink(oldPath, () => {});
  }

  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...user, isOwner: !!user.is_owner, accountType: req.user.accountType || 'local' });
});

// DELETE /api/profile/me/avatar
router.delete('/me/avatar', (req, res) => {
  const existing = db.prepare('SELECT avatar FROM users WHERE id = ?').get(req.user.id);
  db.prepare('UPDATE users SET avatar = NULL WHERE id = ?').run(req.user.id);
  updateOnlineUserAvatar(req.user.id, null);

  if (existing?.avatar && existing.avatar.startsWith('/uploads/avatars/')) {
    const oldPath = path.join(UPLOADS_DIR, existing.avatar.replace('/uploads/', ''));
    fs.unlink(oldPath, () => {});
  }

  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...user, isOwner: !!user.is_owner, accountType: req.user.accountType || 'local' });
});

// DELETE /api/profile/me/banner
router.delete('/me/banner', (req, res) => {
  const existing = db.prepare('SELECT banner FROM users WHERE id = ?').get(req.user.id);
  db.prepare('UPDATE users SET banner = NULL WHERE id = ?').run(req.user.id);

  if (existing?.banner && existing.banner.startsWith('/uploads/banners/')) {
    const oldPath = path.join(UPLOADS_DIR, existing.banner.replace('/uploads/', ''));
    fs.unlink(oldPath, () => {});
  }

  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...user, isOwner: !!user.is_owner, accountType: req.user.accountType || 'local' });
});

// GET /api/profile/:userId
router.get('/:userId([0-9a-fA-F-]{36})', ensureProfileAllowed, (req, res) => {
  const { userId } = req.params;
  const user = db.prepare(`
    SELECT u.id, u.username, u.role, u.avatar, u.banner, u.bio, u.is_owner, u.status, u.display_name, u.activity_type, u.activity_text, u.account_type,
      COALESCE(dno.display_name, u.display_name) as effective_display_name
    FROM users u
    LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
    WHERE u.id = ?
  `).get(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    ...user,
    display_name: user.effective_display_name,
    isOwner: !!user.is_owner,
    accountType: user.account_type || 'local'
  });
});

// GET /api/profile/:userId/roles
router.get('/:userId([0-9a-fA-F-]{36})/roles', ensureProfileAllowed, (req, res) => {
  const { userId } = req.params;
  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const roles = db.prepare(`
    SELECT r.*
    FROM roles r
    JOIN user_roles ur ON ur.role_id = r.id
    WHERE ur.user_id = ?
    ORDER BY r.position DESC, r.name COLLATE NOCASE
  `).all(userId);
  res.json({ roleIds: roles.map((r) => r.id), roles });
});

// PUT /api/profile/me/status
router.put('/me/status', ensureProfileAllowed, (req, res) => {
  const { status } = req.body ?? {};
  const allowed = ['online', 'away', 'sleeping', 'invisible'];
  if (typeof status !== 'string' || !allowed.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, req.user.id);
  updateOnlineUserStatus(req.user.id, status);
  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...user, isOwner: !!user.is_owner, accountType: req.user.accountType || 'local' });
});

// PUT /api/profile/me/display-name
router.put('/me/display-name', ensureProfileAllowed, (req, res) => {
  const { displayName } = req.body ?? {};

  if (typeof displayName !== 'string' || displayName.trim().length === 0 || displayName.length > 32) {
    return res.status(400).json({ error: 'Display name must be 1-32 characters' });
  }
  if (/[\n\r]/.test(displayName)) {
    return res.status(400).json({ error: 'Display name cannot contain newlines' });
  }

  const trimmed = displayName.trim();

  if (req.user.accountType === 'central') {
    // Server-specific override for central accounts
    db.prepare('INSERT OR REPLACE INTO display_name_overrides (user_id, display_name) VALUES (?, ?)')
      .run(req.user.id, trimmed);
  } else {
    // Direct update for local accounts
    db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(trimmed, req.user.id);
  }

  updateOnlineUserDisplayName(req.user.id, trimmed);

  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...user, display_name: trimmed, isOwner: !!user.is_owner, accountType: req.user.accountType || 'local' });
});

// DELETE /api/profile/me/display-name
router.delete('/me/display-name', ensureProfileAllowed, (req, res) => {
  if (req.user.accountType === 'central') {
    // Remove server-specific override (falls back to global)
    db.prepare('DELETE FROM display_name_overrides WHERE user_id = ?').run(req.user.id);
  } else {
    // Clear display name for local accounts (falls back to username)
    db.prepare('UPDATE users SET display_name = NULL WHERE id = ?').run(req.user.id);
  }

  updateOnlineUserDisplayName(req.user.id, null);

  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?').get(req.user.id);
  res.json({ ...user, isOwner: !!user.is_owner, accountType: req.user.accountType || 'local' });
});

// GET /api/profile/nicknames
router.get('/nicknames', (req, res) => {
  const nicknames = db.prepare('SELECT target_user_id, nickname FROM friend_nicknames WHERE user_id = ?').all(req.user.id);
  res.json(nicknames);
});

// PUT /api/profile/nicknames/:targetUserId
router.put('/nicknames/:targetUserId', (req, res) => {
  const { nickname } = req.body ?? {};
  const { targetUserId } = req.params;

  if (typeof nickname !== 'string' || nickname.trim().length === 0 || nickname.length > 32) {
    return res.status(400).json({ error: 'Nickname must be 1-32 characters' });
  }

  const target = db.prepare('SELECT id FROM users WHERE id = ?').get(targetUserId);
  if (!target) return res.status(404).json({ error: 'User not found' });

  db.prepare('INSERT OR REPLACE INTO friend_nicknames (user_id, target_user_id, nickname) VALUES (?, ?, ?)')
    .run(req.user.id, targetUserId, nickname.trim());

  res.json({ success: true, targetUserId, nickname: nickname.trim() });
});

// DELETE /api/profile/nicknames/:targetUserId
router.delete('/nicknames/:targetUserId', (req, res) => {
  db.prepare('DELETE FROM friend_nicknames WHERE user_id = ? AND target_user_id = ?')
    .run(req.user.id, req.params.targetUserId);
  res.json({ success: true });
});

// PUT /api/profile/me/activity
router.put('/me/activity', ensureProfileAllowed, (req, res) => {
  const { activityType, activityText } = req.body ?? {};

  const allowedTypes = ['Playing', 'Listening', 'Watching', 'Custom', null];
  if (activityType !== null && !allowedTypes.includes(activityType)) {
    return res.status(400).json({ error: 'Invalid activity type' });
  }

  if (activityText !== null && activityText !== undefined) {
    if (typeof activityText !== 'string' || activityText.length > 128) {
      return res.status(400).json({ error: 'Activity text must be 128 characters or less' });
    }
  }

  const finalType = activityType || null;
  const finalText = (activityText && activityText.trim()) || null;

  db.prepare('UPDATE users SET activity_type = ?, activity_text = ? WHERE id = ?')
    .run(finalType, finalText, req.user.id);

  updateOnlineUserActivity(req.user.id, finalType, finalText);

  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?')
    .get(req.user.id);
  res.json({ ...user, isOwner: !!user.is_owner, accountType: req.user.accountType || 'local' });
});

// DELETE /api/profile/me/activity
router.delete('/me/activity', ensureProfileAllowed, (req, res) => {
  db.prepare('UPDATE users SET activity_type = NULL, activity_text = NULL WHERE id = ?').run(req.user.id);
  updateOnlineUserActivity(req.user.id, null, null);

  const user = db.prepare('SELECT id, username, role, avatar, banner, bio, is_owner, status, display_name, activity_type, activity_text FROM users WHERE id = ?')
    .get(req.user.id);
  res.json({ ...user, isOwner: !!user.is_owner, accountType: req.user.accountType || 'local' });
});

// GET /api/profile/nsfw-preferences
router.get('/nsfw-preferences', (req, res) => {
  const prefs = db.prepare('SELECT * FROM user_nsfw_preferences WHERE user_id = ?').get(req.user.id);
  if (!prefs) {
    return res.json({
      blood: false,
      gore: false,
      violence: false,
      lewd: false,
      sexual: false,
      disturbing: false,
      ageVerified: false
    });
  }
  const parsed = JSON.parse(prefs.preferences);
  res.json({
    ...parsed,
    ageVerified: !!prefs.age_verified
  });
});

// PUT /api/profile/nsfw-preferences
router.put('/nsfw-preferences', (req, res) => {
  const { blood, gore, violence, lewd, sexual, disturbing, ageVerified } = req.body ?? {};
  const preferences = {
    blood: !!blood,
    gore: !!gore,
    violence: !!violence,
    lewd: !!lewd,
    sexual: !!sexual,
    disturbing: !!disturbing
  };

  db.prepare(`
    INSERT INTO user_nsfw_preferences (user_id, preferences, age_verified)
    VALUES (?, ?, ?)
    ON CONFLICT(user_id)
    DO UPDATE SET preferences = excluded.preferences, age_verified = excluded.age_verified
  `).run(req.user.id, JSON.stringify(preferences), ageVerified ? 1 : 0);

  res.json({ ...preferences, ageVerified: !!ageVerified });
});

// GET /api/profile/content-social-preferences
router.get('/content-social-preferences', (req, res) => {
  const prefs = db.prepare('SELECT * FROM user_content_social_prefs WHERE user_id = ?').get(req.user.id);
  if (!prefs) {
    return res.json({
      allowNsfw: false,
      nsfwLewds: false,
      nsfwBlood: false,
      nsfwGore: false,
      dmFilter: 'non-friends',
      allowDms: false,
      frEveryone: true,
      frFriendOfFriends: true,
      frServerMembers: true
    });
  }
  const parsed = JSON.parse(prefs.preferences);
  res.json(parsed);
});

// PUT /api/profile/content-social-preferences
router.put('/content-social-preferences', (req, res) => {
  const {
    allowNsfw,
    nsfwLewds,
    nsfwBlood,
    nsfwGore,
    dmFilter,
    allowDms,
    frEveryone,
    frFriendOfFriends,
    frServerMembers
  } = req.body ?? {};

  const preferences = {
    allowNsfw: !!allowNsfw,
    nsfwLewds: !!nsfwLewds,
    nsfwBlood: !!nsfwBlood,
    nsfwGore: !!nsfwGore,
    dmFilter: dmFilter || 'non-friends',
    allowDms: !!allowDms,
    frEveryone: frEveryone !== undefined ? !!frEveryone : true,
    frFriendOfFriends: frFriendOfFriends !== undefined ? !!frFriendOfFriends : true,
    frServerMembers: frServerMembers !== undefined ? !!frServerMembers : true
  };

  db.prepare(`
    INSERT INTO user_content_social_prefs (user_id, preferences)
    VALUES (?, ?)
    ON CONFLICT(user_id)
    DO UPDATE SET preferences = excluded.preferences
  `).run(req.user.id, JSON.stringify(preferences));

  res.json(preferences);
});

// Multer error handler
router.use((err, _req, res, next) => {
  if (!err) return next();
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'Avatar file too large' });
  }
  return res.status(400).json({ error: err.message || 'Upload failed' });
});

module.exports = router;
