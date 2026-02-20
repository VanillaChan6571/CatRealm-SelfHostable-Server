const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { randomUUID } = require('crypto');
const db = require('../db');
const { JWT_SECRET, SERVER_MODE, checkUsernameConflict, authenticateToken } = require('../middleware/auth');
const { computePermissionsForUser } = require('../permissions');
const pteroLog = require('../logger');
const { isBlockedUsername } = require('../usernameBlocklist');
const DEFAULT_AVATAR_URL = (
  process.env.DEFAULT_AVATAR_URL ||
  'https://catrealm.app/uploads/avatars/default.jpg'
).trim();

// POST /api/auth/register  (local/decentral accounts only)
router.post('/register', async (req, res) => {
  if (SERVER_MODE === 'central_only') {
    return res.status(403).json({ error: 'This server uses CatRealm central accounts only. Register at catrealm.app' });
  }
  if (process.env.REGISTRATION_OPEN === 'false') {
    return res.status(403).json({ error: 'Registration is closed on this server' });
  }

  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3 || username.length > 32) return res.status(400).json({ error: 'Username must be 3-32 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username can only contain letters, numbers, and underscores' });
  if (SERVER_MODE === 'decentral_only' && isBlockedUsername(username)) {
    return res.status(409).json({ error: 'That username is reserved. Please choose another username.' });
  }

  // In mixed mode, check username doesn't conflict with a central account
  if (SERVER_MODE === 'mixed') {
    const conflict = await checkUsernameConflict(username);
    if (conflict) {
      return res.status(409).json({ error: 'That username is reserved by CatRealm central. Please choose a different name or log in with your central account.' });
    }
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const id = randomUUID();
  const hashed = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (id, username, password, avatar) VALUES (?, ?, ?, ?)')
    .run(id, username, hashed, DEFAULT_AVATAR_URL || null);
  const defaultRole = db.prepare('SELECT id FROM roles WHERE is_default = 1').get();
  if (defaultRole) {
    db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)').run(id, defaultRole.id);
  }

  const permissions = computePermissionsForUser(id, 'member', 0, db);
  const token = jwt.sign({ id, username, role: 'member', is_owner: 0, permissions }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({ token, user: { id, username, role: 'member', isOwner: false, permissions, accountType: 'local', status: 'online' } });
});

// POST /api/auth/login  (local accounts only — central accounts log in via central auth)
router.post('/login', (req, res) => {
  if (SERVER_MODE === 'central_only') {
    return res.status(403).json({ error: 'This server uses CatRealm central accounts only.' });
  }

  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const permissions = computePermissionsForUser(user.id, user.role, user.is_owner, db);
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, is_owner: user.is_owner ? 1 : 0, permissions },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, isOwner: !!user.is_owner, permissions, accountType: 'local', status: user.status || 'online', avatar: user.avatar || null, banner: user.banner || null, bio: user.bio || null },
  });
});

// GET /api/auth/me - return current user with freshly computed permissions
router.get('/me', authenticateToken, (req, res) => {
  const current = db.prepare(`
    SELECT id, username, role, is_owner, status, avatar, banner, bio, account_type
    FROM users
    WHERE id = ?
  `).get(req.user.id);
  if (!current) return res.status(404).json({ error: 'User not found' });

  const permissions = computePermissionsForUser(current.id, current.role, current.is_owner, db);
  const accountType = current.account_type === 'central' ? 'central' : 'local';
  const tokenPayload = {
    id: current.id,
    username: current.username,
    role: current.role,
    is_owner: current.is_owner ? 1 : 0,
    permissions,
  };
  if (accountType === 'central') {
    tokenPayload.account_type = 'central';
  }
  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });

  res.json({
    token,
    user: {
      id: current.id,
      username: current.username,
      role: current.role,
      isOwner: !!current.is_owner,
      permissions,
      accountType,
      status: current.status || 'online',
      avatar: current.avatar || null,
      banner: current.banner || null,
      bio: current.bio || null,
    },
  });
});

// POST /api/auth/claim-admin  (one-time admin token claim)
router.post('/claim-admin', authenticateToken, (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Admin token required' });

  const stored = db.prepare('SELECT token FROM admin_tokens WHERE token = ?').get(token);
  if (!stored) return res.status(403).json({ error: 'Invalid or expired admin token' });

  const ownerExists = db.prepare(`SELECT id FROM users WHERE is_owner = 1`).get();
  if (ownerExists) return res.status(403).json({ error: 'An owner already exists' });

  // Promote user to admin
  db.prepare('UPDATE users SET role = ?, is_owner = 1 WHERE id = ?').run('owner', req.user.id);

  // Delete the token (one-time use)
  db.prepare('DELETE FROM admin_tokens WHERE token = ?').run(token);

  pteroLog(`[CatRealm] ${req.user.username} claimed owner via setup token`);

  // Issue a new JWT with the updated role
  const permissions = computePermissionsForUser(req.user.id, 'owner', 1, db);
  const tokenPayload = {
    id: req.user.id,
    username: req.user.username,
    role: 'owner',
    is_owner: 1,
    permissions,
  };
  if (req.user.accountType === 'central') {
    tokenPayload.account_type = 'central';
  }
  const newToken = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '7d' });

  res.json({
    token: newToken,
    user: {
      id: req.user.id,
      username: req.user.username,
      role: 'owner',
      isOwner: true,
      permissions,
      accountType: req.user.accountType === 'central' ? 'central' : 'local',
      status: 'online',
    },
  });
});

// GET /api/auth/needs-admin  (check if server needs an admin)
router.get('/needs-admin', (req, res) => {
  const ownerExists = db.prepare(`SELECT id FROM users WHERE is_owner = 1`).get();
  res.json({ needsAdmin: !ownerExists });
});

// POST /api/auth/central  (central account authentication for game servers)
router.post('/central', async (req, res) => {
  if (SERVER_MODE === 'decentral_only') {
    return res.status(403).json({ error: 'This server only accepts local accounts' });
  }

  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Central token required' });

  // Verify the central token with the auth server
  let centralUser;
  try {
    const resp = await axios.get(`${AUTH_SERVER_URL}/api/verify`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: AUTH_VERIFY_TIMEOUT,
    });
    if (!resp.data.valid) return res.status(401).json({ error: 'Central account verification failed' });
    centralUser = resp.data.user;
  } catch (err) {
    if (axios.isAxiosError(err)) {
      pteroLog(`[CatRealm] Central auth verify failed: ${err.code || 'ERR'} ${err.message} ${err.response?.status || ''}`.trim());
    }
    return res.status(503).json({ error: 'Could not reach CatRealm auth server' });
  }

  // Look up or create a local user record for this central account
  let localUser = db.prepare('SELECT * FROM users WHERE central_id = ?').get(centralUser.id);

  if (!localUser) {
    // Check username conflict
    const existingByName = db.prepare('SELECT id FROM users WHERE username = ? AND central_id IS NULL').get(centralUser.username);
    const username = existingByName ? `${centralUser.username}_central` : centralUser.username;

    const id = randomUUID();
    db.prepare('INSERT INTO users (id, username, password, role, central_id, account_type, avatar) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(id, username, '', 'member', centralUser.id, 'central', DEFAULT_AVATAR_URL || null);

    // Assign default role
    const defaultRole = db.prepare('SELECT id FROM roles WHERE is_default = 1').get();
    if (defaultRole) {
      db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)').run(id, defaultRole.id);
    }

    localUser = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  }

  // Sync central avatar into local record when no server-specific avatar is set
  const centralAvatar = centralUser.avatar || centralUser.avatar_url || null;
  if (centralAvatar) {
    const avatarUrl = /^https?:\/\//i.test(centralAvatar)
      ? centralAvatar
      : `${AUTH_SERVER_URL}${centralAvatar}`;
    const existing = db.prepare('SELECT avatar FROM users WHERE id = ?').get(localUser.id);
    const existingAvatar = existing?.avatar || null;
    const isLocalUpload = !!existingAvatar && existingAvatar.startsWith('/uploads/avatars/');
    if (!existingAvatar || !isLocalUpload) {
      db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(avatarUrl, localUser.id);
      localUser = db.prepare('SELECT * FROM users WHERE id = ?').get(localUser.id);
    }
  }

  // Sync central banner into local record when no server-specific banner is set
  const centralBanner = centralUser.banner || centralUser.banner_url || null;
  if (centralBanner) {
    const bannerUrl = /^https?:\/\//i.test(centralBanner)
      ? centralBanner
      : `${AUTH_SERVER_URL}${centralBanner}`;
    const existing = db.prepare('SELECT banner FROM users WHERE id = ?').get(localUser.id);
    const existingBanner = existing?.banner || null;
    const isLocalBannerUpload = !!existingBanner && existingBanner.startsWith('/uploads/banners/');
    if (!existingBanner || !isLocalBannerUpload) {
      db.prepare('UPDATE users SET banner = ? WHERE id = ?').run(bannerUrl, localUser.id);
      localUser = db.prepare('SELECT * FROM users WHERE id = ?').get(localUser.id);
    }
  }

  // Sync central display name into local record (server-specific override takes precedence in rendering)
  const centralDisplayName = centralUser.display_name || centralUser.displayName || null;
  if (typeof centralDisplayName === 'string') {
    const trimmedDisplayName = centralDisplayName.trim();
    db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(
      trimmedDisplayName.length > 0 ? trimmedDisplayName : null,
      localUser.id
    );
    localUser = db.prepare('SELECT * FROM users WHERE id = ?').get(localUser.id);
  }

  const permissions = computePermissionsForUser(localUser.id, localUser.role, localUser.is_owner, db);
  const localToken = jwt.sign(
    {
      id: localUser.id,
      username: localUser.username,
      role: localUser.role,
      is_owner: localUser.is_owner ? 1 : 0,
      permissions,
      account_type: 'central',
      verified: centralUser.verified || false
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    token: localToken,
    user: {
      id: localUser.id,
      username: localUser.username,
      role: localUser.role,
      isOwner: !!localUser.is_owner,
      permissions,
      accountType: 'central',
      status: localUser.status || 'online',
      avatar: localUser.avatar || null,
      banner: localUser.banner || null,
      verified: centralUser.verified || false,
    },
  });
});

module.exports = router;
const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL || 'https://auth.catrealm.app';
const AUTH_VERIFY_TIMEOUT = Number(process.env.AUTH_VERIFY_TIMEOUT || 5000);
