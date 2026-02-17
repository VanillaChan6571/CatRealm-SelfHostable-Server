const router = require('express').Router();
const db = require('../db');
const { SERVER_MODE } = require('../middleware/auth');
const { getSetting, setSetting } = require('../settings');
const { PERMISSIONS, hasPermission } = require('../permissions');
const { emitServerInfoUpdate } = require('../socket/handler');
const { randomUUID } = require('crypto');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { decryptMessageContent, encryptMessageContent } = require('../messageCrypto');

function requirePermission(permission) {
  return (req, res, next) => {
    if (!hasPermission(req.user, permission)) {
      return res.status(403).json({ error: 'Missing permission' });
    }
    next();
  };
}

function runDiagnosticCommand(raw) {
  const commandLine = String(raw || '').trim();
  if (!commandLine) return { ok: false, error: 'Command is required' };
  const [command, ...args] = commandLine.split(/\s+/);
  const cmd = command.toLowerCase();

  if (cmd === 'help' || cmd === 'catrealm-help') {
    return {
      ok: true,
      lines: ['Commands: help, secure-status, db-status, db-latest [n], db-checkpoint, db-encrypt-legacy'],
    };
  }

  if (cmd === 'secure-status' || cmd === 'catrealm-secure') {
    const enabled = process.env.CATREALM_SECURE_MODE_EFFECTIVE === '1';
    const locked = process.env.CATREALM_SECURE_MODE_LOCKED === '1';
    return {
      ok: true,
      lines: [`Secure mode: ${enabled ? 'ENABLED' : 'DISABLED'} (locked=${locked ? 1 : 0})`],
    };
  }

  if (cmd === 'db-status' || cmd === 'catrealm-db-status') {
    const dbPath = process.env.DB_PATH || path.join(__dirname, '../../data/catrealm.db');
    const walPath = `${dbPath}-wal`;
    const shmPath = `${dbPath}-shm`;
    const messageCount = db.prepare('SELECT COUNT(*) as c FROM messages').get().c;
    const latest = db.prepare('SELECT created_at FROM messages ORDER BY created_at DESC LIMIT 1').get();
    const walSize = fs.existsSync(walPath) ? fs.statSync(walPath).size : 0;
    const shmSize = fs.existsSync(shmPath) ? fs.statSync(shmPath).size : 0;
    return {
      ok: true,
      lines: [
        `DB_PATH=${dbPath}`,
        `messages=${messageCount} latest_created_at=${latest?.created_at || 'none'}`,
        `wal_size=${walSize} shm_size=${shmSize}`,
      ],
    };
  }

  if (cmd === 'db-latest' || cmd === 'catrealm-db-latest') {
    const limit = Math.min(Math.max(parseInt(args[0], 10) || 5, 1), 50);
    const rows = db.prepare(`
      SELECT id, channel_id, user_id, created_at, content
      FROM messages
      ORDER BY created_at DESC
      LIMIT ?
    `).all(limit);
    if (rows.length === 0) {
      return { ok: true, lines: ['No messages found.'] };
    }
    return {
      ok: true,
      lines: rows.map((row) => {
        const encrypted = typeof row.content === 'string' && row.content.startsWith('enc:v1:');
        const previewSource = encrypted ? decryptMessageContent(row.content) : row.content;
        const preview = String(previewSource || '').slice(0, 36).replace(/\s+/g, ' ');
        return `msg=${row.id} ch=${row.channel_id} user=${row.user_id} ts=${row.created_at} encrypted=${encrypted ? 1 : 0} preview=${preview}`;
      }),
    };
  }

  if (cmd === 'db-checkpoint' || cmd === 'catrealm-db-checkpoint') {
    try {
      const result = db.prepare('PRAGMA wal_checkpoint(FULL)').get();
      if (result && typeof result === 'object') {
        const busy = result.busy ?? 'n/a';
        const logFrames = result.log ?? result['wal frames'] ?? 'n/a';
        const checkpointed = result.checkpointed ?? result['checkpointed frames'] ?? 'n/a';
        return {
          ok: true,
          lines: [`WAL checkpoint complete (busy=${busy} log=${logFrames} checkpointed=${checkpointed})`],
        };
      }
      return { ok: true, lines: ['WAL checkpoint complete.'] };
    } catch (err) {
      return { ok: false, error: `WAL checkpoint failed: ${err.message}` };
    }
  }

  if (cmd === 'db-encrypt-legacy' || cmd === 'catrealm-db-encrypt-legacy') {
    const rows = db.prepare(`
      SELECT id, content
      FROM messages
      WHERE content NOT LIKE 'enc:v1:%'
    `).all();
    if (rows.length === 0) {
      return { ok: true, lines: ['No legacy plaintext messages found.'] };
    }

    const updateMessage = db.prepare('UPDATE messages SET content = ? WHERE id = ?');
    const migrateMessages = db.transaction((items) => {
      for (const row of items) {
        updateMessage.run(encryptMessageContent(row.content || ''), row.id);
      }
    });
    migrateMessages(rows);
    return { ok: true, lines: [`Encrypted ${rows.length} legacy plaintext messages.`] };
  }

  return { ok: false, error: `Unknown command: ${cmd}` };
}

// Helper function to log audit actions
function logAuditAction(actionType, moderatorId, targetId = null, details = null) {
  const id = randomUUID();
  db.prepare(`
    INSERT INTO audit_log (id, action_type, moderator_id, target_id, details, created_at)
    VALUES (?, ?, ?, ?, ?, unixepoch())
  `).run(id, actionType, moderatorId, targetId, details ? JSON.stringify(details) : null);
}

// GET /api/admin/settings
router.get('/settings', requirePermission(PERMISSIONS.MANAGE_SERVER), (req, res) => {
  const name = getSetting('server_name', process.env.SERVER_NAME || 'CatRealm Server');
  const description = getSetting(
    'server_description',
    process.env.SERVER_DESCRIPTION || 'A self-hosted CatRealm server'
  );
  const registrationOpen = getSetting(
    'registration_open',
    process.env.REGISTRATION_OPEN !== 'false' ? 'true' : 'false'
  );
  const mediaMaxMb = Number(getSetting('media_max_mb', '20'));
  const maxPins = Number(getSetting('max_pins', '300'));
  const avatarMaxMb = Number(getSetting('avatar_max_mb', '10'));
  const mentionAlias = getSetting('mention_alias', '@everyone');
  const serverIcon = getSetting('server_icon', null);
  const serverBanner = getSetting('server_banner', null);
  const maxEmotes = Number(getSetting('max_emotes', '100'));
  const maxAnimatedEmotes = Number(getSetting('max_animated_emotes', '50'));
  const maxStickers = Number(getSetting('max_stickers', '100'));
  const maxAnimatedStickers = Number(getSetting('max_animated_stickers', '50'));

  res.json({
    name,
    description,
    registrationOpen: registrationOpen === 'true',
    mediaMaxMb,
    maxPins,
    avatarMaxMb,
    mentionAlias,
    serverIcon,
    serverBanner,
    maxEmotes,
    maxAnimatedEmotes,
    maxStickers,
    maxAnimatedStickers,
  });
});

// PUT /api/admin/settings
router.put('/settings', requirePermission(PERMISSIONS.MANAGE_SERVER), (req, res) => {
  const { name, description, registrationOpen, mentionAlias } = req.body ?? {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 50) {
    return res.status(400).json({ error: 'Server name must be 2-50 characters' });
  }
  if (typeof description === 'string' && description.length > 200) {
    return res.status(400).json({ error: 'Description must be 200 characters or less' });
  }
  if (typeof mentionAlias === 'string') {
    const alias = mentionAlias.trim();
    if (alias.length < 2 || alias.length > 20) {
      return res.status(400).json({ error: 'Mention alias must be 2-20 characters' });
    }
    setSetting('mention_alias', alias.startsWith('@') ? alias : `@${alias}`);
  }

  setSetting('server_name', name.trim());
  setSetting('server_description', typeof description === 'string' ? description.trim() : '');
  if (typeof registrationOpen === 'boolean') {
    setSetting('registration_open', registrationOpen ? 'true' : 'false');
  }

  if (req.user?.is_owner) {
    if (typeof req.body?.mediaMaxMb === 'number' && req.body.mediaMaxMb >= 1 && req.body.mediaMaxMb <= 200) {
      setSetting('media_max_mb', String(req.body.mediaMaxMb));
    }
    if (typeof req.body?.maxPins === 'number' && req.body.maxPins >= 50 && req.body.maxPins <= 1000) {
      setSetting('max_pins', String(req.body.maxPins));
    }
    if (typeof req.body?.avatarMaxMb === 'number' && req.body.avatarMaxMb >= 1 && req.body.avatarMaxMb <= 50) {
      setSetting('avatar_max_mb', String(req.body.avatarMaxMb));
    }
    if (typeof req.body?.maxEmotes === 'number' && req.body.maxEmotes >= 1 && req.body.maxEmotes <= 500) {
      setSetting('max_emotes', String(req.body.maxEmotes));
    }
    if (typeof req.body?.maxAnimatedEmotes === 'number' && req.body.maxAnimatedEmotes >= 1 && req.body.maxAnimatedEmotes <= 500) {
      setSetting('max_animated_emotes', String(req.body.maxAnimatedEmotes));
    }
    if (typeof req.body?.maxStickers === 'number' && req.body.maxStickers >= 1 && req.body.maxStickers <= 500) {
      setSetting('max_stickers', String(req.body.maxStickers));
    }
    if (typeof req.body?.maxAnimatedStickers === 'number' && req.body.maxAnimatedStickers >= 1 && req.body.maxAnimatedStickers <= 500) {
      setSetting('max_animated_stickers', String(req.body.maxAnimatedStickers));
    }
  }

  const response = {
    name: getSetting('server_name', name.trim()),
    description: getSetting('server_description', ''),
    registrationOpen: getSetting('registration_open', 'true') === 'true',
    mediaMaxMb: Number(getSetting('media_max_mb', '20')),
    maxPins: Number(getSetting('max_pins', '300')),
    avatarMaxMb: Number(getSetting('avatar_max_mb', '10')),
    mentionAlias: getSetting('mention_alias', '@everyone'),
    serverIcon: getSetting('server_icon', null),
    serverBanner: getSetting('server_banner', null),
    maxEmotes: Number(getSetting('max_emotes', '100')),
    maxAnimatedEmotes: Number(getSetting('max_animated_emotes', '50')),
    maxStickers: Number(getSetting('max_stickers', '100')),
    maxAnimatedStickers: Number(getSetting('max_animated_stickers', '50')),
  };

  // Push live server-info updates to all connected clients.
  emitServerInfoUpdate({
    name: response.name,
    description: response.description,
    registrationOpen: response.registrationOpen,
    mentionAlias: response.mentionAlias,
    serverIcon: response.serverIcon,
    serverBanner: response.serverBanner,
  });

  res.json(response);
});

// GET /api/admin/users
router.get('/users', requirePermission(PERMISSIONS.MANAGE_ROLES), (_req, res) => {
  const users = db.prepare('SELECT id, username, role, avatar, bio, is_owner FROM users ORDER BY username COLLATE NOCASE').all();
  const roleRows = db.prepare('SELECT user_id, role_id FROM user_roles').all();
  const rolesByUser = new Map();
  for (const row of roleRows) {
    const list = rolesByUser.get(row.user_id) ?? [];
    list.push(row.role_id);
    rolesByUser.set(row.user_id, list);
  }
  res.json(users.map((u) => ({
    ...u,
    isOwner: !!u.is_owner,
    roleIds: rolesByUser.get(u.id) ?? [],
    accountType: 'local',
  })));
});

// PUT /api/admin/users/:id/role
router.put('/users/:id/role', requirePermission(PERMISSIONS.MANAGE_ROLES), (req, res) => {
  if (SERVER_MODE === 'central_only') {
    return res.status(403).json({ error: 'Role management is not available in central-only mode' });
  }
  const { role } = req.body ?? {};
  if (!['admin', 'member'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }

  const { id } = req.params;
  const user = db.prepare('SELECT id, role, is_owner FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.is_owner) return res.status(400).json({ error: 'Cannot change role for the server owner' });

  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
  res.json({ id, role });
});

// GET /api/admin/roles
router.get('/roles', requirePermission(PERMISSIONS.MANAGE_ROLES), (_req, res) => {
  const roles = db.prepare('SELECT * FROM roles ORDER BY position DESC, name COLLATE NOCASE').all();
  res.json(roles);
});

// POST /api/admin/roles
router.post('/roles', requirePermission(PERMISSIONS.MANAGE_ROLES), (req, res) => {
  const { randomUUID } = require('crypto');
  const { name, permissions = 0, color = null, mentionable = 0, hoist = 0, icon = null } = req.body ?? {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 32) {
    return res.status(400).json({ error: 'Role name must be 2-32 characters' });
  }
  const maxPos = db.prepare('SELECT MAX(position) as m FROM roles').get().m || 0;
  const id = randomUUID();
  db.prepare('INSERT INTO roles (id, name, color, permissions, position, is_default, mentionable, hoist, icon) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, name.trim(), color, permissions, maxPos + 1, 0, mentionable ? 1 : 0, hoist ? 1 : 0, icon);
  const role = db.prepare('SELECT * FROM roles WHERE id = ?').get(id);
  res.status(201).json(role);
});

// PUT /api/admin/roles/:id
router.put('/roles/:id', requirePermission(PERMISSIONS.MANAGE_ROLES), (req, res) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT * FROM roles WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Role not found' });
  const { name, permissions, color, position, mentionable, hoist, icon } = req.body ?? {};
  if (typeof name === 'string') {
    if (name.trim().length < 2 || name.trim().length > 32) {
      return res.status(400).json({ error: 'Role name must be 2-32 characters' });
    }
    db.prepare('UPDATE roles SET name = ? WHERE id = ?').run(name.trim(), id);
  }
  if (typeof permissions === 'number') {
    db.prepare('UPDATE roles SET permissions = ? WHERE id = ?').run(permissions, id);
  }
  if (typeof color === 'string' || color === null) {
    db.prepare('UPDATE roles SET color = ? WHERE id = ?').run(color, id);
  }
  if (typeof position === 'number') {
    db.prepare('UPDATE roles SET position = ? WHERE id = ?').run(position, id);
  }
  if (typeof mentionable === 'boolean' || typeof mentionable === 'number') {
    db.prepare('UPDATE roles SET mentionable = ? WHERE id = ?').run(mentionable ? 1 : 0, id);
  }
  if (typeof hoist === 'boolean' || typeof hoist === 'number') {
    db.prepare('UPDATE roles SET hoist = ? WHERE id = ?').run(hoist ? 1 : 0, id);
  }
  if (typeof icon === 'string' || icon === null) {
    db.prepare('UPDATE roles SET icon = ? WHERE id = ?').run(icon, id);
  }
  const role = db.prepare('SELECT * FROM roles WHERE id = ?').get(id);
  res.json(role);
});

// DELETE /api/admin/roles/:id
router.delete('/roles/:id', requirePermission(PERMISSIONS.MANAGE_ROLES), (req, res) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT * FROM roles WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Role not found' });
  if (existing.is_default) return res.status(400).json({ error: 'Cannot delete default role' });
  db.prepare('DELETE FROM roles WHERE id = ?').run(id);
  res.json({ success: true });
});

// POST /api/admin/roles/:id/icon - Upload role icon
router.post('/roles/:id/icon', requirePermission(PERMISSIONS.MANAGE_ROLES), (req, res) => {
  const multer = require('multer');
  const fs = require('fs');
  const path = require('path');

  const UGC_IMAGES_DIR = process.env.UGC_IMAGES_DIR || path.join(__dirname, '../../data/ugc/images');
  if (!fs.existsSync(UGC_IMAGES_DIR)) fs.mkdirSync(UGC_IMAGES_DIR, { recursive: true });

  const MIME_TO_EXT = {
    'image/png': '.png',
    'image/jpeg': '.jpg',
    'image/webp': '.webp',
    'image/gif': '.gif',
  };

  const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UGC_IMAGES_DIR),
    filename: (req, file, cb) => {
      const ext = MIME_TO_EXT[file.mimetype];
      if (!ext) return cb(new Error('Invalid file type'));
      const safeId = String(req.params.id).replace(/[^a-zA-Z0-9_-]/g, '');
      const filename = `role-${safeId}-${Date.now()}${ext}`;
      cb(null, filename);
    },
  });

  const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (_req, file, cb) => {
      if (!MIME_TO_EXT[file.mimetype]) return cb(new Error('Invalid file type'));
      cb(null, true);
    },
  }).single('file');

  upload(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'File required' });

    const { id } = req.params;
    const existing = db.prepare('SELECT * FROM roles WHERE id = ?').get(id);
    if (!existing) {
      fs.unlinkSync(req.file.path);
      return res.status(404).json({ error: 'Role not found' });
    }

    // Delete old icon if exists
    if (existing.icon) {
      const oldIconPath = path.join(__dirname, '../../data', existing.icon);
      if (fs.existsSync(oldIconPath)) {
        fs.unlinkSync(oldIconPath);
      }
    }

    const iconUrl = `/ugc/images/${req.file.filename}`;
    db.prepare('UPDATE roles SET icon = ? WHERE id = ?').run(iconUrl, id);

    res.json({ icon: iconUrl });
  });
});

// DELETE /api/admin/roles/:id/icon - Delete role icon
router.delete('/roles/:id/icon', requirePermission(PERMISSIONS.MANAGE_ROLES), (req, res) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT * FROM roles WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Role not found' });

  if (existing.icon) {
    const fs = require('fs');
    const path = require('path');
    const iconPath = path.join(__dirname, '../../data', existing.icon);
    if (fs.existsSync(iconPath)) {
      fs.unlinkSync(iconPath);
    }
  }

  db.prepare('UPDATE roles SET icon = NULL WHERE id = ?').run(id);
  res.json({ success: true });
});

// PUT /api/admin/users/:id/roles
router.put('/users/:id/roles', requirePermission(PERMISSIONS.ASSIGN_ROLES), (req, res) => {
  const { id } = req.params;
  const user = db.prepare('SELECT id, is_owner FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.is_owner) return res.status(400).json({ error: 'Cannot modify roles for the server owner' });

  const { roleIds } = req.body ?? {};
  if (!Array.isArray(roleIds)) return res.status(400).json({ error: 'roleIds must be an array' });
  const existingRoles = db.prepare('SELECT id, is_default FROM roles').all();
  const roleSet = new Set(existingRoles.map((r) => r.id));
  const defaultRole = existingRoles.find((r) => r.is_default);
  const filtered = roleIds.filter((rid) => roleSet.has(rid));
  if (defaultRole && !filtered.includes(defaultRole.id)) {
    filtered.push(defaultRole.id);
  }

  const tx = db.transaction(() => {
    db.prepare('DELETE FROM user_roles WHERE user_id = ?').run(id);
    const insert = db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)');
    for (const rid of filtered) {
      insert.run(id, rid);
    }
  });
  tx();

  res.json({ id, roleIds: filtered });
});

// POST /api/admin/users/:id/kick - Kick a member
router.post('/users/:id/kick', requirePermission(PERMISSIONS.KICK_MEMBER), (req, res) => {
  const { id } = req.params;
  const { reason } = req.body || {};

  const user = db.prepare('SELECT id, username, is_owner FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.is_owner) return res.status(400).json({ error: 'Cannot kick the server owner' });

  // For kick, we'll just disconnect them (they can rejoin)
  // In a real implementation, you might want to temporarily block reconnection
  logAuditAction('MEMBER_KICK', req.user.id, id, {
    username: user.username,
    reason
  });

  // Emit socket event to disconnect the user (handled by socket handler)
  // For now, just log it
  res.json({ success: true, kicked: user.username });
});

// POST /api/admin/users/:id/ban - Ban a member
router.post('/users/:id/ban', requirePermission(PERMISSIONS.BAN_MEMBER), (req, res) => {
  const { id } = req.params;
  const { reason } = req.body || {};

  const user = db.prepare('SELECT id, username, is_owner FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.is_owner) return res.status(400).json({ error: 'Cannot ban the server owner' });

  // Check if already banned
  const existingBan = db.prepare('SELECT * FROM bans WHERE user_id = ?').get(id);
  if (existingBan) {
    return res.status(400).json({ error: 'User is already banned' });
  }

  db.prepare(`
    INSERT INTO bans (user_id, banned_by, reason, created_at)
    VALUES (?, ?, ?, unixepoch())
  `).run(id, req.user.id, reason || null);

  logAuditAction('MEMBER_BAN', req.user.id, id, {
    username: user.username,
    reason
  });

  res.json({ success: true, banned: user.username });
});

// DELETE /api/admin/users/:id/ban - Unban a member
router.delete('/users/:id/ban', requirePermission(PERMISSIONS.BAN_MEMBER), (req, res) => {
  const { id } = req.params;

  const ban = db.prepare('SELECT * FROM bans WHERE user_id = ?').get(id);
  if (!ban) {
    return res.status(404).json({ error: 'User is not banned' });
  }

  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(id);

  db.prepare('DELETE FROM bans WHERE user_id = ?').run(id);

  logAuditAction('MEMBER_UNBAN', req.user.id, id, {
    username: user?.username || 'Unknown'
  });

  res.json({ success: true, unbanned: user?.username || id });
});

// GET /api/admin/bans - List all bans
router.get('/bans', requirePermission(PERMISSIONS.BAN_MEMBER), (req, res) => {
  const bans = db.prepare(`
    SELECT
      b.user_id,
      b.banned_by,
      b.reason,
      b.created_at,
      u.username as banned_username,
      m.username as moderator_username
    FROM bans b
    LEFT JOIN users u ON u.id = b.user_id
    LEFT JOIN users m ON m.id = b.banned_by
    ORDER BY b.created_at DESC
  `).all();

  res.json(bans);
});

// POST /api/admin/fetch-template - Fetch Discord template from URL
router.post('/fetch-template', requirePermission(PERMISSIONS.MANAGE_SERVER), async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    // Extract template code from URL
    const urlPattern = /discord\.(?:new|com)\/template\/([a-zA-Z0-9]+)/;
    const shortPattern = /discord\.new\/([a-zA-Z0-9]+)/;

    let templateCode = '';
    const match1 = url.match(urlPattern);
    const match2 = url.match(shortPattern);

    if (match1) {
      templateCode = match1[1];
    } else if (match2) {
      templateCode = match2[1];
    } else {
      return res.status(400).json({ error: 'Invalid Discord template URL format' });
    }

    // Use Discord's official API endpoint
    const https = require('https');
    const apiUrl = `https://discord.com/api/v10/guilds/templates/${templateCode}`;

    const apiResponse = await new Promise((resolve, reject) => {
      https.get(apiUrl, {
        headers: {
          'User-Agent': 'CatRealm-Server/1.0'
        }
      }, (response) => {
        let data = '';
        response.on('data', (chunk) => data += chunk);
        response.on('end', () => {
          if (response.statusCode === 200) {
            resolve(data);
          } else if (response.statusCode === 404) {
            reject(new Error('Template not found. It may be expired or deleted.'));
          } else {
            reject(new Error(`Discord API returned status ${response.statusCode}`));
          }
        });
        response.on('error', reject);
      }).on('error', reject);
    });

    const templateResponse = JSON.parse(apiResponse);
    const templateData = templateResponse.serialized_source_guild;

    if (!templateData) {
      return res.status(404).json({
        error: 'Template data not found in Discord API response.'
      });
    }

    res.json({ template: templateData });
  } catch (err) {
    console.error('Template fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch template from Discord' });
  }
});

// POST /api/admin/generate-import-token - Generate one-time import token for local owners
router.post('/generate-import-token', requirePermission(PERMISSIONS.MANAGE_SERVER), (req, res) => {
  const user = db.prepare('SELECT id, account_type, is_owner FROM users WHERE id = ?').get(req.user.id);

  if (!user || !user.is_owner) {
    return res.status(403).json({ error: 'Only the server owner can import templates' });
  }

  if (user.account_type !== 'local') {
    return res.status(400).json({ error: 'Token generation is only for local accounts. Central accounts use TOTP.' });
  }

  // Generate random 8-character token
  const crypto = require('crypto');
  const token = crypto.randomBytes(4).toString('hex').toUpperCase();
  const expiresAt = Math.floor(Date.now() / 1000) + (10 * 60); // 10 minutes

  // Clean up expired tokens
  db.prepare('DELETE FROM import_tokens WHERE expires_at < unixepoch() OR used = 1').run();

  // Store token
  db.prepare('INSERT INTO import_tokens (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, user.id, expiresAt);

  const pteroLog = require('../logger');
  pteroLog('╔══════════════════════════════════════════════════════════╗');
  pteroLog('║          TEMPLATE IMPORT VERIFICATION TOKEN             ║');
  pteroLog(`║                    ${token}                        ║`);
  pteroLog('║  This token expires in 10 minutes and can only be used  ║');
  pteroLog('║  once. Use it to confirm the template import.           ║');
  pteroLog('╚══════════════════════════════════════════════════════════╝');

  res.json({ message: 'Token generated. Check server console for the token.' });
});

// POST /api/admin/import-template - Import Discord server template
router.post('/import-template', requirePermission(PERMISSIONS.MANAGE_SERVER), async (req, res) => {
  const { template, verificationToken, totp } = req.body;

  if (!template || typeof template !== 'object') {
    return res.status(400).json({ error: 'Invalid template format' });
  }

  // Verify user is owner
  const user = db.prepare('SELECT id, account_type, is_owner FROM users WHERE id = ?').get(req.user.id);
  if (!user || !user.is_owner) {
    return res.status(403).json({ error: 'Only the server owner can import templates' });
  }

  // Verify token or TOTP
  if (user.account_type === 'local') {
    // Local account: verify token
    if (!verificationToken) {
      return res.status(400).json({ error: 'Verification token required. Generate one first.' });
    }

    const tokenRecord = db.prepare(`
      SELECT * FROM import_tokens
      WHERE token = ? AND user_id = ? AND used = 0 AND expires_at > unixepoch()
    `).get(verificationToken, user.id);

    if (!tokenRecord) {
      return res.status(401).json({ error: 'Invalid or expired verification token' });
    }

    // Mark token as used
    db.prepare('UPDATE import_tokens SET used = 1 WHERE token = ?').run(verificationToken);
  } else {
    // Central account: verify TOTP
    if (!totp) {
      return res.status(400).json({ error: 'TOTP code required for central accounts' });
    }

    // TODO: Implement TOTP verification with central auth server
    // For now, just check if totp is provided
    if (totp.length !== 6 || !/^\d{6}$/.test(totp)) {
      return res.status(400).json({ error: 'Invalid TOTP code format' });
    }
  }

  // Emit start event to all clients
  const { emitServerImportStatus } = require('../socket/handler');
  emitServerImportStatus('start', { message: 'Owner is now importing a template... Cats are purring and rebuild the realm!' });

  try {
    const { name, description, roles, channels } = template;
    const imported = { roles: [], channels: [], categories: [] };

    const pteroLog = require('../logger');

    // DELETE ALL EXISTING DATA
    pteroLog('[Template Import] Deleting all existing channels...');
    emitServerImportStatus('progress', { message: 'Removing existing channels...' });
    db.prepare('DELETE FROM channels').run();

    pteroLog('[Template Import] Deleting all existing categories...');
    emitServerImportStatus('progress', { message: 'Removing existing categories...' });
    db.prepare('DELETE FROM categories').run();

    pteroLog('[Template Import] Deleting all existing roles (except default)...');
    emitServerImportStatus('progress', { message: 'Removing existing roles...' });
    db.prepare('DELETE FROM roles WHERE is_default = 0').run();

    pteroLog('[Template Import] Clearing existing data complete.');
    emitServerImportStatus('progress', { message: 'Starting template import...' });

    // Discord permission mapping
    const DISCORD_PERMS = {
      ADMINISTRATOR: 0x8,
      VIEW_AUDIT_LOG: 0x80,
      MANAGE_GUILD: 0x20,
      MANAGE_ROLES: 0x10000000,
      MANAGE_CHANNELS: 0x10,
      KICK_MEMBERS: 0x2,
      BAN_MEMBERS: 0x4,
      MODERATE_MEMBERS: 0x1099511627776,
      MANAGE_NICKNAMES: 0x8000000,
      EMBED_LINKS: 0x4000,
      ATTACH_FILES: 0x8000,
      MENTION_EVERYONE: 0x20000,
      MANAGE_MESSAGES: 0x2000,
      MANAGE_WEBHOOKS: 0x20000000,
      CREATE_INSTANT_INVITE: 0x1,
      CREATE_PUBLIC_THREADS: 0x800000000,
      MANAGE_THREADS: 0x400000000,
    };

    function mapDiscordPermissions(discordPerms) {
      const perms = parseInt(discordPerms);
      let catrealmPerms = 0;

      if (perms & DISCORD_PERMS.ADMINISTRATOR) {
        return (1 << 20) - 1; // All permissions
      }

      if (perms & DISCORD_PERMS.VIEW_AUDIT_LOG) catrealmPerms |= PERMISSIONS.VIEW_AUDIT_LOG;
      if (perms & DISCORD_PERMS.MANAGE_GUILD) catrealmPerms |= PERMISSIONS.MANAGE_SERVER;
      if (perms & DISCORD_PERMS.MANAGE_ROLES) catrealmPerms |= PERMISSIONS.MANAGE_ROLES;
      if (perms & DISCORD_PERMS.MANAGE_CHANNELS) catrealmPerms |= PERMISSIONS.MANAGE_CHANNELS;
      if (perms & DISCORD_PERMS.KICK_MEMBERS) catrealmPerms |= PERMISSIONS.KICK_MEMBER;
      if (perms & DISCORD_PERMS.BAN_MEMBERS) catrealmPerms |= PERMISSIONS.BAN_MEMBER;
      if (perms & DISCORD_PERMS.MODERATE_MEMBERS) catrealmPerms |= PERMISSIONS.TIMEOUT_USER;
      if (perms & DISCORD_PERMS.MANAGE_NICKNAMES) catrealmPerms |= PERMISSIONS.MANAGE_NICKNAMES;
      if (perms & (DISCORD_PERMS.EMBED_LINKS | DISCORD_PERMS.ATTACH_FILES)) catrealmPerms |= PERMISSIONS.SEND_MEDIA;
      if (perms & DISCORD_PERMS.MENTION_EVERYONE) catrealmPerms |= PERMISSIONS.MENTION_EVERYONE;
      if (perms & DISCORD_PERMS.MANAGE_MESSAGES) catrealmPerms |= PERMISSIONS.DELETE_MESSAGES;
      if (perms & DISCORD_PERMS.MANAGE_WEBHOOKS) catrealmPerms |= PERMISSIONS.MANAGE_WEBHOOKS;
      if (perms & DISCORD_PERMS.CREATE_INSTANT_INVITE) catrealmPerms |= PERMISSIONS.CREATE_INVITES;
      if (perms & (DISCORD_PERMS.CREATE_PUBLIC_THREADS | DISCORD_PERMS.MANAGE_THREADS)) {
        catrealmPerms |= PERMISSIONS.CREATE_THREADS;
      }

      return catrealmPerms;
    }

    // Import roles
    if (Array.isArray(roles)) {
      pteroLog(`[Template Import] Importing ${roles.length} roles...`);
      emitServerImportStatus('progress', { message: `Creating ${roles.length} roles...` });

      const maxPos = db.prepare('SELECT MAX(position) as m FROM roles').get().m || 0;
      let positionOffset = maxPos + 1;

      for (const role of roles) {
        if (role.name === '@everyone') continue; // Skip @everyone

        const roleId = randomUUID();
        const color = role.color ? `#${role.color.toString(16).padStart(6, '0')}` : null;
        const permissions = mapDiscordPermissions(role.permissions || '0');

        db.prepare(`
          INSERT INTO roles (id, name, color, permissions, position, mentionable, hoist)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(roleId, role.name, color, permissions, positionOffset++, role.mentionable ? 1 : 0, role.hoist ? 1 : 0);

        imported.roles.push({ id: roleId, name: role.name, permissions });
        pteroLog(`[Template Import]   ✓ Created role: ${role.name}`);
      }
    }

    // Import channels and categories
    if (Array.isArray(channels)) {
      const channelMap = new Map(); // Discord ID -> CatRealm ID
      const categories = channels.filter(ch => ch.type === 4);
      const textVoiceChannels = channels.filter(ch => ch.type === 0 || ch.type === 2);

      pteroLog(`[Template Import] Importing ${categories.length} categories...`);
      emitServerImportStatus('progress', { message: `Creating ${categories.length} categories...` });

      // First pass: create categories
      for (const channel of channels) {
        if (channel.type === 4) { // Category
          const categoryId = randomUUID();
          db.prepare(`
            INSERT INTO categories (id, name, position)
            VALUES (?, ?, ?)
          `).run(categoryId, channel.name, channel.position || 0);

          channelMap.set(channel.id, categoryId);
          imported.categories.push({ id: categoryId, name: channel.name });
          pteroLog(`[Template Import]   ✓ Created category: ${channel.name}`);
        }
      }

      pteroLog(`[Template Import] Importing ${textVoiceChannels.length} channels...`);
      emitServerImportStatus('progress', { message: `Creating ${textVoiceChannels.length} channels...` });

      // Second pass: create channels
      for (const channel of channels) {
        if (channel.type === 0 || channel.type === 2) { // Text or Voice
          const channelId = randomUUID();
          const categoryId = channel.parent_id ? channelMap.get(channel.parent_id) : null;
          const channelType = channel.type === 2 ? 'voice' : 'basic';

          db.prepare(`
            INSERT INTO channels (id, name, type, position, category_id, nsfw)
            VALUES (?, ?, ?, ?, ?, ?)
          `).run(channelId, channel.name, channelType, channel.position || 0, categoryId, channel.nsfw ? 1 : 0);

          imported.channels.push({ id: channelId, name: channel.name, category: categoryId });
          pteroLog(`[Template Import]   ✓ Created channel: #${channel.name} (${channelType})`);
        }
      }
    }

    // Update server name/description if provided
    if (name) {
      pteroLog(`[Template Import] Renaming server to: ${name}`);
      emitServerImportStatus('progress', { message: 'Updating server settings...' });
      setSetting('server_name', name);
    }
    if (description) {
      setSetting('server_description', description);
    }

    logAuditAction('TEMPLATE_IMPORT', req.user.id, null, {
      template_name: name || 'Unknown',
      roles_imported: imported.roles.length,
      channels_imported: imported.channels.length,
      categories_imported: imported.categories.length
    });

    pteroLog('[Template Import] ✓ Import complete!');
    pteroLog(`[Template Import]   Roles: ${imported.roles.length}`);
    pteroLog(`[Template Import]   Categories: ${imported.categories.length}`);
    pteroLog(`[Template Import]   Channels: ${imported.channels.length}`);

    // Emit completion event
    emitServerImportStatus('complete', {
      message: 'Template import complete! Welcome to your new realm.',
      imported
    });

    // Broadcast updates to all clients
    const { broadcastChannelUpdate, emitServerInfoUpdate } = require('../socket/handler');
    broadcastChannelUpdate();
    const serverName = getSetting('server_name', 'CatRealm Server');
    const serverDescription = getSetting('server_description', '');
    emitServerInfoUpdate({ name: serverName, description: serverDescription });

    res.json({
      success: true,
      imported
    });
  } catch (error) {
    console.error('Template import error:', error);
    emitServerImportStatus('error', { message: 'Import failed: ' + error.message });
    res.status(500).json({ error: 'Failed to import template', details: error.message });
  }
});

// ── Server Icon/Banner Upload ──────────────────────────────────────────────────
const UGC_SERVER_DIR = process.env.UGC_SERVER_DIR || path.join(__dirname, '../../data/ugc/server');
if (!fs.existsSync(UGC_SERVER_DIR)) fs.mkdirSync(UGC_SERVER_DIR, { recursive: true });

const MIME_TO_EXT = {
  'image/png': '.png',
  'image/apng': '.apng',
  'image/jpeg': '.jpg',
  'image/gif': '.gif',
};

const iconBannerStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UGC_SERVER_DIR),
  filename: (req, file, cb) => {
    const ext = MIME_TO_EXT[file.mimetype];
    if (!ext) return cb(new Error('Invalid file type'));
    const isIcon = req.path.includes('icon');
    const filename = `${isIcon ? 'RealmIcon' : 'RealmBanner'}${ext}`;
    cb(null, filename);
  },
});

const iconBannerUpload = multer({
  storage: iconBannerStorage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max
  },
  fileFilter: (_req, file, cb) => {
    if (!MIME_TO_EXT[file.mimetype]) return cb(new Error('Invalid file type (must be PNG, APNG, JPG/JPEG, or GIF)'));
    cb(null, true);
  },
});

function removeRealmAsset(baseName) {
  const files = fs.readdirSync(UGC_SERVER_DIR);
  for (const file of files) {
    if (file.startsWith(`${baseName}.`)) {
      const oldPath = path.join(UGC_SERVER_DIR, file);
      if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
    }
  }
}

// POST /api/admin/server-icon
router.post('/server-icon', requirePermission(PERMISSIONS.MANAGE_SERVER), iconBannerUpload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File required' });

  removeRealmAsset('RealmIcon');

  const iconUrl = `/ugc/server/${req.file.filename}`;
  setSetting('server_icon', iconUrl);

  // Broadcast update
  emitServerInfoUpdate({
    serverIcon: iconUrl,
    serverBanner: getSetting('server_banner', null),
  });

  res.json({ serverIcon: iconUrl });
});

// DELETE /api/admin/server-icon
router.delete('/server-icon', requirePermission(PERMISSIONS.MANAGE_SERVER), (req, res) => {
  removeRealmAsset('RealmIcon');
  db.prepare('DELETE FROM server_settings WHERE key = ?').run('server_icon');

  // Broadcast update
  emitServerInfoUpdate({
    serverIcon: null,
    serverBanner: getSetting('server_banner', null),
  });

  res.json({ success: true });
});

// POST /api/admin/server-banner
router.post('/server-banner', requirePermission(PERMISSIONS.MANAGE_SERVER), iconBannerUpload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File required' });

  removeRealmAsset('RealmBanner');

  const bannerUrl = `/ugc/server/${req.file.filename}`;
  setSetting('server_banner', bannerUrl);

  // Broadcast update
  emitServerInfoUpdate({
    serverIcon: getSetting('server_icon', null),
    serverBanner: bannerUrl,
  });

  res.json({ serverBanner: bannerUrl });
});

// DELETE /api/admin/server-banner
router.delete('/server-banner', requirePermission(PERMISSIONS.MANAGE_SERVER), (req, res) => {
  removeRealmAsset('RealmBanner');
  db.prepare('DELETE FROM server_settings WHERE key = ?').run('server_banner');

  // Broadcast update
  emitServerInfoUpdate({
    serverIcon: getSetting('server_icon', null),
    serverBanner: null,
  });

  res.json({ success: true });
});

// POST /api/admin/console-command
router.post('/console-command', requirePermission(PERMISSIONS.MANAGE_SERVER), (req, res) => {
  const command = typeof req.body?.command === 'string' ? req.body.command : '';
  const result = runDiagnosticCommand(command);
  if (!result.ok) {
    return res.status(400).json(result);
  }

  for (const line of result.lines || []) {
    const msg = `[CatRealm Console API] ${line}`;
    try { pteroLog(msg); } catch {}
  }
  res.json(result);
});

module.exports = router;
