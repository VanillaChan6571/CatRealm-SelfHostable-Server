const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticateToken } = require('../middleware/auth');
const { hasPermission, PERMISSIONS } = require('../permissions');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const { URL } = require('url');

// Generate random invite code
function generateInviteCode() {
  return crypto.randomBytes(6).toString('base64url').slice(0, 8);
}

// Register invite with central auth server
async function registerInviteWithAuth(inviteData) {
  const authServerUrl = process.env.AUTH_SERVER_URL;
  if (!authServerUrl) {
    console.log('[Invites] AUTH_SERVER_URL not configured, skipping central registration');
    return false;
  }

  const serverUrl = process.env.SERVER_URL || 'http://localhost:3001';
  const serverName = db.prepare('SELECT value FROM server_settings WHERE key = ?').get('server_name')?.value || 'CatRealm Server';
  const serverDescription = db.prepare('SELECT value FROM server_settings WHERE key = ?').get('server_description')?.value || '';
  const serverIcon = db.prepare('SELECT value FROM server_settings WHERE key = ?').get('server_icon')?.value || null;
  const serverBanner = db.prepare('SELECT value FROM server_settings WHERE key = ?').get('server_banner')?.value || null;
  const memberCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;

  const payload = JSON.stringify({
    code: inviteData.code,
    serverUrl,
    serverName,
    serverDescription,
    serverIcon: serverIcon ? `${serverUrl}${serverIcon}` : null, // Full URL for icon
    serverBanner: serverBanner ? `${serverUrl}${serverBanner}` : null, // Full URL for banner
    memberCount,
    channelId: inviteData.channelId,
    creatorId: inviteData.creatorId,
    maxUses: inviteData.maxUses,
    expiresAt: inviteData.expiresAt,
  });

  return new Promise((resolve) => {
    try {
      const apiUrl = new URL(`${authServerUrl}/api/invites/register`);
      const httpLib = apiUrl.protocol === 'https:' ? https : http;

      const req = httpLib.request({
        hostname: apiUrl.hostname,
        port: apiUrl.port,
        path: apiUrl.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 200) {
            console.log('[Invites] Successfully registered with central auth');
            resolve(true);
          } else {
            console.error('[Invites] Failed to register with auth:', data);
            resolve(false);
          }
        });
      });

      req.on('error', (err) => {
        console.error('[Invites] Error registering with auth:', err.message);
        resolve(false);
      });

      req.write(payload);
      req.end();
    } catch (err) {
      console.error('[Invites] Error in registerInviteWithAuth:', err);
      resolve(false);
    }
  });
}

// GET /api/invites - List all invites (admin only)
router.get('/', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!hasPermission(user, PERMISSIONS.MANAGE_SERVER)) {
    return res.status(403).json({ error: 'Missing permission: MANAGE_SERVER' });
  }

  const invites = db.prepare(`
    SELECT
      invites.*,
      users.username as creator_username,
      channels.name as channel_name
    FROM invites
    LEFT JOIN users ON invites.creator_user_id = users.id
    LEFT JOIN channels ON invites.channel_id = channels.id
    ORDER BY invites.created_at DESC
  `).all();

  res.json(invites);
});

// POST /api/invites - Create new invite
router.post('/', authenticateToken, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!hasPermission(user, PERMISSIONS.CREATE_INVITE)) {
    return res.status(403).json({ error: 'Missing permission: CREATE_INVITE' });
  }

  const { channelId, maxUses, expiresIn } = req.body;

  // Validate channel if provided
  if (channelId) {
    const channel = db.prepare('SELECT * FROM channels WHERE id = ?').get(channelId);
    if (!channel) {
      return res.status(404).json({ error: 'Channel not found' });
    }
  }

  const code = generateInviteCode();
  const expiresAt = expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : null;

  // Store locally
  try {
    db.prepare(`
      INSERT INTO invites (code, channel_id, creator_user_id, max_uses, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(code, channelId || null, req.user.id, maxUses || 0, expiresAt);
  } catch (err) {
    console.error('[Invites] Error creating invite:', err);
    return res.status(500).json({ error: 'Failed to create invite' });
  }

  // Register with central auth (async, don't block response)
  registerInviteWithAuth({
    code,
    channelId,
    creatorId: req.user.id,
    maxUses: maxUses || 0,
    expiresAt,
  });

  const authServerUrl = process.env.AUTH_SERVER_URL;
  const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';

  res.json({
    code,
    centralUrl: authServerUrl ? `${clientUrl}/invite/${code}` : null,
    directUrl: `${process.env.SERVER_URL || 'http://localhost:3001'}/invite/${code}`,
  });
});

// DELETE /api/invites/:code - Revoke invite
router.delete('/:code', authenticateToken, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!hasPermission(user, PERMISSIONS.MANAGE_SERVER)) {
    return res.status(403).json({ error: 'Missing permission: MANAGE_SERVER' });
  }

  const result = db.prepare('DELETE FROM invites WHERE code = ?').run(req.params.code);

  if (result.changes === 0) {
    return res.status(404).json({ error: 'Invite not found' });
  }

  // Delete from central auth server
  const authServerUrl = process.env.AUTH_SERVER_URL;
  if (authServerUrl) {
    try {
      const apiUrl = new URL(`${authServerUrl}/api/invites/${req.params.code}`);
      const httpLib = apiUrl.protocol === 'https:' ? https : http;

      await new Promise((resolve) => {
        const req = httpLib.request({
          hostname: apiUrl.hostname,
          port: apiUrl.port,
          path: apiUrl.pathname,
          method: 'DELETE',
        }, (res) => {
          res.on('data', () => {});
          res.on('end', () => resolve(true));
        });

        req.on('error', (err) => {
          console.error('[Invites] Error deleting from auth server:', err.message);
          resolve(false);
        });

        req.end();
      });
    } catch (err) {
      console.error('[Invites] Error in deleteFromAuth:', err);
    }
  }

  res.json({ success: true });
});

// POST /api/invites/:code/accept - Accept invite (used for direct server invites)
router.post('/:code/accept', (req, res) => {
  const { code } = req.params;

  const invite = db.prepare('SELECT * FROM invites WHERE code = ?').get(code);

  if (!invite) {
    return res.status(404).json({ error: 'Invalid invite code' });
  }

  // Check expiry
  const now = Math.floor(Date.now() / 1000);
  if (invite.expires_at && invite.expires_at < now) {
    return res.status(410).json({ error: 'Invite expired' });
  }

  // Check max uses
  if (invite.max_uses > 0 && invite.current_uses >= invite.max_uses) {
    return res.status(410).json({ error: 'Invite has reached maximum uses' });
  }

  // Increment usage count
  db.prepare('UPDATE invites SET current_uses = current_uses + 1 WHERE code = ?').run(code);

  const serverName = db.prepare('SELECT value FROM server_settings WHERE key = ?').get('server_name')?.value || 'CatRealm Server';

  res.json({
    success: true,
    serverUrl: process.env.SERVER_URL || 'http://localhost:3001',
    serverName,
    channelId: invite.channel_id,
  });
});

module.exports = router;
