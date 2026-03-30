const jwt = require('jsonwebtoken');
const axios = require('axios');
const db = require('../db');
const { computePermissionsForUser } = require('../permissions');
const { applyRoleViewToUser } = require('../viewAsRole');
const pteroLog = require('../logger');

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const SERVER_MODE = process.env.SERVER_MODE || 'decentral_only'; // central_only | mixed | decentral_only
const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL || 'https://auth.catrealm.app';
const AUTH_VERIFY_TIMEOUT = Number(process.env.AUTH_VERIFY_TIMEOUT || 5000);

// ── Verify a token based on server mode ────────────────────────────────────────
async function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1] ?? req.query?.token;
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    if (payload.type === 'central') {
      // Central account — must be in central_only or mixed mode
      if (SERVER_MODE === 'decentral_only') {
        return res.status(403).json({ error: 'This server only accepts local accounts' });
      }
      try {
        const resp = await axios.get(`${AUTH_SERVER_URL}/api/verify`, {
          headers: { Authorization: `Bearer ${token}` },
          timeout: AUTH_VERIFY_TIMEOUT
        });
        if (!resp.data.valid) return res.status(401).json({ error: 'Central account verification failed' });

        // Look up local user record by central_id
        const centralId = resp.data.user.id;
        const localUser = db.prepare('SELECT id, username, role, is_owner, is_member, onboarding_completed FROM users WHERE central_id = ?').get(centralId);
        if (localUser) {
          const isBanned = !!db.prepare('SELECT 1 FROM bans WHERE user_id = ?').get(localUser.id);
          if (isBanned) {
            return res.status(403).json({ error: 'Banned from server' });
          }
          if (Number(localUser.is_member ?? 1) !== 1) {
            return res.status(403).json({ error: 'Removed from server' });
          }
          const permissions = computePermissionsForUser(localUser.id, localUser.role, localUser.is_owner, db);
          req.authUser = {
            ...localUser,
            is_owner: localUser.is_owner ? 1 : 0,
            permissions,
            accountType: 'central',
          };
        } else {
          req.authUser = { ...resp.data.user, permissions: 0, accountType: 'central' };
        }
      } catch (err) {
        if (axios.isAxiosError(err)) {
          pteroLog(`[CatRealm] Central auth verify failed: ${err.code || 'ERR'} ${err.message} ${err.response?.status || ''}`.trim());
        }
        return res.status(503).json({ error: 'Could not reach CatRealm auth server' });
      }
    } else if (payload.account_type === 'central') {
      // Server-issued token for central account (verified at issuance time)
      if (SERVER_MODE === 'decentral_only') {
        return res.status(403).json({ error: 'This server only accepts local accounts' });
      }
      const user = db.prepare('SELECT id, username, role, is_owner, is_member, onboarding_completed FROM users WHERE id = ?').get(payload.id);
      if (!user) return res.status(401).json({ error: 'User not found' });
      if (db.prepare('SELECT 1 FROM bans WHERE user_id = ?').get(user.id)) return res.status(403).json({ error: 'Banned from server' });
      if (Number(user.is_member ?? 1) !== 1) return res.status(403).json({ error: 'Removed from server' });
      const permissions = computePermissionsForUser(user.id, user.role, user.is_owner, db);
      req.authUser = {
        ...user,
        is_owner: user.is_owner ? 1 : 0,
        permissions,
        accountType: 'central',
      };
    } else {
      // Local/decentral account
      if (SERVER_MODE === 'central_only') {
        return res.status(403).json({ error: 'This server only accepts CatRealm central accounts' });
      }
      const user = db.prepare('SELECT id, username, role, is_owner, is_member, onboarding_completed FROM users WHERE id = ?').get(payload.id);
      if (!user) return res.status(401).json({ error: 'User not found' });
      if (db.prepare('SELECT 1 FROM bans WHERE user_id = ?').get(user.id)) return res.status(403).json({ error: 'Banned from server' });
      if (Number(user.is_member ?? 1) !== 1) return res.status(403).json({ error: 'Removed from server' });
      const permissions = computePermissionsForUser(user.id, user.role, user.is_owner, db);

      req.authUser = {
        ...user,
        is_owner: user.is_owner ? 1 : 0,
        permissions,
        accountType: 'local',
      };
    }

    const { user, session } = applyRoleViewToUser(req.authUser, db);
    req.user = user;
    req.viewAsRole = session;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// ── Check if a username conflicts with a central account (mixed mode only) ─────
async function checkUsernameConflict(username) {
  if (SERVER_MODE !== 'mixed') return false;
  try {
    const resp = await axios.get(`${AUTH_SERVER_URL}/api/verify/username/${encodeURIComponent(username)}`, {
      timeout: 5000
    });
    return !!(resp.data.taken || resp.data.reserved);
  } catch {
    return true; // If auth server unreachable, block the name to be safe
  }
}

module.exports = { authenticateToken, JWT_SECRET, SERVER_MODE, checkUsernameConflict };
