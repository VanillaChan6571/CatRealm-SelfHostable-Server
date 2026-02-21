const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticateToken } = require('../middleware/auth');
const { hasPermission, PERMISSIONS } = require('../permissions');
const { getSetting, setSetting } = require('../settings');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const net = require('net');
const { URL } = require('url');
const DEFAULT_AUTH_SERVER_URL = 'https://auth.catrealm.app';
const PUBLIC_IP_LOOKUP_TIMEOUT_MS = 3500;
const DEFAULT_AUTH_REGISTER_TIMEOUT_MS = 30000;
const PUBLIC_IP_PROVIDERS = [
  'https://api64.ipify.org?format=json',
  'https://api.ipify.org?format=json',
  'https://ifconfig.me/ip',
  'https://checkip.amazonaws.com',
];
const DISCOVERY_INVITE_SETTING_KEY = 'discovery_invite_code';

function isOwnerLevelUser(user) {
  if (!user) return false;
  return Boolean(user.is_owner) || user.role === 'owner';
}

// Generate random invite code
function generateInviteCode() {
  return crypto.randomBytes(6).toString('base64url').slice(0, 8);
}

function normalizeOrigin(value) {
  if (!value || typeof value !== 'string') return null;
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

function inferRequestOrigin(req) {
  const originHeader = normalizeOrigin(req.get('origin'));
  if (originHeader) return originHeader;

  const refererHeader = req.get('referer');
  if (refererHeader) {
    try {
      const referer = new URL(refererHeader);
      if (referer.protocol === 'http:' || referer.protocol === 'https:') {
        return `${referer.protocol}//${referer.host}`;
      }
    } catch {
      // ignore invalid referer values
    }
  }

  const forwardedHost = req.get('x-forwarded-host');
  if (forwardedHost) {
    const host = forwardedHost.split(',')[0].trim();
    const forwardedProto = req.get('x-forwarded-proto');
    const proto = forwardedProto ? forwardedProto.split(',')[0].trim() : (req.protocol || 'http');
    if (host) return `${proto}://${host}`;
  }

  const host = req.get('host');
  if (host) return `${req.protocol || 'http'}://${host}`;

  return null;
}

function inferServerOrigin(req) {
  const forwardedHost = req.get('x-forwarded-host');
  if (forwardedHost) {
    const host = forwardedHost.split(',')[0].trim();
    const forwardedProto = req.get('x-forwarded-proto');
    const proto = forwardedProto ? forwardedProto.split(',')[0].trim() : (req.protocol || 'http');
    if (host) return `${proto}://${host}`;
  }

  const host = req.get('host');
  if (host) return `${req.protocol || 'http'}://${host}`;

  return null;
}

function getPublicServerUrl(req) {
  return normalizeOrigin(process.env.PUBLIC_SERVER_URL)
    || normalizeOrigin(process.env.SERVER_URL)
    || inferServerOrigin(req)
    || 'http://localhost:3001';
}

function getPublicClientUrl(req) {
  return normalizeOrigin(process.env.CLIENT_URL)
    || inferRequestOrigin(req)
    || 'http://localhost:5173';
}

function getAuthServerUrl() {
  return normalizeOrigin(process.env.AUTH_SERVER_URL) || DEFAULT_AUTH_SERVER_URL;
}

function getAuthRegisterTimeoutMs() {
  const configured = Number(process.env.AUTH_REGISTER_TIMEOUT_MS);
  if (!Number.isFinite(configured) || configured <= 0) return DEFAULT_AUTH_REGISTER_TIMEOUT_MS;
  return Math.max(5000, Math.min(120000, Math.floor(configured)));
}

function getHostPortFromUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    const port = parsed.port
      ? Number(parsed.port)
      : (parsed.protocol === 'https:' ? 443 : parsed.protocol === 'http:' ? 80 : null);
    return {
      host: parsed.hostname || null,
      port: Number.isFinite(port) ? Number(port) : null,
    };
  } catch {
    return { host: null, port: null };
  }
}

function formatInviteRegistrationError(registration, serverUrl) {
  const raw = String(registration?.error || '').trim();
  const { host, port } = getHostPortFromUrl(serverUrl);
  const reachabilityPattern = /ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|timed out|socket hang up|connect\s+/i;

  if (reachabilityPattern.test(raw)) {
    const target = host && port ? `${host}:${port}` : (host || 'the configured server address');
    const portLabel = port ? `port forwarding of ${port}` : 'port forwarding';
    return `Server ${portLabel} is not reachable at ${target}. Invite failed to create.`;
  }

  if (raw) return raw;
  return 'Invite creation rejected by central auth';
}

function isUnroutableHostname(hostname) {
  const host = String(hostname || '').trim().toLowerCase();
  if (!host) return true;

  if (host === 'localhost' || host === '0.0.0.0' || host === '::' || host === '::1') return true;
  if (host.endsWith('.local')) return true;

  const ipVersion = net.isIP(host);
  if (ipVersion === 4) {
    const parts = host.split('.').map((v) => Number(v));
    if (parts.length !== 4 || parts.some((v) => Number.isNaN(v))) return true;
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a >= 224) return true;
    return false;
  }

  if (ipVersion === 6) {
    if (host === '::1' || host === '::') return true;
    if (host.startsWith('fe80:')) return true; // link-local
    if (host.startsWith('fc') || host.startsWith('fd')) return true; // unique local
    return false;
  }

  return false;
}

function parseIpFromLookupResponse(body) {
  const raw = String(body || '').trim();
  if (!raw) return null;

  if (raw.startsWith('{')) {
    try {
      const parsed = JSON.parse(raw);
      const value = typeof parsed?.ip === 'string' ? parsed.ip.trim() : '';
      return net.isIP(value) ? value : null;
    } catch {
      return null;
    }
  }

  const candidate = raw.split(/\s+/)[0].trim();
  return net.isIP(candidate) ? candidate : null;
}

function requestText(url, timeoutMs = PUBLIC_IP_LOOKUP_TIMEOUT_MS) {
  return new Promise((resolve) => {
    try {
      const target = new URL(url);
      const httpLib = target.protocol === 'https:' ? https : http;
      const req = httpLib.request({
        hostname: target.hostname,
        port: target.port,
        path: `${target.pathname}${target.search || ''}`,
        method: 'GET',
        headers: {
          Accept: 'application/json,text/plain;q=0.9,*/*;q=0.8',
          'User-Agent': 'CatRealm-SelfHost-Invite/1.0',
        },
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve(data);
          } else {
            resolve(null);
          }
        });
      });
      req.setTimeout(timeoutMs, () => req.destroy(new Error('timeout')));
      req.on('error', () => resolve(null));
      req.end();
    } catch {
      resolve(null);
    }
  });
}

async function resolvePublicIpAddress() {
  for (const provider of PUBLIC_IP_PROVIDERS) {
    const response = await requestText(provider);
    if (!response) continue;
    const ip = parseIpFromLookupResponse(response);
    if (ip && !isUnroutableHostname(ip)) return ip;
  }
  return null;
}

async function resolvePublicServerUrl(req) {
  const base = getPublicServerUrl(req);
  try {
    const parsed = new URL(base);
    if (!isUnroutableHostname(parsed.hostname)) {
      return `${parsed.protocol}//${parsed.host}`;
    }

    const publicIp = await resolvePublicIpAddress();
    if (!publicIp) return `${parsed.protocol}//${parsed.host}`;

    const previousHost = parsed.hostname;
    parsed.hostname = publicIp;
    const resolved = `${parsed.protocol}//${parsed.host}`;
    console.log(`[Invites] Resolved public host ${previousHost} -> ${publicIp} for invite registration`);
    return resolved;
  } catch {
    return base;
  }
}

// Register invite with central auth server
async function registerInviteWithAuth(inviteData) {
  const authServerUrl = getAuthServerUrl();
  const authRegisterTimeoutMs = getAuthRegisterTimeoutMs();

  const serverUrl = inviteData.serverUrl;
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

      const request = httpLib.request({
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
          let parsed = null;
          try {
            parsed = data ? JSON.parse(data) : null;
          } catch {
            parsed = null;
          }

          if (res.statusCode === 200) {
            console.log('[Invites] Successfully registered with central auth');
            resolve({
              ok: true,
              status: 200,
              centralUrl: parsed?.centralUrl || null,
            });
          } else {
            const errorMessage = parsed?.error || `Auth registration failed with status ${res.statusCode}`;
            console.error('[Invites] Failed to register with auth:', errorMessage);
            resolve({
              ok: false,
              status: Number(res.statusCode || 500),
              error: errorMessage,
            });
          }
        });
      });

      request.setTimeout(authRegisterTimeoutMs, () => {
        request.destroy(new Error('Auth registration request timed out'));
      });

      request.on('error', (err) => {
        console.error('[Invites] Error registering with auth:', err.message);
        resolve({ ok: false, status: 502, error: err.message });
      });

      request.write(payload);
      request.end();
    } catch (err) {
      console.error('[Invites] Error in registerInviteWithAuth:', err);
      resolve({ ok: false, status: 500, error: err.message || 'Unknown auth registration error' });
    }
  });
}

function requestToAuthServer({ path, method, payload = null, timeoutMs = 10000 }) {
  return new Promise((resolve) => {
    try {
      const authServerUrl = getAuthServerUrl();
      const apiUrl = new URL(`${authServerUrl}${path}`);
      const httpLib = apiUrl.protocol === 'https:' ? https : http;
      const body = payload ? JSON.stringify(payload) : null;

      const request = httpLib.request({
        hostname: apiUrl.hostname,
        port: apiUrl.port,
        path: `${apiUrl.pathname}${apiUrl.search || ''}`,
        method,
        headers: body ? {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        } : {},
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          let parsed = null;
          try {
            parsed = data ? JSON.parse(data) : null;
          } catch {
            parsed = null;
          }
          const ok = Number(res.statusCode || 500) >= 200 && Number(res.statusCode || 500) < 300;
          resolve({
            ok,
            status: Number(res.statusCode || 500),
            data: parsed,
            error: parsed?.error || (!ok ? `Auth request failed with status ${res.statusCode}` : null),
          });
        });
      });

      request.setTimeout(timeoutMs, () => {
        request.destroy(new Error('Auth request timed out'));
      });

      request.on('error', (err) => {
        resolve({ ok: false, status: 502, data: null, error: err.message || 'Auth request failed' });
      });

      if (body) request.write(body);
      request.end();
    } catch (err) {
      resolve({ ok: false, status: 500, data: null, error: err.message || 'Invalid auth request' });
    }
  });
}

async function deleteInviteFromAuth(code) {
  return requestToAuthServer({
    path: `/api/invites/${encodeURIComponent(code)}`,
    method: 'DELETE',
  });
}

async function deleteDiscoveryFromAuth(code) {
  return requestToAuthServer({
    path: `/api/discovery/by-invite/${encodeURIComponent(code)}`,
    method: 'DELETE',
  });
}

async function registerDiscoveryWithAuth(code, publishedBy) {
  return requestToAuthServer({
    path: '/api/discovery/register',
    method: 'POST',
    payload: {
      inviteCode: code,
      publishedBy: publishedBy || null,
    },
  });
}

async function createInviteAndRegister(req, inviteInput) {
  const serverUrl = await resolvePublicServerUrl(req);
  const authServerUrl = getAuthServerUrl();
  const clientUrl = getPublicClientUrl(req);
  const channelId = inviteInput.channelId || null;
  const normalizedMaxUses = Number(inviteInput.maxUses) || 0;
  const normalizedExpiresIn = Number(inviteInput.expiresIn) || 0;
  const expiresAt = normalizedExpiresIn > 0 ? Math.floor(Date.now() / 1000) + normalizedExpiresIn : null;
  const maxAttempts = authServerUrl ? 8 : 1;
  let lastAuthError = null;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const code = generateInviteCode();
    try {
      db.prepare(`
        INSERT INTO invites (code, channel_id, creator_user_id, max_uses, expires_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(code, channelId, inviteInput.creatorId, normalizedMaxUses, expiresAt);
    } catch {
      continue;
    }

    if (authServerUrl) {
      const registration = await registerInviteWithAuth({
        code,
        serverUrl,
        channelId,
        creatorId: inviteInput.creatorId,
        maxUses: normalizedMaxUses,
        expiresAt,
      });
      if (!registration.ok) {
        db.prepare('DELETE FROM invites WHERE code = ?').run(code);
        lastAuthError = registration;
        if (registration.status === 409) continue;
        return {
          ok: false,
          status: 502,
          error: formatInviteRegistrationError(registration, serverUrl),
        };
      }

      return {
        ok: true,
        status: 200,
        code,
        centralUrl: registration.centralUrl || `${clientUrl}/invite/${code}`,
        directUrl: `${serverUrl}/invite/${code}`,
      };
    }

    return {
      ok: true,
      status: 200,
      code,
      centralUrl: null,
      directUrl: `${serverUrl}/invite/${code}`,
    };
  }

  if (lastAuthError?.error) {
    return { ok: false, status: 500, error: lastAuthError.error };
  }
  return { ok: false, status: 500, error: 'Failed to generate a unique invite code' };
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

  const created = await createInviteAndRegister(req, {
    channelId: channelId || null,
    maxUses: maxUses || 0,
    expiresIn: expiresIn || 0,
    creatorId: req.user.id,
  });
  if (!created.ok) {
    return res.status(created.status || 500).json({ error: created.error || 'Failed to create invite' });
  }
  return res.json({
    code: created.code,
    centralUrl: created.centralUrl,
    directUrl: created.directUrl,
  });
});

// GET /api/invites/discovery/status - Owner-only discovery publication status
router.get('/discovery/status', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!isOwnerLevelUser(user)) {
    return res.status(403).json({ error: 'Only server owner can manage discovery publication', owner: false });
  }

  const inviteCode = String(getSetting(DISCOVERY_INVITE_SETTING_KEY, '') || '').trim();
  if (!inviteCode) {
    return res.json({ owner: true, published: false });
  }

  const invite = db.prepare('SELECT code, max_uses, expires_at FROM invites WHERE code = ?').get(inviteCode);
  if (!invite) {
    setSetting(DISCOVERY_INVITE_SETTING_KEY, '');
    return res.json({ owner: true, published: false });
  }

  const clientUrl = getPublicClientUrl(req);
  return res.json({
    owner: true,
    published: true,
    inviteCode,
    inviteUrl: `${clientUrl}/invite/${encodeURIComponent(inviteCode)}`,
    permanent: Number(invite.max_uses || 0) === 0 && invite.expires_at === null,
  });
});

// POST /api/invites/discovery/publish - Owner-only publish using permanent invite
router.post('/discovery/publish', authenticateToken, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!isOwnerLevelUser(user)) {
    return res.status(403).json({ error: 'Only server owner can publish server discovery' });
  }

  const existingCode = String(getSetting(DISCOVERY_INVITE_SETTING_KEY, '') || '').trim();
  if (existingCode) {
    const existingInvite = db.prepare('SELECT code, max_uses, expires_at FROM invites WHERE code = ?').get(existingCode);
    if (existingInvite && Number(existingInvite.max_uses || 0) === 0 && existingInvite.expires_at === null) {
      const discoveryRegistration = await registerDiscoveryWithAuth(existingCode, req.user.id);
      if (!discoveryRegistration.ok) {
        return res.status(502).json({ error: discoveryRegistration.error || 'Failed to refresh discovery registration' });
      }
      const clientUrl = getPublicClientUrl(req);
      return res.json({
        success: true,
        inviteCode: existingCode,
        inviteUrl: `${clientUrl}/invite/${encodeURIComponent(existingCode)}`,
        published: true,
      });
    }
    setSetting(DISCOVERY_INVITE_SETTING_KEY, '');
  }

  const created = await createInviteAndRegister(req, {
    channelId: null,
    maxUses: 0,
    expiresIn: 0,
    creatorId: req.user.id,
  });
  if (!created.ok || !created.code) {
    return res.status(created.status || 500).json({ error: created.error || 'Failed to create permanent invite for discovery' });
  }

  const discoveryRegistration = await registerDiscoveryWithAuth(created.code, req.user.id);
  if (!discoveryRegistration.ok) {
    db.prepare('DELETE FROM invites WHERE code = ?').run(created.code);
    await deleteInviteFromAuth(created.code);
    return res.status(502).json({ error: discoveryRegistration.error || 'Failed to publish discovery entry' });
  }

  setSetting(DISCOVERY_INVITE_SETTING_KEY, created.code);
  return res.json({
    success: true,
    inviteCode: created.code,
    inviteUrl: created.centralUrl || created.directUrl,
    published: true,
  });
});

// DELETE /api/invites/discovery/unpublish - Owner-only unpublish (revokes discovery invite)
router.delete('/discovery/unpublish', authenticateToken, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!isOwnerLevelUser(user)) {
    return res.status(403).json({ error: 'Only server owner can unpublish server discovery' });
  }

  const inviteCode = String(
    req.body?.inviteCode
    || getSetting(DISCOVERY_INVITE_SETTING_KEY, '')
    || ''
  ).trim();

  if (!inviteCode) {
    return res.json({ success: true, published: false });
  }

  db.prepare('DELETE FROM invites WHERE code = ?').run(inviteCode);
  setSetting(DISCOVERY_INVITE_SETTING_KEY, '');
  await deleteInviteFromAuth(inviteCode);
  await deleteDiscoveryFromAuth(inviteCode);

  return res.json({ success: true, published: false });
});

// DELETE /api/invites/:code - Revoke invite
router.delete('/:code', authenticateToken, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!hasPermission(user, PERMISSIONS.MANAGE_SERVER)) {
    return res.status(403).json({ error: 'Missing permission: MANAGE_SERVER' });
  }

  const code = String(req.params.code || '').trim();
  const result = db.prepare('DELETE FROM invites WHERE code = ?').run(code);

  if (result.changes === 0) {
    return res.status(404).json({ error: 'Invite not found' });
  }

  if (String(getSetting(DISCOVERY_INVITE_SETTING_KEY, '') || '').trim() === code) {
    setSetting(DISCOVERY_INVITE_SETTING_KEY, '');
  }

  await deleteInviteFromAuth(code);
  await deleteDiscoveryFromAuth(code);

  res.json({ success: true });
});

// GET /api/invites/:code/probe - Used by central auth to verify invite existence/metadata
router.get('/:code/probe', (req, res) => {
  const { code } = req.params;
  const invite = db.prepare(`
    SELECT code, channel_id, max_uses, expires_at
    FROM invites
    WHERE code = ?
  `).get(code);

  if (!invite) {
    return res.status(404).json({ valid: false, error: 'Invite code not found' });
  }

  const now = Math.floor(Date.now() / 1000);
  if (invite.expires_at && invite.expires_at < now) {
    return res.status(410).json({ valid: false, error: 'Invite expired' });
  }

  return res.json({
    valid: true,
    code: invite.code,
    channelId: invite.channel_id || null,
    maxUses: Number(invite.max_uses || 0),
    expiresAt: invite.expires_at || null,
  });
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
  const serverUrl = getPublicServerUrl(req);

  res.json({
    success: true,
    serverUrl,
    serverName,
    channelId: invite.channel_id,
  });
});

module.exports = router;
