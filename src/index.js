require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const pteroLog = require('./logger');

function isTruthy(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

function safeBranch(value) {
  const branch = (value || 'main').trim();
  if (/^[A-Za-z0-9._/-]+$/.test(branch)) return branch;
  return 'main';
}

function runGit(repoRoot, args) {
  return spawnSync('git', args, {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function runNpmInstall(repoRoot) {
  const npm = spawnSync('npm', ['install', '--omit=dev'], {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: 'inherit',
  });
  return npm.status === 0;
}

function ensureGitRepoAndUpdate() {
  const autoUpdate = isTruthy(process.env.AUTO_UPDATE, true);
  if (!autoUpdate) {
    pteroLog('[CatRealm] Auto-update disabled.');
    return;
  }

  const repoRoot = path.join(__dirname, '..');
  const branch = safeBranch(process.env.GIT_BRANCH || 'main');
  const repo = (process.env.GIT_REPO || 'https://github.com/VanillaChan6571/CatRealm-SelfHostable-Server.git').trim();

  const gitVersion = spawnSync('git', ['--version'], { encoding: 'utf8' });
  if (gitVersion.status !== 0) {
    pteroLog('[CatRealm] Auto-update skipped: git is not installed.');
    return;
  }

  pteroLog(`[CatRealm] Auto-update check (branch=${branch})`);

  const gitDir = path.join(repoRoot, '.git');
  if (!fs.existsSync(gitDir)) {
    pteroLog('[CatRealm] .git not found. Initializing repository from GIT_REPO...');
    if (runGit(repoRoot, ['init']).status !== 0) {
      pteroLog('[CatRealm] Auto-update failed: git init failed.');
      return;
    }
    runGit(repoRoot, ['remote', 'remove', 'origin']);
    if (runGit(repoRoot, ['remote', 'add', 'origin', repo]).status !== 0) {
      pteroLog('[CatRealm] Auto-update failed: unable to add origin remote.');
      return;
    }
    if (runGit(repoRoot, ['fetch', '--depth=1', 'origin', branch]).status !== 0) {
      pteroLog('[CatRealm] Auto-update failed: unable to fetch branch from origin.');
      return;
    }
    if (runGit(repoRoot, ['checkout', '-B', branch, `origin/${branch}`]).status !== 0) {
      pteroLog('[CatRealm] Auto-update failed: unable to checkout fetched branch.');
      return;
    }
    pteroLog('[CatRealm] Repository initialized from remote.');
    runNpmInstall(repoRoot);
    return;
  }

  // Ensure origin points at configured repository.
  const currentOrigin = runGit(repoRoot, ['remote', 'get-url', 'origin']);
  if (currentOrigin.status !== 0) {
    runGit(repoRoot, ['remote', 'add', 'origin', repo]);
  } else if ((currentOrigin.stdout || '').trim() !== repo) {
    runGit(repoRoot, ['remote', 'set-url', 'origin', repo]);
  }

  const localSha = runGit(repoRoot, ['rev-parse', 'HEAD']);
  if (localSha.status !== 0) {
    pteroLog('[CatRealm] Auto-update failed: could not read local HEAD.');
    return;
  }

  if (runGit(repoRoot, ['fetch', '--all', '--prune']).status !== 0) {
    pteroLog('[CatRealm] Auto-update failed: git fetch failed.');
    return;
  }

  const remoteSha = runGit(repoRoot, ['rev-parse', `origin/${branch}`]);
  if (remoteSha.status !== 0) {
    pteroLog(`[CatRealm] Auto-update skipped: origin/${branch} not found.`);
    return;
  }

  const local = (localSha.stdout || '').trim();
  const remote = (remoteSha.stdout || '').trim();
  if (!local || !remote) {
    pteroLog('[CatRealm] Auto-update skipped: invalid revision data.');
    return;
  }
  if (local === remote) {
    pteroLog('[CatRealm] Auto-update: already up-to-date.');
    return;
  }

  pteroLog(`[CatRealm] Update found: ${local.slice(0, 7)} -> ${remote.slice(0, 7)}. Applying...`);
  if (runGit(repoRoot, ['reset', '--hard', `origin/${branch}`]).status !== 0) {
    pteroLog('[CatRealm] Auto-update failed: git reset failed.');
    return;
  }
  runNpmInstall(repoRoot);
  pteroLog('[CatRealm] Auto-update applied.');
}

ensureGitRepoAndUpdate();

function ensureJwtSecret() {
  const current = process.env.JWT_SECRET;
  const isPlaceholder = !current || current === 'change-this-secret-in-production' || current === 'change-this-to-a-long-random-string';
  if (!isPlaceholder) return;

  const envPath = path.join(__dirname, '../.env');
  const envExamplePath = path.join(__dirname, '../.env.example');

  if (!fs.existsSync(envPath)) {
    if (fs.existsSync(envExamplePath)) {
      fs.copyFileSync(envExamplePath, envPath);
    }
  }

  let envContents = '';
  if (fs.existsSync(envPath)) {
    envContents = fs.readFileSync(envPath, 'utf8');
  }

  const secret = crypto.randomBytes(48).toString('hex');
  process.env.JWT_SECRET = secret;

  if (/^JWT_SECRET=.*$/m.test(envContents)) {
    envContents = envContents.replace(/^JWT_SECRET=.*$/m, `JWT_SECRET=${secret}`);
  } else {
    envContents = `${envContents.trimEnd()}\nJWT_SECRET=${secret}\n`;
  }

  fs.writeFileSync(envPath, envContents, 'utf8');
  pteroLog('[CatRealm] Generated JWT_SECRET and saved it to .env');
}

function ensurePortSync() {
  const pteroPort = process.env.SERVER_PORT;
  if (!pteroPort) return;

  const envPath = path.join(__dirname, '../.env');
  let envContents = '';
  if (fs.existsSync(envPath)) {
    envContents = fs.readFileSync(envPath, 'utf8');
  }

  process.env.PORT = pteroPort;

  if (/^PORT=.*$/m.test(envContents)) {
    envContents = envContents.replace(/^PORT=.*$/m, `PORT=${pteroPort}`);
  } else {
    envContents = `${envContents.trimEnd()}\nPORT=${pteroPort}\n`;
  }

  if (envContents.length > 0) {
    fs.writeFileSync(envPath, envContents, 'utf8');
    pteroLog(`[CatRealm] Synced PORT to ${pteroPort} from SERVER_PORT`);
  }
}

function ensureTurnSecretIfPlaceholder() {
  const modeRaw = (process.env.TURN_MODE || '').trim().toLowerCase();
  if (modeRaw && modeRaw !== 'custom') return;

  const envPath = path.join(__dirname, '../.env');
  if (!fs.existsSync(envPath)) return;

  let envContents = fs.readFileSync(envPath, 'utf8');
  const match = envContents.match(/^TURN_SECRET=(.*)$/m);
  if (!match) return;

  const current = (match[1] || '').trim();
  if (current !== 'replace-with-a-long-random-secret') return;

  const secret = crypto.randomBytes(48).toString('hex');
  envContents = envContents.replace(/^TURN_SECRET=.*$/m, `TURN_SECRET=${secret}`);
  fs.writeFileSync(envPath, envContents, 'utf8');
  process.env.TURN_SECRET = secret;
  pteroLog('[CatRealm] Replaced placeholder TURN_SECRET with a generated secret');
}

function logTurnStatus() {
  const modeRaw = (process.env.TURN_MODE || '').trim().toLowerCase();
  const mode = modeRaw || 'central';
  const turnSecret = (process.env.TURN_SECRET || '').trim();
  const turnHost = (process.env.TURN_HOST || '').trim();
  const turnPort = (process.env.TURN_PORT || '3478').trim();
  const turnTlsPort = (process.env.TURN_TLS_PORT || '').trim();
  if (mode === 'central') {
    const turnModule = require('./routes/turn');
    const centralCfg = typeof turnModule.getCentralTurnConfig === 'function'
      ? turnModule.getCentralTurnConfig()
      : { host: '', secret: '' };
    const centralHost = (centralCfg.host || '').trim();
    const centralSecret = (centralCfg.secret || '').trim();
    pteroLog('[CatRealm] TURN: mode=central (baked-in central TURN config).');
    if (centralHost && centralSecret) {
      pteroLog('[CatRealm] TURN: Keys SUCCESSFUL. Using native selection.');
    } else {
      pteroLog('[CatRealm] TURN: Keys FAILED. Using fallback method.');
    }
    return;
  }

  if (mode === 'fallback') {
    pteroLog('[CatRealm] TURN: fallback mode (TURN_SECRET is not set).');
    pteroLog('[CatRealm] TURN: using public fallback relay from /api/turn/credentials.');
    pteroLog('[CatRealm] TURN: Keys FAILED. Using fallback method.');
    return;
  }

  if (/^https?:\/\//i.test(turnHost)) {
    pteroLog('[CatRealm] TURN: WARNING TURN_HOST should be hostname only (no http/https, no port).');
  }

  const hostLabel = turnHost || 'request-host auto-detect';
  const tlsLabel = turnTlsPort || 'disabled';
  if (!turnSecret) {
    pteroLog('[CatRealm] TURN: mode=custom but TURN_SECRET is empty. Route will fallback.');
    pteroLog('[CatRealm] TURN: Keys FAILED. Using fallback method.');
    return;
  }
  pteroLog(`[CatRealm] TURN: mode=custom host=${hostLabel} port=${turnPort} tlsPort=${tlsLabel}`);
  pteroLog('[CatRealm] TURN: ensure coturn static-auth-secret matches TURN_SECRET and ports are publicly reachable.');
  pteroLog('[CatRealm] TURN: Keys SUCCESSFUL. Using native selection.');
}

ensureJwtSecret();
ensurePortSync();
ensureTurnSecretIfPlaceholder();
logTurnStatus();

const express = require('express');
const http = require('http');
const https = require('https');
const { Server } = require('socket.io');
const cors = require('cors');

const db = require('./db');
const authRoutes = require('./routes/auth');
const channelRoutes = require('./routes/channels');
const messageRoutes = require('./routes/messages');
const serverRoutes = require('./routes/server');
const profileRoutes = require('./routes/profile');
const adminRoutes = require('./routes/admin');
const moderationRoutes = require('./routes/moderation');
const uploadRoutes = require('./routes/uploads');
const categoryRoutes = require('./routes/categories');
const threadRoutes = require('./routes/threads');
const usersRoutes = require('./routes/users');
const rolesRoutes = require('./routes/roles');
const turnRoutes = require('./routes/turn');
const invitesRoutes = require('./routes/invites');
const { authenticateToken } = require('./middleware/auth');
const setupSocketHandlers = require('./socket/handler');

const app = express();

const PORT = process.env.PORT || 3000;
const CLIENT_URL = process.env.CLIENT_URL || '*';

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(cors({ origin: CLIENT_URL }));
app.use(express.json());
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, '../data/uploads');
app.use('/uploads', express.static(UPLOADS_DIR));
const UGC_IMAGES_DIR = process.env.UGC_IMAGES_DIR || path.join(__dirname, '../data/ugc/images');
app.use('/ugc/images', express.static(UGC_IMAGES_DIR));

// ── REST Routes ────────────────────────────────────────────────────────────────
app.use('/api/auth',     authRoutes);
app.use('/api/channels', authenticateToken, channelRoutes);
app.use('/api/messages', authenticateToken, messageRoutes);
app.use('/api/server',   serverRoutes); // public info endpoint
app.use('/api/profile',  authenticateToken, profileRoutes);
app.use('/api/admin',    authenticateToken, adminRoutes);
app.use('/api/moderation', authenticateToken, moderationRoutes);
app.use('/api/uploads',  authenticateToken, uploadRoutes);
app.use('/api/categories', authenticateToken, categoryRoutes);
app.use('/api/threads', authenticateToken, threadRoutes);
app.use('/api/users', authenticateToken, usersRoutes);
app.use('/api/roles', authenticateToken, rolesRoutes);
app.use('/api/invites', invitesRoutes); // Some endpoints public, some require auth
app.use('/api/turn', turnRoutes); // TURN/STUN credentials (no auth required)

// ── Create server & start ─────────────────────────────────────────────────────
async function start() {
  let httpServer;
  const sslCert = process.env.SSL_CERT_PATH;
  const sslKey = process.env.SSL_KEY_PATH;
  const sslDomain = process.env.SSL_DOMAIN;
  const sslEmail = process.env.SSL_EMAIL;

  // Priority 1: Auto-SSL via Let's Encrypt (HTTP-01 or DNS-01 challenge)
  if (sslDomain && sslEmail) {
    try {
      const { initAutoSSL } = require('./autossl');
      const dnsApiToken = process.env.SSL_DNS_API_TOKEN;
      const dnsProvider = process.env.SSL_DNS_PROVIDER || (dnsApiToken ? 'cloudflare' : '');
      const dnsOpts = dnsProvider && dnsApiToken ? { provider: dnsProvider, apiToken: dnsApiToken } : null;
      const { cert, key } = await initAutoSSL(sslDomain, sslEmail, dnsOpts);
      httpServer = https.createServer({ cert, key }, app);
      pteroLog('[CatRealm] Auto-SSL enabled — serving over HTTPS');
    } catch (err) {
      pteroLog(`[CatRealm] Auto-SSL failed: ${err.message}`);
      pteroLog('[CatRealm] Falling back to HTTP');
      httpServer = http.createServer(app);
    }
  }
  // Priority 2: Manual cert files
  else if (sslCert && sslKey) {
    try {
      const sslOptions = {
        cert: fs.readFileSync(sslCert),
        key: fs.readFileSync(sslKey),
      };
      httpServer = https.createServer(sslOptions, app);
      pteroLog('[CatRealm] SSL enabled — serving over HTTPS');
    } catch (err) {
      pteroLog(`[CatRealm] SSL cert/key failed to load: ${err.message}`);
      pteroLog('[CatRealm] Falling back to HTTP');
      httpServer = http.createServer(app);
    }
  }
  // Priority 3: Plain HTTP
  else {
    httpServer = http.createServer(app);
    pteroLog('[CatRealm] WARNING: SSL is not enabled. The web app at https://catrealm.app/app requires HTTPS to connect.');
  }

  // ── Socket.io ───────────────────────────────────────────────────────────────
  const io = new Server(httpServer, {
    cors: { origin: CLIENT_URL, methods: ['GET', 'POST'] }
  });

  setupSocketHandlers(io);

  // ── Start ───────────────────────────────────────────────────────────────────
  httpServer.listen(PORT, '0.0.0.0', () => {
    pteroLog(`Listening on port ${PORT}`);
    pteroLog(`[CatRealm] Server running on port ${PORT}`);
    pteroLog(`[CatRealm] Server name: ${process.env.SERVER_NAME || 'CatRealm Server'}`);
    pteroLog(`[CatRealm] Registration: ${process.env.REGISTRATION_OPEN === 'false' ? 'CLOSED' : 'OPEN'}`);
  });

  // ── Graceful shutdown ───────────────────────────────────────────────────────
  let shuttingDown = false;

  function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;

    pteroLog(`[CatRealm] Received ${signal}, shutting down...`);

    // Force close all Socket.io connections immediately
    pteroLog('[CatRealm] Closing Socket.io connections...');
    io.disconnectSockets(true);
    io.close(() => {
      pteroLog('[CatRealm] Socket.io closed');
    });

    // Close HTTP server (stop accepting new connections)
    pteroLog('[CatRealm] Closing HTTP server...');
    httpServer.close(() => {
      pteroLog('[CatRealm] HTTP server closed');
      try {
        db.close();
        pteroLog('[CatRealm] Database closed');
      } catch (err) {
        pteroLog(`[CatRealm] Error closing database: ${err.message}`);
      }
      pteroLog('[CatRealm] Shutdown complete');
      process.exit(0);
    });

    // Force exit after 3 seconds if graceful shutdown fails
    setTimeout(() => {
      pteroLog('[CatRealm] Shutdown timeout reached, forcing exit...');
      process.exit(0);
    }, 3000);
  }

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  // Handle uncaught exceptions during shutdown
  process.on('uncaughtException', (err) => {
    pteroLog(`[CatRealm] Uncaught exception: ${err.message}`);
    if (shuttingDown) {
      process.exit(1);
    }
  });
}

start().catch((err) => {
  pteroLog(`[CatRealm] Fatal startup error: ${err.message}`);
  process.exit(1);
});
