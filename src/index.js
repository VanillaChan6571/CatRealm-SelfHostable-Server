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

const updateRuntime = {
  checkerDisabled: false,
  updateInProgress: false,
};

function shortHash(value) {
  const hash = (value || '').trim();
  return hash ? hash.slice(0, 7) : 'unknown';
}

function shouldAutoUpdate() {
  return isTruthy(process.env.AUTO_UPDATE, true);
}

function updateConfig() {
  return {
    repoRoot: path.join(__dirname, '..'),
    branch: safeBranch(process.env.GIT_BRANCH || 'main'),
    repo: (process.env.GIT_REPO || 'https://github.com/VanillaChan6571/CatRealm-SelfHostable-Server.git').trim(),
    checkerMs: Math.max(60_000, Number(process.env.AUTO_UPDATE_CHECK_INTERVAL_MS || 300_000) || 300_000),
    voiceDelayThreshold: Math.max(1, Number(process.env.AUTO_UPDATE_VOICE_DELAY_THRESHOLD || 2) || 2),
    restartOnStartupUpdate: isTruthy(process.env.AUTO_UPDATE_RESTART_ON_START, true),
  };
}

function ensureRepoReady(repoRoot, repo, branch) {
  const gitVersion = spawnSync('git', ['--version'], { encoding: 'utf8' });
  if (gitVersion.status !== 0) {
    pteroLog('[CatRealm <- GitHub]: Git is unavailable. Auto update checks are disabled.');
    updateRuntime.checkerDisabled = true;
    return false;
  }

  const gitDir = path.join(repoRoot, '.git');
  if (!fs.existsSync(gitDir)) {
    pteroLog('[CatRealm] .git not found. Initializing repository from GIT_REPO...');
    if (runGit(repoRoot, ['init']).status !== 0) return false;
    runGit(repoRoot, ['remote', 'remove', 'origin']);
    if (runGit(repoRoot, ['remote', 'add', 'origin', repo]).status !== 0) return false;
    if (runGit(repoRoot, ['fetch', '--depth=1', 'origin', branch]).status !== 0) return false;
    if (runGit(repoRoot, ['checkout', '-B', branch, `origin/${branch}`]).status !== 0) return false;
    pteroLog('[CatRealm] Repository initialized from remote.');
    if (!runNpmInstall(repoRoot)) return false;
  }

  const currentOrigin = runGit(repoRoot, ['remote', 'get-url', 'origin']);
  if (currentOrigin.status !== 0) {
    if (runGit(repoRoot, ['remote', 'add', 'origin', repo]).status !== 0) return false;
  } else if ((currentOrigin.stdout || '').trim() !== repo) {
    if (runGit(repoRoot, ['remote', 'set-url', 'origin', repo]).status !== 0) return false;
  }

  return true;
}

function getHashState(repoRoot, branch) {
  const localSha = runGit(repoRoot, ['rev-parse', 'HEAD']);
  if (localSha.status !== 0) return null;

  if (runGit(repoRoot, ['fetch', '--all', '--prune']).status !== 0) return null;

  const remoteSha = runGit(repoRoot, ['rev-parse', `origin/${branch}`]);
  if (remoteSha.status !== 0) return null;

  const local = (localSha.stdout || '').trim();
  const remote = (remoteSha.stdout || '').trim();
  if (!local || !remote) return null;
  return { local, remote };
}

function applyUpdateAndMaybeRestart(config, remoteHash, shouldRestart) {
  if (runGit(config.repoRoot, ['reset', '--hard', `origin/${config.branch}`]).status !== 0) {
    pteroLog('[CatRealm <- GitHub]: Update apply failed during git reset.');
    return false;
  }
  if (!runNpmInstall(config.repoRoot)) {
    pteroLog('[CatRealm <- GitHub]: Update apply failed during npm install.');
    return false;
  }
  pteroLog(`[CatRealm] Update Applied... Restarting Now... (${shortHash(remoteHash)})`);
  if (shouldRestart) {
    setTimeout(() => process.exit(0), 250);
  }
  return true;
}

function runUpdateCheck(opts = {}) {
  const source = opts.source === 'task' ? 'task' : 'startup';
  const config = updateConfig();
  const getActiveVoiceUserCount = typeof opts.getActiveVoiceUserCount === 'function'
    ? opts.getActiveVoiceUserCount
    : (() => 0);

  if (updateRuntime.checkerDisabled) return;
  if (updateRuntime.updateInProgress) return;

  if (!shouldAutoUpdate()) {
    pteroLog('[CatRealm <- GitHub]: There is an update however won\'t download as manually marked as Do Not Update. Disabling Auto Checker Task....');
    updateRuntime.checkerDisabled = true;
    return;
  }

  if (source === 'startup') {
    pteroLog('[CatRealm] Checking For Updates...');
  } else {
    pteroLog('[CatRealm -> Auto Checker Task]: Running a check if there is an update...');
  }

  if (!ensureRepoReady(config.repoRoot, config.repo, config.branch)) {
    pteroLog('[CatRealm <- GitHub]: Unable to prepare git repository for update checks.');
    return;
  }

  const hashes = getHashState(config.repoRoot, config.branch);
  if (!hashes) {
    pteroLog('[CatRealm <- GitHub]: Unable to compare local and remote hashes.');
    return;
  }

  const localShort = shortHash(hashes.local);
  const remoteShort = shortHash(hashes.remote);
  pteroLog(`[CatRealm -> GitHub]: Checking ${localShort} vs remote hash is ${remoteShort}`);

  if (hashes.local === hashes.remote) {
    if (source === 'startup') {
      pteroLog('[CatRealm <- GitHub]: On Latest Build');
    } else {
      pteroLog('[CatRealm <- GitHub]: On Latest Build, Continuing with Life.');
    }
    return;
  }

  updateRuntime.updateInProgress = true;
  try {
    if (source === 'startup') {
      pteroLog(`[CatRealm <- GitHub]: There is an update to ${remoteShort}! Downloading & Applying...`);
      applyUpdateAndMaybeRestart(config, hashes.remote, config.restartOnStartupUpdate);
      return;
    }

    pteroLog(`[CatRealm <- GitHub]: There is an update to ${remoteShort}! Unable to Download & Apply since we are mid running!`);
    pteroLog('[CatRealm] Update Found - Checking if anyone in a Voice Call on Realm..');

    const activeVoiceUsers = Number(getActiveVoiceUserCount()) || 0;
    if (activeVoiceUsers >= config.voiceDelayThreshold) {
      pteroLog(`[CatRealm <- GitHub]: Called to continue to check ${localShort} vs ${remoteShort}`);
      pteroLog(`[CatRealm] There are ${activeVoiceUsers} users in a Voice Call.. Delay Update, Callback in 5 minutes..`);
      return;
    }

    if (activeVoiceUsers === 0) {
      pteroLog(`[CatRealm <- GitHub]: Called to Download & Apply ${remoteShort} since no one is in a Voice Call.`);
    } else {
      pteroLog(`[CatRealm <- GitHub]: Called to Download & Apply ${remoteShort} since active voice users are below delay threshold (${config.voiceDelayThreshold}).`);
    }
    applyUpdateAndMaybeRestart(config, hashes.remote, true);
  } finally {
    updateRuntime.updateInProgress = false;
  }
}

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
  runUpdateCheck({
    source: 'startup',
    getActiveVoiceUserCount: setupSocketHandlers.getActiveVoiceUserCount,
  });

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

  if (!updateRuntime.checkerDisabled && shouldAutoUpdate()) {
    const checkerMs = updateConfig().checkerMs;
    setInterval(() => {
      runUpdateCheck({
        source: 'task',
        getActiveVoiceUserCount: setupSocketHandlers.getActiveVoiceUserCount,
      });
    }, checkerMs);
  }

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
