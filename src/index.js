require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
const { spawnSync } = require('child_process');
const pteroLog = require('./logger');
const { getDiagnosticHelpText, runDiagnosticCommand } = require('./diagnosticCommands');
const { startBundledLiveKit } = require('./livekitRuntime');

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

function logMediaDependencyStatus() {
  const ytDlp = spawnSync('yt-dlp', ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (ytDlp.status === 0) {
    pteroLog(`[CatRealm] yt-dlp detected: ${(ytDlp.stdout || '').trim()}`);
  } else {
    pteroLog('[CatRealm] WARNING: yt-dlp not found. Theater YouTube links will fall back to iframe playback.');
  }

  const ffmpeg = spawnSync('ffmpeg', ['-version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (ffmpeg.status === 0) {
    pteroLog('[CatRealm] ffmpeg detected');
  } else {
    pteroLog('[CatRealm] WARNING: ffmpeg not found. Theater YouTube downloads will be limited to progressive formats and media processing features may be reduced.');
  }

  const livekit = spawnSync('livekit-server', ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (livekit.status === 0) {
    pteroLog(`[CatRealm] livekit-server detected: ${(livekit.stdout || livekit.stderr || '').trim()}`);
  } else {
    pteroLog('[CatRealm] livekit-server not detected in PATH. Bundled LiveKit requires the CatRealm Runtime image.');
  }
}

function logLiveKitRuntimeStatus() {
  const bundledRequested = isTruthy(process.env.HOST_LIVEKIT_MEDIA || process.env.CATREALM_HOST_LIVEKIT_MEDIA, false);
  const enabled = isTruthy(process.env.MEDIA_LIVEKIT_ENABLED, false);
  const apiKey = (process.env.MEDIA_LIVEKIT_API_KEY || process.env.LIVEKIT_API_KEY || '').trim();
  const apiSecret = (process.env.MEDIA_LIVEKIT_API_SECRET || process.env.LIVEKIT_API_SECRET || '').trim();
  const publicUrl = (
    process.env.MEDIA_LIVEKIT_PUBLIC_WS_URL ||
    process.env.MEDIA_LIVEKIT_PUBLIC_URL ||
    process.env.LIVEKIT_PUBLIC_WS_URL ||
    process.env.LIVEKIT_URL ||
    ''
  ).trim();
  const fallbackToLegacy = isTruthy(process.env.MEDIA_FALLBACK_TO_LEGACY, true);
  const missing = [];
  if (!apiKey) missing.push('apiKey');
  if (!apiSecret) missing.push('apiSecret');
  if (!publicUrl) missing.push('publicUrl');

  if (enabled && missing.length === 0) {
    pteroLog(`[CatRealm] LiveKit media: ENABLED (${bundledRequested ? 'bundled' : 'external'}) public=${publicUrl} fallbackLegacy=${fallbackToLegacy ? 'true' : 'false'}`);
    return;
  }

  if (enabled) {
    pteroLog(`[CatRealm] LiveKit media: MISCONFIGURED missing=${missing.join(',')} fallbackLegacy=${fallbackToLegacy ? 'true' : 'false'}`);
    return;
  }

  if (bundledRequested) {
    pteroLog('[CatRealm] WARNING: HOST_LIVEKIT_MEDIA=true but LiveKit media is not enabled. Start with node scripts/pterodactyl-bootstrap.js so bundled LiveKit can launch.');
    return;
  }

  pteroLog(`[CatRealm] LiveKit media: DISABLED fallbackLegacy=${fallbackToLegacy ? 'true' : 'false'}`);
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
    const steps = [
      { args: ['init'], label: 'git init' },
      { args: ['remote', 'remove', 'origin'], label: 'remove old origin', allowFail: true },
      { args: ['remote', 'add', 'origin', repo], label: 'add origin' },
      { args: ['fetch', '--depth=1', 'origin', branch], label: 'fetch' },
      { args: ['checkout', '-f', '-B', branch, `origin/${branch}`], label: 'checkout' },
    ];
    for (const step of steps) {
      const result = runGit(repoRoot, step.args);
      if (result.status !== 0 && !step.allowFail) {
        pteroLog(`[CatRealm <- GitHub]: "${step.label}" failed: ${(result.stderr || '').trim()}`);
        return false;
      }
    }
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
  if (localSha.status !== 0) {
    pteroLog(`[CatRealm <- GitHub]: rev-parse HEAD failed: ${(localSha.stderr || '').trim()}`);
    return null;
  }

  let fetchResult = runGit(repoRoot, ['fetch', '--all', '--prune']);
  if (fetchResult.status !== 0) {
    pteroLog(`[CatRealm <- GitHub]: fetch --all failed: ${(fetchResult.stderr || '').trim()}`);
    pteroLog('[CatRealm <- GitHub]: Retrying with unshallow fetch...');
    runGit(repoRoot, ['fetch', '--unshallow', 'origin', branch]);
    fetchResult = runGit(repoRoot, ['fetch', 'origin', branch]);
    if (fetchResult.status !== 0) {
      pteroLog(`[CatRealm <- GitHub]: fetch retry failed: ${(fetchResult.stderr || '').trim()}`);
      return null;
    }
  }

  const remoteSha = runGit(repoRoot, ['rev-parse', `origin/${branch}`]);
  if (remoteSha.status !== 0) {
    pteroLog(`[CatRealm <- GitHub]: rev-parse origin/${branch} failed: ${(remoteSha.stderr || '').trim()}`);
    return null;
  }

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
  const getActiveTheaterUserCount = typeof opts.getActiveTheaterUserCount === 'function'
    ? opts.getActiveTheaterUserCount
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
    pteroLog('[CatRealm] Update Found - Checking if anyone is active in Voice or Theater on Realm..');

    const activeVoiceUsers = Number(getActiveVoiceUserCount()) || 0;
    const activeTheaterUsers = Number(getActiveTheaterUserCount()) || 0;
    const activeRealtimeUsers = activeVoiceUsers + activeTheaterUsers;
    if (activeRealtimeUsers >= config.voiceDelayThreshold) {
      pteroLog(`[CatRealm <- GitHub]: Called to continue to check ${localShort} vs ${remoteShort}`);
      pteroLog(`[CatRealm] There are ${activeRealtimeUsers} active realtime users (Voice: ${activeVoiceUsers}, Theater: ${activeTheaterUsers}).. Delay Update, Callback in 5 minutes..`);
      return;
    }

    if (activeRealtimeUsers === 0) {
      pteroLog(`[CatRealm <- GitHub]: Called to Download & Apply ${remoteShort} since no one is active in Voice or Theater.`);
    } else {
      pteroLog(`[CatRealm <- GitHub]: Called to Download & Apply ${remoteShort} since active realtime users are below delay threshold (${config.voiceDelayThreshold}). Voice: ${activeVoiceUsers}, Theater: ${activeTheaterUsers}.`);
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

function ensureServerUrl(scheme, domain) {
  const port = process.env.PORT || '3000';
  const host = domain || '0.0.0.0';
  const newUrl = `${scheme}://${host}:${port}`;

  const envPath = path.join(__dirname, '../.env');
  let envContents = '';
  if (fs.existsSync(envPath)) {
    envContents = fs.readFileSync(envPath, 'utf8');
  }

  process.env.SERVER_URL = newUrl;

  if (/^SERVER_URL=.*$/m.test(envContents)) {
    const current = ((envContents.match(/^SERVER_URL=(.*)$/m) || [])[1] || '').trim();
    if (current === newUrl) return;
    envContents = envContents.replace(/^SERVER_URL=.*$/m, `SERVER_URL=${newUrl}`);
  } else {
    envContents = `${envContents.trimEnd()}\nSERVER_URL=${newUrl}\n`;
  }

  fs.writeFileSync(envPath, envContents, 'utf8');
  pteroLog(`[CatRealm] Updated SERVER_URL to ${newUrl}`);
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

function setupConsoleCommands(db) {
  if (!process.stdin || typeof process.stdin.on !== 'function') return;

  try {
    process.stdin.setEncoding('utf8');
    if (typeof process.stdin.setRawMode === 'function') {
      process.stdin.setRawMode(false);
    }
    process.stdin.resume();
  } catch {
    return;
  }

  function printHelp() {
    pteroLog(`[CatRealm Console] ${getDiagnosticHelpText()}`);
  }

  function handleCommand(rawInput) {
    const raw = String(rawInput || '').trim();
    if (!raw) return;
    if (raw.toLowerCase() === 'help' || raw.toLowerCase() === 'catrealm-help') {
      printHelp();
      return;
    }

    const result = runDiagnosticCommand(db, raw);
    if (!result) return;

    if (result.ok) {
      for (const line of result.lines || []) {
        pteroLog(`[CatRealm Console] ${line}`);
      }
      return;
    }

    pteroLog(`[CatRealm Console] ${result.error}. Type "help".`);
  }

  let stdinBuffer = '';
  let pendingSingleCommandTimer = null;
  let sawAnyConsoleInput = false;

  function flushPendingSingleCommand() {
    if (pendingSingleCommandTimer) {
      clearTimeout(pendingSingleCommandTimer);
      pendingSingleCommandTimer = null;
    }
    const single = stdinBuffer.trim();
    stdinBuffer = '';
    if (single.length > 0) {
      handleCommand(single);
    }
  }

  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
    terminal: false,
  });

  rl.on('line', (line) => {
    sawAnyConsoleInput = true;
    handleCommand(line);
  });

  process.stdin.on('data', (chunk) => {
    const text = String(chunk || '');
    if (!text) return;
    sawAnyConsoleInput = true;
    stdinBuffer += text;

    if (!/[\r\n]/.test(stdinBuffer)) {
      // Some hosts deliver a full command without a newline, while others
      // stream one keystroke at a time. Debounce briefly so both work.
      if (pendingSingleCommandTimer) {
        clearTimeout(pendingSingleCommandTimer);
      }
      pendingSingleCommandTimer = setTimeout(() => {
        pendingSingleCommandTimer = null;
        flushPendingSingleCommand();
      }, 120);
      return;
    }

    if (pendingSingleCommandTimer) {
      clearTimeout(pendingSingleCommandTimer);
      pendingSingleCommandTimer = null;
    }

    const lines = stdinBuffer.split(/\r?\n/);
    stdinBuffer = lines.pop() || '';
  });

  pteroLog('[CatRealm] Console command support enabled. Type "help" for commands.');
  pteroLog(`[CatRealm] Console stdin state: isTTY=${process.stdin.isTTY ? 1 : 0} readable=${process.stdin.readable ? 1 : 0} fd=${typeof process.stdin.fd === 'number' ? process.stdin.fd : 'n/a'}`);
  setTimeout(() => {
    if (!sawAnyConsoleInput) {
      pteroLog('[CatRealm] Console stdin diagnostic: no input received yet.');
    }
  }, 15_000).unref?.();
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
const expressionsRoutes = require('./routes/expressions');
const embedsRoutes = require('./routes/embeds');
const embedMediaRoutes = require('./routes/embedMedia');
const webhooksRoutes = require('./routes/webhooks');
const welcomeRoutes = require('./routes/welcome');
const theaterRoutes = require('./routes/theater');
const mediaRoutes = require('./routes/media').router;
const landingRoutes = require('./routes/landing');
const { authenticateToken } = require('./middleware/auth');
const setupSocketHandlers = require('./socket/handler');
const { startWebhookWorker, stopWebhookWorker } = require('./webhooks');

const app = express();
setupConsoleCommands(db);

const PORT = process.env.PORT || 3000;
const CLIENT_URL = process.env.CLIENT_URL || '*';

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(cors({ origin: CLIENT_URL }));
app.use(express.json({
  verify: (req, _res, buf) => {
    req.rawBody = buf.toString('utf8');
  },
}));
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, '../data/uploads');
app.use('/uploads', express.static(UPLOADS_DIR, { maxAge: '7d', etag: true }));
const UGC_IMAGES_DIR = process.env.UGC_IMAGES_DIR || path.join(__dirname, '../data/ugc/images');
app.use('/ugc/images', express.static(UGC_IMAGES_DIR, { maxAge: '7d', etag: true }));
const UGC_SERVER_DIR = process.env.UGC_SERVER_DIR || path.join(__dirname, '../data/ugc/server');
if (!fs.existsSync(UGC_SERVER_DIR)) fs.mkdirSync(UGC_SERVER_DIR, { recursive: true });
app.use('/ugc/server', express.static(UGC_SERVER_DIR, { maxAge: '7d', etag: true }));
const UGC_EXPRESSIONS_DIR = process.env.UGC_EXPRESSIONS_DIR || path.join(__dirname, '../data/ugc/expressions');
if (!fs.existsSync(UGC_EXPRESSIONS_DIR)) fs.mkdirSync(UGC_EXPRESSIONS_DIR, { recursive: true });
app.use('/ugc/expressions', express.static(UGC_EXPRESSIONS_DIR, { maxAge: '7d', etag: true }));
const THEATER_CACHE_DIR = process.env.THEATER_CACHE_DIR || path.join(__dirname, '../data/ugc/temp-theater');
if (!fs.existsSync(THEATER_CACHE_DIR)) fs.mkdirSync(THEATER_CACHE_DIR, { recursive: true });
// Serve theater video files with auth — token passed as query param or Authorization header
app.use('/ugc/temp-theater', authenticateToken, (req, res, next) => {
  // Path format: /:channelId/filename — verify user has VIEW_CHANNELS on that channel
  const parts = req.path.split('/').filter(Boolean);
  if (parts.length < 2) return res.status(400).json({ error: 'Invalid path' });
  const channelId = parts[0];
  const {
    PERMISSIONS: P,
    hasChannelPermission,
  } = require('./permissions');
  const db = require('./db');
  if (!hasChannelPermission(req.user, channelId, P.VIEW_CHANNELS, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  next();
}, express.static(THEATER_CACHE_DIR, { maxAge: '0', etag: true }));

// ── Landing page ───────────────────────────────────────────────────────────────
app.use('/', landingRoutes);

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
app.use('/api/expressions', expressionsRoutes);
app.use('/api/embed-media', embedMediaRoutes);
app.use('/api/embeds', authenticateToken, embedsRoutes);
app.use('/api/theater',  authenticateToken, theaterRoutes);
app.use('/api/media', mediaRoutes);
app.use('/api/webhooks', webhooksRoutes);
app.use('/api', welcomeRoutes);

// ── Create server & start ─────────────────────────────────────────────────────
async function start() {
  runUpdateCheck({
    source: 'startup',
    getActiveVoiceUserCount: setupSocketHandlers.getActiveVoiceUserCount,
    getActiveTheaterUserCount: setupSocketHandlers.getActiveTheaterUserCount,
  });
  startBundledLiveKit({ logger: pteroLog });
  logMediaDependencyStatus();
  logLiveKitRuntimeStatus();

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
      ensureServerUrl('https', sslDomain);
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
  startWebhookWorker();

  if (!updateRuntime.checkerDisabled && shouldAutoUpdate()) {
    const checkerMs = updateConfig().checkerMs;
    setInterval(() => {
      runUpdateCheck({
        source: 'task',
        getActiveVoiceUserCount: setupSocketHandlers.getActiveVoiceUserCount,
        getActiveTheaterUserCount: setupSocketHandlers.getActiveTheaterUserCount,
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
        stopWebhookWorker();
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
