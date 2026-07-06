const fs = require('fs');
const path = require('path');
const { fork } = require('child_process');
const pteroLog = require('../logger');
const { startBundledLiveKit, stopBundledLiveKit } = require('../livekitRuntime');
const {
  dataDir,
  registryPath,
  registryExists,
  loadRegistry,
  bootstrapRegistryFromEnv,
  resolveRealmDbPath,
  ensureRealmEnvFile,
  readRealmEnv,
} = require('./registry');
const { migrateSingleDbIfNeeded } = require('./migrate');

const repoRoot = path.join(__dirname, '../..');
const entryPath = path.join(repoRoot, 'src/index.js');
const sslCertPath = path.join(dataDir, 'ssl/cert.pem');
const sslKeyPath = path.join(dataDir, 'ssl/key.pem');

// Env keys that must never leak into realm children: per-child values the
// supervisor computes itself, plus anything that would make a child try to
// own shared infrastructure (bundled LiveKit, Auto-SSL) or collapse the
// per-realm LiveKit room namespace.
const CHILD_ENV_STRIP = [
  'PORT',
  'SERVER_PORT',
  'DB_PATH',
  'SERVER_URL',
  'SERVER_NAME',
  'HOST_LIVEKIT_MEDIA',
  'CATREALM_HOST_LIVEKIT_MEDIA',
  'HOST_LIVEKIT_INGRESS',
  'SERVER_ID',
  'CATREALM_SERVER_ID',
  'SSL_DOMAIN',
  'SSL_EMAIL',
  'SSL_DNS_PROVIDER',
  'SSL_DNS_API_TOKEN',
  'LIVEKIT_PUBLIC_PORT',
  'MEDIA_LIVEKIT_PUBLIC_WS_URL',
  'MEDIA_LIVEKIT_PUBLIC_URL',
  'MEDIA_LIVEKIT_WHIP_PUBLIC_URL',
  'LIVEKIT_WHIP_PUBLIC_URL',
];

const realmStates = new Map(); // port -> { realm, child, backoffMs, startedAt, restartTimer, stopping }
let shuttingDown = false;

function log(message) {
  pteroLog(`[MultiRealm] ${message}`);
}

function prefixChildStream(stream, port) {
  let buffered = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    buffered += chunk;
    const lines = buffered.split(/\r?\n/);
    buffered = lines.pop() || '';
    for (const line of lines) {
      if (line.trim()) pteroLog(`[${port}] ${line}`);
    }
  });
  stream.on('end', () => {
    if (buffered.trim()) pteroLog(`[${port}] ${buffered}`);
    buffered = '';
  });
}

function derivePublicHost() {
  return (
    process.env.SSL_DOMAIN ||
    process.env.LIVEKIT_PUBLIC_HOST ||
    process.env.MEDIA_LIVEKIT_PUBLIC_HOST ||
    ''
  ).trim();
}

function deriveServerUrlHost() {
  const domain = (process.env.SSL_DOMAIN || '').trim();
  if (domain) return domain;
  const base = (process.env.SERVER_URL || '').trim();
  if (base) {
    try {
      return new URL(base).hostname;
    } catch {
      // Fall through to default.
    }
  }
  return '0.0.0.0';
}

function buildChildEnv(realm, shared) {
  const env = { ...process.env };
  for (const key of CHILD_ENV_STRIP) delete env[key];

  // Layer per-realm overrides (secrets + host-supplied settings) over the base env.
  Object.assign(env, readRealmEnv(realm.port));

  // Supervisor-forced values win over everything.
  env.CATREALM_REALM_CHILD = '1';
  env.CATREALM_REALM_ENV_FILE = ensureRealmEnvFile(realm.port);
  env.PORT = String(realm.port);
  env.DB_PATH = resolveRealmDbPath(realm);
  env.AUTO_UPDATE = 'false';
  if (!env.SERVER_NAME) env.SERVER_NAME = realm.name;
  if (!env.SERVER_URL) {
    env.SERVER_URL = `${shared.scheme}://${shared.serverUrlHost}:${realm.port}`;
  }
  if (shared.sslCert && !env.SSL_CERT_PATH && !env.SSL_KEY_PATH) {
    env.SSL_CERT_PATH = shared.sslCert;
    env.SSL_KEY_PATH = shared.sslKey;
  }
  // Children re-derive their public LiveKit URLs from their own PORT; give them
  // the public host since SSL_DOMAIN is stripped from their env.
  if (shared.publicHost && !env.MEDIA_LIVEKIT_PUBLIC_HOST && !env.LIVEKIT_PUBLIC_HOST) {
    env.MEDIA_LIVEKIT_PUBLIC_HOST = shared.publicHost;
  }
  return env;
}

function startRealm(realm, shared) {
  const state = realmStates.get(realm.port) || {
    realm,
    child: null,
    backoffMs: 1000,
    startedAt: 0,
    restartTimer: null,
    stopping: false,
  };
  realmStates.set(realm.port, state);
  state.realm = realm;

  const child = fork(entryPath, [], {
    cwd: repoRoot,
    env: buildChildEnv(realm, shared),
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  state.child = child;
  state.startedAt = Date.now();
  log(`Starting realm "${realm.name}" on port ${realm.port} (db: ${realm.dbFile}, pid: ${child.pid})`);

  prefixChildStream(child.stdout, realm.port);
  prefixChildStream(child.stderr, realm.port);

  child.on('exit', (code, signal) => {
    state.child = null;
    if (shuttingDown || state.stopping) return;

    const uptimeMs = Date.now() - state.startedAt;
    if (uptimeMs >= 60_000) state.backoffMs = 1000;
    log(`Realm "${realm.name}" (port ${realm.port}) exited (code=${code}, signal=${signal || 'none'}). Restarting in ${Math.round(state.backoffMs / 1000)}s...`);
    state.restartTimer = setTimeout(() => {
      state.restartTimer = null;
      if (!shuttingDown && !state.stopping) startRealm(state.realm, shared);
    }, state.backoffMs);
    state.backoffMs = Math.min(state.backoffMs * 2, 60_000);
  });

  child.on('error', (err) => {
    log(`Realm "${realm.name}" (port ${realm.port}) process error: ${err.message}`);
  });
}

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log(`Received ${signal}, stopping all realms...`);

  for (const state of realmStates.values()) {
    state.stopping = true;
    if (state.restartTimer) clearTimeout(state.restartTimer);
    if (state.child && !state.child.killed) state.child.kill('SIGTERM');
  }

  const deadline = setTimeout(() => {
    for (const state of realmStates.values()) {
      if (state.child && !state.child.killed) state.child.kill('SIGKILL');
    }
  }, 8000);
  deadline.unref();

  const waiter = setInterval(() => {
    const anyAlive = [...realmStates.values()].some((state) => state.child);
    if (anyAlive) return;
    clearInterval(waiter);
    clearTimeout(deadline);
    stopBundledLiveKit();
    log('Shutdown complete');
    process.exit(0);
  }, 200);
}

// Auto-SSL renews inside the supervisor, but children only read cert files at
// boot — rolling-restart them when the cert file changes.
function watchCertRenewal(shared) {
  let lastMtime = 0;
  try {
    lastMtime = fs.statSync(sslCertPath).mtimeMs;
  } catch {
    return;
  }
  const timer = setInterval(() => {
    let mtime = 0;
    try {
      mtime = fs.statSync(sslCertPath).mtimeMs;
    } catch {
      return;
    }
    if (mtime === lastMtime) return;
    lastMtime = mtime;
    log('TLS certificate renewed — rolling restart of all realms...');
    let delay = 0;
    for (const state of realmStates.values()) {
      if (!state.child) continue;
      const child = state.child;
      setTimeout(() => {
        if (!shuttingDown && !child.killed) child.kill('SIGTERM');
      }, delay);
      delay += 5000;
    }
  }, 60_000);
  timer.unref();
}

async function run() {
  log('Multi-realm mode enabled (MULTI_REALM=true)');

  if ((process.env.SERVER_ID || process.env.CATREALM_SERVER_ID || '').trim()) {
    log('WARNING: SERVER_ID/CATREALM_SERVER_ID is set but ignored in multi-realm mode — a shared server id would collapse the per-realm LiveKit room namespace.');
  }

  let registry;
  if (registryExists()) {
    registry = loadRegistry();
  } else {
    registry = bootstrapRegistryFromEnv();
    log(`Created ${registryPath} — edit this file to add or remove realms, then restart.`);
  }

  await migrateSingleDbIfNeeded(registry, log);

  const enabledRealms = registry.realms.filter((realm) => realm.enabled);
  if (enabledRealms.length === 0) {
    log('No enabled realms in realms.json — nothing to start.');
    process.exit(1);
  }
  for (const realm of enabledRealms) ensureRealmEnvFile(realm.port);

  // Auto-SSL runs once here; children get the resulting cert files and take
  // the manual-cert path (SSL_DOMAIN/SSL_EMAIL are stripped from their env).
  const shared = {
    scheme: 'http',
    serverUrlHost: deriveServerUrlHost(),
    publicHost: derivePublicHost(),
    sslCert: null,
    sslKey: null,
  };
  const sslDomain = (process.env.SSL_DOMAIN || '').trim();
  const sslEmail = (process.env.SSL_EMAIL || '').trim();
  if (sslDomain && sslEmail) {
    try {
      const { initAutoSSL } = require('../autossl');
      const dnsApiToken = process.env.SSL_DNS_API_TOKEN;
      const dnsProvider = process.env.SSL_DNS_PROVIDER || (dnsApiToken ? 'cloudflare' : '');
      const dnsOpts = dnsProvider && dnsApiToken ? { provider: dnsProvider, apiToken: dnsApiToken } : null;
      await initAutoSSL(sslDomain, sslEmail, dnsOpts);
      shared.scheme = 'https';
      shared.sslCert = sslCertPath;
      shared.sslKey = sslKeyPath;
      log('Auto-SSL ready — realms will serve HTTPS with the shared certificate');
    } catch (err) {
      log(`Auto-SSL failed: ${err.message} — realms will fall back to their own SSL settings or HTTP`);
    }
  } else if (process.env.SSL_CERT_PATH && process.env.SSL_KEY_PATH) {
    shared.scheme = 'https';
  }

  // One bundled LiveKit for all realms; startBundledLiveKit publishes the
  // MEDIA_LIVEKIT_* connection env that children then inherit.
  startBundledLiveKit({ logger: pteroLog, logDisabled: true });

  for (const realm of enabledRealms) startRealm(realm, shared);
  log(`${enabledRealms.length} realm(s) starting. Manage realms by editing ${registryPath} and restarting.`);

  if (shared.sslCert) watchCertRenewal(shared);

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

module.exports = { run };
