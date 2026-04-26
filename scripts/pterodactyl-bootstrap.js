const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');
const dataDir = path.join(repoRoot, 'data');
const nodeModulesDir = path.join(repoRoot, 'node_modules');
const betterSqliteBinary = path.join(
  repoRoot,
  'node_modules',
  'better-sqlite3',
  'build',
  'Release',
  'better_sqlite3.node'
);

function needsInstall() {
  return !fs.existsSync(nodeModulesDir) || !fs.existsSync(betterSqliteBinary);
}

function installDependencies() {
  const result = spawnSync('npm', ['install', '--production'], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: {
      ...process.env,
      npm_config_libc: process.env.npm_config_libc || 'musl',
    },
  });

  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

function isTruthy(value, fallback = false) {
  if (value == null || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

function numberEnv(name, fallback, min = 1, max = 65535) {
  const raw = Number(process.env[name] || fallback);
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.round(raw)));
}

function yamlQuote(value) {
  return JSON.stringify(String(value));
}

function getLiveKitSecrets() {
  const envKey = (process.env.MEDIA_LIVEKIT_API_KEY || process.env.LIVEKIT_API_KEY || '').trim();
  const envSecret = (process.env.MEDIA_LIVEKIT_API_SECRET || process.env.LIVEKIT_API_SECRET || '').trim();
  if (envKey && envSecret) {
    return { apiKey: envKey, apiSecret: envSecret };
  }

  const secretsPath = path.join(dataDir, 'livekit-secrets.json');
  try {
    const existing = JSON.parse(fs.readFileSync(secretsPath, 'utf8'));
    if (existing?.apiKey && existing?.apiSecret) {
      return { apiKey: String(existing.apiKey), apiSecret: String(existing.apiSecret) };
    }
  } catch {
    // Generate below.
  }

  fs.mkdirSync(dataDir, { recursive: true });
  const generated = {
    apiKey: 'catrealm',
    apiSecret: crypto.randomBytes(32).toString('hex'),
  };
  fs.writeFileSync(secretsPath, `${JSON.stringify(generated, null, 2)}\n`, { mode: 0o600 });
  return generated;
}

function getPublicLiveKitHost() {
  return (
    process.env.LIVEKIT_PUBLIC_HOST ||
    process.env.MEDIA_LIVEKIT_PUBLIC_HOST ||
    process.env.SSL_DOMAIN ||
    ''
  ).trim();
}

function getPublicLiveKitUrl(host, port) {
  const explicit = (process.env.MEDIA_LIVEKIT_PUBLIC_WS_URL || process.env.MEDIA_LIVEKIT_PUBLIC_URL || '').trim();
  if (explicit) return explicit;
  if (!host) return `ws://127.0.0.1:${port}`;
  const suffix = port === 443 ? '' : `:${port}`;
  return `wss://${host}${suffix}`;
}

function startBundledLiveKit() {
  if (!isTruthy(process.env.HOST_LIVEKIT_MEDIA || process.env.CATREALM_HOST_LIVEKIT_MEDIA, false)) {
    console.log('[CatRealm] Bundled LiveKit media: disabled (set HOST_LIVEKIT_MEDIA=true to run LiveKit with this server).');
    return null;
  }

  const signalingPort = numberEnv('LIVEKIT_SIGNALING_PORT', 7880);
  const tcpPort = numberEnv('LIVEKIT_RTC_TCP_PORT', 7881);
  const udpStart = numberEnv('LIVEKIT_RTC_UDP_PORT_START', 50000);
  const udpEnd = Math.max(udpStart, numberEnv('LIVEKIT_RTC_UDP_PORT_END', 50100));
  const publicHost = getPublicLiveKitHost();
  const { apiKey, apiSecret } = getLiveKitSecrets();
  const configPath = path.join(dataDir, 'livekit.yaml');
  const internalUrl = (process.env.MEDIA_LIVEKIT_URL || process.env.LIVEKIT_URL || `ws://127.0.0.1:${signalingPort}`).trim();
  const publicUrl = getPublicLiveKitUrl(publicHost, signalingPort);

  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(configPath, [
    `port: ${signalingPort}`,
    'log_level: info',
    'rtc:',
    `  tcp_port: ${tcpPort}`,
    `  port_range_start: ${udpStart}`,
    `  port_range_end: ${udpEnd}`,
    '  use_external_ip: true',
    'keys:',
    `  ${yamlQuote(apiKey)}: ${yamlQuote(apiSecret)}`,
    '',
  ].join('\n'));

  process.env.MEDIA_LIVEKIT_ENABLED = 'true';
  process.env.MEDIA_LIVEKIT_URL = internalUrl;
  process.env.MEDIA_LIVEKIT_PUBLIC_WS_URL = publicUrl;
  process.env.MEDIA_LIVEKIT_API_KEY = apiKey;
  process.env.MEDIA_LIVEKIT_API_SECRET = apiSecret;
  process.env.MEDIA_FALLBACK_TO_LEGACY = process.env.MEDIA_FALLBACK_TO_LEGACY || 'true';

  console.log(`[CatRealm] Starting bundled LiveKit media server on ${internalUrl}`);
  console.log(`[CatRealm] LiveKit public URL: ${publicUrl}`);
  console.log(`[CatRealm] LiveKit RTC ports: tcp=${tcpPort}, udp=${udpStart}-${udpEnd}`);

  const child = spawn('livekit-server', ['--config', configPath], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: process.env,
  });

  child.on('spawn', () => {
    console.log(`[CatRealm] Bundled LiveKit process started pid=${child.pid}`);
  });

  child.on('error', (err) => {
    console.error(`[CatRealm] Failed to start bundled LiveKit: ${err.message}`);
  });

  child.on('exit', (code, signal) => {
    if (code === 0 || signal) return;
    console.error(`[CatRealm] Bundled LiveKit exited with code ${code}.`);
  });

  return child;
}

if (needsInstall()) {
  installDependencies();
}

const livekitChild = startBundledLiveKit();

function stopBundledLiveKit() {
  if (livekitChild && !livekitChild.killed) {
    livekitChild.kill('SIGTERM');
  }
}

process.once('exit', stopBundledLiveKit);

require(path.join(repoRoot, 'src', 'index.js'));
