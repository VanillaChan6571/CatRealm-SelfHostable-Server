const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');
const dataDir = path.join(repoRoot, 'data');

let livekitChild = null;

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

function getLogger(logger) {
  if (typeof logger === 'function') {
    return {
      log: logger,
      error: logger,
    };
  }
  return {
    log: console.log,
    error: console.error,
  };
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
  const publicPort = Number(process.env.LIVEKIT_PUBLIC_PORT || process.env.SERVER_PORT || process.env.PORT || port);
  const suffix = publicPort === 443 ? '' : `:${publicPort}`;
  return `wss://${host}${suffix}`;
}

function writeLiveKitConfig(configPath, apiKey, apiSecret, signalingPort, tcpPort, udpStart, udpEnd) {
  const livekitUdpEnd = Math.max(udpStart + 1, udpEnd);
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(configPath, [
    `port: ${signalingPort}`,
    'log_level: info',
    'rtc:',
    `  tcp_port: ${tcpPort}`,
    `  port_range_start: ${udpStart}`,
    `  port_range_end: ${livekitUdpEnd}`,
    '  use_external_ip: true',
    'keys:',
    `  ${yamlQuote(apiKey)}: ${yamlQuote(apiSecret)}`,
    '',
  ].join('\n'));
}

function liveKitServerAvailable() {
  return spawnSync('livekit-server', ['--version'], { stdio: 'ignore' }).status === 0;
}

function stopBundledLiveKit() {
  if (livekitChild && !livekitChild.killed) {
    livekitChild.kill('SIGTERM');
  }
}

function startBundledLiveKit(options = {}) {
  const { log, error } = getLogger(options.logger);

  if (livekitChild || process.env.CATREALM_BUNDLED_LIVEKIT_STARTED === 'true') {
    return livekitChild;
  }

  if (!isTruthy(process.env.HOST_LIVEKIT_MEDIA || process.env.CATREALM_HOST_LIVEKIT_MEDIA, false)) {
    if (options.logDisabled) {
      log('[CatRealm] Bundled LiveKit media: disabled (set HOST_LIVEKIT_MEDIA=true to run LiveKit with this server).');
    }
    return null;
  }

  if (!liveKitServerAvailable()) {
    error('[CatRealm] Cannot start bundled LiveKit: livekit-server was not found in PATH. Select the CatRealm Runtime image that includes LiveKit.');
    return null;
  }

  const signalingPort = numberEnv('LIVEKIT_SIGNALING_PORT', 7880);
  const tcpPort = numberEnv('LIVEKIT_RTC_TCP_PORT', 7881);
  const udpStart = numberEnv('LIVEKIT_RTC_UDP_PORT_START', numberEnv('LIVEKIT_RTC_UDP_PORT', 50000));
  const udpEnd = Math.max(udpStart, numberEnv('LIVEKIT_RTC_UDP_PORT_END', udpStart));
  const publicHost = getPublicLiveKitHost();
  const { apiKey, apiSecret } = getLiveKitSecrets();
  const configPath = path.join(dataDir, 'livekit.yaml');
  const internalUrl = (process.env.MEDIA_LIVEKIT_URL || process.env.LIVEKIT_URL || `ws://127.0.0.1:${signalingPort}`).trim();
  const publicUrl = getPublicLiveKitUrl(publicHost, signalingPort);

  writeLiveKitConfig(configPath, apiKey, apiSecret, signalingPort, tcpPort, udpStart, udpEnd);

  process.env.CATREALM_BUNDLED_LIVEKIT_STARTED = 'true';
  process.env.MEDIA_LIVEKIT_ENABLED = 'true';
  process.env.MEDIA_LIVEKIT_PROXY_ENABLED = 'true';
  process.env.MEDIA_LIVEKIT_URL = internalUrl;
  process.env.MEDIA_LIVEKIT_PUBLIC_WS_URL = publicUrl;
  process.env.MEDIA_LIVEKIT_API_KEY = apiKey;
  process.env.MEDIA_LIVEKIT_API_SECRET = apiSecret;
  process.env.MEDIA_FALLBACK_TO_LEGACY = process.env.MEDIA_FALLBACK_TO_LEGACY || 'true';

  log(`[CatRealm] Starting bundled LiveKit media server on ${internalUrl}`);
  log(`[CatRealm] LiveKit public URL: ${publicUrl}`);
  log('[CatRealm] LiveKit signaling proxy: enabled on CatRealm /rtc over HTTPS');
  log(`[CatRealm] LiveKit RTC ports: tcp=${tcpPort}, udp=${udpStart === udpEnd ? udpStart : `${udpStart}-${udpEnd}`}`);
  if (udpEnd > udpStart) {
    log(`[CatRealm] LiveKit UDP range requires every UDP port from ${udpStart} through ${udpEnd} to be allocated in Docker/Pterodactyl.`);
  } else {
    log('[CatRealm] LiveKit UDP single-port mode: writing exclusive LiveKit range internally to avoid LiveKit single-port startup panic.');
  }

  livekitChild = spawn('livekit-server', ['--config', configPath], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: process.env,
  });

  livekitChild.on('spawn', () => {
    log(`[CatRealm] Bundled LiveKit process started pid=${livekitChild.pid}`);
  });

  livekitChild.on('error', (err) => {
    error(`[CatRealm] Failed to start bundled LiveKit: ${err.message}`);
  });

  livekitChild.on('exit', (code, signal) => {
    livekitChild = null;
    if (code === 0 || signal) return;
    error(`[CatRealm] Bundled LiveKit exited with code ${code}.`);
  });

  process.once('exit', stopBundledLiveKit);
  return livekitChild;
}

module.exports = {
  startBundledLiveKit,
  stopBundledLiveKit,
};
