const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const { initHostUdpBufferLimit, getHostUdpBufferWarningLines } = require('./lib/hostNetworkLimits');

const repoRoot = path.join(__dirname, '..');
const dataDir = path.join(repoRoot, 'data');

let livekitChild = null;
let redisChild = null;
let ingressChild = null;

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

function getPublicWhipUrl(host) {
  const explicit = (process.env.MEDIA_LIVEKIT_WHIP_PUBLIC_URL || process.env.LIVEKIT_WHIP_PUBLIC_URL || '').trim();
  if (explicit) return explicit.replace(/\/+$/, '');
  const publicPort = Number(process.env.LIVEKIT_PUBLIC_PORT || process.env.SERVER_PORT || process.env.PORT || 443);
  if (!host) return `http://127.0.0.1:${publicPort}/whip`;
  const suffix = publicPort === 443 ? '' : `:${publicPort}`;
  return `https://${host}${suffix}/whip`;
}

function parseLiveKitVersion(output) {
  const match = String(output || '').match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    raw: String(output || '').trim(),
  };
}

function getLiveKitServerVersion() {
  const result = spawnSync('livekit-server', ['--version'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.status !== 0) return null;
  const raw = `${result.stdout || ''}${result.stderr || ''}`.trim();
  return parseLiveKitVersion(raw) || { major: 0, minor: 0, patch: 0, raw };
}

function liveKitSupportsAdvertiseInternalIp(version) {
  if (!version) return false;
  if (version.major > 1) return true;
  if (version.major < 1) return false;
  if (version.minor > 13) return true;
  if (version.minor < 13) return false;
  return version.patch >= 0;
}

function shouldAdvertiseInternalIp(ingressOptions = null, liveKitVersion = null) {
  if (!ingressOptions) return false;
  const requested = isTruthy(
    process.env.LIVEKIT_ADVERTISE_INTERNAL_IP || process.env.MEDIA_LIVEKIT_ADVERTISE_INTERNAL_IP,
    true,
  );
  return requested && liveKitSupportsAdvertiseInternalIp(liveKitVersion);
}

function liveKitSupportsSkipExternalIpValidation(version) {
  return liveKitSupportsAdvertiseInternalIp(version);
}

function shouldSkipExternalIpValidation(ingressOptions = null, liveKitVersion = null) {
  if (!ingressOptions) return false;
  const requested = isTruthy(
    process.env.LIVEKIT_SKIP_EXTERNAL_IP_VALIDATION || process.env.MEDIA_LIVEKIT_SKIP_EXTERNAL_IP_VALIDATION,
    true,
  );
  return requested && liveKitSupportsSkipExternalIpValidation(liveKitVersion);
}

function writeLiveKitConfig(configPath, apiKey, apiSecret, signalingPort, tcpPort, udpStart, udpEnd, ingressOptions = null, advertiseInternalIp = false, skipExternalIpValidation = false) {
  const singleUdpPort = udpStart === udpEnd;
  const lines = [
    `port: ${signalingPort}`,
    'log_level: info',
    'rtc:',
    `  tcp_port: ${tcpPort}`,
    ...(singleUdpPort
      ? [`  udp_port: ${udpStart}`]
      : [
        `  port_range_start: ${udpStart}`,
        `  port_range_end: ${udpEnd}`,
      ]),
    '  use_external_ip: true',
    ...(advertiseInternalIp ? ['  advertise_internal_ip: true'] : []),
    ...(skipExternalIpValidation ? ['  skip_external_ip_validation: true'] : []),
    'keys:',
    `  ${yamlQuote(apiKey)}: ${yamlQuote(apiSecret)}`,
  ];

  if (ingressOptions?.redisAddress) {
    lines.push(
      'redis:',
      `  address: ${yamlQuote(ingressOptions.redisAddress)}`,
    );
  }

  if (ingressOptions?.whipBaseUrl) {
    lines.push(
      'ingress:',
      `  whip_base_url: ${yamlQuote(ingressOptions.whipBaseUrl)}`,
    );
  }

  lines.push('');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(configPath, lines.join('\n'));
}

function liveKitServerAvailable() {
  return !!getLiveKitServerVersion();
}

function commandAvailable(command, args = ['--version']) {
  return spawnSync(command, args, { stdio: 'ignore' }).status === 0;
}

function getIngressCommand() {
  return (process.env.LIVEKIT_INGRESS_BIN || process.env.INGRESS_BIN || 'ingress').trim();
}

function getRedisAddress(redisPort) {
  const explicit = (process.env.LIVEKIT_REDIS_ADDRESS || process.env.REDIS_ADDRESS || '').trim();
  return explicit || `127.0.0.1:${redisPort}`;
}

function writeRedisConfig(configPath, redisPort) {
  const redisDir = path.join(dataDir, 'redis');
  fs.mkdirSync(redisDir, { recursive: true });
  fs.writeFileSync(configPath, [
    `port ${redisPort}`,
    'bind 127.0.0.1',
    'protected-mode yes',
    `dir ${redisDir.replace(/\\/g, '/')}`,
    'save ""',
    'appendonly no',
    '',
  ].join('\n'));
}

function writeIngressConfig(configPath, apiKey, apiSecret, internalUrl, redisAddress, whipPort, ingressUdpPort) {
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(configPath, [
    'logging:',
    '  level: info',
    `api_key: ${yamlQuote(apiKey)}`,
    `api_secret: ${yamlQuote(apiSecret)}`,
    `ws_url: ${yamlQuote(internalUrl)}`,
    'redis:',
    `  address: ${yamlQuote(redisAddress)}`,
    `whip_port: ${whipPort}`,
    'rtc_config:',
    `  udp_port: ${ingressUdpPort}`,
    '  use_external_ip: true',
    'cpu_cost:',
    '  whip_bypass_transcoding_cpu_cost: 0.05',
    '',
  ].join('\n'));
}

function startBundledRedis(redisPort, logger) {
  const { log, error } = logger;
  if (redisChild || process.env.CATREALM_BUNDLED_REDIS_STARTED === 'true') return redisChild;
  if ((process.env.LIVEKIT_REDIS_ADDRESS || process.env.REDIS_ADDRESS || '').trim()) {
    return null;
  }
  if (!commandAvailable('redis-server')) {
    error('[CatRealm] Cannot start bundled LiveKit Ingress: redis-server was not found in PATH.');
    return null;
  }

  const configPath = path.join(dataDir, 'redis.conf');
  writeRedisConfig(configPath, redisPort);
  process.env.CATREALM_BUNDLED_REDIS_STARTED = 'true';
  log(`[CatRealm] Starting bundled Redis for LiveKit Ingress on 127.0.0.1:${redisPort}`);
  redisChild = spawn('redis-server', [configPath], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: process.env,
  });

  redisChild.on('spawn', () => {
    log(`[CatRealm] Bundled Redis process started pid=${redisChild.pid}`);
  });

  redisChild.on('error', (err) => {
    error(`[CatRealm] Failed to start bundled Redis: ${err.message}`);
  });

  redisChild.on('exit', (code, signal) => {
    redisChild = null;
    if (code === 0 || signal) return;
    error(`[CatRealm] Bundled Redis exited with code ${code}.`);
  });

  return redisChild;
}

function startBundledIngress({ apiKey, apiSecret, internalUrl, redisAddress, whipPort, ingressUdpPort }, logger) {
  const { log, error } = logger;
  if (ingressChild || process.env.CATREALM_BUNDLED_INGRESS_STARTED === 'true') return ingressChild;
  const ingressCommand = getIngressCommand();
  if (!commandAvailable(ingressCommand, ['--help'])) {
    error(`[CatRealm] Cannot start bundled LiveKit Ingress: ${ingressCommand} was not found in PATH. Select the CatRealm Runtime image that includes LiveKit Ingress.`);
    return null;
  }

  const configPath = path.join(dataDir, 'ingress.yaml');
  writeIngressConfig(configPath, apiKey, apiSecret, internalUrl, redisAddress, whipPort, ingressUdpPort);
  process.env.CATREALM_BUNDLED_INGRESS_STARTED = 'true';
  process.env.MEDIA_LIVEKIT_INGRESS_ENABLED = 'true';
  process.env.MEDIA_LIVEKIT_INGRESS_PROXY_ENABLED = 'true';
  process.env.MEDIA_LIVEKIT_INGRESS_URL = `http://127.0.0.1:${whipPort}`;

  log(`[CatRealm] Starting bundled LiveKit Ingress on http://127.0.0.1:${whipPort}`);
  log(`[CatRealm] LiveKit WHIP proxy: enabled on CatRealm /whip over HTTPS`);
  log(`[CatRealm] LiveKit Ingress WHIP UDP port: ${ingressUdpPort}`);
  ingressChild = spawn(ingressCommand, ['--config', configPath], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: process.env,
  });

  ingressChild.on('spawn', () => {
    log(`[CatRealm] Bundled LiveKit Ingress process started pid=${ingressChild.pid}`);
  });

  ingressChild.on('error', (err) => {
    error(`[CatRealm] Failed to start bundled LiveKit Ingress: ${err.message}`);
  });

  ingressChild.on('exit', (code, signal) => {
    ingressChild = null;
    if (code === 0 || signal) return;
    error(`[CatRealm] Bundled LiveKit Ingress exited with code ${code}.`);
  });

  return ingressChild;
}

function stopBundledLiveKit() {
  if (ingressChild && !ingressChild.killed) {
    ingressChild.kill('SIGTERM');
  }
  if (livekitChild && !livekitChild.killed) {
    livekitChild.kill('SIGTERM');
  }
  if (redisChild && !redisChild.killed) {
    redisChild.kill('SIGTERM');
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

  const liveKitVersion = getLiveKitServerVersion();
  if (!liveKitVersion) {
    error('[CatRealm] Cannot start bundled LiveKit: livekit-server was not found in PATH. Select the CatRealm Runtime image that includes LiveKit.');
    return null;
  }

  const signalingPort = numberEnv('LIVEKIT_SIGNALING_PORT', 7880);
  const tcpPort = numberEnv('LIVEKIT_RTC_TCP_PORT', 7881);
  const udpStart = numberEnv('LIVEKIT_RTC_UDP_PORT_START', numberEnv('LIVEKIT_RTC_UDP_PORT', 50000));
  const udpEnd = Math.max(udpStart, numberEnv('LIVEKIT_RTC_UDP_PORT_END', udpStart));
  let ingressEnabled = isTruthy(process.env.HOST_LIVEKIT_INGRESS || process.env.MEDIA_LIVEKIT_INGRESS_ENABLED, false);
  const redisPort = numberEnv('LIVEKIT_REDIS_PORT', 6379);
  const ingressWhipPort = numberEnv('LIVEKIT_INGRESS_WHIP_PORT', 8080);
  const ingressUdpPort = numberEnv('LIVEKIT_INGRESS_RTC_UDP_PORT', 7885);
  const publicHost = getPublicLiveKitHost();
  const { apiKey, apiSecret } = getLiveKitSecrets();
  const configPath = path.join(dataDir, 'livekit.yaml');
  const internalUrl = (process.env.MEDIA_LIVEKIT_URL || process.env.LIVEKIT_URL || `ws://127.0.0.1:${signalingPort}`).trim();
  const publicUrl = getPublicLiveKitUrl(publicHost, signalingPort);
  const redisAddress = getRedisAddress(redisPort);
  const publicWhipUrl = getPublicWhipUrl(publicHost);

  if (ingressEnabled && !startBundledRedis(redisPort, { log, error }) && !(process.env.LIVEKIT_REDIS_ADDRESS || process.env.REDIS_ADDRESS || '').trim()) {
    error('[CatRealm] Bundled LiveKit Ingress disabled because Redis could not be started.');
    ingressEnabled = false;
  }

  const liveKitIngressOptions = ingressEnabled ? {
    redisAddress,
    whipBaseUrl: publicWhipUrl,
  } : null;
  const advertiseInternalIp = shouldAdvertiseInternalIp(liveKitIngressOptions, liveKitVersion);
  const skipExternalIpValidation = shouldSkipExternalIpValidation(liveKitIngressOptions, liveKitVersion);
  writeLiveKitConfig(
    configPath,
    apiKey,
    apiSecret,
    signalingPort,
    tcpPort,
    udpStart,
    udpEnd,
    liveKitIngressOptions,
    advertiseInternalIp,
    skipExternalIpValidation,
  );

  process.env.CATREALM_BUNDLED_LIVEKIT_STARTED = 'true';
  process.env.MEDIA_LIVEKIT_ENABLED = 'true';
  process.env.MEDIA_LIVEKIT_PROXY_ENABLED = 'true';
  process.env.MEDIA_LIVEKIT_URL = internalUrl;
  process.env.MEDIA_LIVEKIT_PUBLIC_WS_URL = publicUrl;
  process.env.MEDIA_LIVEKIT_API_KEY = apiKey;
  process.env.MEDIA_LIVEKIT_API_SECRET = apiSecret;
  if (ingressEnabled) {
    process.env.MEDIA_LIVEKIT_WHIP_PUBLIC_URL = publicWhipUrl;
    process.env.MEDIA_LIVEKIT_REDIS_ADDRESS = redisAddress;
  } else {
    process.env.MEDIA_LIVEKIT_INGRESS_ENABLED = 'false';
    delete process.env.MEDIA_LIVEKIT_WHIP_PUBLIC_URL;
    delete process.env.MEDIA_LIVEKIT_REDIS_ADDRESS;
    delete process.env.MEDIA_LIVEKIT_INGRESS_URL;
    delete process.env.MEDIA_LIVEKIT_INGRESS_PROXY_ENABLED;
  }
  log(`[CatRealm] Starting bundled LiveKit media server on ${internalUrl}`);
  log(`[CatRealm] LiveKit public URL: ${publicUrl}`);
  log('[CatRealm] LiveKit signaling proxy: enabled on CatRealm /rtc over HTTPS');
  log(`[CatRealm] LiveKit RTC ports: tcp=${tcpPort}, udp=${udpStart === udpEnd ? udpStart : `${udpStart}-${udpEnd}`}`);
  if (udpEnd > udpStart) {
    log(`[CatRealm] LiveKit UDP range requires every UDP port from ${udpStart} through ${udpEnd} to be allocated in Docker/Pterodactyl.`);
  } else {
    log('[CatRealm] LiveKit UDP single-port mode: using LiveKit UDP mux on the allocated port.');
  }
  if (ingressEnabled) {
    if (advertiseInternalIp) {
      log('[CatRealm] LiveKit media: advertising internal ICE candidates for bundled ingress');
    } else if (isTruthy(process.env.LIVEKIT_ADVERTISE_INTERNAL_IP || process.env.MEDIA_LIVEKIT_ADVERTISE_INTERNAL_IP, true)) {
      log(`[CatRealm] LiveKit media: internal ICE candidate advertisement unavailable in ${(liveKitVersion.raw || 'this livekit-server build')}`);
    }
    if (skipExternalIpValidation) {
      log('[CatRealm] LiveKit media: skipping external IP validation for bundled ingress');
    } else if (isTruthy(process.env.LIVEKIT_SKIP_EXTERNAL_IP_VALIDATION || process.env.MEDIA_LIVEKIT_SKIP_EXTERNAL_IP_VALIDATION, true)) {
      log(`[CatRealm] LiveKit media: external IP validation skip unavailable in ${(liveKitVersion.raw || 'this livekit-server build')}`);
    }
    log(`[CatRealm] LiveKit WHIP public URL: ${publicWhipUrl}`);
    // Warn (loudly) if the host's kernel UDP buffers are too small for
    // high-bitrate WHIP ingress — this is the difference between smooth 1440p
    // and a frozen ~2-5 fps stream. When limited, native share is capped to 720p.
    // The probe is async (measures a real socket), so log once it settles.
    initHostUdpBufferLimit()
      .then(() => { for (const line of getHostUdpBufferWarningLines()) error(line); })
      .catch(() => {});
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

  if (ingressEnabled) {
    startBundledIngress({
      apiKey,
      apiSecret,
      internalUrl,
      redisAddress,
      whipPort: ingressWhipPort,
      ingressUdpPort,
    }, { log, error });
  }

  process.once('exit', stopBundledLiveKit);
  return livekitChild;
}

module.exports = {
  startBundledLiveKit,
  stopBundledLiveKit,
};
