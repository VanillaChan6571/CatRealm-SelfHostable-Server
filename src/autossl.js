/**
 * Auto-SSL via Let's Encrypt (ACME HTTP-01 or DNS-01 challenge)
 *
 * When SSL_DOMAIN and SSL_EMAIL are set, this module:
 *   1. Checks for existing certs in ./data/ssl/
 *   2. If missing or expiring within 30 days, provisions new ones from Let's Encrypt
 *   3. Returns { cert, key } buffers for https.createServer
 *   4. Starts an HTTP challenge server on port 80 (HTTP-01) or uses DNS API (DNS-01)
 *   5. Schedules automatic renewal checks every 12 hours
 *
 * Challenge modes:
 *   - HTTP-01 (default): Requires port 80 access
 *   - DNS-01: Requires a supported DNS provider API token (no port 80 needed)
 *
 * Supported DNS providers: cloudflare
 *
 * Requires: npm install acme-client
 */

const acme = require('acme-client');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const tls = require('tls');
const pteroLog = require('./logger');

const SSL_DIR = path.resolve(process.env.SSL_DATA_DIR || './data/ssl');
const CERT_PATH = path.join(SSL_DIR, 'cert.pem');
const KEY_PATH = path.join(SSL_DIR, 'key.pem');
const ACCOUNT_KEY_PATH = path.join(SSL_DIR, 'account-key.pem');
const RENEWAL_INTERVAL_MS = 12 * 60 * 60 * 1000;
const INITIAL_RETRY_MS = 60 * 1000;
const MAX_RETRY_MS = 15 * 60 * 1000;

// In-memory store for pending ACME challenges
const pendingChallenges = new Map();

/* ── DNS-01 provider: Cloudflare ─────────────────────────────────────────────── */

const CF_API = 'https://api.cloudflare.com/client/v4';

async function cfRequest(method, endpoint, apiToken, data) {
  const res = await axios({
    method,
    url: `${CF_API}${endpoint}`,
    headers: { Authorization: `Bearer ${apiToken}`, 'Content-Type': 'application/json' },
    data,
  });
  if (!res.data.success) {
    const msgs = res.data.errors.map((e) => e.message).join(', ');
    throw new Error(`Cloudflare API error: ${msgs}`);
  }
  return res.data;
}

async function cfGetZoneId(domain, apiToken) {
  // Walk up the domain to find the zone (e.g. sub.example.com → example.com)
  const parts = domain.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const zone = parts.slice(i).join('.');
    const res = await cfRequest('get', `/zones?name=${zone}`, apiToken);
    if (res.result && res.result.length > 0) return res.result[0].id;
  }
  throw new Error(`Cloudflare zone not found for ${domain}`);
}

async function cfCreateTxtRecord(zoneId, fqdn, value, apiToken) {
  const res = await cfRequest('post', `/zones/${zoneId}/dns_records`, apiToken, {
    type: 'TXT',
    name: fqdn,
    content: value,
    ttl: 120,
  });
  return res.result.id;
}

async function cfDeleteTxtRecord(zoneId, recordId, apiToken) {
  await cfRequest('delete', `/zones/${zoneId}/dns_records/${recordId}`, apiToken);
}

/**
 * Build challengeCreateFn / challengeRemoveFn for DNS-01 via Cloudflare.
 */
function buildCloudflareChallengeFns(domain, apiToken) {
  let zoneId = null;
  const recordIds = new Map(); // token → recordId

  return {
    challengeCreateFn: async (authz, challenge, keyAuthorization) => {
      if (challenge.type !== 'dns-01') return;
      if (!zoneId) zoneId = await cfGetZoneId(domain, apiToken);

      const dnsRecord = `_acme-challenge.${authz.identifier.value}`;
      pteroLog(`[AutoSSL/DNS] Creating TXT record: ${dnsRecord}`);
      const recordId = await cfCreateTxtRecord(zoneId, dnsRecord, keyAuthorization, apiToken);
      recordIds.set(challenge.token, recordId);

      // Wait for DNS propagation
      pteroLog('[AutoSSL/DNS] Waiting 15s for DNS propagation...');
      await new Promise((r) => setTimeout(r, 15000));
    },
    challengeRemoveFn: async (_authz, challenge) => {
      if (challenge.type !== 'dns-01') return;
      const recordId = recordIds.get(challenge.token);
      if (recordId && zoneId) {
        pteroLog('[AutoSSL/DNS] Cleaning up TXT record');
        await cfDeleteTxtRecord(zoneId, recordId, apiToken).catch(() => {});
        recordIds.delete(challenge.token);
      }
    },
  };
}

/* ── HTTP-01 challenge server ────────────────────────────────────────────────── */

/**
 * Tiny HTTP server on port 80 that serves ACME challenges
 * and redirects everything else to HTTPS.
 */
function startChallengeServer(domain) {
  const srv = http.createServer((req, res) => {
    // Serve ACME HTTP-01 challenges
    if (req.url && req.url.startsWith('/.well-known/acme-challenge/')) {
      const token = req.url.split('/').pop();
      const keyAuth = pendingChallenges.get(token);
      if (keyAuth) {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(keyAuth);
        return;
      }
    }
    // Redirect everything else to HTTPS
    res.writeHead(301, { Location: `https://${domain}${req.url}` });
    res.end();
  });

  srv.listen(80, '0.0.0.0', () => {
    pteroLog('[AutoSSL] Challenge server listening on port 80');
  });

  srv.on('error', (err) => {
    if (err.code === 'EACCES') {
      pteroLog('[AutoSSL] Cannot bind port 80 (permission denied). Run as root or use setcap.');
    } else if (err.code === 'EADDRINUSE') {
      pteroLog('[AutoSSL] Port 80 already in use. ACME challenges may fail.');
    } else {
      pteroLog(`[AutoSSL] Challenge server error: ${err.message}`);
    }
  });

  return srv;
}

/* ── Shared helpers ──────────────────────────────────────────────────────────── */

/**
 * Get or generate an ACME account key (persisted to disk).
 */
async function getAccountKey() {
  if (fs.existsSync(ACCOUNT_KEY_PATH)) {
    return fs.readFileSync(ACCOUNT_KEY_PATH);
  }
  const key = await acme.crypto.createPrivateKey();
  fs.mkdirSync(SSL_DIR, { recursive: true });
  fs.writeFileSync(ACCOUNT_KEY_PATH, key);
  fs.chmodSync(ACCOUNT_KEY_PATH, 0o600);
  return key;
}

/**
 * Validate the pair before serving it; an unexpired certificate can keep HTTPS
 * available while an early renewal attempt fails.
 */
function certificateUsable(cert, key, domain, minimumRemainingMs = 0) {
  try {
    const x509 = new crypto.X509Certificate(cert);
    if (Date.parse(x509.validFrom) > Date.now() || Date.parse(x509.validTo) <= Date.now() + minimumRemainingMs) return false;
    if (!x509.checkHost(domain) || !x509.checkPrivateKey(crypto.createPrivateKey(key))) return false;
    tls.createSecureContext({ cert, key });
    return true;
  } catch {
    return false;
  }
}

function readExistingCertificate(domain, minimumRemainingMs = 0) {
  try {
    const cert = fs.readFileSync(CERT_PATH);
    const key = fs.readFileSync(KEY_PATH);
    return certificateUsable(cert, key, domain, minimumRemainingMs) ? { cert, key } : null;
  } catch {
    return null;
  }
}

/**
 * Request a new certificate from Let's Encrypt.
 * @param {object} opts - { domain, email, dnsProvider?, dnsApiToken? }
 */
async function provisionCert(opts) {
  const { domain, email, dnsProvider, dnsApiToken } = opts;
  const useDns = dnsProvider && dnsApiToken;

  pteroLog(`[AutoSSL] Provisioning cert for ${domain} (${useDns ? 'DNS-01' : 'HTTP-01'})...`);

  const accountKey = await getAccountKey();
  const [csrKey, csr] = await acme.crypto.createCsr({ commonName: domain });

  const client = new acme.Client({
    directoryUrl: acme.directory.letsencrypt.production,
    accountKey,
  });

  await client.createAccount({
    termsOfServiceAgreed: true,
    contact: [`mailto:${email}`],
  });

  let challengeCreateFn, challengeRemoveFn, challengePriority;

  if (useDns) {
    if (dnsProvider !== 'cloudflare') {
      throw new Error(`Unsupported DNS provider: ${dnsProvider}. Supported: cloudflare`);
    }
    const fns = buildCloudflareChallengeFns(domain, dnsApiToken);
    challengeCreateFn = fns.challengeCreateFn;
    challengeRemoveFn = fns.challengeRemoveFn;
    challengePriority = ['dns-01'];
  } else {
    challengeCreateFn = async (_authz, challenge, keyAuthorization) => {
      pendingChallenges.set(challenge.token, keyAuthorization);
    };
    challengeRemoveFn = async (_authz, challenge) => {
      pendingChallenges.delete(challenge.token);
    };
    challengePriority = ['http-01'];
  }

  const cert = await client.auto({
    csr,
    email,
    termsOfServiceAgreed: true,
    challengePriority,
    challengeCreateFn,
    challengeRemoveFn,
  });

  if (!certificateUsable(cert, csrKey, domain)) throw new Error('ACME returned an unusable certificate/key pair');

  fs.mkdirSync(SSL_DIR, { recursive: true });
  // Publish the cert last: the multi-realm watcher treats its mtime as the
  // signal that both files are ready. Readers never see partially written PEMs.
  fs.writeFileSync(`${KEY_PATH}.next`, csrKey, { mode: 0o600 });
  fs.writeFileSync(`${CERT_PATH}.next`, cert);
  fs.renameSync(`${KEY_PATH}.next`, KEY_PATH);
  fs.renameSync(`${CERT_PATH}.next`, CERT_PATH);

  pteroLog(`[AutoSSL] Certificate saved to ${SSL_DIR}`);
  return { cert: Buffer.from(cert), key: csrKey };
}

/* ── Main entry point ────────────────────────────────────────────────────────── */

/**
 * Initialise Auto-SSL. Returns { cert, key } buffers.
 * @param {string} domain
 * @param {string} email
 * @param {object} [dnsOpts] - { provider, apiToken } for DNS-01 challenge
 * @param {object} [lifecycleOpts] - { onRenewed } callback used to activate a renewed cert
 */
async function initAutoSSL(domain, email, dnsOpts, lifecycleOpts = {}) {
  fs.mkdirSync(SSL_DIR, { recursive: true });

  const useDns = dnsOpts && dnsOpts.provider && dnsOpts.apiToken;
  let challengeServer = null;

  if (useDns) {
    pteroLog(`[AutoSSL] Using DNS-01 challenge via ${dnsOpts.provider} (no port 80 needed)`);
  } else {
    // Start challenge server (also handles HTTP→HTTPS redirect)
    challengeServer = startChallengeServer(domain);
  }

  const provisionOpts = {
    domain,
    email,
    dnsProvider: useDns ? dnsOpts.provider : null,
    dnsApiToken: useDns ? dnsOpts.apiToken : null,
  };

  const renewBeforeMs = 30 * 24 * 60 * 60 * 1000;
  let retryMs = INITIAL_RETRY_MS;
  let nextCheckMs = RENEWAL_INTERVAL_MS;
  let active = readExistingCertificate(domain, renewBeforeMs);
  while (!active) {
    try {
      active = await provisionCert(provisionOpts);
    } catch (err) {
      pteroLog(`[AutoSSL] Startup provisioning failed: ${err.message}. Retrying in ${retryMs / 1000}s.`);
      active = readExistingCertificate(domain);
      if (active) {
        pteroLog('[AutoSSL] Keeping the unexpired certificate while renewal is retried.');
        nextCheckMs = retryMs;
        break;
      }
      // Keep startup pending until HTTPS is possible. This also works without
      // a process supervisor and avoids rapid restart loops during ACME outages.
      await new Promise((resolve) => setTimeout(resolve, retryMs));
      retryMs = Math.min(retryMs * 2, MAX_RETRY_MS);
    }
  }

  let stopped = false;
  let timer;
  let pendingActivation = null;
  function schedule(delay) {
    if (stopped) return;
    timer = setTimeout(checkRenewal, delay);
    timer.unref?.();
  }
  async function checkRenewal() {
    let delay = RENEWAL_INTERVAL_MS;
    try {
      if (!pendingActivation && !certificateUsable(active.cert, active.key, domain, renewBeforeMs)) {
        pendingActivation = await provisionCert(provisionOpts);
        pteroLog('[AutoSSL] Renewal complete.');
      }
      if (pendingActivation && !stopped) {
        if (typeof lifecycleOpts.onRenewed === 'function') {
          await lifecycleOpts.onRenewed(pendingActivation);
          pteroLog('[AutoSSL] Renewed certificate activated.');
        } else {
          pteroLog('[AutoSSL] Renewed certificate saved; waiting for the supervisor to restart realms.');
        }
        active = pendingActivation;
        pendingActivation = null;
      }
      retryMs = INITIAL_RETRY_MS;
    } catch (err) {
      delay = retryMs;
      retryMs = Math.min(retryMs * 2, MAX_RETRY_MS);
      pteroLog(`[AutoSSL] Certificate recovery failed: ${err.message}. Retrying in ${delay / 1000}s.`);
    }
    schedule(delay);
  }
  schedule(nextCheckMs);

  return {
    ...active,
    challengeServer,
    stop: () => {
      stopped = true;
      clearTimeout(timer);
      challengeServer?.close();
    },
  };
}

module.exports = { initAutoSSL };
