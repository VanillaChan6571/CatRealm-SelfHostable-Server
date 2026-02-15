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
const pteroLog = require('./logger');

const SSL_DIR = path.resolve(process.env.SSL_DATA_DIR || './data/ssl');
const CERT_PATH = path.join(SSL_DIR, 'cert.pem');
const KEY_PATH = path.join(SSL_DIR, 'key.pem');
const ACCOUNT_KEY_PATH = path.join(SSL_DIR, 'account-key.pem');

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
 * Check if an existing cert is valid and not expiring within 30 days.
 */
function existingCertValid() {
  if (!fs.existsSync(CERT_PATH) || !fs.existsSync(KEY_PATH)) return false;

  try {
    const certPem = fs.readFileSync(CERT_PATH, 'utf8');
    const x509 = new crypto.X509Certificate(certPem);
    const expiresAt = new Date(x509.validTo);
    const daysLeft = (expiresAt - Date.now()) / (1000 * 60 * 60 * 24);
    pteroLog(`[AutoSSL] Existing cert expires ${x509.validTo} (${Math.floor(daysLeft)} days left)`);
    return daysLeft > 30;
  } catch {
    return false;
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

  fs.mkdirSync(SSL_DIR, { recursive: true });
  fs.writeFileSync(CERT_PATH, cert);
  fs.writeFileSync(KEY_PATH, csrKey);
  fs.chmodSync(KEY_PATH, 0o600);

  pteroLog(`[AutoSSL] Certificate saved to ${SSL_DIR}`);
  return { cert: Buffer.from(cert), key: csrKey };
}

/* ── Main entry point ────────────────────────────────────────────────────────── */

/**
 * Initialise Auto-SSL. Returns { cert, key } buffers.
 * @param {string} domain
 * @param {string} email
 * @param {object} [dnsOpts] - { provider, apiToken } for DNS-01 challenge
 */
async function initAutoSSL(domain, email, dnsOpts) {
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

  let cert, key;

  if (existingCertValid()) {
    pteroLog('[AutoSSL] Using existing certificate');
    cert = fs.readFileSync(CERT_PATH);
    key = fs.readFileSync(KEY_PATH);
  } else {
    const result = await provisionCert(provisionOpts);
    cert = result.cert;
    key = result.key;
  }

  // Schedule renewal check every 12 hours
  setInterval(async () => {
    if (!existingCertValid()) {
      pteroLog('[AutoSSL] Certificate expiring soon, renewing...');
      try {
        await provisionCert(provisionOpts);
        pteroLog('[AutoSSL] Renewal complete. Restart server to use new cert.');
      } catch (err) {
        pteroLog(`[AutoSSL] Renewal failed: ${err.message}`);
      }
    }
  }, 12 * 60 * 60 * 1000);

  return { cert, key, challengeServer };
}

module.exports = { initAutoSSL };
