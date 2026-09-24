const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModule } = require('./helpers');

const DAY = 24 * 60 * 60 * 1000;
const DOMAIN = 'realm.example';
const flush = () => new Promise(resolve => setImmediate(resolve));

// Fake only ACME, filesystem, crypto parsing, and time. Exercise the complete
// AutoSSL lifecycle without issuing public certificates or using real timers.
function setup({ cachedDays = null, failures = 0, wrongHost = false } = {}) {
  let now = Date.now();
  let attempts = 0;
  let remainingFailures = failures;
  const timers = [];
  const files = new Map();
  const certPath = '/synthetic-ssl/cert.pem';
  const keyPath = '/synthetic-ssl/key.pem';
  const certificate = (days, domain = DOMAIN, key = 'key') => Buffer.from(JSON.stringify({
    validFrom: new Date(now - DAY).toISOString(), validTo: new Date(now + days * DAY).toISOString(), domain, key,
  }));
  if (cachedDays !== null) {
    files.set(certPath, certificate(cachedDays, wrongHost ? 'wrong.example' : DOMAIN));
    files.set(keyPath, Buffer.from('key'));
  }
  const fs = {
    existsSync: name => files.has(name), mkdirSync() {}, chmodSync() {},
    readFileSync(name) { if (!files.has(name)) throw new Error('ENOENT'); return files.get(name); },
    writeFileSync: (name, data) => files.set(name, data),
    renameSync(from, to) { assert(files.has(from)); files.set(to, files.get(from)); files.delete(from); },
  };
  const crypto = {
    X509Certificate: class {
      constructor(raw) { Object.assign(this, JSON.parse(String(raw))); }
      checkHost(host) { return host === this.domain; }
      checkPrivateKey(key) { return String(key) === this.key; }
    },
    createPrivateKey: value => value,
  };
  const acme = {
    crypto: { createPrivateKey: async () => Buffer.from('account-key'), createCsr: async () => [Buffer.from('key'), 'csr'] },
    directory: { letsencrypt: { production: 'https://acme.invalid' } },
    Client: class {
      async createAccount() {}
      async auto() {
        attempts++;
        if (remainingFailures-- > 0) throw new Error('Synthetic ACME outage');
        return certificate(90);
      }
    },
  };
  const module = loadModule('src/autossl.js', {
    'acme-client': acme, axios: {}, fs, crypto, tls: { createSecureContext() {} }, './logger': () => {},
  }, {
    process: { env: { SSL_DATA_DIR: '/synthetic-ssl' } },
    Date: class extends Date { static now() { return now; } },
    setTimeout(callback, delay) {
      const timer = { callback, delay, unref() {} };
      timers.push(timer);
      return timer;
    },
    clearTimeout(timer) { const index = timers.indexOf(timer); if (index >= 0) timers.splice(index, 1); },
  });
  return {
    timers, files, certPath,
    attempts: () => attempts,
    failNext: count => { remainingFailures = count; },
    advanceDays: days => { now += days * DAY; },
    init: onRenewed => module.initAutoSSL(DOMAIN, 'operator@example.test', { provider: 'cloudflare', apiToken: 'synthetic' }, { onRenewed }),
    async tick() {
      const timer = timers.shift();
      assert(timer, 'expected a recovery timer');
      now += timer.delay;
      await timer.callback();
      await flush();
    },
  };
}

test('startup waits and retries until an HTTPS certificate is available', async () => {
  const h = setup({ failures: 2 });
  let ready = false;
  const startup = h.init().then(session => { ready = true; return session; });
  await flush();
  assert.equal(ready, false);
  assert.equal(h.timers[0].delay, 60_000);
  await h.tick();
  assert.equal(ready, false);
  assert.equal(h.timers[0].delay, 120_000);
  await h.tick();
  const session = await startup;
  assert(session.cert && session.key);
  assert.equal(h.attempts(), 3);
  assert.equal(h.timers[0].delay, 12 * 60 * 60 * 1000);
  session.stop();
  assert.equal(h.timers.length, 0);
});

test('an unexpired cached certificate keeps HTTPS available during early-renewal failure', async () => {
  const h = setup({ cachedDays: 5, failures: 1 });
  const old = h.files.get(h.certPath);
  const activations = [];
  const session = await h.init(pair => activations.push(pair));
  assert.equal(session.cert, old);
  assert.equal(h.timers[0].delay, 60_000);
  await h.tick();
  assert.equal(activations.length, 1);
  assert.notEqual(activations[0].cert, old);
  session.stop();
});

test('expired or wrong-host cached certificates never complete startup after failed issuance', async () => {
  for (const options of [{ cachedDays: -1 }, { cachedDays: 5, wrongHost: true }]) {
    const h = setup({ ...options, failures: 1 });
    let ready = false;
    const startup = h.init().then(session => { ready = true; return session; });
    await flush();
    assert.equal(ready, false);
    await h.tick();
    (await startup).stop();
  }
});

test('renewal failure backs off and eventually activates a new certificate', async () => {
  const h = setup({ cachedDays: 90 });
  const activations = [];
  const session = await h.init(pair => activations.push(pair));
  h.advanceDays(65);
  h.failNext(2);
  await h.tick();
  assert.equal(h.timers[0].delay, 60_000);
  await h.tick();
  assert.equal(h.timers[0].delay, 120_000);
  await h.tick();
  assert.equal(activations.length, 1);
  assert.equal(h.timers[0].delay, 12 * 60 * 60 * 1000);
  session.stop();
});

test('failed activation retries the saved pair without requesting another certificate', async () => {
  const h = setup({ cachedDays: 90 });
  let activations = 0;
  const session = await h.init(() => {
    activations++;
    if (activations === 1) throw new Error('Synthetic activation failure');
  });
  h.advanceDays(65);
  await h.tick();
  assert.equal(h.attempts(), 1);
  assert.equal(h.timers[0].delay, 60_000);
  await h.tick();
  assert.equal(activations, 2);
  assert.equal(h.attempts(), 1);
  session.stop();
});

test('supervisor mode persists the renewed pair without a live-reload callback', async () => {
  const h = setup({ cachedDays: 90 });
  const old = h.files.get(h.certPath);
  const session = await h.init();
  h.advanceDays(65);
  await h.tick();
  assert.notEqual(h.files.get(h.certPath), old);
  assert.equal(h.attempts(), 1);
  session.stop();
});
