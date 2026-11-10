'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

process.env.THEATER_CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'theater-allowlist-'));
const { isDomainAllowed, downloadVideo } = require('../src/lib/theaterDownload');

test('an empty allowlist denies every domain', () => {
  assert.equal(isDomainAllowed('https://example.com/a.mp4', []), false);
  assert.equal(isDomainAllowed('http://127.0.0.1/a.mp4', []), false);
});

test('allowlisted domains match exactly or as a parent domain only', () => {
  assert.equal(isDomainAllowed('https://cdn.example.com/a.mp4', ['example.com']), true);
  assert.equal(isDomainAllowed('https://example.com.evil.test/a.mp4', ['example.com']), false);
  assert.equal(isDomainAllowed('https://notexample.com/a.mp4', ['example.com']), false);
});

test('a direct download refuses a redirect to a host outside the allowlist', async () => {
  let internalHit = false;
  const internal = http.createServer((_req, res) => { internalHit = true; res.end('secret'); });
  await new Promise((resolve) => internal.listen(0, '127.0.0.1', resolve));
  const redirector = http.createServer((_req, res) => {
    res.writeHead(302, { Location: `http://127.0.0.1:${internal.address().port}/secret.mp4` }).end();
  });
  await new Promise((resolve) => redirector.listen(0, '127.0.0.1', resolve));

  try {
    // "localhost" is allowlisted, the 127.0.0.1 redirect target is not.
    const start = `http://localhost:${redirector.address().port}/video.mp4`;
    await assert.rejects(
      downloadVideo(start, 'test-channel', null, (url) => isDomainAllowed(url, ['localhost'])),
      /Domain not in allowlist/,
    );
    assert.equal(internalHit, false);
  } finally {
    redirector.close();
    internal.close();
  }
});
