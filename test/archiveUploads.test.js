const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const express = require('express');
const { loadModule } = require('./helpers');

function startUploadServer(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catrealm-uploads-'));
  const router = loadModule('src/routes/uploads.js', {
    '../db': {},
    '../permissions': { PERMISSIONS: {}, hasPermission: () => true, hasChannelPermission: () => true },
    '../settings': { getSetting: () => '50' },
    '../mediaCompression': {
      classifyChatUploadForCompression: () => ({ kind: 'none' }),
      compressChatImageInline: async () => null,
      enqueueChatVideoCompression: () => {},
    },
  }, { process: { env: { UGC_IMAGES_DIR: dir } } });
  const app = express();
  app.use((req, _res, next) => { req.user = { id: 'alice' }; next(); });
  app.use('/api/uploads', router);
  app.use((err, _req, res, _next) => res.status(400).json({ error: err.message }));
  const server = app.listen(0);
  t.after(() => { server.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    dir,
    upload: async (bytes, filename, type) => {
      const form = new FormData();
      form.append('file', new Blob([bytes], { type }), filename);
      form.append('channelId', 'general');
      const res = await fetch(`${base}/api/uploads/chat`, { method: 'POST', body: form });
      return { status: res.status, body: await res.json() };
    },
  };
}

const zipBytes = Buffer.concat([Buffer.from('PK\x03\x04', 'latin1'), Buffer.alloc(40)]);
const rarBytes = Buffer.concat([Buffer.from('Rar!\x1a\x07\x01\x00', 'latin1'), Buffer.alloc(40)]);

test('archives upload as downloads with a safe display name', async (t) => {
  const { upload, dir } = startUploadServer(t);

  const zip = await upload(zipBytes, 'Mod Pack <v2>.zip', 'application/x-zip-compressed');
  assert.equal(zip.status, 200);
  assert.match(zip.body.url, /^\/ugc\/images\/[0-9a-f-]+\.zip$/);
  assert.equal(zip.body.mime, 'application/zip');
  assert.equal(zip.body.name, 'Mod Pack v2.zip');

  // Windows commonly sends .rar as application/octet-stream; the extension decides.
  const rar = await upload(rarBytes, 'saves.rar', 'application/octet-stream');
  assert.equal(rar.status, 200);
  assert.equal(rar.body.mime, 'application/vnd.rar');
  assert.equal(fs.readdirSync(dir).filter((f) => f.endsWith('.rar')).length, 1);
});

test('files pretending to be archives, and other types, are rejected and not kept', async (t) => {
  const { upload, dir } = startUploadServer(t);
  const fake = await upload(Buffer.from('<html><script>alert(1)</script></html>'), 'totally.zip', 'application/zip');
  assert.equal(fake.status, 400);
  const exe = await upload(Buffer.from('MZ'), 'setup.exe', 'application/octet-stream');
  assert.equal(exe.status, 400);
  const html = await upload(Buffer.from('<html>'), 'page.html', 'text/html');
  assert.equal(html.status, 400);
  assert.deepEqual(fs.readdirSync(dir).filter((f) => f !== 'thumbs'), []);
});
