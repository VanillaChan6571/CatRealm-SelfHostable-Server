const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const express = require('express');
const { loadModule } = require('./helpers');

function startUploadServer(t, { canAttach = true, canManageBoard = false, canManageTracker = false, channelType = 'board' } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catrealm-uploads-'));
  const router = loadModule('src/routes/uploads.js', {
    '../db': { prepare: (sql) => ({ get: () => sql.startsWith('SELECT type FROM channels') ? { type: channelType } : null }) },
    '../permissions': {
      PERMISSIONS: { ATTACH_FILES: 'ATTACH_FILES', SEND_MEDIA: 'SEND_MEDIA' },
      hasPermission: () => canAttach,
      hasChannelPermission: (_user, _channelId, permission) => permission === 'MANAGE_BOARDS' ? canManageBoard
        : permission === 'MANAGE_ISSUES' ? canManageTracker : canAttach,
    },
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
    upload: async (bytes, filename, type, purpose) => {
      const form = new FormData();
      form.append('file', new Blob([bytes], { type }), filename);
      form.append('channelId', 'general');
      if (purpose) form.append('purpose', purpose);
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

test('board managers can upload only board background images without attachment permission', async (t) => {
  const png = Buffer.from('89504e470d0a1a0a00000000', 'hex');
  const manager = startUploadServer(t, { canAttach: false, canManageBoard: true });
  const ordinary = await manager.upload(png, 'background.png', 'image/png');
  assert.equal(ordinary.status, 403, 'board management does not grant general attachment uploads');
  const valid = await manager.upload(png, 'background.png', 'image/png', 'board-background');
  assert.equal(valid.status, 200);
  assert.match(valid.body.url, /^\/ugc\/images\/[0-9a-f-]+\.png$/);
  const fake = await manager.upload(Buffer.from('<html>'), 'background.png', 'image/png', 'board-background');
  assert.equal(fake.status, 400);
  const video = await manager.upload(Buffer.from('not an image'), 'background.mp4', 'video/mp4', 'board-background');
  assert.equal(video.status, 400);
  assert.equal(fs.readdirSync(manager.dir).filter((f) => f !== 'thumbs').length, 1);

  const nonManager = startUploadServer(t, { canAttach: true });
  assert.equal((await nonManager.upload(png, 'background.png', 'image/png', 'board-background')).status, 403);
  const wrongChannel = startUploadServer(t, { canManageBoard: true, channelType: 'basic' });
  assert.equal((await wrongChannel.upload(png, 'background.png', 'image/png', 'board-background')).status, 403);

  const trackerManager = startUploadServer(t, { canAttach: false, canManageTracker: true, channelType: 'tracker' });
  assert.equal((await trackerManager.upload(png, 'background.png', 'image/png', 'tracker-background')).status, 200);
  assert.equal((await trackerManager.upload(png, 'background.png', 'image/png', 'board-background')).status, 403);
  assert.equal((await manager.upload(png, 'background.png', 'image/png', 'tracker-background')).status, 403);
});
