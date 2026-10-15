const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { ensureDependenciesInstalled } = require('../src/lib/dependencyInstall');

test('a changed server package installs dependencies before startup', { skip: process.platform === 'win32' }, t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catrealm-dependencies-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const npm = path.join(root, 'fake-npm');
  fs.writeFileSync(npm, '#!/bin/sh\nmkdir -p node_modules\nprintf "install\\n" >> install-calls\n');
  fs.chmodSync(npm, 0o700);
  const manifest = path.join(root, 'package.json');
  fs.writeFileSync(manifest, '{"version":"1.8.7"}\n');

  assert.equal(ensureDependenciesInstalled(root, { npmCommand: npm }), true);
  assert.equal(ensureDependenciesInstalled(root, { npmCommand: npm }), false);
  fs.writeFileSync(manifest, '{"version":"1.8.8"}\n');
  assert.equal(ensureDependenciesInstalled(root, { npmCommand: npm }), true);
  assert.equal(fs.readFileSync(path.join(root, 'install-calls'), 'utf8'), 'install\ninstall\n');
});
