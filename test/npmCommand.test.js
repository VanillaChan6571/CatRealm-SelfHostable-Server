const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { npmSpawnSpec } = require('../src/lib/npmCommand');
const { ensureDependenciesInstalled } = require('../src/lib/dependencyInstall');

test('non-Windows hosts keep spawning plain npm without a shell', () => {
  assert.deepEqual(npmSpawnSpec(['install'], null, 'linux'), { command: 'npm', args: ['install'], shell: false });
});

test('Windows .cmd overrides get a shell, other overrides do not', () => {
  assert.equal(npmSpawnSpec(['-v'], 'C:\npm\npm.cmd', 'win32').shell, true);
  assert.equal(npmSpawnSpec(['-v'], '/usr/bin/fake-npm', 'linux').shell, false);
});

test('the resolved npm runs synchronously on this host', () => {
  const npm = npmSpawnSpec(['-v']);
  const result = spawnSync(npm.command, npm.args, { shell: npm.shell, encoding: 'utf8' });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0);
  assert.match(result.stdout.trim(), /^\d+\.\d+\.\d+/);
});

test('the resolved npm runs asynchronously and can be killed', async () => {
  const npm = npmSpawnSpec(['-v']);
  const child = spawn(npm.command, npm.args, { shell: npm.shell, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  let stdout = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  const code = await new Promise((resolve, reject) => { child.on('error', reject); child.on('exit', resolve); });
  assert.equal(code, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+/);
});

test('Windows startup install runs through a .cmd npm override', { skip: process.platform !== 'win32' }, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catrealm-dependencies-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const npm = path.join(root, 'fake-npm.cmd');
  fs.writeFileSync(npm, '@echo off\r\nif not exist node_modules mkdir node_modules\r\necho install>> install-calls\r\n');
  fs.writeFileSync(path.join(root, 'package.json'), '{"version":"1.8.7"}\n');
  assert.equal(ensureDependenciesInstalled(root, { npmCommand: npm }), true);
  assert.equal(ensureDependenciesInstalled(root, { npmCommand: npm }), false);
  assert.equal(fs.readFileSync(path.join(root, 'install-calls'), 'utf8').trim(), 'install');
});
