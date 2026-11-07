'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { npmSpawnSpec } = require('./npmCommand');

function ensureDependenciesInstalled(repoRoot = path.resolve(__dirname, '../..'), options = {}) {
  const manifest = fs.readFileSync(path.join(repoRoot, 'package.json'));
  const fingerprint = crypto.createHash('sha256').update(manifest).digest('hex');
  const modulesPath = path.join(repoRoot, 'node_modules');
  const markerPath = path.join(modulesPath, '.catrealm-package-fingerprint');
  if (!options.force && fs.existsSync(markerPath)
      && fs.readFileSync(markerPath, 'utf8').trim() === fingerprint) return false;

  const npm = npmSpawnSpec(['install', '--omit=dev'], options.npmCommand);
  console.log('[CatRealm] Installing production dependencies for this server build...');
  const result = spawnSync(npm.command, npm.args, {
    cwd: repoRoot,
    stdio: 'inherit',
    shell: npm.shell,
  });
  if (result.status !== 0) {
    throw new Error(`Production dependency installation failed (${result.error?.message || result.status || 'unknown error'})`);
  }
  fs.writeFileSync(markerPath, `${fingerprint}\n`);
  return true;
}

if (require.main === module) ensureDependenciesInstalled();

module.exports = { ensureDependenciesInstalled };
