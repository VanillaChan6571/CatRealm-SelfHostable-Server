const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');
const nodeModulesDir = path.join(repoRoot, 'node_modules');
const betterSqliteBinary = path.join(
  repoRoot,
  'node_modules',
  'better-sqlite3',
  'build',
  'Release',
  'better_sqlite3.node'
);

function needsInstall() {
  return !fs.existsSync(nodeModulesDir) || !fs.existsSync(betterSqliteBinary);
}

function installDependencies() {
  const result = spawnSync('npm', ['install', '--production'], {
    cwd: repoRoot,
    stdio: 'inherit',
    env: {
      ...process.env,
      npm_config_libc: process.env.npm_config_libc || 'musl',
    },
  });

  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

if (needsInstall()) {
  installDependencies();
}

require(path.join(repoRoot, 'src', 'index.js'));
