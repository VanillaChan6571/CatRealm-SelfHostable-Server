// Runtime bootstrap for Pterodactyl: ensures dependencies exist, then starts
// the server. Only Node builtins may be required before the dependency check —
// after a panel Reinstall node_modules can be missing entirely, and this
// script must still be able to repair itself.
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

// A binary built for another Node major (e.g. the runtime image moved from
// Node 20 to 24) still exists on disk but cannot load. Probe in a child
// process: on musl an in-process dlopen succeeds lazily and only fails later.
function nativeModuleStale() {
  const probe = spawnSync(
    process.execPath,
    ['-e', "new (require('better-sqlite3'))(':memory:').close()"],
    { cwd: repoRoot, stdio: 'ignore' }
  );
  return probe.status !== 0;
}

function runNpm(args, reason) {
  console.log(`[CatRealm] ${reason} — running npm ${args.join(' ')}...`);
  const result = spawnSync('npm', args, {
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
  runNpm(['install', '--omit=dev'], 'Dependencies missing');
} else if (nativeModuleStale()) {
  runNpm(['rebuild', 'better-sqlite3'], `Native modules do not match Node ${process.version}`);
}

// Pterodactyl passes every egg variable into the container, blank ones as "".
// dotenv never overrides an existing key, so a blank panel field would hide
// the same key in .env. Treat blank panel values as unset instead.
for (const [key, value] of Object.entries(process.env)) {
  if (value === '') delete process.env[key];
}

require('dotenv').config({ quiet: true });

const { startBundledLiveKit } = require(path.join(repoRoot, 'src', 'livekitRuntime'));

startBundledLiveKit({ logDisabled: true });

require(path.join(repoRoot, 'src', 'index.js'));
