'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Since the CVE-2024-27980 fix (Node 18.20+, 20.12+, 22), Windows refuses to
// spawn .cmd/.bat files without a shell (EINVAL), and plain `npm` is ENOENT
// because npm ships as npm.cmd. Prefer running npm-cli.js through the current
// node binary: no shell, and kill() reaches npm itself rather than cmd.exe.
function findNpmCli() {
  const candidates = [
    process.env.npm_execpath,
    path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ];
  return candidates.find((file) => file && /npm-cli\.js$/i.test(file) && fs.existsSync(file)) || null;
}

// Returns { command, args, shell } for spawn/spawnSync. `override` is a custom
// npm executable (used by tests); Windows .cmd/.bat overrides get a shell.
function npmSpawnSpec(args, override = null, platform = process.platform) {
  if (override) {
    return { command: override, args, shell: platform === 'win32' && /\.(cmd|bat)$/i.test(override) };
  }
  if (platform !== 'win32') return { command: 'npm', args, shell: false };
  const cli = findNpmCli();
  if (cli) return { command: process.execPath, args: [cli, ...args], shell: false };
  return { command: 'npm.cmd', args, shell: true };
}

module.exports = { npmSpawnSpec };
