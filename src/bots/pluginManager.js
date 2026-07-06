const path = require('path');
const fs = require('fs');
const { fork, spawnSync } = require('child_process');
const { randomUUID } = require('crypto');
const db = require('../db');
const pteroLog = require('../logger');
const { createBotAccount, rotateBotToken, getBotByUserId } = require('./core');
const { normalizeRequestedScopes } = require('./scopes');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '../../data');
// Primary plugin location is ./realm-plugins/<name>/ at the install root so
// it's easy to find; data/bots/<name>/ still works as a legacy fallback.
const PLUGINS_DIR = process.env.BOTS_DIR || path.join(__dirname, '../../realm-plugins');
const LEGACY_PLUGINS_DIR = path.join(DATA_DIR, 'bots');

const BACKOFF_START_MS = 1000;
const BACKOFF_CAP_MS = 60 * 1000;
const HEALTHY_UPTIME_MS = 60 * 1000;
const MAX_CONSECUTIVE_CRASHES = 10;

// pluginName -> { manifest, botRow, child, status, backoffMs, crashes, startedAt, restartTimer }
const plugins = new Map();
let shuttingDown = false;

function isTruthy(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function pluginsEnabled() {
  return isTruthy(process.env.BOTS_PLUGINS_ENABLED, true);
}

function readManifest(baseDir, dir) {
  const botDir = path.join(baseDir, dir);
  const manifestPath = path.join(botDir, 'bot.json');
  if (!fs.existsSync(manifestPath)) return null;
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    pteroLog(`[Bots] Ignoring ${dir}/bot.json — invalid JSON: ${err.message}`);
    return null;
  }
  const name = String(manifest.name || dir).toLowerCase().trim();
  if (!/^[a-z0-9_-]{1,32}$/.test(name)) {
    pteroLog(`[Bots] Ignoring ${dir}/bot.json — invalid name "${name}"`);
    return null;
  }
  const username = String(manifest.username || '').trim();
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
    pteroLog(`[Bots] Ignoring ${dir}/bot.json — invalid username "${username}"`);
    return null;
  }
  const entry = String(manifest.entry || 'index.js');
  const entryPath = path.resolve(botDir, entry);
  if (!entryPath.startsWith(path.resolve(botDir))) {
    pteroLog(`[Bots] Ignoring ${dir}/bot.json — entry escapes the bot directory`);
    return null;
  }
  if (!fs.existsSync(entryPath)) {
    pteroLog(`[Bots] Ignoring ${dir}/bot.json — entry not found: ${entry}`);
    return null;
  }
  return {
    name,
    username,
    dir: botDir,
    entryPath,
    scopes: normalizeRequestedScopes(manifest.scopes),
    commands: Array.isArray(manifest.commands) ? manifest.commands : null,
  };
}

// Ensure a bots row + user exists for this plugin; commands from the manifest
// (if any) are pre-registered so they work before the bot's first API call.
function provisionPlugin(manifest) {
  let botRow = db.prepare('SELECT * FROM bots WHERE kind = ? AND plugin_name = ?').get('plugin', manifest.name);
  if (!botRow) {
    const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(manifest.username);
    if (existingUser) {
      const existingBot = getBotByUserId(db, existingUser.id);
      if (!existingBot) {
        pteroLog(`[Bots] Cannot provision plugin "${manifest.name}" — username "${manifest.username}" is taken by a non-bot user`);
        return null;
      }
      botRow = existingBot;
    } else {
      const { botId } = createBotAccount(db, {
        username: manifest.username,
        requestedScopes: manifest.scopes,
        kind: 'plugin',
        pluginName: manifest.name,
      });
      botRow = db.prepare('SELECT * FROM bots WHERE id = ?').get(botId);
      pteroLog(`[Bots] Provisioned plugin bot "${manifest.name}" as @${manifest.username}`);
    }
  } else {
    db.prepare('UPDATE bots SET requested_scopes = ?, updated_at = unixepoch() WHERE id = ?')
      .run(JSON.stringify(manifest.scopes), botRow.id);
  }

  if (manifest.commands) {
    const replace = db.transaction(() => {
      db.prepare('DELETE FROM bot_commands WHERE bot_id = ?').run(botRow.id);
      const insert = db.prepare(`
        INSERT INTO bot_commands (id, bot_id, name, description, options, updated_at)
        VALUES (?, ?, ?, ?, ?, unixepoch())
      `);
      for (const cmd of manifest.commands.slice(0, 50)) {
        const name = String(cmd?.name || '').toLowerCase().trim();
        if (!/^[a-z0-9_-]{1,32}$/.test(name)) continue;
        insert.run(randomUUID(), botRow.id, name, String(cmd?.description || '').slice(0, 200),
          JSON.stringify(Array.isArray(cmd?.options) ? cmd.options : []));
      }
    });
    replace();
  }

  return db.prepare('SELECT * FROM bots WHERE id = ?').get(botRow.id);
}

// Plugins ship a package.json but hosts (especially on Pterodactyl, where
// there is no shell) can't always run npm install themselves — do it for them
// the first time the plugin starts without a node_modules folder.
function ensureDependencies(manifest) {
  if (!fs.existsSync(path.join(manifest.dir, 'package.json'))) return true;
  if (fs.existsSync(path.join(manifest.dir, 'node_modules'))) return true;
  pteroLog(`[Bots] Installing dependencies for plugin "${manifest.name}" (npm install)...`);
  const result = spawnSync('npm', ['install', '--omit=dev', '--no-audit', '--no-fund'], {
    cwd: manifest.dir,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.status !== 0) {
    pteroLog(`[Bots] npm install failed for "${manifest.name}": ${(result.stderr || result.error?.message || '').trim().slice(0, 500)}`);
    return false;
  }
  pteroLog(`[Bots] Dependencies installed for "${manifest.name}"`);
  return true;
}

function launchChild(state) {
  if (shuttingDown) return;
  const { manifest, botRow } = state;
  // Fresh token every launch — no plaintext token is ever stored on disk.
  const token = rotateBotToken(db, botRow.id, botRow.user_id);
  const username = db.prepare('SELECT username FROM users WHERE id = ?').get(botRow.user_id)?.username || manifest.username;
  const port = process.env.PORT || process.env.SERVER_PORT || 3000;

  const child = fork(state.manifest.entryPath, [], {
    cwd: manifest.dir,
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      LANG: process.env.LANG,
      NODE_ENV: process.env.NODE_ENV || 'production',
      CATREALM_BOT_NAME: manifest.name,
      CATREALM_BOT_TOKEN: token,
      CATREALM_SERVER_URL: `http://127.0.0.1:${port}`,
      CATREALM_BOT_DB: path.join(DATA_DIR, `bot-${username}.db`),
    },
  });

  state.child = child;
  state.status = 'running';
  state.startedAt = Date.now();

  const prefixLogs = (stream) => {
    let buffer = '';
    stream.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (line.trim()) pteroLog(`[bot:${manifest.name}] ${line}`);
      }
    });
  };
  if (child.stdout) prefixLogs(child.stdout);
  if (child.stderr) prefixLogs(child.stderr);

  child.on('exit', (code, signal) => {
    state.child = null;
    if (shuttingDown || state.status === 'stopped') return;
    const uptime = Date.now() - state.startedAt;
    if (uptime >= HEALTHY_UPTIME_MS) {
      state.crashes = 0;
      state.backoffMs = BACKOFF_START_MS;
    } else {
      state.crashes += 1;
    }
    if (state.crashes >= MAX_CONSECUTIVE_CRASHES) {
      state.status = 'crashed';
      pteroLog(`[Bots] Plugin "${manifest.name}" crashed ${state.crashes} times in a row — giving up (fix it and restart the server or toggle it in the Bots tab)`);
      return;
    }
    state.status = 'restarting';
    pteroLog(`[Bots] Plugin "${manifest.name}" exited (code=${code} signal=${signal || 'none'}) — restarting in ${Math.round(state.backoffMs / 1000)}s`);
    state.restartTimer = setTimeout(() => {
      state.restartTimer = null;
      launchChild(state);
    }, state.backoffMs);
    state.restartTimer.unref?.();
    state.backoffMs = Math.min(state.backoffMs * 2, BACKOFF_CAP_MS);
  });

  pteroLog(`[Bots] Started plugin bot "${manifest.name}" (@${username}, pid ${child.pid})`);
}

function stopChild(state) {
  if (state.restartTimer) {
    clearTimeout(state.restartTimer);
    state.restartTimer = null;
  }
  state.status = 'stopped';
  if (state.child) {
    try {
      state.child.kill('SIGTERM');
    } catch {
      // Already gone.
    }
    state.child = null;
  }
}

function startPluginBots() {
  if (!pluginsEnabled()) {
    pteroLog('[Bots] Plugin bots disabled (BOTS_PLUGINS_ENABLED=false)');
    return;
  }
  // Create the primary folder so hosts can find where plugins go.
  try {
    fs.mkdirSync(PLUGINS_DIR, { recursive: true });
  } catch (err) {
    pteroLog(`[Bots] Could not create ${PLUGINS_DIR}: ${err.message}`);
  }
  const baseDirs = [PLUGINS_DIR];
  if (path.resolve(LEGACY_PLUGINS_DIR) !== path.resolve(PLUGINS_DIR)) {
    baseDirs.push(LEGACY_PLUGINS_DIR);
  }
  const candidates = [];
  for (const baseDir of baseDirs) {
    if (!fs.existsSync(baseDir)) continue;
    for (const d of fs.readdirSync(baseDir, { withFileTypes: true })) {
      if (d.isDirectory()) candidates.push({ baseDir, dir: d.name });
    }
  }

  for (const { baseDir, dir } of candidates) {
    const manifest = readManifest(baseDir, dir);
    if (!manifest) continue;
    if (plugins.has(manifest.name)) {
      pteroLog(`[Bots] Duplicate plugin name "${manifest.name}" — skipping ${path.join(baseDir, dir)}`);
      continue;
    }
    if (baseDir === LEGACY_PLUGINS_DIR) {
      pteroLog(`[Bots] Plugin "${manifest.name}" loaded from legacy data/bots/ — consider moving it to realm-plugins/`);
    }
    const botRow = provisionPlugin(manifest);
    if (!botRow) continue;
    const state = {
      manifest,
      botRow,
      child: null,
      status: 'stopped',
      backoffMs: BACKOFF_START_MS,
      crashes: 0,
      startedAt: 0,
      restartTimer: null,
    };
    plugins.set(manifest.name, state);
    if (Number(botRow.enabled) === 1) {
      if (ensureDependencies(manifest)) {
        launchChild(state);
      } else {
        state.status = 'crashed';
      }
    } else {
      pteroLog(`[Bots] Plugin "${manifest.name}" is disabled — not starting`);
    }
  }
}

function stopPluginBots() {
  shuttingDown = true;
  for (const state of plugins.values()) stopChild(state);
}

function setPluginEnabled(name, enabled) {
  const state = plugins.get(name);
  if (!state) return false;
  if (enabled) {
    if (state.child) return true;
    state.crashes = 0;
    state.backoffMs = BACKOFF_START_MS;
    state.botRow = db.prepare('SELECT * FROM bots WHERE id = ?').get(state.botRow.id) || state.botRow;
    if (!ensureDependencies(state.manifest)) {
      state.status = 'crashed';
      return true;
    }
    launchChild(state);
  } else {
    stopChild(state);
  }
  return true;
}

function getPluginStatuses() {
  const statuses = new Map();
  for (const [name, state] of plugins.entries()) statuses.set(name, state.status);
  return statuses;
}

module.exports = {
  startPluginBots,
  stopPluginBots,
  setPluginEnabled,
  getPluginStatuses,
  PLUGINS_DIR,
};
