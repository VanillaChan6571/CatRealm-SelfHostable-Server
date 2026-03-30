const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { decryptMessageContent, encryptMessageContent } = require('./messageCrypto');

const HELP_TEXT = 'Commands: help, secure-status, media-status, ffmpeg-status, yt-dlp-status, db-status, db-latest [n], db-checkpoint, db-encrypt-legacy';

function firstNonEmptyLine(...values) {
  for (const value of values) {
    const text = String(value || '')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find(Boolean);
    if (text) return text;
  }
  return '';
}

function resolveExecutable(command) {
  const pathValue = String(process.env.PATH || '');
  for (const dir of pathValue.split(path.delimiter)) {
    if (!dir) continue;
    const fullPath = path.join(dir, command);
    try {
      fs.accessSync(fullPath, fs.constants.X_OK);
      return fullPath;
    } catch {
      continue;
    }
  }
  return null;
}

function describeBinary(command, versionArgs) {
  const resolvedPath = resolveExecutable(command);
  const result = spawnSync(command, versionArgs, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const available = result.status === 0;
  const detail = firstNonEmptyLine(result.stdout, result.stderr, result.error?.message);
  const lines = [
    `${command}: ${available ? 'available' : 'missing'} path=${resolvedPath || 'not-found'}`,
  ];

  if (available) {
    lines.push(`${command}: ${detail || 'version available'}`);
  } else {
    lines.push(`${command}: ${detail || 'not available in the runtime image PATH'}`);
  }

  return { ok: available, lines };
}

function mediaStatusLines() {
  return [
    ...describeBinary('ffmpeg', ['-version']).lines,
    ...describeBinary('yt-dlp', ['--version']).lines,
  ];
}

function getDiagnosticHelpText() {
  return HELP_TEXT;
}

function runDiagnosticCommand(db, raw) {
  const commandLine = String(raw || '').trim();
  if (!commandLine) return null;

  const [command, ...args] = commandLine.split(/\s+/);
  const cmd = command.toLowerCase();

  if (cmd === 'help' || cmd === 'catrealm-help') {
    return { ok: true, lines: [HELP_TEXT] };
  }

  if (cmd === 'secure-status' || cmd === 'catrealm-secure') {
    const enabled = process.env.CATREALM_SECURE_MODE_EFFECTIVE === '1';
    const locked = process.env.CATREALM_SECURE_MODE_LOCKED === '1';
    return {
      ok: true,
      lines: [`Secure mode: ${enabled ? 'ENABLED' : 'DISABLED'} (locked=${locked ? 1 : 0})`],
    };
  }

  if (cmd === 'media-status' || cmd === 'catrealm-media-status') {
    return { ok: true, lines: mediaStatusLines() };
  }

  if (cmd === 'ffmpeg-status' || cmd === 'catrealm-ffmpeg-status' || cmd === 'ffmpeg') {
    return { ok: true, lines: describeBinary('ffmpeg', ['-version']).lines };
  }

  if (cmd === 'yt-dlp-status' || cmd === 'catrealm-yt-dlp-status' || cmd === 'yt-dlp') {
    return { ok: true, lines: describeBinary('yt-dlp', ['--version']).lines };
  }

  if (cmd === 'db-status' || cmd === 'catrealm-db-status') {
    const dbPath = process.env.DB_PATH || path.join(__dirname, '../data/catrealm.db');
    const walPath = `${dbPath}-wal`;
    const shmPath = `${dbPath}-shm`;
    const messageCount = db.prepare('SELECT COUNT(*) as c FROM messages').get().c;
    const latest = db.prepare('SELECT created_at FROM messages ORDER BY created_at DESC LIMIT 1').get();
    const walSize = fs.existsSync(walPath) ? fs.statSync(walPath).size : 0;
    const shmSize = fs.existsSync(shmPath) ? fs.statSync(shmPath).size : 0;
    return {
      ok: true,
      lines: [
        `DB_PATH=${dbPath}`,
        `messages=${messageCount} latest_created_at=${latest?.created_at || 'none'}`,
        `wal_size=${walSize} shm_size=${shmSize}`,
      ],
    };
  }

  if (cmd === 'db-latest' || cmd === 'catrealm-db-latest') {
    const limit = Math.min(Math.max(parseInt(args[0], 10) || 5, 1), 50);
    const rows = db.prepare(`
      SELECT id, channel_id, user_id, created_at, content
      FROM messages
      ORDER BY created_at DESC
      LIMIT ?
    `).all(limit);
    if (rows.length === 0) {
      return { ok: true, lines: ['No messages found.'] };
    }
    return {
      ok: true,
      lines: rows.map((row) => {
        const encrypted = typeof row.content === 'string' && row.content.startsWith('enc:v1:');
        const previewSource = encrypted ? decryptMessageContent(row.content) : row.content;
        const preview = String(previewSource || '').slice(0, 36).replace(/\s+/g, ' ');
        return `msg=${row.id} ch=${row.channel_id} user=${row.user_id} ts=${row.created_at} encrypted=${encrypted ? 1 : 0} preview=${preview}`;
      }),
    };
  }

  if (cmd === 'db-checkpoint' || cmd === 'catrealm-db-checkpoint') {
    try {
      const result = db.prepare('PRAGMA wal_checkpoint(FULL)').get();
      if (result && typeof result === 'object') {
        const busy = result.busy ?? 'n/a';
        const logFrames = result.log ?? result['wal frames'] ?? 'n/a';
        const checkpointed = result.checkpointed ?? result['checkpointed frames'] ?? 'n/a';
        return {
          ok: true,
          lines: [`WAL checkpoint complete (busy=${busy} log=${logFrames} checkpointed=${checkpointed})`],
        };
      }
      return { ok: true, lines: ['WAL checkpoint complete.'] };
    } catch (err) {
      return { ok: false, error: `WAL checkpoint failed: ${err.message}` };
    }
  }

  if (cmd === 'db-encrypt-legacy' || cmd === 'catrealm-db-encrypt-legacy') {
    const rows = db.prepare(`
      SELECT id, content
      FROM messages
      WHERE content NOT LIKE 'enc:v1:%'
    `).all();
    if (rows.length === 0) {
      return { ok: true, lines: ['No legacy plaintext messages found.'] };
    }

    const updateMessage = db.prepare('UPDATE messages SET content = ? WHERE id = ?');
    const migrateMessages = db.transaction((items) => {
      for (const row of items) {
        updateMessage.run(encryptMessageContent(row.content || ''), row.id);
      }
    });
    migrateMessages(rows);
    return { ok: true, lines: [`Encrypted ${rows.length} legacy plaintext messages.`] };
  }

  return { ok: false, error: `Unknown command: ${cmd}` };
}

module.exports = {
  getDiagnosticHelpText,
  runDiagnosticCommand,
};
