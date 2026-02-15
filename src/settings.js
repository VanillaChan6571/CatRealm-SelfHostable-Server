const db = require('./db');

function getSetting(key, fallback) {
  const row = db.prepare('SELECT value FROM server_settings WHERE key = ?').get(key);
  if (!row) return fallback;
  return row.value;
}

function setSetting(key, value) {
  db.prepare(`
    INSERT INTO server_settings (key, value)
    VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `).run(key, value);
}

module.exports = { getSetting, setSetting };
