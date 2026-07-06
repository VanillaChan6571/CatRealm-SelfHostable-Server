const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const { dataDir, resolveRealmDbPath, ensureRealmEnvFile } = require('./registry');

function resolveLegacyDbPath() {
  const raw = (process.env.DB_PATH || '').trim();
  if (raw) return path.resolve(raw);
  return path.join(dataDir, 'catrealm.db');
}

function renameIfExists(from, to) {
  if (fs.existsSync(from)) fs.renameSync(from, to);
}

// First multi-realm boot: copy the single-mode database into the port-named
// db for realm #1 (WAL-safe via the SQLite backup API), then park the original
// as *.pre-multirealm.bak so a later single-mode boot can't silently write to
// stale data. Skipped when the target db already exists (a host renaming a db
// into place is explicitly supported).
async function migrateSingleDbIfNeeded(registry, log) {
  const primary = registry.realms.find((realm) => realm.enabled) || registry.realms[0];
  if (!primary) return;

  const legacyPath = resolveLegacyDbPath();
  const targetPath = resolveRealmDbPath(primary);

  // Seed realm #1's env file with the current secrets so existing tokens and
  // encrypted messages keep working after the switch.
  ensureRealmEnvFile(primary.port, {
    JWT_SECRET: (process.env.JWT_SECRET || '').trim() || undefined,
    SECURE_MODE_KEY: (process.env.SECURE_MODE_KEY || '').trim() || undefined,
  });

  if (!fs.existsSync(legacyPath) || legacyPath === targetPath) return;
  if (fs.existsSync(targetPath)) {
    log(`[MultiRealm] ${path.basename(targetPath)} already exists — skipping migration of ${path.basename(legacyPath)}.`);
    return;
  }

  log(`[MultiRealm] Migrating ${legacyPath} -> ${targetPath} (safe copy)...`);
  const sourceDb = new Database(legacyPath, { readonly: true });
  try {
    await sourceDb.backup(targetPath);
  } finally {
    sourceDb.close();
  }

  const backupPath = `${legacyPath}.pre-multirealm.bak`;
  renameIfExists(legacyPath, backupPath);
  renameIfExists(`${legacyPath}-wal`, `${backupPath}-wal`);
  renameIfExists(`${legacyPath}-shm`, `${backupPath}-shm`);

  log(`[MultiRealm] Migration complete. Original kept at ${backupPath}`);
  log('[MultiRealm] To roll back: set MULTI_REALM=false and rename the .pre-multirealm.bak file back.');
}

module.exports = { migrateSingleDbIfNeeded };
