const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dotenv = require('dotenv');

const repoRoot = path.join(__dirname, '../..');
const dataDir = path.join(repoRoot, 'data');
const realmsDir = path.join(dataDir, 'realms');
const registryPath = path.join(dataDir, 'realms.json');

const REGISTRY_VERSION = 1;

function isValidPort(port) {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

// dbFile must stay inside data/ — reject absolute paths and traversal.
function isSafeDbFile(dbFile) {
  if (typeof dbFile !== 'string' || !dbFile.trim()) return false;
  if (path.isAbsolute(dbFile)) return false;
  const resolved = path.resolve(dataDir, dbFile);
  return resolved.startsWith(dataDir + path.sep);
}

function normalizeRealm(raw, index) {
  const port = Number(raw?.port);
  if (!isValidPort(port)) {
    throw new Error(`realms.json: realm #${index + 1} has invalid "port" (${raw?.port}). Ports must be integers 1-65535.`);
  }
  const dbFile = raw.dbFile === undefined || raw.dbFile === null || raw.dbFile === ''
    ? `${port}.db`
    : String(raw.dbFile);
  if (!isSafeDbFile(dbFile)) {
    throw new Error(`realms.json: realm ${port} has invalid "dbFile" (${raw.dbFile}). Use a relative path inside the data/ directory, e.g. "${port}.db".`);
  }
  return {
    port,
    name: typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : `Realm ${port}`,
    dbFile,
    enabled: raw.enabled !== false,
    createdAt: typeof raw.createdAt === 'string' ? raw.createdAt : new Date().toISOString(),
  };
}

function validateRegistry(registry) {
  if (!registry || !Array.isArray(registry.realms)) {
    throw new Error('realms.json: expected { "version": 1, "realms": [ ... ] }');
  }
  const realms = registry.realms.map(normalizeRealm);
  if (realms.length === 0) {
    throw new Error('realms.json: at least one realm is required in multi-realm mode.');
  }
  const seenPorts = new Set();
  const seenDbs = new Set();
  for (const realm of realms) {
    if (seenPorts.has(realm.port)) {
      throw new Error(`realms.json: duplicate port ${realm.port}. Each realm needs a unique port.`);
    }
    seenPorts.add(realm.port);
    const dbKey = path.resolve(dataDir, realm.dbFile);
    if (seenDbs.has(dbKey)) {
      throw new Error(`realms.json: two realms point at the same database file "${realm.dbFile}".`);
    }
    seenDbs.add(dbKey);
  }
  return { version: REGISTRY_VERSION, realms };
}

function registryExists() {
  return fs.existsSync(registryPath);
}

function loadRegistry() {
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  } catch (err) {
    throw new Error(`Failed to read ${registryPath}: ${err.message}`);
  }
  return validateRegistry(parsed);
}

function saveRegistry(registry) {
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(registryPath, `${JSON.stringify(registry, null, 2)}\n`, 'utf8');
}

function bootstrapRegistryFromEnv() {
  const port = Number(process.env.SERVER_PORT || process.env.PORT || 3000);
  const registry = validateRegistry({
    version: REGISTRY_VERSION,
    realms: [{
      port,
      name: process.env.SERVER_NAME || 'CatRealm Server',
      dbFile: `${port}.db`,
      enabled: true,
      createdAt: new Date().toISOString(),
    }],
  });
  saveRegistry(registry);
  return registry;
}

function resolveRealmDbPath(realm) {
  return path.resolve(dataDir, realm.dbFile);
}

function realmEnvPath(port) {
  return path.join(realmsDir, `${port}.env`);
}

// Creates data/realms/<port>.env (0600) with a fresh JWT_SECRET plus any
// seed values (used to carry the old .env secrets into realm #1 on migration).
function ensureRealmEnvFile(port, seed = {}) {
  const envPath = realmEnvPath(port);
  if (fs.existsSync(envPath)) return envPath;
  fs.mkdirSync(realmsDir, { recursive: true });
  const values = {
    JWT_SECRET: crypto.randomBytes(48).toString('hex'),
    ...seed,
  };
  const lines = Object.entries(values)
    .filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== '')
    .map(([key, value]) => `${key}=${value}`);
  fs.writeFileSync(envPath, `${lines.join('\n')}\n`, { mode: 0o600 });
  return envPath;
}

function readRealmEnv(port) {
  const envPath = realmEnvPath(port);
  if (!fs.existsSync(envPath)) return {};
  try {
    return dotenv.parse(fs.readFileSync(envPath, 'utf8'));
  } catch {
    return {};
  }
}

module.exports = {
  dataDir,
  realmsDir,
  registryPath,
  registryExists,
  loadRegistry,
  saveRegistry,
  bootstrapRegistryFromEnv,
  resolveRealmDbPath,
  realmEnvPath,
  ensureRealmEnvFile,
  readRealmEnv,
};
