const router = require('express').Router();
const db = require('../db');
const { getSetting } = require('../settings');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Read version from package.json
let packageVersion = '1.0.0';
let gitHash = 'unknown';

try {
  const packagePath = path.join(__dirname, '../../package.json');
  const packageData = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  packageVersion = packageData.version || '1.0.0';
} catch (err) {
  console.error('Failed to read package.json version:', err.message);
}

// Get git commit hash (silent fallback when deployment is not a git checkout)
const repoRoot = path.join(__dirname, '../..');
if (fs.existsSync(path.join(repoRoot, '.git'))) {
  try {
    gitHash = execSync('git rev-parse --short HEAD', {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    gitHash = 'unknown';
  }
}

// GET /api/server — public info shown to client before login
router.get('/', (req, res) => {
  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const mode = process.env.SERVER_MODE || 'decentral_only';
  const name = getSetting('server_name', process.env.SERVER_NAME || 'CatRealm Server');
  const description = getSetting(
    'server_description',
    process.env.SERVER_DESCRIPTION || 'A self-hosted CatRealm server'
  );
  const registrationOpen = getSetting(
    'registration_open',
    process.env.REGISTRATION_OPEN !== 'false' ? 'true' : 'false'
  );
  const mentionAlias = getSetting('mention_alias', '@everyone');
  const serverIcon = getSetting('server_icon', null);
  const serverBanner = getSetting('server_banner', null);

  res.json({
    name,
    description,
    mode,             // 'central_only' | 'mixed' | 'decentral_only'
    registrationOpen: registrationOpen === 'true',
    userCount,
    mentionAlias,
    serverIcon,
    serverBanner,
    version: packageVersion,
    gitHash: gitHash,
    buildInfo: `v${packageVersion} (${gitHash})`
  });
});

module.exports = router;
