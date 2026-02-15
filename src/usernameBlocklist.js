const fs = require('fs');
const path = require('path');
const pteroLog = require('./logger');

const DEFAULT_FILE = path.join(__dirname, '../blocked-usernames.txt');

function normalizeUsername(value) {
  return String(value || '').trim().toLowerCase();
}

function parseList(raw) {
  if (!raw) return [];
  return raw
    .split(',')
    .map((item) => normalizeUsername(item))
    .filter(Boolean);
}

function parseFile(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return [];
  try {
    return fs.readFileSync(filePath, 'utf8')
      .split(/\r?\n/g)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'))
      .map((line) => normalizeUsername(line))
      .filter(Boolean);
  } catch (err) {
    pteroLog(`[CatRealm] Could not read blocked username file: ${filePath} (${err.message})`);
    return [];
  }
}

const BLOCKED_USERNAMES = new Set([
  ...parseFile(process.env.BLOCKED_USERNAMES_FILE || DEFAULT_FILE),
  ...parseList(process.env.BLOCKED_USERNAMES),
]);

function isBlockedUsername(username) {
  return BLOCKED_USERNAMES.has(normalizeUsername(username));
}

module.exports = {
  isBlockedUsername,
  blockedUsernameCount: BLOCKED_USERNAMES.size,
};
