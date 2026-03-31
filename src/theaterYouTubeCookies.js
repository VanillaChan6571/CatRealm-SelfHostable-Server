const fs = require('fs');
const path = require('path');
const db = require('./db');
const { getSetting, setSetting } = require('./settings');

const THEATER_YOUTUBE_COOKIE_FILE = process.env.THEATER_YT_COOKIE_FILE
  || path.join(__dirname, '../data/private/theater-youtube-cookies.txt');
const MAX_COOKIE_TEXT_BYTES = 512 * 1024;
const ALLOWED_COOKIE_DOMAINS = [
  'youtube.com',
  'google.com',
  'googlevideo.com',
  'googleapis.com',
  'gstatic.com',
  'ytimg.com',
];

function ensureCookieDir() {
  fs.mkdirSync(path.dirname(THEATER_YOUTUBE_COOKIE_FILE), { recursive: true });
}

function isAllowedCookieDomain(domain) {
  const normalized = String(domain || '').trim().toLowerCase().replace(/^\./, '');
  return ALLOWED_COOKIE_DOMAINS.some((allowed) => (
    normalized === allowed || normalized.endsWith(`.${allowed}`)
  ));
}

function normalizeCookieField(value) {
  return String(value ?? '').replace(/[\r\n\t]/g, ' ').trim();
}

function parseCookieLine(line) {
  const parts = line.split('\t');
  if (parts.length < 7) return null;
  const [domain, includeSubdomains, cookiePath, secure, expiresAt, name, ...valueParts] = parts;
  const value = valueParts.join('\t');
  if (!domain || !name) return null;
  if (!isAllowedCookieDomain(domain)) return null;
  return [
    normalizeCookieField(domain),
    String(includeSubdomains || 'FALSE').toUpperCase() === 'TRUE' ? 'TRUE' : 'FALSE',
    normalizeCookieField(cookiePath || '/'),
    String(secure || 'FALSE').toUpperCase() === 'TRUE' ? 'TRUE' : 'FALSE',
    /^\d+$/.test(String(expiresAt || '').trim()) ? String(expiresAt).trim() : '0',
    normalizeCookieField(name),
    normalizeCookieField(value),
  ].join('\t');
}

function normalizeCookieText(cookieText) {
  if (typeof cookieText !== 'string' || !cookieText.trim()) {
    throw new Error('Cookie text is required');
  }
  if (Buffer.byteLength(cookieText, 'utf8') > MAX_COOKIE_TEXT_BYTES) {
    throw new Error('Cookie file is too large');
  }

  const lines = String(cookieText)
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  const uniqueLines = new Set();
  for (const line of lines) {
    if (line.startsWith('#')) continue;
    const parsed = parseCookieLine(line);
    if (parsed) uniqueLines.add(parsed);
  }

  if (uniqueLines.size === 0) {
    throw new Error('No supported YouTube/Google cookies were found in the uploaded cookie file');
  }

  return {
    text: `# Netscape HTTP Cookie File\n${Array.from(uniqueLines).join('\n')}\n`,
    cookieCount: uniqueLines.size,
  };
}

function setCookieMetadata({ source, syncedByUser, cookieCount }) {
  const now = Date.now();
  setSetting('theater_yt_cookie_source', source || 'manual');
  setSetting('theater_yt_cookie_updated_at', String(now));
  setSetting('theater_yt_cookie_cookie_count', String(cookieCount || 0));
  setSetting('theater_yt_cookie_synced_by_id', syncedByUser?.id || '');
  setSetting('theater_yt_cookie_synced_by_name', syncedByUser?.username || '');
  setSetting('theater_yt_cookie_has_file', 'true');
}

function clearCookieMetadata() {
  const keys = [
    'theater_yt_cookie_source',
    'theater_yt_cookie_updated_at',
    'theater_yt_cookie_cookie_count',
    'theater_yt_cookie_synced_by_id',
    'theater_yt_cookie_synced_by_name',
    'theater_yt_cookie_has_file',
  ];
  for (const key of keys) {
    db.prepare('DELETE FROM server_settings WHERE key = ?').run(key);
  }
}

function hasStoredYouTubeCookies() {
  try {
    return fs.existsSync(THEATER_YOUTUBE_COOKIE_FILE) && fs.statSync(THEATER_YOUTUBE_COOKIE_FILE).size > 0;
  } catch {
    return false;
  }
}

function getTheaterYouTubeCookieStatus() {
  const hasCookies = hasStoredYouTubeCookies();
  const updatedAtRaw = Number(getSetting('theater_yt_cookie_updated_at', '0'));
  const cookieCountRaw = Number(getSetting('theater_yt_cookie_cookie_count', '0'));
  return {
    hasCookies,
    source: getSetting('theater_yt_cookie_source', hasCookies ? 'manual' : null),
    updatedAt: Number.isFinite(updatedAtRaw) && updatedAtRaw > 0 ? updatedAtRaw : null,
    syncedByName: getSetting('theater_yt_cookie_synced_by_name', '') || null,
    cookieCount: Number.isFinite(cookieCountRaw) && cookieCountRaw > 0 ? cookieCountRaw : 0,
    cookieFilePath: THEATER_YOUTUBE_COOKIE_FILE,
    managedByServer: !process.env.THEATER_YT_COOKIE_FILE,
  };
}

function saveTheaterYouTubeCookies(cookieText, options = {}) {
  const { text, cookieCount } = normalizeCookieText(cookieText);
  ensureCookieDir();
  fs.writeFileSync(THEATER_YOUTUBE_COOKIE_FILE, text, { encoding: 'utf8', mode: 0o600 });
  try {
    fs.chmodSync(THEATER_YOUTUBE_COOKIE_FILE, 0o600);
  } catch {
    // Ignore chmod failures on unsupported platforms/filesystems.
  }
  setCookieMetadata({
    source: options.source || 'manual',
    syncedByUser: options.syncedByUser || null,
    cookieCount,
  });
  return getTheaterYouTubeCookieStatus();
}

function clearTheaterYouTubeCookies() {
  try {
    fs.rmSync(THEATER_YOUTUBE_COOKIE_FILE, { force: true });
  } catch {
    // Ignore cleanup failures here; metadata is still cleared.
  }
  clearCookieMetadata();
  return getTheaterYouTubeCookieStatus();
}

function getYtDlpCookieArgs() {
  if (!hasStoredYouTubeCookies()) return [];
  return ['--cookies', THEATER_YOUTUBE_COOKIE_FILE];
}

module.exports = {
  THEATER_YOUTUBE_COOKIE_FILE,
  getTheaterYouTubeCookieStatus,
  saveTheaterYouTubeCookies,
  clearTheaterYouTubeCookies,
  getYtDlpCookieArgs,
  hasStoredYouTubeCookies,
};
