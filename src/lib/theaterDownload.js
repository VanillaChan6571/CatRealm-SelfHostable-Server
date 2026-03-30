const { spawnSync, spawn } = require('child_process');
const fs = require('fs');
const https = require('https');
const http = require('http');
const path = require('path');
const { randomUUID } = require('crypto');
const pteroLog = require('../logger');

const THEATER_BASE_DIR = process.env.THEATER_CACHE_DIR || path.join(__dirname, '../../data/ugc/temp-theater');

let ytDlpAvailable = null;
function isYtDlpAvailable() {
  if (ytDlpAvailable !== null) return ytDlpAvailable;
  const result = spawnSync('yt-dlp', ['--version'], { encoding: 'utf8' });
  ytDlpAvailable = result.status === 0;
  return ytDlpAvailable;
}

const DIRECT_VIDEO_EXTENSIONS = /\.(mp4|webm|mkv|mov|avi|m4v|ogg|ogv)(\?.*)?$/i;
function isDirectVideoUrl(url) {
  try {
    const u = new URL(url);
    return DIRECT_VIDEO_EXTENSIONS.test(u.pathname);
  } catch {
    return false;
  }
}

function isDomainAllowed(url, allowlist) {
  if (!allowlist || allowlist.length === 0) return true;
  try {
    const hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
    return allowlist.some((d) => {
      const domain = d.toLowerCase().replace(/^www\./, '');
      return hostname === domain || hostname.endsWith(`.${domain}`);
    });
  } catch {
    return false;
  }
}

function channelCacheDir(channelId) {
  return path.join(THEATER_BASE_DIR, channelId);
}

function ensureCacheDir(channelId) {
  const dir = channelCacheDir(channelId);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

async function deleteChannelCache(channelId) {
  const dir = channelCacheDir(channelId);
  try {
    await fs.promises.rm(dir, { recursive: true, force: true });
  } catch (err) {
    if (err.code !== 'ENOENT') {
      pteroLog(`[Theater] Failed to delete cache for ${channelId}: ${err.message}`);
    }
  }
}

async function getVideoMetadata(url) {
  if (isYtDlpAvailable()) {
    return new Promise((resolve) => {
      const proc = spawn('yt-dlp', [
        '--dump-single-json',
        '--no-playlist',
        '--quiet',
        url,
      ]);
      let output = '';
      proc.stdout.on('data', (chunk) => { output += chunk; });
      proc.on('close', (code) => {
        if (code !== 0) {
          resolve({ title: extractFilenameFromUrl(url), durationSeconds: null, thumbnailUrl: null });
          return;
        }
        try {
          const info = JSON.parse(output);
          resolve({
            title: info.title || extractFilenameFromUrl(url),
            durationSeconds: info.duration || null,
            thumbnailUrl: info.thumbnail || null,
          });
        } catch {
          resolve({ title: extractFilenameFromUrl(url), durationSeconds: null, thumbnailUrl: null });
        }
      });
      proc.on('error', () => {
        resolve({ title: extractFilenameFromUrl(url), durationSeconds: null, thumbnailUrl: null });
      });
    });
  }
  // Fallback: just use the URL filename
  return { title: extractFilenameFromUrl(url), durationSeconds: null, thumbnailUrl: null };
}

function extractFilenameFromUrl(url) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split('/').filter(Boolean);
    const last = parts[parts.length - 1] || 'video';
    return decodeURIComponent(last).replace(/\.[^.]+$/, '').replace(/[-_]+/g, ' ').trim() || 'Video';
  } catch {
    return 'Video';
  }
}

async function downloadVideo(url, channelId, onProgress) {
  const dir = ensureCacheDir(channelId);
  const fileId = randomUUID();

  if (isYtDlpAvailable() && !isDirectVideoUrl(url)) {
    return downloadWithYtDlp(url, dir, fileId, onProgress);
  }
  return downloadDirect(url, dir, fileId, onProgress);
}

function downloadWithYtDlp(url, dir, fileId, onProgress) {
  return new Promise((resolve, reject) => {
    const outputTemplate = path.join(dir, `${fileId}.%(ext)s`);
    const args = [
      '--no-playlist',
      '--format', 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best',
      '--merge-output-format', 'mp4',
      '--output', outputTemplate,
      '--newline',
      '--progress',
      url,
    ];
    const proc = spawn('yt-dlp', args);
    let filename = null;
    let durationSeconds = null;

    proc.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      // Parse progress lines: [download]  45.3% of ~123.45MiB
      const progressMatch = text.match(/(\d+(?:\.\d+)?)%/);
      if (progressMatch && onProgress) {
        onProgress(Math.min(99, parseFloat(progressMatch[1])));
      }
      // Capture destination filename
      const destMatch = text.match(/Destination:\s+(.+)/);
      if (destMatch) filename = destMatch[1].trim();
      const mergeMatch = text.match(/Merging formats into "(.+)"/);
      if (mergeMatch) filename = mergeMatch[1].trim();
    });

    proc.stderr.on('data', (chunk) => {
      const text = chunk.toString();
      // yt-dlp duration in JSON output sometimes emitted to stderr
      const durMatch = text.match(/"duration":\s*(\d+)/);
      if (durMatch) durationSeconds = parseInt(durMatch[1], 10);
    });

    proc.on('close', (code) => {
      if (code !== 0) {
        return reject(new Error(`yt-dlp exited with code ${code}`));
      }
      // If filename wasn't captured, glob for our file
      if (!filename) {
        try {
          const files = fs.readdirSync(path.dirname(outputTemplate));
          const match = files.find((f) => f.startsWith(fileId));
          if (match) filename = path.join(path.dirname(outputTemplate), match);
        } catch { /* ignore */ }
      }
      if (!filename) return reject(new Error('Could not determine output filename'));
      if (onProgress) onProgress(100);
      resolve({ filename, durationSeconds });
    });

    proc.on('error', reject);
  });
}

function downloadDirect(url, dir, fileId, onProgress) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const extMatch = urlObj.pathname.match(/\.([a-z0-9]+)(\?|$)/i);
    const ext = extMatch ? extMatch[1].toLowerCase() : 'mp4';
    const filename = path.join(dir, `${fileId}.${ext}`);
    const file = fs.createWriteStream(filename);

    const protocol = urlObj.protocol === 'https:' ? https : http;
    const request = protocol.get(url, { timeout: 30000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        file.close();
        fs.unlink(filename, () => {});
        return downloadDirect(res.headers.location, dir, fileId, onProgress)
          .then(resolve)
          .catch(reject);
      }
      if (res.statusCode !== 200) {
        file.close();
        fs.unlink(filename, () => {});
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      const totalBytes = parseInt(res.headers['content-length'] || '0', 10);
      let receivedBytes = 0;
      res.on('data', (chunk) => {
        receivedBytes += chunk.length;
        if (totalBytes > 0 && onProgress) {
          onProgress(Math.min(99, Math.floor((receivedBytes / totalBytes) * 100)));
        }
      });
      res.pipe(file);
      file.on('finish', () => {
        file.close();
        if (onProgress) onProgress(100);
        resolve({ filename, durationSeconds: null });
      });
    });

    request.on('error', (err) => {
      file.close();
      fs.unlink(filename, () => {});
      reject(err);
    });

    request.on('timeout', () => {
      request.destroy();
      file.close();
      fs.unlink(filename, () => {});
      reject(new Error('Request timed out'));
    });
  });
}

module.exports = {
  isYtDlpAvailable,
  isDomainAllowed,
  getVideoMetadata,
  downloadVideo,
  deleteChannelCache,
  channelCacheDir,
  ensureCacheDir,
  THEATER_BASE_DIR,
};
