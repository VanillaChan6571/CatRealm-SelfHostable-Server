const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const pteroLog = require('./logger');

let sharp = null;
try {
  sharp = require('sharp');
} catch (_err) {
  sharp = null;
}

function isTruthy(value, fallback = false) {
  if (value === undefined || value === null || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

function getCompressionLevel() {
  const raw = Number.parseInt(String(process.env.LEVEL_OF_COMPRESSION || '6'), 10);
  if (!Number.isFinite(raw)) return 6;
  return clamp(raw, 0, 9);
}

function getImageQuality(level) {
  return clamp(92 - (level * 4), 55, 92);
}

function getVideoCrf(level) {
  return clamp(18 + (level * 2), 18, 36);
}

function getVideoPreset(level) {
  if (level <= 2) return 'veryfast';
  if (level <= 5) return 'medium';
  if (level <= 7) return 'slow';
  return 'slower';
}

const compressionConfig = (() => {
  const enabled = isTruthy(process.env.COMPRESS_MEDIA, false);
  const level = getCompressionLevel();
  return {
    enabled,
    level,
    pngCompressionLevel: level,
    imageQuality: getImageQuality(level),
    videoCrf: getVideoCrf(level),
    videoPreset: getVideoPreset(level),
  };
})();

let sharpMissingWarned = false;
let ffmpegAvailable = null;
let ffmpegDetectPromise = null;
let ffmpegMissingWarned = false;

let activeVideoJobs = 0;
const MAX_CONCURRENT_VIDEO_JOBS = 1;
const videoJobQueue = [];

function log(message) {
  pteroLog(`[CatRealm][MediaCompress] ${message}`);
}

if (compressionConfig.enabled) {
  log(
    `enabled level=${compressionConfig.level} imageQuality=${compressionConfig.imageQuality} ` +
    `pngLevel=${compressionConfig.pngCompressionLevel} videoCrf=${compressionConfig.videoCrf} ` +
    `videoPreset=${compressionConfig.videoPreset}`
  );
} else {
  log('disabled (COMPRESS_MEDIA=0)');
}

function getChatMediaCompressionConfig() {
  return { ...compressionConfig };
}

function isChatMediaCompressionEnabled() {
  return compressionConfig.enabled;
}

function isApngByName(file) {
  const lower = String(file?.originalname || '').toLowerCase();
  return lower.endsWith('.apng');
}

function classifyChatUploadForCompression(file) {
  if (!compressionConfig.enabled) {
    return { kind: 'skip', reason: 'disabled' };
  }
  const mime = String(file?.mimetype || '').toLowerCase();
  if (!mime) return { kind: 'skip', reason: 'missing_mime' };

  if (mime === 'image/gif') return { kind: 'skip', reason: 'gif_excluded' };
  if (mime === 'image/png' && isApngByName(file)) return { kind: 'skip', reason: 'apng_excluded' };

  if (mime === 'image/png' || mime === 'image/jpeg' || mime === 'image/webp') {
    return { kind: 'image', reason: null };
  }
  if (mime === 'video/mp4') {
    return { kind: 'video', reason: null };
  }

  return { kind: 'skip', reason: 'unsupported_mime' };
}

async function fileSize(filePath) {
  const stat = await fs.promises.stat(filePath);
  return stat.size;
}

function tempOutputPath(originalPath) {
  const ext = path.extname(originalPath);
  const base = path.basename(originalPath, ext);
  const dir = path.dirname(originalPath);
  return path.join(dir, `${base}.compress-${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
}

async function safeUnlink(filePath) {
  if (!filePath) return;
  try {
    await fs.promises.unlink(filePath);
  } catch (_err) {}
}

async function replaceIfSmaller(sourcePath, tempPath, labelForLogs) {
  const before = await fileSize(sourcePath);
  const after = await fileSize(tempPath);
  if (!Number.isFinite(before) || !Number.isFinite(after)) {
    await safeUnlink(tempPath);
    return { changed: false, sizeBefore: before, sizeAfter: before, reason: 'invalid_size' };
  }
  if (after <= 0) {
    await safeUnlink(tempPath);
    return { changed: false, sizeBefore: before, sizeAfter: before, reason: 'empty_output' };
  }
  if (after >= before) {
    await safeUnlink(tempPath);
    log(`${labelForLogs}: skipped (no gain ${before} -> ${after})`);
    return { changed: false, sizeBefore: before, sizeAfter: before, reason: 'no_gain' };
  }
  await fs.promises.rename(tempPath, sourcePath);
  log(`${labelForLogs}: compressed ${before} -> ${after}`);
  return { changed: true, sizeBefore: before, sizeAfter: after };
}

async function compressChatImageInline(file) {
  const classification = classifyChatUploadForCompression(file);
  if (classification.kind !== 'image') {
    return { changed: false, sizeBefore: file?.size ?? 0, sizeAfter: file?.size ?? 0, reason: classification.reason || 'not_image' };
  }
  if (!sharp) {
    if (!sharpMissingWarned) {
      sharpMissingWarned = true;
      log('sharp not available; skipping image compression');
    }
    return { changed: false, sizeBefore: file?.size ?? 0, sizeAfter: file?.size ?? 0, reason: 'sharp_missing' };
  }

  const sourcePath = file.path;
  const mime = String(file.mimetype || '').toLowerCase();
  const outPath = tempOutputPath(sourcePath);

  try {
    let pipeline = sharp(sourcePath, { failOn: 'none' });
    if (mime === 'image/png') {
      pipeline = pipeline.png({
        compressionLevel: compressionConfig.pngCompressionLevel,
        adaptiveFiltering: true,
      });
    } else if (mime === 'image/jpeg') {
      pipeline = pipeline.jpeg({
        quality: compressionConfig.imageQuality,
        mozjpeg: true,
      });
    } else if (mime === 'image/webp') {
      pipeline = pipeline.webp({
        quality: compressionConfig.imageQuality,
      });
    } else {
      return { changed: false, sizeBefore: file?.size ?? 0, sizeAfter: file?.size ?? 0, reason: 'unsupported_mime' };
    }

    await pipeline.toFile(outPath);
    const result = await replaceIfSmaller(sourcePath, outPath, `image ${path.basename(sourcePath)}`);
    return result;
  } catch (err) {
    await safeUnlink(outPath);
    log(`image ${path.basename(sourcePath)}: error (${err.message})`);
    return { changed: false, sizeBefore: file?.size ?? 0, sizeAfter: file?.size ?? 0, reason: 'error' };
  }
}

function runProcess(command, args, options = {}) {
  const { timeoutMs = 10000, captureOutput = false } = options;
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let finished = false;
    let timeoutId = null;
    let child;
    try {
      child = spawn(command, args, {
        stdio: captureOutput ? ['ignore', 'pipe', 'pipe'] : ['ignore', 'ignore', 'pipe'],
      });
    } catch (err) {
      resolve({ ok: false, code: null, error: err, stdout, stderr });
      return;
    }

    if (captureOutput && child.stdout) {
      child.stdout.on('data', (chunk) => { stdout += String(chunk); });
    }
    if (child.stderr) {
      child.stderr.on('data', (chunk) => { stderr += String(chunk); });
    }

    const done = (result) => {
      if (finished) return;
      finished = true;
      if (timeoutId) clearTimeout(timeoutId);
      resolve(result);
    };

    timeoutId = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch (_err) {}
      done({ ok: false, code: null, timeout: true, stdout, stderr });
    }, timeoutMs);

    child.on('error', (error) => done({ ok: false, code: null, error, stdout, stderr }));
    child.on('close', (code) => done({ ok: code === 0, code, stdout, stderr }));
  });
}

async function detectFfmpegAvailable() {
  if (ffmpegAvailable !== null) return ffmpegAvailable;
  if (ffmpegDetectPromise) return ffmpegDetectPromise;

  ffmpegDetectPromise = (async () => {
    const result = await runProcess('ffmpeg', ['-version'], { timeoutMs: 5000, captureOutput: true });
    ffmpegAvailable = !!result.ok;
    if (ffmpegAvailable) {
      log('ffmpeg detected; video compression enabled');
    } else if (!ffmpegMissingWarned) {
      ffmpegMissingWarned = true;
      log('ffmpeg not found; skipping video compression (uploads still work)');
    }
    ffmpegDetectPromise = null;
    return ffmpegAvailable;
  })();

  return ffmpegDetectPromise;
}

async function compressVideoJob(job) {
  const sourcePath = job.path;
  const filename = path.basename(sourcePath);

  const exists = fs.existsSync(sourcePath);
  if (!exists) {
    log(`video ${filename}: skipped (file missing before compression)`);
    return;
  }

  const ffmpegOk = await detectFfmpegAvailable();
  if (!ffmpegOk) return;

  const tempPath = tempOutputPath(sourcePath);
  const args = [
    '-y',
    '-i', sourcePath,
    '-map', '0:v:0',
    '-map', '0:a?',
    '-c:v', 'libx264',
    '-preset', compressionConfig.videoPreset,
    '-crf', String(compressionConfig.videoCrf),
    '-pix_fmt', 'yuv420p',
    '-c:a', 'aac',
    '-b:a', '128k',
    '-movflags', '+faststart',
    tempPath,
  ];

  try {
    log(`video ${filename}: queued -> compressing`);
    const proc = await runProcess('ffmpeg', args, { timeoutMs: 20 * 60 * 1000, captureOutput: false });
    if (!proc.ok) {
      await safeUnlink(tempPath);
      log(`video ${filename}: ffmpeg failed${proc.timeout ? ' (timeout)' : ''}`);
      return;
    }
    await replaceIfSmaller(sourcePath, tempPath, `video ${filename}`);
  } catch (err) {
    await safeUnlink(tempPath);
    log(`video ${filename}: error (${err.message})`);
  }
}

async function drainVideoQueue() {
  if (activeVideoJobs >= MAX_CONCURRENT_VIDEO_JOBS) return;
  const job = videoJobQueue.shift();
  if (!job) return;
  activeVideoJobs += 1;
  try {
    await compressVideoJob(job);
  } finally {
    activeVideoJobs -= 1;
    void drainVideoQueue();
  }
}

function enqueueChatVideoCompression(file) {
  const classification = classifyChatUploadForCompression(file);
  if (classification.kind !== 'video') {
    return { queued: false, reason: classification.reason || 'not_video' };
  }
  videoJobQueue.push({
    path: file.path,
    filename: file.filename,
    mimetype: file.mimetype,
    originalname: file.originalname || null,
    createdAt: Date.now(),
  });
  void drainVideoQueue();
  return { queued: true };
}

module.exports = {
  classifyChatUploadForCompression,
  compressChatImageInline,
  enqueueChatVideoCompression,
  getChatMediaCompressionConfig,
  isChatMediaCompressionEnabled,
};
