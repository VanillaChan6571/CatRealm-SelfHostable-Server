const fs = require('fs');
const path = require('path');

let sharp = null;
try {
  sharp = require('sharp');
} catch {
  sharp = null;
}

// Avatars are drawn at 18-128 px, but every client decodes the file at its full
// pixel size: a 1340x1356 upload costs ~7 MB of memory per viewer for a 32 px
// circle. 512 px keeps the profile viewer sharp on high-DPI screens.
const MAX_AVATAR_DIMENSION = 512;
// Animated formats are left alone so they keep animating.
const STATIC_AVATAR_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.webp']);

/**
 * Downscales a stored avatar in place when it is larger than MAX_AVATAR_DIMENSION,
 * keeping its format and filename. Resolves true when the file was rewritten;
 * never throws, so an upload still succeeds with the original on any failure.
 */
async function shrinkAvatarFile(filePath) {
  if (!sharp || !STATIC_AVATAR_EXTENSIONS.has(path.extname(filePath).toLowerCase())) return false;
  const tempPath = `${filePath}.resize-tmp`;
  try {
    // Read into memory first: sharp keeps a path-opened file locked on Windows.
    const input = await fs.promises.readFile(filePath);
    const meta = await sharp(input).metadata();
    if (!meta.width || !meta.height || (meta.pages ?? 1) > 1) return false;
    if (Math.max(meta.width, meta.height) <= MAX_AVATAR_DIMENSION) return false;
    const output = await sharp(input)
      .rotate()
      .resize({ width: MAX_AVATAR_DIMENSION, height: MAX_AVATAR_DIMENSION, fit: 'inside', withoutEnlargement: true })
      .toBuffer();
    await fs.promises.writeFile(tempPath, output);
    await fs.promises.rename(tempPath, filePath);
    return true;
  } catch {
    fs.promises.unlink(tempPath).catch(() => {});
    return false;
  }
}

module.exports = { MAX_AVATAR_DIMENSION, shrinkAvatarFile };
