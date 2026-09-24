const fs = require('fs');
const path = require('path');

// Generated filenames, optionally inside thumbs/. Never interpret escapes,
// traversal segments, query strings, or platform path separators here.
function localUploadSuffix(url, prefix = '/ugc/images/') {
  if (typeof url !== 'string' || !url.startsWith(prefix)) return null;
  const suffix = url.slice(prefix.length);
  const segments = suffix.split('/');
  if (segments.length > 2 || (segments.length === 2 && segments[0] !== 'thumbs')) return null;
  if (segments.some((part) => !/^[a-zA-Z0-9_.-]+$/.test(part) || part === '.' || part === '..')) return null;
  return suffix;
}

function resolveUploadForDeletion(directory, url) {
  const suffix = localUploadSuffix(url);
  if (!suffix) return null;
  try {
    const root = fs.realpathSync(directory);
    const file = path.resolve(root, suffix);
    const realFile = fs.realpathSync(file);
    const relative = path.relative(root, realFile);
    if (!relative || relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative)) return null;
    if (!fs.lstatSync(file).isFile()) return null;
    return file;
  } catch {
    return null;
  }
}

module.exports = { localUploadSuffix, resolveUploadForDeletion };
