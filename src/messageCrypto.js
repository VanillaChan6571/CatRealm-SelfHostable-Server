const crypto = require('crypto');

const SECURE_PREFIX = 'enc:v1:';
const secureModeEnabled = process.env.CATREALM_SECURE_MODE_EFFECTIVE === '1';
const secureModeKeyRaw = process.env.SECURE_MODE_KEY || process.env['secure-mode-key'] || '';
const secureModeKey = secureModeEnabled
  ? crypto.createHash('sha256').update(String(secureModeKeyRaw), 'utf8').digest()
  : null;

function isSecureModeEnabled() {
  return secureModeEnabled;
}

function encryptMessageContent(content) {
  const text = typeof content === 'string' ? content : '';
  if (!secureModeEnabled) return text;

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', secureModeKey, iv);
  const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `${SECURE_PREFIX}${iv.toString('base64url')}:${authTag.toString('base64url')}:${ciphertext.toString('base64url')}`;
}

function decryptMessageContent(content) {
  if (typeof content !== 'string' || !content.startsWith(SECURE_PREFIX)) return content;
  if (!secureModeEnabled) return content;

  const encoded = content.slice(SECURE_PREFIX.length);
  const parts = encoded.split(':');
  if (parts.length !== 3) return content;

  try {
    const iv = Buffer.from(parts[0], 'base64url');
    const authTag = Buffer.from(parts[1], 'base64url');
    const ciphertext = Buffer.from(parts[2], 'base64url');
    const decipher = crypto.createDecipheriv('aes-256-gcm', secureModeKey, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
  } catch {
    return content;
  }
}

function decryptMessageRow(row) {
  if (!row || typeof row !== 'object') return row;
  const next = { ...row };
  if (Object.prototype.hasOwnProperty.call(next, 'content')) {
    next.content = decryptMessageContent(next.content);
  }
  if (Object.prototype.hasOwnProperty.call(next, 'reply_to_content')) {
    next.reply_to_content = decryptMessageContent(next.reply_to_content);
  }
  return next;
}

function decryptMessageRows(rows) {
  if (!Array.isArray(rows)) return [];
  return rows.map(decryptMessageRow);
}

module.exports = {
  isSecureModeEnabled,
  encryptMessageContent,
  decryptMessageContent,
  decryptMessageRow,
  decryptMessageRows,
};
