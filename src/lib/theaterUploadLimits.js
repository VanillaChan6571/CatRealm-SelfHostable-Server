const { getSetting } = require('../settings');

const DEFAULT_THEATER_UPLOAD_MAX_MB = 2048;
const DEFAULT_THEATER_UPLOAD_HARD_MAX_MB = 10240;
const DEFAULT_THEATER_UPLOAD_RESERVE_MB = 256;

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return parsed;
}

function getTheaterUploadHardMaxMb() {
  return parsePositiveInteger(process.env.THEATER_UPLOAD_HARD_MAX_MB, DEFAULT_THEATER_UPLOAD_HARD_MAX_MB);
}

function getTheaterUploadDefaultMaxMb() {
  return parsePositiveInteger(process.env.THEATER_UPLOAD_MAX_MB, DEFAULT_THEATER_UPLOAD_MAX_MB);
}

function getTheaterUploadMaxMb() {
  const configured = parsePositiveInteger(
    getSetting('theater_upload_max_mb', String(getTheaterUploadDefaultMaxMb())),
    getTheaterUploadDefaultMaxMb(),
  );
  return Math.min(configured, getTheaterUploadHardMaxMb());
}

function getTheaterUploadMaxBytes() {
  return getTheaterUploadMaxMb() * 1024 * 1024;
}

function getTheaterUploadHardMaxBytes() {
  return getTheaterUploadHardMaxMb() * 1024 * 1024;
}

function getTheaterUploadReserveBytes() {
  return parsePositiveInteger(process.env.THEATER_UPLOAD_RESERVE_MB, DEFAULT_THEATER_UPLOAD_RESERVE_MB) * 1024 * 1024;
}

function validateTheaterUploadMaxMb(value) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    return { ok: false, error: 'Theater upload limit must be a whole number of MB' };
  }
  const hardMax = getTheaterUploadHardMaxMb();
  if (parsed > hardMax) {
    return { ok: false, error: `Theater upload limit cannot exceed ${hardMax} MB` };
  }
  return { ok: true, value: parsed };
}

module.exports = {
  getTheaterUploadHardMaxMb,
  getTheaterUploadHardMaxBytes,
  getTheaterUploadMaxBytes,
  getTheaterUploadMaxMb,
  getTheaterUploadReserveBytes,
  validateTheaterUploadMaxMb,
};
