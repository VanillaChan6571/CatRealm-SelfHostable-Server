const { InputError } = require('./channelItems');

const PATTERNS = ['radial', 'linear', 'diagonal', 'stripes', 'mesh'];
const SCENES = ['rings', 'orbit', 'particles', 'pixels'];
const MAX_COLORS = 6;

// Images must be this realm's own uploads. An outside URL would let whoever set it
// log the address of everyone who opens the channel.
const UPLOADED_IMAGE = /^\/(uploads|ugc)\/\S{1,500}$/;

// Shared by Board and Tracker channel appearance settings.
function backgroundInput(value) {
  if (value === null) return null;
  if (!value || typeof value !== 'object') throw new InputError('background must be an object or null');
  if (value.kind === 'image') {
    if (typeof value.image !== 'string' || !UPLOADED_IMAGE.test(value.image.trim())) {
      throw new InputError('Background image must be an uploaded image');
    }
    if (value.fit !== undefined && typeof value.fit !== 'boolean') throw new InputError('Background fit must be true or false');
    if (value.stretch !== undefined && typeof value.stretch !== 'boolean') throw new InputError('Background stretch must be true or false');
    if (value.fit && value.stretch) throw new InputError('Background cannot fit and stretch at the same time');
    for (const key of ['positionX', 'positionY']) {
      if (value[key] !== undefined && (!Number.isInteger(value[key]) || value[key] < 0 || value[key] > 100)) {
        throw new InputError(`Background ${key} must be between 0 and 100`);
      }
    }
    return {
      kind: 'image', image: value.image.trim(),
      ...(value.fit !== undefined ? { fit: value.fit } : {}),
      ...(value.stretch !== undefined ? { stretch: value.stretch } : {}),
      ...(value.positionX !== undefined ? { positionX: value.positionX } : {}),
      ...(value.positionY !== undefined ? { positionY: value.positionY } : {}),
    };
  }
  if (value.kind === 'pattern') {
    const colors = Array.isArray(value.colors) ? value.colors.map((color) => String(color).trim().toLowerCase()) : [];
    if (colors.length < 1 || colors.length > MAX_COLORS || colors.some((color) => !/^#[0-9a-f]{6}$/.test(color))) {
      throw new InputError(`background colors must be 1-${MAX_COLORS} hex colors like #ff8800`);
    }
    if (!PATTERNS.includes(value.pattern)) throw new InputError(`background pattern must be one of ${PATTERNS.join(', ')}`);
    if (value.scene != null && !SCENES.includes(value.scene)) throw new InputError(`background scene must be one of ${SCENES.join(', ')}`);
    return { kind: 'pattern', colors, pattern: value.pattern, animated: !!value.animated, scene: value.scene ?? null };
  }
  throw new InputError("background kind must be 'pattern' or 'image'");
}

module.exports = { backgroundInput, UPLOADED_IMAGE };
