const DEFAULT_AVATAR_URL = (
  process.env.DEFAULT_AVATAR_URL ||
  'https://catrealm.app/uploads/avatars/default.jpg'
).trim();

function isServerAvatarOverride(avatar) {
  return typeof avatar === 'string'
    && avatar.startsWith('/uploads/avatars/')
    && avatar !== DEFAULT_AVATAR_URL
    && !/^\/uploads\/avatars\/default(?:-v2)?\.jpg$/i.test(avatar);
}

module.exports = { DEFAULT_AVATAR_URL, isServerAvatarOverride };
