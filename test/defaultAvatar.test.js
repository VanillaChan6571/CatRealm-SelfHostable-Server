const test = require('node:test');
const assert = require('node:assert/strict');

test('a configured default avatar is never a server-specific override', () => {
  const modulePath = require.resolve('../src/lib/defaultAvatar');
  const original = process.env.DEFAULT_AVATAR_URL;
  try {
    process.env.DEFAULT_AVATAR_URL = '/uploads/avatars/default-v2.jpg';
    delete require.cache[modulePath];
    const { DEFAULT_AVATAR_URL, isServerAvatarOverride } = require(modulePath);
    assert.equal(DEFAULT_AVATAR_URL, '/uploads/avatars/default-v2.jpg');
    assert.equal(isServerAvatarOverride(DEFAULT_AVATAR_URL), false);
    assert.equal(isServerAvatarOverride('/uploads/avatars/default.jpg'), false);
    assert.equal(isServerAvatarOverride('/uploads/avatars/user-upload.png'), true);
    assert.equal(isServerAvatarOverride('https://auth.example/avatar.png'), false);
  } finally {
    if (original === undefined) delete process.env.DEFAULT_AVATAR_URL;
    else process.env.DEFAULT_AVATAR_URL = original;
    delete require.cache[modulePath];
  }
});
