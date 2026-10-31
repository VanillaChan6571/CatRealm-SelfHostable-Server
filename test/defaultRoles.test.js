const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { PERMISSIONS } = require('../src/permissions');

// Seed a brand-new realm database in a child process so the module-level
// migrations in src/db.js run against an isolated in-memory DB.
function seededMemberPermissions() {
  const script = `
    const db = require(${JSON.stringify(path.resolve(__dirname, '../src/db.js'))});
    process.stdout.write(String(db.prepare('SELECT permissions FROM roles WHERE is_default = 1').get().permissions));
  `;
  return Number(execFileSync(process.execPath, ['-e', script], {
    env: { ...process.env, DB_PATH: ':memory:', NODE_ENV: 'test' },
    encoding: 'utf8',
  }).trim().split('\n').pop());
}

test('new realms let the default Member role use voice and theater', () => {
  const raw = seededMemberPermissions();
  assert.ok(Number.isSafeInteger(raw) && raw > 0);
  // BigInt: plain & truncates to 32 bits and would hide high permission bits.
  const has = (name) => (BigInt(raw) & BigInt(PERMISSIONS[name])) !== 0n;
  for (const name of ['VIEW_CHANNELS', 'SEND_MESSAGES', 'ATTACH_FILES', 'ADD_REACTIONS',
    'CONNECT_TO_VOICE', 'USE_VOICE_ACTIVITY', 'USE_PUSH_TO_TALK', 'CAMERA', 'SCREENSHARE']) {
    assert.ok(has(name), `Member should have ${name}`);
  }
  for (const name of ['ADMINISTRATOR', 'MANAGE_MESSAGES', 'KICK_MEMBER', 'BAN_MEMBER', 'MANAGE_ROLES',
    'MANAGE_CHANNELS', 'MENTION_EVERYONE', 'MOVE_VOICE_MEMBERS', 'SERVER_MUTE_MEMBERS']) {
    assert.equal(has(name), false, `Member should not have ${name}`);
  }
});
