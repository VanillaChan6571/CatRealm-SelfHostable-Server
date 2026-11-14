'use strict';

const { randomUUID, createHash } = require('crypto');
const permissions = require('./permissionModel');

// Discord positions are interpreted with BigInt at the import boundary.
// Every grant here is intentional; unmapped Discord flags grant nothing.
const DISCORD_TO_REALM = Object.freeze({
  0: ['CREATE_INVITE'], 1: ['KICK_MEMBER'], 2: ['BAN_MEMBER'],
  4: ['MANAGE_CHANNELS'], 6: ['ADD_REACTIONS'], 7: ['VIEW_AUDIT_LOG'],
  9: ['SCREENSHARE', 'CAMERA'], 10: ['VIEW_CHANNELS'],
  11: ['SEND_MESSAGES', 'SEND_MESSAGES_IN_POSTS', 'SEND_VOICE_MESSAGES'],
  12: ['SEND_AUTO_TTS'], 13: ['BYPASS_SLOWMODE', 'MANAGE_MESSAGES', 'PIN_MESSAGES'],
  14: ['EMBED_LINKS'], 15: ['ATTACH_FILES'], 16: ['READ_CHAT_HISTORY'],
  17: ['MENTION_EVERYONE'], 18: ['USE_EXTERNAL_EMOTES'],
  20: ['CONNECT_TO_VOICE', 'USE_PUSH_TO_TALK'], 22: ['SERVER_MUTE_MEMBERS'],
  23: ['SERVER_DEAFEN_MEMBERS'], 24: ['MOVE_VOICE_MEMBERS'],
  25: ['USE_VOICE_ACTIVITY'], 26: ['CHANGE_SELF_NICKNAME'],
  27: ['MANAGE_NICKNAMES'], 28: ['MANAGE_ROLES'], 29: ['MANAGE_WEBHOOKS'],
  30: ['MANAGE_CUSTOM_EMOTES', 'MANAGE_CUSTOM_STICKERS'],
  33: ['CREATE_EVENTS', 'MANAGE_EVENTS'], 34: ['MANAGE_POSTS'],
  35: ['CREATE_PUBLIC_THREADS', 'CREATE_POST_IN_FORUMS'],
  36: ['CREATE_PRIVATE_THREADS'], 37: ['USE_EXTERNAL_STICKERS'],
  38: ['SEND_MESSAGES_IN_THREADS'], 40: ['TIMEOUT_USER'],
});
const SUPPORTED_DISCORD_MASK = Object.keys(DISCORD_TO_REALM)
  .reduce((mask, position) => mask | (1n << BigInt(position)), 1n << 3n);

function parseDiscordBits(value) {
  if (value === undefined || value === null) return 0n;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) {
    throw new RangeError('Discord permissions must be a decimal string');
  }
  const bits = BigInt(value);
  if (bits >= (1n << 64n)) throw new RangeError('Discord permission mask exceeds 64 bits');
  return bits;
}

function mapDiscordPermissions(value) {
  const bits = parseDiscordBits(value);
  if ((bits & (1n << 3n)) !== 0n) return ['ADMINISTRATOR'];
  const keys = [];
  for (const [position, mapped] of Object.entries(DISCORD_TO_REALM)) {
    if ((bits & (1n << BigInt(position))) !== 0n) keys.push(...mapped);
  }
  return permissions.normalizeKeys(keys);
}

function validId(value) {
  return typeof value === 'string' && /^[0-9]{1,32}$/.test(value);
}

function prepareDiscordTemplate(template) {
  if (!template || typeof template !== 'object' || Array.isArray(template)) throw new RangeError('Invalid template');
  if (typeof template.name !== 'string' || !template.name.trim() || template.name.length > 50) {
    throw new RangeError('Invalid template name');
  }
  if (!Array.isArray(template.roles) || template.roles.length > 250 ||
      !Array.isArray(template.channels) || template.channels.length > 500) {
    throw new RangeError('Invalid template roles or channels');
  }
  const roleIds = new Set();
  const roles = template.roles.map((role) => {
    if (!validId(role?.id) || roleIds.has(role.id) || typeof role.name !== 'string' ||
        !role.name.trim() || role.name.length > 32) throw new RangeError('Invalid or duplicate role');
    roleIds.add(role.id);
    return {
      id: role.id, name: role.name, color: Number.isInteger(role.color) && role.color >= 0 && role.color <= 0xffffff ? role.color : 0,
      position: Number.isSafeInteger(role.position) ? role.position : 0,
      mentionable: role.mentionable === true, hoist: role.hoist === true,
      permissionKeys: mapDiscordPermissions(role.permissions),
    };
  });
  const everyone = roles.find((role) => role.name === '@everyone');
  if (!everyone) throw new RangeError('Template is missing @everyone role');
  if (everyone.permissionKeys.includes('ADMINISTRATOR')) {
    throw new RangeError('Template cannot grant Administrator to @everyone');
  }
  const channelIds = new Set();
  const warnings = ['Default member permissions will be replaced by the template @everyone role'];
  const channels = template.channels.map((channel) => {
    if (!validId(channel?.id) || channelIds.has(channel.id) || typeof channel.name !== 'string' ||
        !channel.name.trim() || channel.name.length > 100 || !Number.isInteger(channel.type)) {
      throw new RangeError('Invalid or duplicate channel');
    }
    channelIds.add(channel.id);
    const overwrites = Array.isArray(channel.permission_overwrites) ? channel.permission_overwrites : [];
    if (overwrites.length > 250) throw new RangeError('Too many channel overwrites');
    const overwriteTargets = new Set();
    const parsedOverwrites = overwrites.map((overwrite) => {
      if (!validId(overwrite?.id) || ![0, 1].includes(overwrite.type)) throw new RangeError('Invalid channel overwrite');
      if (overwrite.type === 0 && !roleIds.has(overwrite.id)) throw new RangeError('Overwrite references an unknown role');
      const target = `${overwrite.type}:${overwrite.id}`;
      if (overwriteTargets.has(target)) throw new RangeError('Duplicate channel overwrite target');
      overwriteTargets.add(target);
      const allowKeys = mapDiscordPermissions(overwrite.allow).filter((key) => key !== 'ADMINISTRATOR');
      const denyKeys = mapDiscordPermissions(overwrite.deny).filter((key) => key !== 'ADMINISTRATOR');
      if (allowKeys.some((key) => denyKeys.includes(key))) throw new RangeError('Conflicting channel overwrite');
      return {
        targetId: overwrite.id, targetType: overwrite.type === 0 ? 'role' : 'user',
        allowKeys, denyKeys,
      };
    });
    return {
      id: channel.id, name: channel.name, type: channel.type,
      position: Number.isSafeInteger(channel.position) ? channel.position : 0,
      parentId: channel.parent_id || null, nsfw: channel.nsfw === true,
      overwrites: parsedOverwrites,
    };
  });
  const channelTypeById = new Map(channels.map((channel) => [channel.id, channel.type]));
  for (const channel of channels) {
    if (channel.parentId && channelTypeById.get(channel.parentId) !== 4) {
      throw new RangeError('Channel references an unknown category');
    }
    if (![0, 2, 4, 5].includes(channel.type)) warnings.push(`Unsupported channel type ${channel.type} skipped`);
    if (channel.overwrites.some((item) => item.targetType === 'user')) warnings.push(`User overrides in ${channel.name} cannot be imported`);
  }
  const rawMasks = [
    ...template.roles.map((role) => role.permissions),
    ...template.channels.flatMap((channel) => (Array.isArray(channel.permission_overwrites) ? channel.permission_overwrites : [])
      .flatMap((overwrite) => [overwrite.allow, overwrite.deny])),
  ];
  if (rawMasks.some((mask) => (parseDiscordBits(mask) & ~SUPPORTED_DISCORD_MASK) !== 0n)) {
    warnings.push('Some Discord permissions have no CatRealm equivalent and were skipped');
  }
  return { name: template.name.trim(), description: typeof template.description === 'string' ? template.description.slice(0, 200) : '', roles, channels, warnings };
}

function importDiscordTemplate(db, prepared, token, userId, setSetting) {
  const imported = { roles: [], channels: [], categories: [], warnings: [...prepared.warnings] };
  const tokenHash = createHash('sha256').update(token).digest('hex');
  db.transaction(() => {
    const used = db.prepare(`UPDATE import_tokens SET used = 1
      WHERE token = ? AND user_id = ? AND used = 0 AND expires_at > unixepoch()`)
      .run(tokenHash, userId);
    if (used.changes !== 1) throw new RangeError('Invalid or expired verification token');

    db.prepare('DELETE FROM channels').run();
    db.prepare('DELETE FROM categories').run();
    db.prepare('DELETE FROM roles WHERE is_default = 0').run();
    const defaultRole = db.prepare('SELECT id FROM roles WHERE is_default = 1 LIMIT 1').get();
    if (!defaultRole) throw new RangeError('Realm has no default role');
    const roleMap = new Map();
    const everyone = prepared.roles.find((role) => role.name === '@everyone');
    roleMap.set(everyone.id, defaultRole.id);
    permissions.writeRoleKeys(db, defaultRole.id, everyone.permissionKeys);
    let position = (db.prepare('SELECT MAX(position) AS value FROM roles').get().value || 0) + 1;
    for (const role of prepared.roles.filter((item) => item.id !== everyone.id)
      .sort((a, b) => a.position - b.position)) {
      const id = randomUUID();
      db.prepare(`INSERT INTO roles (id, name, color, permissions, position, mentionable, hoist)
        VALUES (?, ?, ?, 0, ?, ?, ?)`).run(
        id, role.name, role.color ? `#${role.color.toString(16).padStart(6, '0')}` : null,
        position++, role.mentionable ? 1 : 0, role.hoist ? 1 : 0
      );
      permissions.writeRoleKeys(db, id, role.permissionKeys);
      roleMap.set(role.id, id);
      imported.roles.push({ id, name: role.name, permissions: permissions.encodeLegacy(role.permissionKeys), permissionKeys: role.permissionKeys });
    }
    const categoryMap = new Map();
    for (const channel of prepared.channels.filter((item) => item.type === 4)) {
      const id = randomUUID();
      db.prepare('INSERT INTO categories (id, name, position) VALUES (?, ?, ?)').run(id, channel.name, channel.position);
      categoryMap.set(channel.id, id);
      imported.categories.push({ id, name: channel.name });
    }
    const insertChannel = db.prepare(`INSERT INTO channels (id, name, type, position, category_id, nsfw)
      VALUES (?, ?, ?, ?, ?, ?)`);
    for (const channel of prepared.channels.filter((item) => [0, 2, 5].includes(item.type))) {
      const id = randomUUID();
      const categoryId = channel.parentId ? categoryMap.get(channel.parentId) : null;
      if (channel.parentId && !categoryId) throw new RangeError('Channel parent is not a category');
      insertChannel.run(id, channel.name, channel.type === 2 ? 'voice' : 'basic', channel.position, categoryId, channel.nsfw ? 1 : 0);
      imported.channels.push({ id, name: channel.name, category: categoryId });
      writeOverwrites(db, 'channel', id, channel.overwrites, roleMap);
    }
    for (const channel of prepared.channels.filter((item) => item.type === 4)) {
      writeOverwrites(db, 'category', categoryMap.get(channel.id), channel.overwrites, roleMap);
    }
    setSetting('server_name', prepared.name);
    setSetting('server_description', prepared.description);
  })();
  return imported;
}

function writeOverwrites(db, scope, scopeId, overwrites, roleMap) {
  const table = `${scope}_permission_overwrites`;
  const idColumn = `${scope}_id`;
  const insert = db.prepare(`INSERT INTO ${table} (id, ${idColumn}, target_type, target_id, allow, deny)
    VALUES (?, ?, 'role', ?, 0, 0)`);
  for (const item of overwrites) {
    if (item.targetType !== 'role') continue;
    const targetId = roleMap.get(item.targetId);
    if (!targetId) throw new RangeError('Overwrite role not imported');
    const id = randomUUID();
    insert.run(id, scopeId, targetId);
    permissions.writeOverwriteKeys(db, scope, id, item.allowKeys, item.denyKeys);
  }
}

module.exports = { parseDiscordBits, mapDiscordPermissions, prepareDiscordTemplate, importDiscordTemplate };
