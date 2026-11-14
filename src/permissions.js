const bit = (position) => 2 ** position;
const permissionModel = require('./permissionModel');

const USER_GENERAL = {
  VIEW_CHANNELS: bit(0),
  READ_CHAT_HISTORY: bit(1),
  SEND_MESSAGES: bit(2),
  SEND_MESSAGES_IN_THREADS: bit(3),
  SEND_MESSAGES_IN_POSTS: bit(4),
  SEND_VOICE_MESSAGES: bit(5),
  CREATE_PUBLIC_THREADS: bit(6),
  CREATE_POST_IN_FORUMS: bit(7),
  EMBED_LINKS: bit(8),
  ATTACH_FILES: bit(9),
  ADD_REACTIONS: bit(10),
  SCREENSHARE: bit(11),
  CAMERA: bit(12),
  CONNECT_TO_VOICE: bit(13),
  USE_VOICE_ACTIVITY: bit(14),
  USE_PUSH_TO_TALK: bit(15),
  SEND_AUTO_TTS: bit(16),
  CHANGE_SELF_NICKNAME: bit(17),
};

const HELPER_GENERAL = {
  BYPASS_SLOWMODE: bit(18),
  MANAGE_MESSAGES: bit(19),
  PIN_MESSAGES: bit(20),
  TIMEOUT_USER: bit(21),
  MOVE_VOICE_MEMBERS: bit(22),
  SERVER_DEAFEN_MEMBERS: bit(23),
  SERVER_MUTE_MEMBERS: bit(24),
  ACCEPT_OR_REJECT_MEMBER_APPLICATION: bit(25),
};

const MOD_GENERAL = {
  CREATE_EVENTS: bit(26),
  CREATE_POLLS: bit(27),
  CREATE_PRIVATE_THREADS: bit(28),
  KICK_MEMBER: bit(29),
  MENTION_EVERYONE: bit(30),
  MANAGE_NICKNAMES: bit(31),
  MANAGE_POSTS: bit(32),
  MANAGE_EVENTS: bit(33),
  MANAGE_CUSTOM_EMOTES: bit(34),
  MANAGE_CUSTOM_STICKERS: bit(35),
  VIEW_AUDIT_LOG: bit(36),
};

const ADMIN_GENERAL = {
  BAN_MEMBER: bit(37),
  TOGGLE_LOCAL_REGISTERING: bit(38),
  MANAGE_WEBHOOKS: bit(39),
  MANAGE_CHANNELS: bit(40),
  MANAGE_ROLES: bit(41),
  CREATE_INVITE: bit(42),
};

const CO_OWNER = {
  ADMINISTRATOR: bit(43),
};

const FLAT_PERMISSIONS = {
  ...USER_GENERAL,
  ...HELPER_GENERAL,
  ...MOD_GENERAL,
  ...ADMIN_GENERAL,
  ...CO_OWNER,
};

const PERMISSIONS = {
  USER: USER_GENERAL,
  HELPER: HELPER_GENERAL,
  MOD: MOD_GENERAL,
  ADMIN: ADMIN_GENERAL,
  CO_OWNER: CO_OWNER,
  ...FLAT_PERMISSIONS,
};

// External expression usage. These must not collide with grouped permission bits.
PERMISSIONS.USE_EXTERNAL_EMOTES = bit(44);
PERMISSIONS.USE_EXTERNAL_STICKERS = bit(45);
PERMISSIONS.SCHEDULE_MESSAGES = bit(46);
// Theater channel — submit videos / control playback when open-queuing is off.
PERMISSIONS.PLAY_IN_THEATER = bit(47);
// Create/manage bot accounts (Realm Settings → Bots).
PERMISSIONS.MANAGE_BOTS = bit(48);

// Backward-compatible aliases used across older routes/components.
PERMISSIONS.SEND_MEDIA = USER_GENERAL.ATTACH_FILES;
PERMISSIONS.MANAGE_SERVER = ADMIN_GENERAL.MANAGE_ROLES;
PERMISSIONS.ASSIGN_ROLES = ADMIN_GENERAL.MANAGE_ROLES;
PERMISSIONS.EDIT_MESSAGES = HELPER_GENERAL.MANAGE_MESSAGES;
PERMISSIONS.DELETE_MESSAGES = HELPER_GENERAL.MANAGE_MESSAGES;
PERMISSIONS.CREATE_THREADS = USER_GENERAL.CREATE_PUBLIC_THREADS;
PERMISSIONS.CREATE_INVITES = ADMIN_GENERAL.CREATE_INVITE;
PERMISSIONS.USE_EXTERNAL_EMOJIS = PERMISSIONS.USE_EXTERNAL_EMOTES;

const ALL_PERMISSIONS = permissionModel.encodeLegacy(permissionModel.KEYS);

function computePermissionKeysForUser(userId, role, isOwner, db) {
  if (isOwner || role === 'owner' || role === 'admin') return [...permissionModel.KEYS];
  let keys;
  try {
    const rows = db.prepare(`
      SELECT DISTINCT g.permission_key FROM role_permission_grants g
      JOIN user_roles ur ON ur.role_id = g.role_id WHERE ur.user_id = ?
    `).all(userId);
    keys = permissionModel.normalizeKeys(rows.map((r) => r.permission_key));
  } catch (error) {
    if (!/no such table: role_permission_grants/.test(error.message)) throw error;
    const roles = db.prepare(`SELECT r.permissions FROM roles r
      JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?`).all(userId);
    keys = permissionModel.normalizeKeys(roles.flatMap((r) => permissionModel.decodeLegacy(r.permissions || 0)));
  }
  return keys.includes('ADMINISTRATOR') ? [...permissionModel.KEYS] : keys;
}

function computePermissionsForUser(userId, role, isOwner, db) {
  return permissionModel.encodeLegacy(computePermissionKeysForUser(userId, role, isOwner, db));
}

function hasPermission(user, permission) {
  if (!user) return false;
  if (user.is_owner || user.role === 'owner') return true;
  try {
    const keys = Array.isArray(user.permission_keys)
      ? permissionModel.normalizeKeys(user.permission_keys)
      : permissionModel.decodeLegacy(user.permissions || 0);
    const required = permissionModel.requiredKeys(permission);
    return keys.includes('ADMINISTRATOR') || required.every((key) => keys.includes(key));
  } catch {
    return false;
  }
}

function applyPermissionOverwrites(currentKeys, overwrites, scope, userRoles, defaultRoleId, userId, db) {
  const permissions = new Set(currentKeys);
  for (const group of ['everyone', 'roles', 'user']) {
    const allow = new Set();
    const deny = new Set();
    for (const overwrite of overwrites) {
      const applies = group === 'everyone'
        ? overwrite.target_type === 'role' && overwrite.target_id === defaultRoleId
        : group === 'roles'
          ? overwrite.target_type === 'role' && overwrite.target_id !== defaultRoleId && userRoles.includes(overwrite.target_id)
          : overwrite.target_type === 'user' && overwrite.target_id === userId;
      if (!applies) continue;
      const rules = permissionModel.overwriteKeys(db, scope, overwrite);
      for (const key of rules.allow) if (key !== 'ADMINISTRATOR') allow.add(key);
      for (const key of rules.deny) if (key !== 'ADMINISTRATOR') deny.add(key);
    }
    for (const key of deny) permissions.delete(key);
    for (const key of allow) permissions.add(key);
  }
  return [...permissions];
}

/**
 * Compute channel-specific permissions for a user
 * Permission Resolution Order:
 * 1. Start with base permissions (from user's roles)
 * 2. Apply @everyone role overwrites (deny, then allow)
 * 3. Apply user's other role overwrites (deny, then allow)
 * 4. Apply user-specific overwrites (deny, then allow)
 * 5. Owner/Administrator always has all permissions
 */
function computeChannelPermissions(userId, channelId, basePermissions, db, overwriteRoleIds = null, effectiveUser = null) {
  return permissionModel.encodeLegacy(computeChannelPermissionKeys(userId, channelId, basePermissions, db, overwriteRoleIds, effectiveUser));
}

function computeChannelPermissionKeys(userId, channelId, basePermissions, db, overwriteRoleIds = null, effectiveUser = null) {
  // Owner and Administrator always have all permissions, but use the effective
  // user first so "view as role" does not fall back to the real DB user.
  const user = effectiveUser || db.prepare('SELECT is_owner, role FROM users WHERE id = ?').get(userId);
  if (user?.is_owner || user?.role === 'owner') return [...permissionModel.KEYS];
  const baseKeys = Array.isArray(user?.permission_keys)
    ? permissionModel.normalizeKeys(user.permission_keys)
    : permissionModel.decodeLegacy(basePermissions || 0);
  if (baseKeys.includes('ADMINISTRATOR')) return [...permissionModel.KEYS];

  let permissions = baseKeys;
  const channel = db.prepare('SELECT category_id FROM channels WHERE id = ?').get(channelId);
  if (!channel) return permissions;

  // Get user's roles
  const userRoles = Array.isArray(overwriteRoleIds)
    ? overwriteRoleIds
    : db.prepare(`
      SELECT role_id FROM user_roles WHERE user_id = ?
    `).all(userId).map(r => r.role_id);

  // Get default role
  const defaultRole = db.prepare('SELECT id FROM roles WHERE is_default = 1').get();

  // Apply category-level overwrites first (if any), then channel-level overwrites.
  if (channel.category_id) {
    const categoryOverwrites = permissionModel.listOverwrites(db, 'category', channel.category_id);
    permissions = applyPermissionOverwrites(permissions, categoryOverwrites, 'category', userRoles, defaultRole?.id, userId, db);
  }

  const channelOverwrites = permissionModel.listOverwrites(db, 'channel', channelId);
  permissions = applyPermissionOverwrites(permissions, channelOverwrites, 'channel', userRoles, defaultRole?.id, userId, db);

  return permissions;
}

function computeUserChannelPermissions(user, channelId, db) {
  return permissionModel.encodeLegacy(computeUserChannelPermissionKeys(user, channelId, db));
}

function computeUserChannelPermissionKeys(user, channelId, db) {
  if (!user) return [];
  if (user.is_owner || user.role === 'owner') return [...permissionModel.KEYS];
  const viewedRoleId = typeof user.view_as_role?.roleId === 'string'
    ? user.view_as_role.roleId
    : null;
  const overwriteRoleIds = viewedRoleId ? [viewedRoleId] : null;
  return computeChannelPermissionKeys(user.id, channelId, user.permissions || 0, db, overwriteRoleIds, user);
}

function hasChannelPermission(user, channelId, permission, db) {
  if (!user) return false;
  if (user.is_owner || user.role === 'owner') return true;
  const keys = computeUserChannelPermissionKeys(user, channelId, db);
  try {
    return keys.includes('ADMINISTRATOR') || permissionModel.requiredKeys(permission).every((key) => keys.includes(key));
  } catch {
    return false;
  }
}

module.exports = {
  PERMISSIONS,
  ALL_PERMISSIONS,
  hasPermission,
  computePermissionsForUser,
  computePermissionKeysForUser,
  computeChannelPermissions,
  computeChannelPermissionKeys,
  computeUserChannelPermissions,
  computeUserChannelPermissionKeys,
  hasChannelPermission,
};
