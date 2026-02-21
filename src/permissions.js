const bit = (position) => 2 ** position;

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

// External expression usage (kept aligned with current client role editor values).
PERMISSIONS.USE_EXTERNAL_EMOTES = 0x40000;
PERMISSIONS.USE_EXTERNAL_STICKERS = 0x2000000000;

// Backward-compatible aliases used across older routes/components.
PERMISSIONS.SEND_MEDIA = USER_GENERAL.ATTACH_FILES;
PERMISSIONS.MANAGE_SERVER = ADMIN_GENERAL.MANAGE_ROLES;
PERMISSIONS.ASSIGN_ROLES = ADMIN_GENERAL.MANAGE_ROLES;
PERMISSIONS.EDIT_MESSAGES = HELPER_GENERAL.MANAGE_MESSAGES;
PERMISSIONS.DELETE_MESSAGES = HELPER_GENERAL.MANAGE_MESSAGES;
PERMISSIONS.CREATE_THREADS = USER_GENERAL.CREATE_PUBLIC_THREADS;
PERMISSIONS.CREATE_INVITES = ADMIN_GENERAL.CREATE_INVITE;
PERMISSIONS.USE_EXTERNAL_EMOJIS = PERMISSIONS.USE_EXTERNAL_EMOTES;

function toPermissionBits(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0n;
  const normalized = Math.trunc(value);
  // Legacy signed-32 values should be interpreted as unsigned masks.
  if (normalized < 0) return BigInt(normalized >>> 0);
  return BigInt(normalized);
}

const ALL_PERMISSIONS = Number(
  Object.values(FLAT_PERMISSIONS).reduce((acc, val) => (acc | toPermissionBits(val)), 0n)
);

function computePermissionsForUser(userId, role, isOwner, db) {
  if (isOwner || role === 'owner' || role === 'admin') return ALL_PERMISSIONS;

  const roleRows = db.prepare(`
    SELECT r.permissions FROM roles r
    JOIN user_roles ur ON ur.role_id = r.id
    WHERE ur.user_id = ?
  `).all(userId);

  let permissions = 0n;
  const administratorMask = toPermissionBits(PERMISSIONS.ADMINISTRATOR);

  for (const r of roleRows) {
    permissions |= toPermissionBits(r.permissions);
    // If user has ADMINISTRATOR permission, grant all permissions
    if ((permissions & administratorMask) === administratorMask) {
      return ALL_PERMISSIONS;
    }
  }

  return Number(permissions);
}

function hasPermission(user, permission) {
  if (!user) return false;
  if (user.is_owner || user.role === 'owner') return true;
  const userBits = toPermissionBits(user.permissions);
  const permissionBits = toPermissionBits(permission);
  // Check for ADMINISTRATOR permission which grants all
  const administratorMask = toPermissionBits(PERMISSIONS.ADMINISTRATOR);
  if ((userBits & administratorMask) === administratorMask) return true;
  return (userBits & permissionBits) === permissionBits;
}

function applyPermissionOverwrites(currentPermissions, overwrites, userRoles, defaultRoleId, userId) {
  let permissions = currentPermissions;
  let everyoneAllow = 0n;
  let everyoneDeny = 0n;
  let rolesAllow = 0n;
  let rolesDeny = 0n;
  let userAllow = 0n;
  let userDeny = 0n;

  for (const overwrite of overwrites) {
    const allow = toPermissionBits(Number(overwrite.allow || 0));
    const deny = toPermissionBits(Number(overwrite.deny || 0));
    if (overwrite.target_type === 'role') {
      if (overwrite.target_id === defaultRoleId) {
        everyoneAllow |= allow;
        everyoneDeny |= deny;
      } else if (userRoles.includes(overwrite.target_id)) {
        rolesAllow |= allow;
        rolesDeny |= deny;
      }
    } else if (overwrite.target_type === 'user' && overwrite.target_id === userId) {
      userAllow |= allow;
      userDeny |= deny;
    }
  }

  permissions = (permissions & ~everyoneDeny) | everyoneAllow;
  permissions = (permissions & ~rolesDeny) | rolesAllow;
  permissions = (permissions & ~userDeny) | userAllow;
  return permissions;
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
function computeChannelPermissions(userId, channelId, basePermissions, db) {
  // Owner and Administrator always have all permissions
  const user = db.prepare('SELECT is_owner, role FROM users WHERE id = ?').get(userId);
  if (user?.is_owner || user?.role === 'owner') return ALL_PERMISSIONS;
  const administratorMask = toPermissionBits(PERMISSIONS.ADMINISTRATOR);
  if ((toPermissionBits(basePermissions) & administratorMask) === administratorMask) return ALL_PERMISSIONS;

  let permissions = toPermissionBits(basePermissions);
  const channel = db.prepare('SELECT category_id FROM channels WHERE id = ?').get(channelId);
  if (!channel) return Number(permissions);

  // Get user's roles
  const userRoles = db.prepare(`
    SELECT role_id FROM user_roles WHERE user_id = ?
  `).all(userId).map(r => r.role_id);

  // Get default role
  const defaultRole = db.prepare('SELECT id FROM roles WHERE is_default = 1').get();

  // Apply category-level overwrites first (if any), then channel-level overwrites.
  if (channel.category_id) {
    const categoryOverwrites = db.prepare(`
      SELECT * FROM category_permission_overwrites
      WHERE category_id = ?
    `).all(channel.category_id);
    permissions = applyPermissionOverwrites(permissions, categoryOverwrites, userRoles, defaultRole?.id, userId);
  }

  const channelOverwrites = db.prepare(`
    SELECT * FROM channel_permission_overwrites
    WHERE channel_id = ?
  `).all(channelId);
  permissions = applyPermissionOverwrites(permissions, channelOverwrites, userRoles, defaultRole?.id, userId);

  return Number(permissions);
}

function computeUserChannelPermissions(user, channelId, db) {
  if (!user) return 0;
  if (user.is_owner || user.role === 'owner') return ALL_PERMISSIONS;
  return computeChannelPermissions(user.id, channelId, user.permissions || 0, db);
}

function hasChannelPermission(user, channelId, permission, db) {
  if (!user) return false;
  if (user.is_owner || user.role === 'owner') return true;
  const channelBits = toPermissionBits(computeUserChannelPermissions(user, channelId, db));
  const permissionBits = toPermissionBits(permission);
  const administratorMask = toPermissionBits(PERMISSIONS.ADMINISTRATOR);
  if ((channelBits & administratorMask) === administratorMask) return true;
  return (channelBits & permissionBits) === permissionBits;
}

module.exports = {
  PERMISSIONS,
  ALL_PERMISSIONS,
  hasPermission,
  computePermissionsForUser,
  computeChannelPermissions,
  computeUserChannelPermissions,
  hasChannelPermission,
};
