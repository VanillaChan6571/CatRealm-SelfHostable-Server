// ═══════════════════════════════════════════════════════════════════════════
// USER GENERAL PERMISSIONS (Bits 0-17) - Basic user abilities
// ═══════════════════════════════════════════════════════════════════════════
const PERMISSIONS = {
  VIEW_CHANNELS: 1 << 0,
  READ_CHAT_HISTORY: 1 << 1,
  SEND_MESSAGES: 1 << 2,
  SEND_MESSAGES_IN_THREADS: 1 << 3,
  SEND_MESSAGES_IN_POSTS: 1 << 4,
  SEND_VOICE_MESSAGES: 1 << 5,
  CREATE_PUBLIC_THREADS: 1 << 6,
  CREATE_POST_IN_FORUMS: 1 << 7,
  EMBED_LINKS: 1 << 8,
  ATTACH_FILES: 1 << 9,
  ADD_REACTIONS: 1 << 10,
  SCREENSHARE: 1 << 11,
  CAMERA: 1 << 12,
  CONNECT_TO_VOICE: 1 << 13,
  USE_VOICE_ACTIVITY: 1 << 14,
  USE_PUSH_TO_TALK: 1 << 15,
  SEND_AUTO_TTS: 1 << 16,
  CHANGE_SELF_NICKNAME: 1 << 17,

  // ═══════════════════════════════════════════════════════════════════════════
  // HELPER GENERAL PERMISSIONS (Bits 18-25) - Helper/moderator lite abilities
  // ═══════════════════════════════════════════════════════════════════════════
  BYPASS_SLOWMODE: 1 << 18,
  MANAGE_MESSAGES: 1 << 19,
  PIN_MESSAGES: 1 << 20,
  TIMEOUT_USER: 1 << 21,
  MOVE_VOICE_MEMBERS: 1 << 22,
  SERVER_DEAFEN_MEMBERS: 1 << 23,
  SERVER_MUTE_MEMBERS: 1 << 24,
  ACCEPT_OR_REJECT_MEMBER_APPLICATION: 1 << 25,

  // ═══════════════════════════════════════════════════════════════════════════
  // MOD GENERAL PERMISSIONS (Bits 26-36) - Moderator abilities
  // ═══════════════════════════════════════════════════════════════════════════
  CREATE_EVENTS: 1 << 26,
  CREATE_POLLS: 1 << 27,
  CREATE_PRIVATE_THREADS: 1 << 28,
  KICK_MEMBER: 1 << 29,
  MENTION_EVERYONE: 1 << 30,
  MANAGE_NICKNAMES: 1 << 31,
  MANAGE_POSTS: 1 << 32,
  MANAGE_EVENTS: 1 << 33,
  MANAGE_CUSTOM_EMOTES: 1 << 34,
  MANAGE_CUSTOM_STICKERS: 1 << 35,
  VIEW_AUDIT_LOG: 1 << 36,

  // ═══════════════════════════════════════════════════════════════════════════
  // ADMIN GENERAL PERMISSIONS (Bits 37-42) - Administrator abilities
  // ═══════════════════════════════════════════════════════════════════════════
  BAN_MEMBER: 1 << 37,
  TOGGLE_LOCAL_REGISTERING: 1 << 38,
  MANAGE_WEBHOOKS: 1 << 39,
  MANAGE_CHANNELS: 1 << 40,
  MANAGE_ROLES: 1 << 41,
  CREATE_INVITE: 1 << 42,

  // ═══════════════════════════════════════════════════════════════════════════
  // CO-OWNER PERMISSIONS (Bit 43) - All permissions except ownership transfer
  // ═══════════════════════════════════════════════════════════════════════════
  ADMINISTRATOR: 1 << 43,
};

// External expression usage (kept aligned with current client role editor values).
PERMISSIONS.USE_EXTERNAL_EMOTES = 0x40000;
PERMISSIONS.USE_EXTERNAL_STICKERS = 0x2000000000;

// Backward-compatible aliases used across older routes/components.
PERMISSIONS.SEND_MEDIA = PERMISSIONS.ATTACH_FILES;
PERMISSIONS.MANAGE_SERVER = PERMISSIONS.MANAGE_ROLES;
PERMISSIONS.ASSIGN_ROLES = PERMISSIONS.MANAGE_ROLES;
PERMISSIONS.EDIT_MESSAGES = PERMISSIONS.MANAGE_MESSAGES;
PERMISSIONS.DELETE_MESSAGES = PERMISSIONS.MANAGE_MESSAGES;
PERMISSIONS.CREATE_THREADS = PERMISSIONS.CREATE_PUBLIC_THREADS;
PERMISSIONS.CREATE_INVITES = PERMISSIONS.CREATE_INVITE;
PERMISSIONS.USE_EXTERNAL_EMOJIS = PERMISSIONS.USE_EXTERNAL_EMOTES;

function toPermissionBits(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0n;
  const normalized = Math.trunc(value);
  // Legacy signed-32 values should be interpreted as unsigned masks.
  if (normalized < 0) return BigInt(normalized >>> 0);
  return BigInt(normalized);
}

const ALL_PERMISSIONS = Number(
  Object.values(PERMISSIONS).reduce((acc, val) => (acc | toPermissionBits(val)), 0n)
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

  // Get all overwrites for this channel.
  const overwrites = db.prepare(`
    SELECT * FROM channel_permission_overwrites
    WHERE channel_id = ?
  `).all(channelId);

  // Get user's roles
  const userRoles = db.prepare(`
    SELECT role_id FROM user_roles WHERE user_id = ?
  `).all(userId).map(r => r.role_id);

  // Get default role
  const defaultRole = db.prepare('SELECT id FROM roles WHERE is_default = 1').get();

  // Discord-style precedence:
  // 1) @everyone overwrite
  // 2) aggregate all role overwrites
  // 3) user-specific overwrite
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
      if (overwrite.target_id === defaultRole?.id) {
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
