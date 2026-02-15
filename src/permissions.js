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

const ALL_PERMISSIONS = Object.values(PERMISSIONS).reduce((acc, val) => acc | val, 0);

function computePermissionsForUser(userId, role, isOwner, db) {
  if (isOwner || role === 'owner' || role === 'admin') return ALL_PERMISSIONS;

  const roleRows = db.prepare(`
    SELECT r.permissions FROM roles r
    JOIN user_roles ur ON ur.role_id = r.id
    WHERE ur.user_id = ?
  `).all(userId);

  let permissions = 0;
  for (const r of roleRows) {
    permissions |= r.permissions;
    // If user has ADMINISTRATOR permission, grant all permissions
    if ((r.permissions & PERMISSIONS.ADMINISTRATOR) === PERMISSIONS.ADMINISTRATOR) {
      return ALL_PERMISSIONS;
    }
  }

  return permissions;
}

function hasPermission(user, permission) {
  if (!user) return false;
  if (user.is_owner || user.role === 'owner') return true;
  // Check for ADMINISTRATOR permission which grants all
  if ((user.permissions & PERMISSIONS.ADMINISTRATOR) === PERMISSIONS.ADMINISTRATOR) return true;
  return (user.permissions & permission) === permission;
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
  if ((basePermissions & PERMISSIONS.ADMINISTRATOR) === PERMISSIONS.ADMINISTRATOR) return ALL_PERMISSIONS;

  let permissions = basePermissions;

  // Get all overwrites for this channel
  const overwrites = db.prepare(`
    SELECT * FROM channel_permission_overwrites
    WHERE channel_id = ?
    ORDER BY
      CASE
        WHEN target_type = 'role' THEN 0
        WHEN target_type = 'user' THEN 1
      END
  `).all(channelId);

  // Get user's roles
  const userRoles = db.prepare(`
    SELECT role_id FROM user_roles WHERE user_id = ?
  `).all(userId).map(r => r.role_id);

  // Get default role
  const defaultRole = db.prepare('SELECT id FROM roles WHERE is_default = 1').get();

  // Apply overwrites in order
  for (const overwrite of overwrites) {
    let applies = false;

    if (overwrite.target_type === 'role') {
      // Check if user has this role
      if (overwrite.target_id === defaultRole?.id || userRoles.includes(overwrite.target_id)) {
        applies = true;
      }
    } else if (overwrite.target_type === 'user') {
      // Check if this is the user
      if (overwrite.target_id === userId) {
        applies = true;
      }
    }

    if (applies) {
      // Apply deny first, then allow
      permissions = (permissions & ~overwrite.deny) | overwrite.allow;
    }
  }

  return permissions;
}

module.exports = { PERMISSIONS, ALL_PERMISSIONS, hasPermission, computePermissionsForUser, computeChannelPermissions };
