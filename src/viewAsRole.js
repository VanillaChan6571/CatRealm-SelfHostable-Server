const { PERMISSIONS, ALL_PERMISSIONS } = require('./permissions');

const roleViewSessions = new Map();

function toPermissionBits(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 0n;
  const normalized = Math.trunc(value);
  if (normalized < 0) return BigInt(normalized >>> 0);
  return BigInt(normalized);
}

function getRoleViewSession(userId) {
  return roleViewSessions.get(userId) || null;
}

function clearRoleViewSession(userId) {
  roleViewSessions.delete(userId);
}

function startRoleViewSession(userId, roleId) {
  const session = {
    roleId,
    startedAt: Date.now(),
  };
  roleViewSessions.set(userId, session);
  return session;
}

function buildRoleViewInfo(role, session) {
  if (!role || !session) return null;
  return {
    roleId: role.id,
    roleName: role.name,
    startedAt: session.startedAt,
  };
}

function buildViewedPermissions(role, defaultRole) {
  let permissions = 0n;
  if (defaultRole?.permissions != null) {
    permissions |= toPermissionBits(Number(defaultRole.permissions));
  }
  if (role?.permissions != null) {
    permissions |= toPermissionBits(Number(role.permissions));
  }
  const administratorMask = toPermissionBits(PERMISSIONS.ADMINISTRATOR);
  if ((permissions & administratorMask) === administratorMask) {
    return ALL_PERMISSIONS;
  }
  return Number(permissions);
}

function applyRoleViewToUser(user, db) {
  if (!user?.id) {
    return { user, session: null };
  }

  const session = getRoleViewSession(user.id);
  if (!session?.roleId) {
    return { user, session: null };
  }

  const role = db.prepare(`
    SELECT id, name, permissions, is_default
    FROM roles
    WHERE id = ?
  `).get(session.roleId);
  if (!role) {
    clearRoleViewSession(user.id);
    return { user, session: null };
  }

  const defaultRole = db.prepare(`
    SELECT id, name, permissions, is_default
    FROM roles
    WHERE is_default = 1
    LIMIT 1
  `).get();
  const viewedPermissions = buildViewedPermissions(role, defaultRole);
  const viewAsRole = buildRoleViewInfo(role, session);

  return {
    user: {
      ...user,
      role: role.name,
      is_owner: 0,
      permissions: viewedPermissions,
      view_as_role: viewAsRole,
    },
    session: viewAsRole,
  };
}

module.exports = {
  getRoleViewSession,
  clearRoleViewSession,
  startRoleViewSession,
  applyRoleViewToUser,
};
