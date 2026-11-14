const permissionModel = require('./permissionModel');

const roleViewSessions = new Map();

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

function buildViewedPermissionKeys(role, defaultRole, db) {
  const keys = new Set([
    ...(defaultRole ? permissionModel.roleKeys(db, defaultRole.id) : []),
    ...permissionModel.roleKeys(db, role.id),
  ]);
  return keys.has('ADMINISTRATOR') ? [...permissionModel.KEYS] : [...keys];
}

function applyRoleViewToUser(user, db) {
  if (!user?.id) {
    return { user, session: null };
  }

  if (user.is_owner || user.role === 'owner') {
    return { user, session: getRoleViewSession(user.id) };
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
  const permissionKeys = buildViewedPermissionKeys(role, defaultRole, db);
  const viewedPermissions = permissionModel.encodeLegacy(permissionKeys);
  const viewAsRole = buildRoleViewInfo(role, session);

  return {
    user: {
      ...user,
      role: role.name,
      is_owner: 0,
      permissions: viewedPermissions,
      permission_keys: permissionKeys,
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
