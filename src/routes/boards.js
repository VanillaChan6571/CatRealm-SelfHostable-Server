// Board channels: Trello-style lists of cards. Mounted at /api/boards.
const router = require('express').Router();
const { randomUUID } = require('crypto');
const db = require('../db');
const { emitToChannel, emitToChannelEach } = require('../socket/handler');
const { logAuditAction } = require('../lib/auditLog');
const items = require('../channelItems');
const { backgroundInput, UPLOADED_IMAGE } = require('../workItemBackground');
const { hasChannelPermission } = require('../permissions');

const { InputError, LIMITS } = items;
const perms = { create: 'CREATE_CARDS', comment: 'COMMENT_ON_CARDS', assign: 'ASSIGN_CARDS', manage: 'MANAGE_BOARDS' };
const MAX_LIST_ROLES = 50;
const COVER_SIZES = [64, 128, 256, 512];
const BOARD_TITLE_MAX = 100;
function dueAt(value) {
  if (value === null) return null;
  if (!Number.isInteger(value) || value < 0 || value > 32503680000) throw new InputError('dueAt must be a unix timestamp or null');
  return value;
}

// ── List visibility ───────────────────────────────────────────────────────
// A list is public unless it is staff-only. A staff-only list, and every card in
// it, is seen by board managers and by members of the roles named on the list.
// Everyone else is answered as if the list did not exist.
const rawLists = (channelId) => {
  const lists = db.prepare('SELECT id, name, position, cover_image, cover_size, icon, staff_only FROM board_lists WHERE channel_id = ? ORDER BY position').all(channelId);
  const roles = db.prepare(`SELECT lr.list_id, lr.role_id FROM board_list_roles lr
    JOIN board_lists l ON l.id = lr.list_id WHERE l.channel_id = ?`).all(channelId);
  return lists.map((list) => ({
    ...list,
    staff_only: !!list.staff_only,
    role_ids: roles.filter((r) => r.list_id === list.id).map((r) => r.role_id),
  }));
};

// What one user may see on one board. viewAsRoleId narrows an admin previewing a role.
function viewerFor(user, channelId, viewAsRoleId = null) {
  const manage = hasChannelPermission(user, channelId, perms.manage, db);
  let roleIds = null;
  const sees = (list) => {
    if (!list.staff_only || manage) return true;
    roleIds ??= new Set(viewAsRoleId
      ? [viewAsRoleId]
      : db.prepare('SELECT role_id FROM user_roles WHERE user_id = ?').all(user.id).map((r) => r.role_id));
    return list.role_ids.some((id) => roleIds.has(id));
  };
  // Only managers learn which roles a list is shared with.
  const serialize = ({ role_ids, ...list }) => (manage ? { ...list, role_ids } : list);
  return { manage, sees, serialize };
}
const requestViewer = (req) => viewerFor(req.user, req.channel.id, req.viewAsRole?.roleId ?? null);
const listsFor = (viewer, channelId) => rawLists(channelId).filter(viewer.sees).map(viewer.serialize);

// Sends a board event to each connected member, trimmed to what they may see.
// build(viewer, visibleListIds) returns the payload, or null to skip that member.
function emitFiltered(channelId, event, build) {
  const lists = rawLists(channelId);
  if (!lists.some((list) => list.staff_only)) {
    const everyone = { manage: false, sees: () => true, serialize: ({ role_ids, ...list }) => list };
    // Managers still need role_ids, so list payloads are always built per member.
    if (event !== 'board:lists-updated') {
      const data = build(everyone, new Set(lists.map((list) => list.id)), lists);
      if (data !== null && data !== undefined) emitToChannel(channelId, event, data);
      return;
    }
  }
  emitToChannelEach(channelId, event, (user) => {
    const viewer = viewerFor(user, channelId);
    return build(viewer, new Set(lists.filter(viewer.sees).map((list) => list.id)), lists);
  });
}

const listIdOfItem = (itemId) => db.prepare('SELECT list_id FROM channel_items WHERE id = ?').get(itemId)?.list_id;

// Every event the shared routes emit goes through here so hidden lists stay hidden.
function emit(channelId, event, data) {
  switch (event) {
    case 'board:card-created':
    case 'board:card-updated':
      return emitFiltered(channelId, event, (_viewer, visible) => (visible.has(data.list_id) ? data : null));
    case 'board:comment-created':
    case 'board:comment-updated':
    case 'board:comment-deleted': {
      const listId = listIdOfItem(data.itemId);
      return emitFiltered(channelId, event, (_viewer, visible) => (visible.has(listId) ? data : null));
    }
    default:
      // card-deleted and labels-updated carry nothing a hidden list would reveal.
      return emitToChannel(channelId, event, data);
  }
}

function patchExtra(req, card) {
  const body = req.body ?? {};
  const sets = {};
  const events = [];
  if (body.dueAt !== undefined) sets.due_at = dueAt(body.dueAt);
  if (body.archived !== undefined && !!body.archived !== !!card.archived) {
    sets.archived = body.archived ? 1 : 0;
    // A restored card goes to the end of its list. Archiving leaves a gap in
    // positions, so use max + 1 rather than the count.
    if (!body.archived) {
      sets.position = db.prepare('SELECT COALESCE(MAX(position), -1) + 1 AS next FROM channel_items WHERE list_id = ? AND archived = 0')
        .get(card.list_id).next;
    }
    events.push([body.archived ? 'archived' : 'restored', null]);
  }
  return { sets, events };
}

const canSeeListId = (req, listId) => {
  const list = rawLists(req.channel.id).find((l) => l.id === listId);
  return !!list && requestViewer(req).sees(list);
};

const shared = items.installSharedRoutes(router, {
  kind: 'card', channelType: 'board', noun: 'card', plural: 'cards', prefix: 'board', perms, patchExtra,
  canAccessItem: (req, card) => canSeeListId(req, card.list_id),
}, { db, emit, audit: logAuditAction });
const { handle, loadChannel, loadItem, require_, emitItem, createItem } = shared;

const emitLists = (channelId) => emitFiltered(channelId, 'board:lists-updated',
  (viewer, _visible, lists) => ({ channelId, lists: lists.filter(viewer.sees).map(viewer.serialize) }));
const cardIds = (listId) => db.prepare('SELECT id FROM channel_items WHERE list_id = ? AND archived = 0 ORDER BY position').all(listId).map((r) => r.id);
const setOrder = (table, ids) => {
  const update = db.prepare(`UPDATE ${table} SET position = ? WHERE id = ?`);
  ids.forEach((id, index) => update.run(index, id));
};

// ── Board settings (title and background) ─────────────────────────────────
// title: null = show the channel's name. background: null = none, or
//   { kind: 'pattern', colors: ['#rrggbb', …1-6], pattern, animated, scene } — the same colour
//     patterns voice calls use — or { kind: 'image', image: <upload path> }.
function boardSettings(channelId) {
  const row = db.prepare('SELECT title, background FROM board_settings WHERE channel_id = ?').get(channelId);
  let background = null;
  if (row?.background) {
    try { background = JSON.parse(row.background); } catch { background = null; }
  }
  return { title: row?.title ?? null, background };
}

// GET /api/boards/:channelId?archived=1 — the whole board in one response.
router.get('/:channelId', loadChannel, (req, res) => {
  const archived = req.query.archived === '1' ? 1 : 0;
  const lists = listsFor(requestViewer(req), req.channel.id);
  const visible = new Set(lists.map((list) => list.id));
  const cards = db.prepare("SELECT * FROM channel_items WHERE channel_id = ? AND kind = 'card' AND archived = ? ORDER BY position")
    .all(req.channel.id, archived).filter((card) => visible.has(card.list_id));
  res.json({
    lists, cards: items.serializeItems(db, cards), labels: items.listLabels(db, req.channel.id),
    settings: boardSettings(req.channel.id),
  });
});

// PATCH /api/boards/:channelId/settings { title?, background? } — board managers.
router.patch('/:channelId/settings', loadChannel, require_(perms.manage), handle((req, res) => {
  const body = req.body ?? {};
  const current = boardSettings(req.channel.id);
  let title = current.title;
  if (body.title !== undefined) {
    title = body.title === null ? null : items.text(body.title, BOARD_TITLE_MAX, 'Board title', { required: false }) || null;
  }
  let background = current.background;
  if (body.background !== undefined) {
    if (body.background?.kind === 'image' && !body.background.image) throw new InputError('Background image required');
    background = backgroundInput(body.background);
  }
  db.prepare(`
    INSERT INTO board_settings (channel_id, title, background) VALUES (?, ?, ?)
    ON CONFLICT(channel_id) DO UPDATE SET title = excluded.title, background = excluded.background
  `).run(req.channel.id, title, background ? JSON.stringify(background) : null);
  const settings = boardSettings(req.channel.id);
  emitToChannel(req.channel.id, 'board:settings-updated', { channelId: req.channel.id, settings });
  res.json(settings);
}));

// GET /api/boards/:channelId/roles — roles a manager can share a staff-only list with.
router.get('/:channelId/roles', loadChannel, require_(perms.manage), (_req, res) => {
  res.json(db.prepare('SELECT id, name, color FROM roles WHERE is_default = 0 ORDER BY position DESC, name COLLATE NOCASE').all());
});

// ── Lists (MANAGE_BOARDS) ─────────────────────────────────────────────────
const managerList = (channelId, listId) => rawLists(channelId).find((list) => list.id === listId);

// An uploaded image path (from /api/uploads/chat); null or '' clears it.
function imageRef(value, label) {
  if (value === null || value === '') return null;
  if (typeof value !== 'string' || !UPLOADED_IMAGE.test(value.trim())) {
    throw new InputError(`${label} must be an uploaded image`);
  }
  return value.trim();
}

router.post('/:channelId/lists', loadChannel, require_(perms.manage), handle((req, res) => {
  const name = items.text(req.body?.name, LIMITS.listName, 'List name');
  const count = rawLists(req.channel.id).length;
  if (count >= LIMITS.listsPerBoard) throw new InputError(`List limit reached (${LIMITS.listsPerBoard})`);
  const id = randomUUID();
  db.prepare('INSERT INTO board_lists (id, channel_id, name, position) VALUES (?, ?, ?, ?)').run(id, req.channel.id, name, count);
  emitLists(req.channel.id);
  res.status(201).json(managerList(req.channel.id, id));
}));

// PUT /api/boards/:channelId/lists/order { listIds } — every list exactly once.
router.put('/:channelId/lists/order', loadChannel, require_(perms.manage), handle((req, res) => {
  const ids = items.idList(req.body?.listIds, LIMITS.listsPerBoard, 'lists');
  const current = rawLists(req.channel.id).map((list) => list.id);
  if (ids.length !== current.length || current.some((id) => !ids.includes(id))) throw new InputError('listIds must contain every list exactly once');
  db.transaction(() => setOrder('board_lists', ids))();
  emitLists(req.channel.id);
  res.json(rawLists(req.channel.id));
}));

// PATCH /api/boards/:channelId/lists/:listId { name?, coverImage?, coverSize?, icon?, staffOnly?, roleIds? }
// coverSize is the width the cover is drawn at (64, 128, 256 or 512 px), or null to fit the list.
// roleIds are the extra roles that may see the list while it is staff-only.
router.patch('/:channelId/lists/:listId', loadChannel, require_(perms.manage), handle((req, res) => {
  const body = req.body ?? {};
  if (!managerList(req.channel.id, req.params.listId)) return res.status(404).json({ error: 'List not found' });
  const sets = {};
  if (body.name !== undefined) sets.name = items.text(body.name, LIMITS.listName, 'List name');
  if (body.coverImage !== undefined) sets.cover_image = imageRef(body.coverImage, 'Cover image');
  if (body.coverSize !== undefined) {
    if (body.coverSize !== null && !COVER_SIZES.includes(body.coverSize)) throw new InputError(`coverSize must be null or one of ${COVER_SIZES.join(', ')}`);
    sets.cover_size = body.coverSize;
  }
  if (body.icon !== undefined) sets.icon = imageRef(body.icon, 'Icon');
  if (body.staffOnly !== undefined) sets.staff_only = body.staffOnly ? 1 : 0;
  let roleIds;
  if (body.roleIds !== undefined) {
    roleIds = items.idList(body.roleIds, MAX_LIST_ROLES, 'roles');
    if (roleIds.length) {
      const known = db.prepare(`SELECT id FROM roles WHERE id IN (${items.placeholders(roleIds)})`).all(...roleIds);
      if (known.length !== roleIds.length) throw new InputError('Unknown role');
    }
  }
  db.transaction(() => {
    const columns = Object.keys(sets);
    if (columns.length) {
      db.prepare(`UPDATE board_lists SET ${columns.map((c) => `${c} = ?`).join(', ')} WHERE id = ?`)
        .run(...columns.map((c) => sets[c]), req.params.listId);
    }
    if (roleIds) {
      db.prepare('DELETE FROM board_list_roles WHERE list_id = ?').run(req.params.listId);
      const insert = db.prepare('INSERT INTO board_list_roles (list_id, role_id) VALUES (?, ?)');
      for (const roleId of roleIds) insert.run(req.params.listId, roleId);
    }
  })();
  emitLists(req.channel.id);
  res.json(managerList(req.channel.id, req.params.listId));
}));

// Deleting a list deletes its cards (foreign key cascade).
router.delete('/:channelId/lists/:listId', loadChannel, require_(perms.manage), (req, res) => {
  const list = db.prepare('SELECT id, name FROM board_lists WHERE id = ? AND channel_id = ?').get(req.params.listId, req.channel.id);
  if (!list) return res.status(404).json({ error: 'List not found' });
  const cards = db.prepare('SELECT COUNT(*) AS c FROM channel_items WHERE list_id = ?').get(list.id).c;
  db.transaction(() => {
    db.prepare('DELETE FROM board_lists WHERE id = ?').run(list.id);
    setOrder('board_lists', rawLists(req.channel.id).map((l) => l.id));
  })();
  logAuditAction('CHANNEL_ITEM_DELETE', req.user.id, {
    targetType: 'list', targetId: list.id, channelId: req.channel.id, details: { name: list.name, cards },
  });
  emitToChannel(req.channel.id, 'board:list-deleted', { channelId: req.channel.id, listId: list.id });
  emitLists(req.channel.id);
  res.json({ ok: true });
});

// ── Cards ─────────────────────────────────────────────────────────────────
// A list the requester cannot see is "not found", the same as a missing one.
const findList = (req, listId) => typeof listId === 'string' && canSeeListId(req, listId);

// POST /api/boards/:channelId/cards { listId, title, body?, dueAt?, labelIds?, assigneeIds? }
router.post('/:channelId/cards', loadChannel, require_(perms.create), handle((req, res) => {
  const body = req.body ?? {};
  if (!findList(req, body.listId)) throw new InputError('List not found', 404);
  const id = db.transaction(() => createItem(req, {
    list_id: body.listId,
    position: cardIds(body.listId).length,
    due_at: body.dueAt === undefined ? null : dueAt(body.dueAt),
  }))();
  res.status(201).json(emitItem(id, 'created'));
}));

// PUT /api/boards/:channelId/cards/:itemId/position { listId, index }
// Anyone who can create cards can move them. The server renumbers both lists in
// one transaction and broadcasts the resulting order, so clients never merge.
router.put('/:channelId/cards/:itemId/position', loadChannel, loadItem, require_(perms.create), handle((req, res) => {
  const { listId, index } = req.body ?? {};
  if (!findList(req, listId)) throw new InputError('List not found', 404);
  if (!Number.isInteger(index) || index < 0) throw new InputError('index must be a non-negative integer');
  if (req.item.archived) throw new InputError('Archived cards cannot be moved');
  const from = req.item.list_id;
  const lists = db.transaction(() => {
    const target = cardIds(listId).filter((id) => id !== req.item.id);
    target.splice(Math.min(index, target.length), 0, req.item.id);
    db.prepare('UPDATE channel_items SET list_id = ?, updated_at = unixepoch() WHERE id = ?').run(listId, req.item.id);
    setOrder('channel_items', target);
    const changed = [{ listId, cardIds: target }];
    if (from !== listId) {
      const source = cardIds(from);
      setOrder('channel_items', source);
      changed.push({ listId: from, cardIds: source });
      items.recordEvent(db, req.item.id, req.user.id, 'moved', { from, to: listId });
    }
    return changed;
  })();
  // A member who sees only one of the two lists gets just that list's order: the
  // card leaves the list they can see, or turns up in it.
  emitFiltered(req.channel.id, 'board:cards-moved', (_viewer, visible) => {
    const seen = lists.filter((list) => visible.has(list.listId));
    return seen.length ? { channelId: req.channel.id, cardId: req.item.id, lists: seen } : null;
  });
  res.json({ lists });
}));

module.exports = router;
