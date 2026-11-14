// Board channels: Trello-style lists of cards. Mounted at /api/boards.
const router = require('express').Router();
const { randomUUID } = require('crypto');
const db = require('../db');
const { emitToChannel } = require('../socket/handler');
const { logAuditAction } = require('../lib/auditLog');
const items = require('../channelItems');

const { InputError, LIMITS } = items;
const perms = { create: 'CREATE_CARDS', comment: 'COMMENT_ON_CARDS', assign: 'ASSIGN_CARDS', manage: 'MANAGE_BOARDS' };
function dueAt(value) {
  if (value === null) return null;
  if (!Number.isInteger(value) || value < 0 || value > 32503680000) throw new InputError('dueAt must be a unix timestamp or null');
  return value;
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

const shared = items.installSharedRoutes(router, {
  kind: 'card', channelType: 'board', noun: 'card', plural: 'cards', prefix: 'board', perms, patchExtra,
}, { db, emit: emitToChannel, audit: logAuditAction });
const { handle, loadChannel, loadItem, require_, emitItem, createItem } = shared;

const getLists = (channelId) => db.prepare('SELECT id, name, position FROM board_lists WHERE channel_id = ? ORDER BY position').all(channelId);
const emitLists = (channelId) => emitToChannel(channelId, 'board:lists-updated', { channelId, lists: getLists(channelId) });
const cardIds = (listId) => db.prepare('SELECT id FROM channel_items WHERE list_id = ? AND archived = 0 ORDER BY position').all(listId).map((r) => r.id);
const setOrder = (table, ids) => {
  const update = db.prepare(`UPDATE ${table} SET position = ? WHERE id = ?`);
  ids.forEach((id, index) => update.run(index, id));
};

// GET /api/boards/:channelId?archived=1 — the whole board in one response.
router.get('/:channelId', loadChannel, (req, res) => {
  const archived = req.query.archived === '1' ? 1 : 0;
  const cards = db.prepare("SELECT * FROM channel_items WHERE channel_id = ? AND kind = 'card' AND archived = ? ORDER BY position")
    .all(req.channel.id, archived);
  res.json({ lists: getLists(req.channel.id), cards: items.serializeItems(db, cards), labels: items.listLabels(db, req.channel.id) });
});

// ── Lists (MANAGE_BOARDS) ─────────────────────────────────────────────────
router.post('/:channelId/lists', loadChannel, require_(perms.manage), handle((req, res) => {
  const name = items.text(req.body?.name, LIMITS.listName, 'List name');
  const lists = getLists(req.channel.id);
  if (lists.length >= LIMITS.listsPerBoard) throw new InputError(`List limit reached (${LIMITS.listsPerBoard})`);
  const id = randomUUID();
  db.prepare('INSERT INTO board_lists (id, channel_id, name, position) VALUES (?, ?, ?, ?)').run(id, req.channel.id, name, lists.length);
  emitLists(req.channel.id);
  res.status(201).json({ id, name, position: lists.length });
}));

// PUT /api/boards/:channelId/lists/order { listIds } — every list exactly once.
router.put('/:channelId/lists/order', loadChannel, require_(perms.manage), handle((req, res) => {
  const ids = items.idList(req.body?.listIds, LIMITS.listsPerBoard, 'lists');
  const current = getLists(req.channel.id).map((list) => list.id);
  if (ids.length !== current.length || current.some((id) => !ids.includes(id))) throw new InputError('listIds must contain every list exactly once');
  db.transaction(() => setOrder('board_lists', ids))();
  emitLists(req.channel.id);
  res.json(getLists(req.channel.id));
}));

router.patch('/:channelId/lists/:listId', loadChannel, require_(perms.manage), handle((req, res) => {
  const name = items.text(req.body?.name, LIMITS.listName, 'List name');
  const result = db.prepare('UPDATE board_lists SET name = ? WHERE id = ? AND channel_id = ?').run(name, req.params.listId, req.channel.id);
  if (!result.changes) return res.status(404).json({ error: 'List not found' });
  emitLists(req.channel.id);
  res.json({ id: req.params.listId, name });
}));

// Deleting a list deletes its cards (foreign key cascade).
router.delete('/:channelId/lists/:listId', loadChannel, require_(perms.manage), (req, res) => {
  const list = db.prepare('SELECT id, name FROM board_lists WHERE id = ? AND channel_id = ?').get(req.params.listId, req.channel.id);
  if (!list) return res.status(404).json({ error: 'List not found' });
  const cards = db.prepare('SELECT COUNT(*) AS c FROM channel_items WHERE list_id = ?').get(list.id).c;
  db.transaction(() => {
    db.prepare('DELETE FROM board_lists WHERE id = ?').run(list.id);
    setOrder('board_lists', getLists(req.channel.id).map((l) => l.id));
  })();
  logAuditAction('CHANNEL_ITEM_DELETE', req.user.id, {
    targetType: 'list', targetId: list.id, channelId: req.channel.id, details: { name: list.name, cards },
  });
  emitToChannel(req.channel.id, 'board:list-deleted', { channelId: req.channel.id, listId: list.id });
  emitLists(req.channel.id);
  res.json({ ok: true });
});

// ── Cards ─────────────────────────────────────────────────────────────────
const findList = (channelId, listId) => typeof listId === 'string'
  && db.prepare('SELECT id FROM board_lists WHERE id = ? AND channel_id = ?').get(listId, channelId);

// POST /api/boards/:channelId/cards { listId, title, body?, dueAt?, labelIds?, assigneeIds? }
router.post('/:channelId/cards', loadChannel, require_(perms.create), handle((req, res) => {
  const body = req.body ?? {};
  if (!findList(req.channel.id, body.listId)) throw new InputError('List not found', 404);
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
  if (!findList(req.channel.id, listId)) throw new InputError('List not found', 404);
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
  emitToChannel(req.channel.id, 'board:cards-moved', { channelId: req.channel.id, cardId: req.item.id, lists });
  res.json({ lists });
}));

module.exports = router;
