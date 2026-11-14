'use strict';

// Shared backend for Tracker issues and Board cards. Both are rows in
// channel_items, so labels, assignees, comments and the timeline exist once.
const { randomUUID } = require('crypto');
const { encryptMessageContent, decryptMessageContent } = require('./messageCrypto');
const { hasChannelPermission, computePermissionKeysForUser } = require('./permissions');

const LIMITS = Object.freeze({
  title: 200, body: 20000, comment: 10000, labelName: 50, listName: 100,
  labelsPerChannel: 100, labelsPerItem: 20, assigneesPerItem: 20, listsPerBoard: 50,
});

// Granted to the default role once, when the tables are first created, so new
// channel types work for members the way forums do. Admins can revoke them.
const DEFAULT_MEMBER_KEYS = ['CREATE_ISSUES', 'COMMENT_ON_ISSUES', 'CREATE_CARDS', 'COMMENT_ON_CARDS'];

function migrate(db) {
  const fresh = !db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'channel_items'").get();
  db.exec(`
    CREATE TABLE IF NOT EXISTS board_lists (
      id          TEXT PRIMARY KEY,
      channel_id  TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      position    INTEGER NOT NULL DEFAULT 0,
      created_at  INTEGER NOT NULL DEFAULT (unixepoch())
    );
    CREATE INDEX IF NOT EXISTS idx_board_lists_channel ON board_lists(channel_id, position);

    CREATE TABLE IF NOT EXISTS channel_items (
      id          TEXT PRIMARY KEY,
      channel_id  TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      kind        TEXT NOT NULL CHECK(kind IN ('issue', 'card')),
      title       TEXT NOT NULL,
      body        TEXT NOT NULL DEFAULT '',
      created_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
      created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
      updated_at  INTEGER NOT NULL DEFAULT (unixepoch()),
      -- issues
      number      INTEGER,
      state       TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open', 'closed')),
      closed_at   INTEGER,
      closed_by   TEXT,
      -- cards
      list_id     TEXT REFERENCES board_lists(id) ON DELETE CASCADE,
      position    INTEGER NOT NULL DEFAULT 0,
      due_at      INTEGER,
      archived    INTEGER NOT NULL DEFAULT 0
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_channel_items_number ON channel_items(channel_id, number) WHERE number IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_channel_items_channel ON channel_items(channel_id, kind, state);
    CREATE INDEX IF NOT EXISTS idx_channel_items_list ON channel_items(list_id, position);

    -- Issue numbers are never reused, even after the newest issue is deleted.
    CREATE TABLE IF NOT EXISTS channel_item_counters (
      channel_id  TEXT PRIMARY KEY REFERENCES channels(id) ON DELETE CASCADE,
      last_number INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS channel_item_labels (
      id          TEXT PRIMARY KEY,
      channel_id  TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      name        TEXT NOT NULL,
      color       TEXT NOT NULL,
      UNIQUE(channel_id, name)
    );
    CREATE TABLE IF NOT EXISTS channel_item_label_links (
      item_id   TEXT NOT NULL REFERENCES channel_items(id) ON DELETE CASCADE,
      label_id  TEXT NOT NULL REFERENCES channel_item_labels(id) ON DELETE CASCADE,
      PRIMARY KEY (item_id, label_id)
    );
    CREATE TABLE IF NOT EXISTS channel_item_assignees (
      item_id  TEXT NOT NULL REFERENCES channel_items(id) ON DELETE CASCADE,
      user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (item_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_channel_item_assignees_user ON channel_item_assignees(user_id);
    CREATE TABLE IF NOT EXISTS channel_item_comments (
      id          TEXT PRIMARY KEY,
      item_id     TEXT NOT NULL REFERENCES channel_items(id) ON DELETE CASCADE,
      user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
      body        TEXT NOT NULL,
      created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
      edited_at   INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_channel_item_comments_item ON channel_item_comments(item_id, created_at);
    CREATE TABLE IF NOT EXISTS channel_item_events (
      id          TEXT PRIMARY KEY,
      item_id     TEXT NOT NULL REFERENCES channel_items(id) ON DELETE CASCADE,
      actor_id    TEXT,
      type        TEXT NOT NULL,
      data        TEXT,
      created_at  INTEGER NOT NULL DEFAULT (unixepoch())
    );
    CREATE INDEX IF NOT EXISTS idx_channel_item_events_item ON channel_item_events(item_id, created_at);
  `);
  if (fresh) {
    const grant = db.prepare(`INSERT OR IGNORE INTO role_permission_grants (role_id, permission_key)
      SELECT id, ? FROM roles WHERE is_default = 1`);
    for (const key of DEFAULT_MEMBER_KEYS) grant.run(key);
  }
}

// Permission checks bound to one database handle.
function access(db) {
  const can = (user, channelId, key) => hasChannelPermission(user, channelId, key, db);
  // Used for assignees: someone who cannot see the channel cannot be assigned.
  const canUserIdView = (userId, channelId) => {
    const user = db.prepare('SELECT id, role, is_owner FROM users WHERE id = ?').get(userId);
    if (!user) return false;
    const permission_keys = computePermissionKeysForUser(user.id, user.role, user.is_owner, db);
    return can({ ...user, permission_keys }, channelId, 'VIEW_CHANNELS');
  };
  return { can, canUserIdView };
}

class InputError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

function text(value, max, label, { required = true } = {}) {
  if (value === undefined || value === null) value = '';
  if (typeof value !== 'string') throw new InputError(`${label} must be text`);
  const trimmed = value.trim();
  if (required && !trimmed) throw new InputError(`${label} required`);
  if (trimmed.length > max) throw new InputError(`${label} is too long (max ${max})`);
  return trimmed;
}

function idList(value, max, label) {
  if (!Array.isArray(value) || value.some((id) => typeof id !== 'string')) throw new InputError(`${label} must be a list of ids`);
  const ids = [...new Set(value)];
  if (ids.length > max) throw new InputError(`Too many ${label} (max ${max})`);
  return ids;
}

function placeholders(list) { return list.map(() => '?').join(', '); }

function userSummaries(db, ids) {
  const unique = [...new Set(ids.filter(Boolean))];
  if (unique.length === 0) return new Map();
  const rows = db.prepare(`
    SELECT u.id, u.username, u.avatar, u.account_type,
      COALESCE(dno.display_name, u.display_name) AS display_name
    FROM users u LEFT JOIN display_name_overrides dno ON dno.user_id = u.id
    WHERE u.id IN (${placeholders(unique)})
  `).all(...unique);
  return new Map(rows.map((row) => [row.id, row]));
}

// Turns channel_items rows into API objects with labels, assignees and author.
function serializeItems(db, rows) {
  if (rows.length === 0) return [];
  const ids = rows.map((row) => row.id);
  const marks = placeholders(ids);
  const labels = db.prepare(`SELECT item_id, label_id FROM channel_item_label_links WHERE item_id IN (${marks})`).all(...ids);
  const assignees = db.prepare(`SELECT item_id, user_id FROM channel_item_assignees WHERE item_id IN (${marks})`).all(...ids);
  const comments = db.prepare(`SELECT item_id, COUNT(*) AS count FROM channel_item_comments WHERE item_id IN (${marks}) GROUP BY item_id`).all(...ids);
  const users = userSummaries(db, [...rows.map((row) => row.created_by), ...assignees.map((a) => a.user_id)]);
  const commentCounts = new Map(comments.map((c) => [c.item_id, c.count]));
  return rows.map((row) => {
    const item = {
      id: row.id,
      channel_id: row.channel_id,
      title: row.title,
      body: decryptMessageContent(row.body),
      created_by: row.created_by,
      author: users.get(row.created_by) || null,
      created_at: row.created_at,
      updated_at: row.updated_at,
      label_ids: labels.filter((l) => l.item_id === row.id).map((l) => l.label_id),
      assignees: assignees.filter((a) => a.item_id === row.id).map((a) => users.get(a.user_id)).filter(Boolean),
      comment_count: commentCounts.get(row.id) || 0,
    };
    return row.kind === 'issue'
      ? { ...item, number: row.number, state: row.state, closed_at: row.closed_at, closed_by: row.closed_by }
      : { ...item, list_id: row.list_id, position: row.position, due_at: row.due_at, archived: !!row.archived };
  });
}

function serializeComments(db, rows) {
  const users = userSummaries(db, rows.map((row) => row.user_id));
  return rows.map((row) => ({
    id: row.id, item_id: row.item_id, user_id: row.user_id, author: users.get(row.user_id) || null,
    body: decryptMessageContent(row.body), created_at: row.created_at, edited_at: row.edited_at,
  }));
}

function listLabels(db, channelId) {
  return db.prepare('SELECT id, name, color FROM channel_item_labels WHERE channel_id = ? ORDER BY name COLLATE NOCASE').all(channelId);
}

function recordEvent(db, itemId, actorId, type, data = null) {
  db.prepare('INSERT INTO channel_item_events (id, item_id, actor_id, type, data) VALUES (?, ?, ?, ?, ?)')
    .run(randomUUID(), itemId, actorId, type, data ? JSON.stringify(data) : null);
}

function setLabels(db, item, labelIds, actorId) {
  const ids = idList(labelIds, LIMITS.labelsPerItem, 'labels');
  if (ids.length) {
    const known = db.prepare(`SELECT id FROM channel_item_labels WHERE channel_id = ? AND id IN (${placeholders(ids)})`)
      .all(item.channel_id, ...ids);
    if (known.length !== ids.length) throw new InputError('Unknown label');
  }
  const before = db.prepare('SELECT label_id FROM channel_item_label_links WHERE item_id = ?').all(item.id).map((r) => r.label_id);
  const added = ids.filter((id) => !before.includes(id));
  const removed = before.filter((id) => !ids.includes(id));
  if (!added.length && !removed.length) return false;
  db.prepare('DELETE FROM channel_item_label_links WHERE item_id = ?').run(item.id);
  const insert = db.prepare('INSERT INTO channel_item_label_links (item_id, label_id) VALUES (?, ?)');
  for (const id of ids) insert.run(item.id, id);
  recordEvent(db, item.id, actorId, 'labels', { added, removed });
  return true;
}

// canView(userId) keeps people who cannot see the channel from being assigned.
function setAssignees(db, item, userIds, actorId, canView) {
  const ids = idList(userIds, LIMITS.assigneesPerItem, 'assignees');
  const before = db.prepare('SELECT user_id FROM channel_item_assignees WHERE item_id = ?').all(item.id).map((r) => r.user_id);
  const added = ids.filter((id) => !before.includes(id));
  const removed = before.filter((id) => !ids.includes(id));
  if (added.some((id) => !canView(id))) throw new InputError('Assignee cannot view this channel');
  if (!added.length && !removed.length) return false;
  db.prepare('DELETE FROM channel_item_assignees WHERE item_id = ?').run(item.id);
  const insert = db.prepare('INSERT INTO channel_item_assignees (item_id, user_id) VALUES (?, ?)');
  for (const id of ids) insert.run(item.id, id);
  recordEvent(db, item.id, actorId, 'assignees', { added, removed });
  return true;
}

/**
 * Installs the endpoints Tracker and Boards share onto `router`:
 * labels, item detail/edit/delete, assignees and comments.
 *
 * config: { kind, channelType, noun, plural, prefix, perms: { create, comment, assign, manage },
 *           patchExtra?(req, item, canEdit) -> { sets, events } }
 * deps:   { db, emit(channelId, event, data), audit(action, actorId, info) }
 */
function installSharedRoutes(router, config, deps) {
  const { kind, channelType, noun, plural, prefix, perms } = config;
  const { db, emit, audit } = deps;
  const { can, canUserIdView } = access(db);

  const handle = (fn) => (req, res) => {
    try {
      fn(req, res);
    } catch (error) {
      if (error instanceof InputError) return res.status(error.status).json({ error: error.message });
      throw error;
    }
  };

  function loadChannel(req, res, next) {
    const channel = db.prepare('SELECT id, type FROM channels WHERE id = ?').get(req.params.channelId);
    if (!channel || channel.type !== channelType) return res.status(404).json({ error: `Not a ${channelType} channel` });
    if (!can(req.user, channel.id, 'VIEW_CHANNELS') || !can(req.user, channel.id, 'READ_CHAT_HISTORY')) {
      return res.status(403).json({ error: 'Missing permission: view_channels' });
    }
    req.channel = channel;
    next();
  }

  // :itemId accepts the item id, or the issue number for trackers.
  function loadItem(req, res, next) {
    const ref = req.params.itemId;
    const number = /^\d{1,9}$/.test(ref) ? Number(ref) : null;
    const item = db.prepare('SELECT * FROM channel_items WHERE channel_id = ? AND kind = ? AND (id = ? OR number = ?)')
      .get(req.channel.id, kind, ref, number);
    if (!item) return res.status(404).json({ error: `${noun} not found` });
    req.item = item;
    next();
  }

  const require_ = (key) => (req, res, next) => (can(req.user, req.channel.id, key)
    ? next() : res.status(403).json({ error: `Missing permission: ${key.toLowerCase()}` }));
  const canManage = (req) => can(req.user, req.channel.id, perms.manage);
  const canEdit = (req) => req.item.created_by === req.user.id || canManage(req);
  const serializeOne = (id) => serializeItems(db, [db.prepare('SELECT * FROM channel_items WHERE id = ?').get(id)])[0];
  const emitItem = (id, event = 'updated') => {
    const item = serializeOne(id);
    emit(item.channel_id, `${prefix}:${noun}-${event}`, item);
    return item;
  };
  const emitLabels = (channelId) => emit(channelId, `${prefix}:labels-updated`, { channelId, labels: listLabels(db, channelId) });

  // ── Labels ──────────────────────────────────────────────────────────────
  const labelInput = (body) => {
    const color = typeof body?.color === 'string' ? body.color.trim().toLowerCase() : '';
    if (!/^#[0-9a-f]{6}$/.test(color)) throw new InputError('color must be a hex color like #ff8800');
    return { name: text(body?.name, LIMITS.labelName, 'Label name'), color };
  };
  const labelTaken = (channelId, name, exceptId = '') => !!db.prepare(
    'SELECT 1 FROM channel_item_labels WHERE channel_id = ? AND name = ? COLLATE NOCASE AND id != ?'
  ).get(channelId, name, exceptId);

  router.get('/:channelId/labels', loadChannel, (req, res) => res.json(listLabels(db, req.channel.id)));

  router.post('/:channelId/labels', loadChannel, require_(perms.manage), handle((req, res) => {
    const { name, color } = labelInput(req.body);
    const count = db.prepare('SELECT COUNT(*) AS c FROM channel_item_labels WHERE channel_id = ?').get(req.channel.id).c;
    if (count >= LIMITS.labelsPerChannel) throw new InputError(`Label limit reached (${LIMITS.labelsPerChannel})`);
    if (labelTaken(req.channel.id, name)) throw new InputError('A label with that name already exists', 409);
    const id = randomUUID();
    db.prepare('INSERT INTO channel_item_labels (id, channel_id, name, color) VALUES (?, ?, ?, ?)').run(id, req.channel.id, name, color);
    emitLabels(req.channel.id);
    res.status(201).json({ id, name, color });
  }));

  router.patch('/:channelId/labels/:labelId', loadChannel, require_(perms.manage), handle((req, res) => {
    const { name, color } = labelInput(req.body);
    if (labelTaken(req.channel.id, name, req.params.labelId)) throw new InputError('A label with that name already exists', 409);
    const result = db.prepare('UPDATE channel_item_labels SET name = ?, color = ? WHERE id = ? AND channel_id = ?')
      .run(name, color, req.params.labelId, req.channel.id);
    if (!result.changes) return res.status(404).json({ error: 'Label not found' });
    emitLabels(req.channel.id);
    res.json({ id: req.params.labelId, name, color });
  }));

  router.delete('/:channelId/labels/:labelId', loadChannel, require_(perms.manage), (req, res) => {
    const result = db.prepare('DELETE FROM channel_item_labels WHERE id = ? AND channel_id = ?').run(req.params.labelId, req.channel.id);
    if (!result.changes) return res.status(404).json({ error: 'Label not found' });
    emitLabels(req.channel.id);
    res.json({ ok: true });
  });

  // ── Item detail / edit / delete ─────────────────────────────────────────
  router.get(`/:channelId/${plural}/:itemId`, loadChannel, loadItem, (req, res) => {
    const comments = db.prepare('SELECT * FROM channel_item_comments WHERE item_id = ? ORDER BY created_at, rowid').all(req.item.id);
    const events = db.prepare('SELECT id, actor_id, type, data, created_at FROM channel_item_events WHERE item_id = ? ORDER BY created_at, rowid')
      .all(req.item.id).map((event) => ({ ...event, data: event.data ? JSON.parse(event.data) : null }));
    res.json({ ...serializeItems(db, [req.item])[0], comments: serializeComments(db, comments), events });
  });

  router.patch(`/:channelId/${plural}/:itemId`, loadChannel, loadItem, handle((req, res) => {
    if (!canEdit(req)) return res.status(403).json({ error: `Not allowed to edit this ${noun}` });
    const body = req.body ?? {};
    const sets = {};
    const events = [];
    if (body.title !== undefined) {
      sets.title = text(body.title, LIMITS.title, 'Title');
      if (sets.title !== req.item.title) events.push(['renamed', { from: req.item.title, to: sets.title }]);
    }
    if (body.body !== undefined) sets.body = encryptMessageContent(text(body.body, LIMITS.body, 'Body', { required: false }));
    if (config.patchExtra) {
      const extra = config.patchExtra(req, req.item);
      Object.assign(sets, extra.sets);
      events.push(...extra.events);
    }
    db.transaction(() => {
      const columns = Object.keys(sets);
      db.prepare(`UPDATE channel_items SET ${columns.map((c) => `${c} = ?`).join(', ')}${columns.length ? ', ' : ''}updated_at = unixepoch() WHERE id = ?`)
        .run(...columns.map((c) => sets[c]), req.item.id);
      for (const [type, data] of events) recordEvent(db, req.item.id, req.user.id, type, data);
      if (body.labelIds !== undefined) setLabels(db, req.item, body.labelIds, req.user.id);
    })();
    res.json(emitItem(req.item.id));
  }));

  router.delete(`/:channelId/${plural}/:itemId`, loadChannel, loadItem, require_(perms.manage), (req, res) => {
    db.prepare('DELETE FROM channel_items WHERE id = ?').run(req.item.id);
    audit('CHANNEL_ITEM_DELETE', req.user.id, {
      targetType: noun, targetId: req.item.id, channelId: req.channel.id,
      details: { title: req.item.title, number: req.item.number ?? undefined, author: req.item.created_by },
    });
    emit(req.channel.id, `${prefix}:${noun}-deleted`, { channelId: req.channel.id, id: req.item.id });
    res.json({ ok: true });
  });

  // ── Assignees ───────────────────────────────────────────────────────────
  router.put(`/:channelId/${plural}/:itemId/assignees`, loadChannel, loadItem, require_(perms.assign), handle((req, res) => {
    db.transaction(() => {
      if (setAssignees(db, req.item, req.body?.userIds, req.user.id, (id) => canUserIdView(id, req.channel.id))) {
        db.prepare('UPDATE channel_items SET updated_at = unixepoch() WHERE id = ?').run(req.item.id);
      }
    })();
    res.json(emitItem(req.item.id));
  }));

  // ── Comments ────────────────────────────────────────────────────────────
  const loadComment = (req, res, next) => {
    const comment = db.prepare('SELECT * FROM channel_item_comments WHERE id = ? AND item_id = ?').get(req.params.commentId, req.item.id);
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    req.comment = comment;
    next();
  };
  const emitComment = (req, event, payload) => emit(req.channel.id, `${prefix}:comment-${event}`,
    { channelId: req.channel.id, itemId: req.item.id, ...payload });

  router.post(`/:channelId/${plural}/:itemId/comments`, loadChannel, loadItem, require_(perms.comment), handle((req, res) => {
    const body = text(req.body?.body, LIMITS.comment, 'Comment');
    const id = randomUUID();
    db.prepare('INSERT INTO channel_item_comments (id, item_id, user_id, body) VALUES (?, ?, ?, ?)')
      .run(id, req.item.id, req.user.id, encryptMessageContent(body));
    db.prepare('UPDATE channel_items SET updated_at = unixepoch() WHERE id = ?').run(req.item.id);
    const [comment] = serializeComments(db, [db.prepare('SELECT * FROM channel_item_comments WHERE id = ?').get(id)]);
    emitComment(req, 'created', { comment });
    res.status(201).json(comment);
  }));

  router.patch(`/:channelId/${plural}/:itemId/comments/:commentId`, loadChannel, loadItem, loadComment, handle((req, res) => {
    if (req.comment.user_id !== req.user.id) return res.status(403).json({ error: 'Only the author can edit a comment' });
    const body = text(req.body?.body, LIMITS.comment, 'Comment');
    db.prepare('UPDATE channel_item_comments SET body = ?, edited_at = unixepoch() WHERE id = ?').run(encryptMessageContent(body), req.comment.id);
    const [comment] = serializeComments(db, [db.prepare('SELECT * FROM channel_item_comments WHERE id = ?').get(req.comment.id)]);
    emitComment(req, 'updated', { comment });
    res.json(comment);
  }));

  router.delete(`/:channelId/${plural}/:itemId/comments/:commentId`, loadChannel, loadItem, loadComment, (req, res) => {
    if (req.comment.user_id !== req.user.id && !canManage(req)) return res.status(403).json({ error: 'Not allowed to delete this comment' });
    db.prepare('DELETE FROM channel_item_comments WHERE id = ?').run(req.comment.id);
    emitComment(req, 'deleted', { commentId: req.comment.id });
    res.json({ ok: true });
  });

  // Creates an item with optional labels/assignees; call inside a transaction.
  const createItem = (req, columns) => {
    const input = req.body ?? {};
    const id = randomUUID();
    const row = {
      id, channel_id: req.channel.id, kind, created_by: req.user.id,
      title: text(input.title, LIMITS.title, 'Title'),
      body: encryptMessageContent(text(input.body, LIMITS.body, 'Body', { required: false })),
      ...columns,
    };
    const names = Object.keys(row);
    db.prepare(`INSERT INTO channel_items (${names.join(', ')}) VALUES (${placeholders(names)})`).run(...names.map((n) => row[n]));
    if (input.labelIds?.length) setLabels(db, row, input.labelIds, null);
    if (input.assigneeIds?.length) {
      if (!can(req.user, req.channel.id, perms.assign)) throw new InputError(`Missing permission: ${perms.assign.toLowerCase()}`, 403);
      setAssignees(db, row, input.assigneeIds, null, (userId) => canUserIdView(userId, req.channel.id));
    }
    // The timeline starts after creation; initial labels/assignees are not events.
    db.prepare('DELETE FROM channel_item_events WHERE item_id = ?').run(id);
    return id;
  };

  return { handle, loadChannel, loadItem, require_, can, emitItem, createItem };
}

module.exports = {
  LIMITS, InputError, migrate, text, idList, placeholders, serializeItems, listLabels,
  recordEvent, installSharedRoutes,
};
