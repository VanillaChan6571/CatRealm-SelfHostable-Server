// Tracker channels: GitHub-style issues. Mounted at /api/tracker.
const router = require('express').Router();
const db = require('../db');
const { emitToChannel } = require('../socket/handler');
const { logAuditAction } = require('../lib/auditLog');
const items = require('../channelItems');

const perms = { create: 'CREATE_ISSUES', comment: 'COMMENT_ON_ISSUES', assign: 'ASSIGN_ISSUES', manage: 'MANAGE_ISSUES' };
// Closing and reopening: the author or a manager, same as other edits.
function patchExtra(req, item) {
  const { state } = req.body ?? {};
  if (state === undefined || state === item.state) return { sets: {}, events: [] };
  if (state !== 'open' && state !== 'closed') throw new items.InputError('state must be open or closed');
  const closing = state === 'closed';
  return {
    sets: { state, closed_at: closing ? Math.floor(Date.now() / 1000) : null, closed_by: closing ? req.user.id : null },
    events: [[closing ? 'closed' : 'reopened', null]],
  };
}

const shared = items.installSharedRoutes(router, {
  kind: 'issue', channelType: 'tracker', noun: 'issue', plural: 'issues', prefix: 'tracker', perms, patchExtra,
}, { db, emit: emitToChannel, audit: logAuditAction });
const { handle, loadChannel, require_, emitItem, createItem } = shared;

// GET /api/tracker/:channelId/issues?state=open|closed|all&label=&assignee=&author=&q=&before=&limit=

router.get('/:channelId/issues', loadChannel, (req, res) => {
  const { state = 'open', label, assignee, author, q } = req.query;
  const where = ["i.channel_id = ?", "i.kind = 'issue'"];
  const args = [req.channel.id];
  if (state === 'open' || state === 'closed') { where.push('i.state = ?'); args.push(state); }
  if (typeof label === 'string' && label) {
    where.push('EXISTS (SELECT 1 FROM channel_item_label_links l WHERE l.item_id = i.id AND l.label_id = ?)');
    args.push(label);
  }
  if (typeof assignee === 'string' && assignee) {
    where.push('EXISTS (SELECT 1 FROM channel_item_assignees a WHERE a.item_id = i.id AND a.user_id = ?)');
    args.push(assignee);
  }
  if (typeof author === 'string' && author) { where.push('i.created_by = ?'); args.push(author); }
  // Titles only: bodies may be encrypted at rest.
  if (typeof q === 'string' && q.trim()) {
    where.push("i.title LIKE ? ESCAPE '\\'");
    args.push(`%${q.trim().slice(0, 100).replace(/[\\%_]/g, '\\$&')}%`);
  }
  const before = Number.parseInt(req.query.before, 10);
  if (Number.isInteger(before)) { where.push('i.number < ?'); args.push(before); }
  const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 100);

  const rows = db.prepare(`SELECT i.* FROM channel_items i WHERE ${where.join(' AND ')} ORDER BY i.number DESC LIMIT ?`).all(...args, limit);
  const counts = { open: 0, closed: 0 };
  for (const row of db.prepare("SELECT state, COUNT(*) AS c FROM channel_items WHERE channel_id = ? AND kind = 'issue' GROUP BY state").all(req.channel.id)) {
    counts[row.state] = row.c;
  }
  res.json({ issues: items.serializeItems(db, rows), counts, hasMore: rows.length === limit });
});

// POST /api/tracker/:channelId/issues { title, body?, labelIds?, assigneeIds? }
router.post('/:channelId/issues', loadChannel, require_(perms.create), handle((req, res) => {
  const id = db.transaction(() => {
    db.prepare(`INSERT INTO channel_item_counters (channel_id, last_number) VALUES (?, 1)
      ON CONFLICT(channel_id) DO UPDATE SET last_number = last_number + 1`).run(req.channel.id);
    const number = db.prepare('SELECT last_number FROM channel_item_counters WHERE channel_id = ?').get(req.channel.id).last_number;
    return createItem(req, { number });
  })();
  res.status(201).json(emitItem(id, 'created'));
}));

module.exports = router;
