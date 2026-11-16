// Tracker channels: GitHub-style issues. Mounted at /api/tracker.
const router = require('express').Router();
const path = require('path');
const fs = require('fs');
const { randomUUID } = require('crypto');
const multer = require('multer');
const db = require('../db');
const { emitToChannel, emitToUserSockets } = require('../socket/handler');
const { logAuditAction } = require('../lib/auditLog');
const items = require('../channelItems');
const { backgroundInput } = require('../workItemBackground');
const { hasChannelPermission, computePermissionKeysForUser } = require('../permissions');
const { removeLocalUploads } = require('../lib/uploadPaths');

const perms = { create: 'CREATE_ISSUES', comment: 'COMMENT_ON_ISSUES', assign: 'ASSIGN_ISSUES', manage: 'MANAGE_ISSUES' };
const STATES = new Set(['open', 'in_progress', 'blocked', 'closed']);
const PRIORITIES = new Set(['low', 'normal', 'high', 'urgent']);
const MAX_DUE_AT = 253402300799; // 9999-12-31 in Unix seconds
const MAX_ATTACHMENTS = 20;
const MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024;

function priorityInput(value) {
  if (typeof value !== 'string' || !PRIORITIES.has(value)) throw new items.InputError('priority must be low, normal, high or urgent');
  return value;
}

function dueInput(value) {
  if (value === null) return null;
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_DUE_AT) throw new items.InputError('dueAt must be a Unix timestamp or null');
  return value;
}

function detailExtra(req, item) {
  return {
    watching: !!db.prepare('SELECT 1 FROM tracker_issue_watchers WHERE item_id = ? AND user_id = ?').get(item.id, req.user.id),
    watcher_count: db.prepare('SELECT COUNT(*) AS count FROM tracker_issue_watchers WHERE item_id = ?').get(item.id).count,
    attachments: db.prepare('SELECT id, name, url, mime, size, uploaded_by, created_at FROM tracker_issue_attachments WHERE item_id = ? ORDER BY created_at, rowid').all(item.id),
  };
}

function notifyWatchers(req, item, type) {
  const watchers = db.prepare('SELECT user_id FROM tracker_issue_watchers WHERE item_id = ? AND user_id != ?').all(item.id, req.user.id);
  const summary = type === 'commented' ? 'New comment' : type === 'attached' ? 'New attachment' : type === 'assigned' ? 'Assignees changed' : 'Issue updated';
  for (const { user_id: userId } of watchers) {
    const user = db.prepare('SELECT id, role, is_owner FROM users WHERE id = ?').get(userId);
    if (!user) continue;
    user.permission_keys = computePermissionKeysForUser(user.id, user.role, user.is_owner, db);
    if (!hasChannelPermission(user, item.channel_id, 'VIEW_CHANNELS', db)
      || !hasChannelPermission(user, item.channel_id, 'READ_CHAT_HISTORY', db)) continue;
    emitToUserSockets(userId, 'tracker:watch-notification', {
      channelId: item.channel_id, issueId: item.id, number: item.number, title: item.title,
      actorId: req.user.id, type, summary,
    });
  }
}
// State changes: the author, a manager, or someone the issue is assigned to.
function patchExtra(req, item) {
  const { state, priority, dueAt } = req.body ?? {};
  const sets = {};
  const events = [];
  if (state !== undefined) {
    if (!STATES.has(state)) throw new items.InputError('state must be open, in_progress, blocked or closed');
    if (state !== item.state) {
      sets.state = state;
      sets.closed_at = state === 'closed' ? Math.floor(Date.now() / 1000) : null;
      sets.closed_by = state === 'closed' ? req.user.id : null;
      if (state === 'closed') events.push(['closed', null]);
      else if (item.state === 'closed') events.push(['reopened', null]);
      if (item.state !== 'closed' && state !== 'closed') events.push(['state', { from: item.state, to: state }]);
      else if (item.state === 'closed' && state !== 'open') events.push(['state', { from: 'open', to: state }]);
    }
  }
  if (priority !== undefined) {
    sets.priority = priorityInput(priority);
    if (sets.priority !== item.priority) events.push(['priority', { from: item.priority, to: sets.priority }]);
  }
  if (dueAt !== undefined) {
    sets.due_at = dueInput(dueAt);
    if (sets.due_at !== item.due_at) events.push(['due_date', { from: item.due_at, to: sets.due_at }]);
  }
  return { sets, events };
}

const shared = items.installSharedRoutes(router, {
  kind: 'issue', channelType: 'tracker', noun: 'issue', plural: 'issues', prefix: 'tracker', perms, patchExtra,
  detailExtra, onChanged: notifyWatchers, assigneeFields: ['state'],
  prepareDelete: (_req, item) => {
    const urls = db.prepare('SELECT url FROM tracker_issue_attachments WHERE item_id = ?').all(item.id).map((row) => row.url);
    return () => removeLocalUploads(ATTACHMENT_DIR, urls);
  },
}, { db, emit: emitToChannel, audit: logAuditAction });
const { handle, loadChannel, loadItem, require_, emitItem, createItem } = shared;

function trackerSettings(channelId) {
  const row = db.prepare('SELECT title, background FROM tracker_settings WHERE channel_id = ?').get(channelId);
  let background = null;
  if (row?.background) {
    try { background = JSON.parse(row.background); } catch { background = null; }
  }
  return { title: row?.title ?? null, background };
}

router.get('/:channelId/settings', loadChannel, (req, res) => {
  res.json(trackerSettings(req.channel.id));
});

router.patch('/:channelId/settings', loadChannel, require_(perms.manage), handle((req, res) => {
  const body = req.body ?? {};
  const current = trackerSettings(req.channel.id);
  const title = body.title === undefined ? current.title
    : body.title === null ? null : items.text(body.title, 100, 'Tracker title', { required: false }) || null;
  const background = body.background === undefined ? current.background : backgroundInput(body.background);
  db.prepare(`
    INSERT INTO tracker_settings (channel_id, title, background) VALUES (?, ?, ?)
    ON CONFLICT(channel_id) DO UPDATE SET title = excluded.title, background = excluded.background
  `).run(req.channel.id, title, background ? JSON.stringify(background) : null);
  const settings = trackerSettings(req.channel.id);
  emitToChannel(req.channel.id, 'tracker:settings-updated', { channelId: req.channel.id, settings });
  res.json(settings);
}));

// GET /api/tracker/:channelId/issues?state=active|open|in_progress|blocked|closed|all&label=&assignee=&author=&q=&before=&limit=

router.get('/:channelId/issues', loadChannel, (req, res) => {
  const { state = 'active', label, assignee, author, q } = req.query;
  const where = ["i.channel_id = ?", "i.kind = 'issue'"];
  const args = [req.channel.id];
  if (STATES.has(state)) { where.push('i.state = ?'); args.push(state); }
  else if (state === 'active') where.push("i.state != 'closed'");
  else if (state !== 'all') return res.status(400).json({ error: 'Invalid state filter' });
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
  const counts = { open: 0, in_progress: 0, blocked: 0, closed: 0 };
  for (const row of db.prepare("SELECT state, COUNT(*) AS c FROM channel_items WHERE channel_id = ? AND kind = 'issue' GROUP BY state").all(req.channel.id)) {
    counts[row.state] = row.c;
  }
  res.json({ issues: items.serializeItems(db, rows), counts, hasMore: rows.length === limit, settings: trackerSettings(req.channel.id) });
});

// POST /api/tracker/:channelId/issues { title, body?, labelIds?, assigneeIds?, priority?, dueAt? }
router.post('/:channelId/issues', loadChannel, require_(perms.create), handle((req, res) => {
  const priority = req.body?.priority === undefined ? 'normal' : priorityInput(req.body.priority);
  const due_at = req.body?.dueAt === undefined ? null : dueInput(req.body.dueAt);
  const id = db.transaction(() => {
    db.prepare(`INSERT INTO channel_item_counters (channel_id, last_number) VALUES (?, 1)
      ON CONFLICT(channel_id) DO UPDATE SET last_number = last_number + 1`).run(req.channel.id);
    const number = db.prepare('SELECT last_number FROM channel_item_counters WHERE channel_id = ?').get(req.channel.id).last_number;
    const id = createItem(req, { number, priority, due_at });
    db.prepare('INSERT INTO tracker_issue_watchers (item_id, user_id) VALUES (?, ?)').run(id, req.user.id);
    return id;
  })();
  res.status(201).json(emitItem(id, 'created'));
}));

function watchResult(req) {
  return {
    watching: !!db.prepare('SELECT 1 FROM tracker_issue_watchers WHERE item_id = ? AND user_id = ?').get(req.item.id, req.user.id),
    watcher_count: db.prepare('SELECT COUNT(*) AS count FROM tracker_issue_watchers WHERE item_id = ?').get(req.item.id).count,
  };
}

router.put('/:channelId/issues/:itemId/watch', loadChannel, loadItem, (req, res) => {
  db.prepare('INSERT OR IGNORE INTO tracker_issue_watchers (item_id, user_id) VALUES (?, ?)').run(req.item.id, req.user.id);
  const result = watchResult(req);
  emitToChannel(req.channel.id, 'tracker:watchers-updated', { channelId: req.channel.id, issueId: req.item.id, watcher_count: result.watcher_count });
  res.json(result);
});

router.delete('/:channelId/issues/:itemId/watch', loadChannel, loadItem, (req, res) => {
  db.prepare('DELETE FROM tracker_issue_watchers WHERE item_id = ? AND user_id = ?').run(req.item.id, req.user.id);
  const result = watchResult(req);
  emitToChannel(req.channel.id, 'tracker:watchers-updated', { channelId: req.channel.id, issueId: req.item.id, watcher_count: result.watcher_count });
  res.json(result);
});

const ATTACHMENT_MIMES = new Map([
  ['.png', 'image/png'], ['.jpg', 'image/jpeg'], ['.jpeg', 'image/jpeg'],
  ['.webp', 'image/webp'], ['.gif', 'image/gif'], ['.pdf', 'application/pdf'],
  ['.txt', 'text/plain'], ['.zip', 'application/zip'], ['.7z', 'application/x-7z-compressed'],
  ['.rar', 'application/vnd.rar'],
  ['.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  ['.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
  ['.pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'],
]);
const ATTACHMENT_DIR = process.env.UGC_IMAGES_DIR || path.join(__dirname, '../../data/ugc/images');
fs.mkdirSync(ATTACHMENT_DIR, { recursive: true });
const uploadAttachment = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, done) => done(null, ATTACHMENT_DIR),
    filename: (_req, file, done) => done(null, `${randomUUID()}${path.extname(file.originalname).toLowerCase()}`),
  }),
  limits: { fileSize: MAX_ATTACHMENT_BYTES, files: 1 },
  fileFilter: (_req, file, done) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const expected = ATTACHMENT_MIMES.get(ext);
    const accepted = expected && (file.mimetype === expected ||
      (file.mimetype === 'application/octet-stream' && ['.zip', '.7z', '.rar', '.docx', '.xlsx', '.pptx'].includes(ext)));
    done(accepted ? null : new items.InputError('Unsupported attachment type'), !!accepted);
  },
}).single('file');

function validAttachmentSignature(file) {
  const ext = path.extname(file.filename).toLowerCase();
  if (ext === '.txt') return true;
  const head = Buffer.alloc(12);
  let fd;
  try {
    fd = fs.openSync(file.path, 'r');
    const read = fs.readSync(fd, head, 0, head.length, 0);
    if (ext === '.png') return read >= 8 && head.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'));
    if (ext === '.jpg' || ext === '.jpeg') return read >= 3 && head.subarray(0, 3).equals(Buffer.from('ffd8ff', 'hex'));
    if (ext === '.webp') return read >= 12 && head.toString('ascii', 0, 4) === 'RIFF' && head.toString('ascii', 8, 12) === 'WEBP';
    if (ext === '.gif') return read >= 6 && ['GIF87a', 'GIF89a'].includes(head.toString('ascii', 0, 6));
    if (ext === '.pdf') return read >= 5 && head.toString('ascii', 0, 5) === '%PDF-';
    if (ext === '.7z') return read >= 6 && head.subarray(0, 6).equals(Buffer.from('377abcaf271c', 'hex'));
    if (ext === '.rar') return read >= 7 && head.subarray(0, 7).equals(Buffer.from('526172211a0700', 'hex'));
    return read >= 4 && head.subarray(0, 2).equals(Buffer.from('504b', 'hex')); // ZIP and Office Open XML
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function safeAttachmentName(name) {
  return path.basename(String(name || '')).replace(/[^\p{L}\p{N} ._()-]/gu, '').trim().slice(0, 120) || 'attachment';
}

router.post('/:channelId/issues/:itemId/attachments', loadChannel, loadItem,
  require_(perms.comment), require_('ATTACH_FILES'), (req, res, next) => {
    const count = db.prepare('SELECT COUNT(*) AS count FROM tracker_issue_attachments WHERE item_id = ?').get(req.item.id).count;
    if (count >= MAX_ATTACHMENTS) return res.status(400).json({ error: `Attachment limit reached (${MAX_ATTACHMENTS})` });
    uploadAttachment(req, res, (error) => {
      if (error) return res.status(400).json({ error: error.code === 'LIMIT_FILE_SIZE' ? 'Attachment exceeds 50 MB' : error.message });
      if (!req.file) return res.status(400).json({ error: 'File required' });
      const cleanup = () => { try { fs.unlinkSync(req.file.path); } catch {} };
      try {
        if (!validAttachmentSignature(req.file)) {
          cleanup();
          return res.status(400).json({ error: 'Invalid attachment content' });
        }
        const attachment = {
          id: randomUUID(), name: safeAttachmentName(req.file.originalname),
          url: `/ugc/images/${req.file.filename}`, mime: ATTACHMENT_MIMES.get(path.extname(req.file.filename).toLowerCase()),
          size: req.file.size, uploaded_by: req.user.id,
        };
        db.transaction(() => {
          db.prepare('INSERT INTO tracker_issue_attachments (id, item_id, name, url, mime, size, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?)')
            .run(attachment.id, req.item.id, attachment.name, attachment.url, attachment.mime, attachment.size, attachment.uploaded_by);
          items.recordEvent(db, req.item.id, req.user.id, 'attachment_added', { name: attachment.name });
          db.prepare('UPDATE channel_items SET updated_at = MAX(updated_at + 1, unixepoch()) WHERE id = ?').run(req.item.id);
        })();
        const saved = db.prepare('SELECT id, name, url, mime, size, uploaded_by, created_at FROM tracker_issue_attachments WHERE id = ?').get(attachment.id);
        notifyWatchers(req, emitItem(req.item.id), 'attached');
        res.status(201).json(saved);
      } catch (err) {
        cleanup();
        next(err);
      }
    });
  });

router.delete('/:channelId/issues/:itemId/attachments/:attachmentId', loadChannel, loadItem, (req, res) => {
  const attachment = db.prepare('SELECT * FROM tracker_issue_attachments WHERE id = ? AND item_id = ?').get(req.params.attachmentId, req.item.id);
  if (!attachment) return res.status(404).json({ error: 'Attachment not found' });
  if (attachment.uploaded_by !== req.user.id && !hasChannelPermission(req.user, req.channel.id, perms.manage, db)) {
    return res.status(403).json({ error: 'Not allowed to delete this attachment' });
  }
  db.transaction(() => {
    db.prepare('DELETE FROM tracker_issue_attachments WHERE id = ?').run(attachment.id);
    items.recordEvent(db, req.item.id, req.user.id, 'attachment_removed', { name: attachment.name });
    db.prepare('UPDATE channel_items SET updated_at = MAX(updated_at + 1, unixepoch()) WHERE id = ?').run(req.item.id);
  })();
  removeLocalUploads(ATTACHMENT_DIR, [attachment.url]);
  notifyWatchers(req, emitItem(req.item.id), 'updated');
  res.json({ ok: true });
});

module.exports = router;
