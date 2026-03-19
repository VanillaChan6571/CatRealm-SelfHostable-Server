const router = require('express').Router();
const { randomUUID } = require('crypto');
const db = require('../db');
const { getSetting, setSetting } = require('../settings');
const { authenticateToken } = require('../middleware/auth');
const { PERMISSIONS, hasPermission } = require('../permissions');

function requireManageServer(req, res, next) {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_SERVER)) {
    return res.status(403).json({ error: 'Missing permission' });
  }
  next();
}

function getQuestionsWithAnswers() {
  const questions = db.prepare(
    'SELECT id, question, allow_multiple, required, position FROM welcome_questions ORDER BY position ASC'
  ).all();
  const answers = db.prepare(
    'SELECT id, question_id, text, emoji, role_ids, channel_ids, position FROM welcome_answers ORDER BY position ASC'
  ).all();
  return questions.map((q) => ({
    ...q,
    allow_multiple: !!q.allow_multiple,
    required: !!q.required,
    answers: answers
      .filter((a) => a.question_id === q.id)
      .map((a) => ({
        ...a,
        role_ids: JSON.parse(a.role_ids || '[]'),
        channel_ids: JSON.parse(a.channel_ids || '[]'),
      })),
  }));
}

function getRules() {
  return db.prepare('SELECT id, content, position FROM welcome_rules ORDER BY position ASC').all();
}

function isBoardReady() {
  const questionCount = db.prepare('SELECT COUNT(*) AS c FROM welcome_questions').get().c;
  if (questionCount < 2) return false;
  const rulesMode = getSetting('welcome_rules_mode', 'structured');
  if (rulesMode === 'markdown') {
    const md = getSetting('welcome_rules_markdown', '');
    return !!(md && md.trim());
  }
  const ruleCount = db.prepare('SELECT COUNT(*) AS c FROM welcome_rules').get().c;
  return ruleCount > 0;
}

// ── Public/Authenticated ──────────────────────────────────────────────────────

// GET /api/welcome/settings
router.get('/welcome/settings', authenticateToken, (req, res) => {
  const enabled = getSetting('welcome_board_enabled', '0') === '1';
  const bg = getSetting('welcome_board_bg', '');
  const rulesMode = getSetting('welcome_rules_mode', 'structured');
  const rulesMarkdown = getSetting('welcome_rules_markdown', '');
  const questions = getQuestionsWithAnswers();
  const rules = getRules();
  res.json({ enabled, bg, questions, rules, rulesMode, rulesMarkdown });
});

// POST /api/welcome/complete
router.post('/welcome/complete', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const answers = req.body.answers || {};

  const roleIds = new Set();
  const channelIds = new Set();

  for (const [questionId, selectedAnswerIds] of Object.entries(answers)) {
    const ids = Array.isArray(selectedAnswerIds) ? selectedAnswerIds : [selectedAnswerIds];
    for (const answerId of ids) {
      const answerRow = db.prepare(
        'SELECT role_ids, channel_ids FROM welcome_answers WHERE id = ? AND question_id = ?'
      ).get(answerId, questionId);
      if (!answerRow) continue;
      const roles = JSON.parse(answerRow.role_ids || '[]');
      const channels = JSON.parse(answerRow.channel_ids || '[]');
      for (const r of roles) roleIds.add(r);
      for (const c of channels) channelIds.add(c);
    }
  }

  const insertRole = db.prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)');
  const upsertOverwrite = db.prepare(`
    INSERT INTO channel_permission_overwrites (id, channel_id, target_type, target_id, allow, deny)
    VALUES (?, ?, 'user', ?, 1, 0)
    ON CONFLICT(id) DO NOTHING
  `);
  const existingOverwrite = db.prepare(
    "SELECT id FROM channel_permission_overwrites WHERE channel_id = ? AND target_type = 'user' AND target_id = ?"
  );

  const txn = db.transaction(() => {
    for (const roleId of roleIds) insertRole.run(userId, roleId);
    for (const channelId of channelIds) {
      const existing = existingOverwrite.get(channelId, userId);
      if (!existing) {
        upsertOverwrite.run(randomUUID(), channelId, userId);
      }
    }
    db.prepare('UPDATE users SET onboarding_completed = 1 WHERE id = ?').run(userId);
  });
  txn();

  res.json({ ok: true });
});

// ── Admin ─────────────────────────────────────────────────────────────────────

// GET /api/admin/welcome
router.get('/admin/welcome', authenticateToken, requireManageServer, (req, res) => {
  const enabled = getSetting('welcome_board_enabled', '0') === '1';
  const bg = getSetting('welcome_board_bg', '');
  const rulesMode = getSetting('welcome_rules_mode', 'structured');
  const rulesMarkdown = getSetting('welcome_rules_markdown', '');
  const questions = getQuestionsWithAnswers();
  const rules = getRules();
  res.json({ enabled, bg, questions, rules, rulesMode, rulesMarkdown, boardReady: isBoardReady() });
});

// PUT /api/admin/welcome/settings
router.put('/admin/welcome/settings', authenticateToken, requireManageServer, (req, res) => {
  const { welcome_board_bg, welcome_board_enabled, welcome_rules_mode } = req.body;

  if (welcome_board_bg !== undefined) setSetting('welcome_board_bg', String(welcome_board_bg));
  if (welcome_rules_mode !== undefined) setSetting('welcome_rules_mode', String(welcome_rules_mode));

  if (welcome_board_enabled !== undefined) {
    const enabling = welcome_board_enabled === true || welcome_board_enabled === '1';
    if (enabling && !isBoardReady()) {
      return res.status(400).json({
        error: 'Cannot enable Welcome Board: requires at least 2 questions and at least 1 rule (or non-empty markdown rules).',
      });
    }
    setSetting('welcome_board_enabled', enabling ? '1' : '0');
  }

  res.json({ ok: true });
});

// POST /api/admin/welcome/reset-onboarding
router.post('/admin/welcome/reset-onboarding', authenticateToken, requireManageServer, (_req, res) => {
  const result = db.prepare(`
    UPDATE users
    SET onboarding_completed = 0
    WHERE COALESCE(is_member, 1) = 1
      AND username != '__catrealm_webhook__'
  `).run();
  res.json({ ok: true, resetCount: result.changes || 0 });
});

// PUT /api/admin/welcome/rules
router.put('/admin/welcome/rules', authenticateToken, requireManageServer, (req, res) => {
  const { rulesMode, rulesMarkdown, rules } = req.body;

  if (rulesMode !== undefined) setSetting('welcome_rules_mode', String(rulesMode));
  if (rulesMarkdown !== undefined) setSetting('welcome_rules_markdown', String(rulesMarkdown));

  if (Array.isArray(rules)) {
    const deleteAll = db.prepare('DELETE FROM welcome_rules');
    const insertRule = db.prepare('INSERT INTO welcome_rules (id, content, position) VALUES (?, ?, ?)');
    const txn = db.transaction(() => {
      deleteAll.run();
      rules.forEach((rule, idx) => {
        insertRule.run(rule.id || randomUUID(), String(rule.content), idx);
      });
    });
    txn();
  }

  res.json({ ok: true });
});

// POST /api/admin/welcome/questions
router.post('/admin/welcome/questions', authenticateToken, requireManageServer, (req, res) => {
  const { question, allow_multiple, required } = req.body;
  if (!question || !String(question).trim()) return res.status(400).json({ error: 'Question text required' });

  const maxPos = db.prepare('SELECT COALESCE(MAX(position), -1) AS m FROM welcome_questions').get().m;
  const id = randomUUID();
  db.prepare('INSERT INTO welcome_questions (id, question, allow_multiple, required, position) VALUES (?, ?, ?, ?, ?)')
    .run(id, String(question).trim(), allow_multiple ? 1 : 0, required ? 1 : 0, maxPos + 1);

  res.status(201).json({ id, question: String(question).trim(), allow_multiple: !!allow_multiple, required: !!required, position: maxPos + 1, answers: [] });
});

// PUT /api/admin/welcome/questions/reorder
router.put('/admin/welcome/questions/reorder', authenticateToken, requireManageServer, (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids)) return res.status(400).json({ error: 'ids array required' });
  const update = db.prepare('UPDATE welcome_questions SET position = ? WHERE id = ?');
  const txn = db.transaction(() => { ids.forEach((id, idx) => update.run(idx, id)); });
  txn();
  res.json({ ok: true });
});

// PUT /api/admin/welcome/questions/:id
router.put('/admin/welcome/questions/:id', authenticateToken, requireManageServer, (req, res) => {
  const { question, allow_multiple, required } = req.body;
  const existing = db.prepare('SELECT id FROM welcome_questions WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Question not found' });

  const fields = [];
  const values = [];
  if (question !== undefined) { fields.push('question = ?'); values.push(String(question).trim()); }
  if (allow_multiple !== undefined) { fields.push('allow_multiple = ?'); values.push(allow_multiple ? 1 : 0); }
  if (required !== undefined) { fields.push('required = ?'); values.push(required ? 1 : 0); }
  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  values.push(req.params.id);
  db.prepare(`UPDATE welcome_questions SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  res.json({ ok: true });
});

// DELETE /api/admin/welcome/questions/:id
router.delete('/admin/welcome/questions/:id', authenticateToken, requireManageServer, (req, res) => {
  db.prepare('DELETE FROM welcome_questions WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// POST /api/admin/welcome/questions/:id/answers
router.post('/admin/welcome/questions/:id/answers', authenticateToken, requireManageServer, (req, res) => {
  const question = db.prepare('SELECT id FROM welcome_questions WHERE id = ?').get(req.params.id);
  if (!question) return res.status(404).json({ error: 'Question not found' });

  const { text, emoji, role_ids, channel_ids } = req.body;
  if (!text || !String(text).trim()) return res.status(400).json({ error: 'Answer text required' });

  const maxPos = db.prepare('SELECT COALESCE(MAX(position), -1) AS m FROM welcome_answers WHERE question_id = ?').get(req.params.id).m;
  const id = randomUUID();
  const roleIdsJson = JSON.stringify(Array.isArray(role_ids) ? role_ids : []);
  const channelIdsJson = JSON.stringify(Array.isArray(channel_ids) ? channel_ids : []);

  db.prepare('INSERT INTO welcome_answers (id, question_id, text, emoji, role_ids, channel_ids, position) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, req.params.id, String(text).trim(), emoji || null, roleIdsJson, channelIdsJson, maxPos + 1);

  res.status(201).json({ id, question_id: req.params.id, text: String(text).trim(), emoji: emoji || null, role_ids: JSON.parse(roleIdsJson), channel_ids: JSON.parse(channelIdsJson), position: maxPos + 1 });
});

// PUT /api/admin/welcome/answers/reorder
router.put('/admin/welcome/answers/reorder', authenticateToken, requireManageServer, (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids)) return res.status(400).json({ error: 'ids array required' });
  const update = db.prepare('UPDATE welcome_answers SET position = ? WHERE id = ?');
  const txn = db.transaction(() => { ids.forEach((id, idx) => update.run(idx, id)); });
  txn();
  res.json({ ok: true });
});

// PUT /api/admin/welcome/answers/:id
router.put('/admin/welcome/answers/:id', authenticateToken, requireManageServer, (req, res) => {
  const existing = db.prepare('SELECT id FROM welcome_answers WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Answer not found' });

  const { text, emoji, role_ids, channel_ids } = req.body;
  const fields = [];
  const values = [];
  if (text !== undefined) { fields.push('text = ?'); values.push(String(text).trim()); }
  if (emoji !== undefined) { fields.push('emoji = ?'); values.push(emoji || null); }
  if (role_ids !== undefined) { fields.push('role_ids = ?'); values.push(JSON.stringify(Array.isArray(role_ids) ? role_ids : [])); }
  if (channel_ids !== undefined) { fields.push('channel_ids = ?'); values.push(JSON.stringify(Array.isArray(channel_ids) ? channel_ids : [])); }
  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  values.push(req.params.id);
  db.prepare(`UPDATE welcome_answers SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  res.json({ ok: true });
});

// DELETE /api/admin/welcome/answers/:id
router.delete('/admin/welcome/answers/:id', authenticateToken, requireManageServer, (req, res) => {
  db.prepare('DELETE FROM welcome_answers WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

module.exports = router;
