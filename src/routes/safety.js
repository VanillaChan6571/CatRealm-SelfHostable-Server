const router = require('express').Router();
const db = require('../db');
const { PERMISSIONS, hasChannelPermission, hasPermission } = require('../permissions');
const { reviewReport, serializeReport, submitReport } = require('../safety');
const { emitToChannel } = require('../socket/handler');
const { relayChildSafetySignal } = require('../lib/safetySignalRelay');

router.post('/reports', (req, res) => {
  const channelId = typeof req.body?.channelId === 'string' ? req.body.channelId : '';
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db) || !hasChannelPermission(req.user, channelId, PERMISSIONS.READ_CHAT_HISTORY, db)) return res.status(403).json({ error: 'You cannot report a message you cannot view' });
  try {
    const result = submitReport(req.user.id, req.body);
    if (result.quarantined) emitToChannel(channelId, 'safety:artifact:update', { channelId, messageId: req.body.messageId, artifactKey: req.body.artifactKey, state: 'quarantined' });
    const subject = db.prepare('SELECT subject_user_id FROM safety_reports WHERE id = ?').get(result.id);
    if (subject) void relayChildSafetySignal({ reportId: result.id, subjectLocalUserId: subject.subject_user_id, reason: req.body.reason, artifactKind: req.body.artifactKind });
    return res.status(201).json(result);
  } catch (error) { return res.status(error.status || 500).json({ error: error.status ? error.message : 'Could not submit report' }); }
});

router.get('/visibility', (req, res) => {
  const channelId = String(req.query.channelId || '');
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) return res.status(403).json({ error: 'Missing permission' });
  const rows = db.prepare(`SELECT channel_id AS channelId, message_id AS messageId, artifact_key AS artifactKey, state, viewer_user_id AS viewerUserId FROM safety_artifact_visibility WHERE channel_id = ? AND (viewer_user_id = ? OR state IN ('quarantined','removed'))`).all(channelId, req.user.id);
  res.json({ artifacts: rows.map((row) => ({ ...row, hiddenForUser: row.viewerUserId === req.user.id })) });
});

router.get('/reports', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_SERVER)) return res.status(403).json({ error: 'Missing permission' });
  const status = ['pending', 'confirmed', 'dismissed', 'escalated'].includes(req.query.status) ? req.query.status : 'pending';
  const rows = db.prepare('SELECT * FROM safety_reports WHERE status = ? ORDER BY created_at ASC LIMIT 100').all(status);
  res.json({ reports: rows.map((row) => serializeReport(row, false)) });
});

router.get('/reports/:id', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_SERVER)) return res.status(403).json({ error: 'Missing permission' });
  const row = db.prepare('SELECT * FROM safety_reports WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Report not found' });
  const events = db.prepare('SELECT id, actor_user_id AS actorUserId, event_type AS eventType, created_at AS createdAt FROM safety_report_events WHERE report_id = ? ORDER BY created_at ASC').all(req.params.id);
  res.json({ report: serializeReport(row, true), events });
});

router.patch('/reports/:id', (req, res) => {
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_SERVER)) return res.status(403).json({ error: 'Missing permission' });
  try {
    const report = db.prepare('SELECT channel_id, message_id, artifact_key FROM safety_reports WHERE id = ?').get(req.params.id);
    const result = reviewReport(req.user.id, req.params.id, req.body?.status, req.body?.note);
    if (report) emitToChannel(report.channel_id, 'safety:artifact:update', { channelId: report.channel_id, messageId: report.message_id, artifactKey: report.artifact_key, state: req.body?.status === 'dismissed' ? 'cleared' : 'removed' });
    return res.json(result);
  } catch (error) { return res.status(error.status || 500).json({ error: error.status ? error.message : 'Could not review report' }); }
});

module.exports = router;
