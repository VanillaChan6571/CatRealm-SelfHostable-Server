// Thread settings and media settings for categories, channels and single threads.
// Mounted at /api/policy. The rules for combining them live in ../channelPolicy.
const router = require('express').Router();
const db = require('../db');
const { PERMISSIONS, hasPermission, hasChannelPermission } = require('../permissions');
const policy = require('../channelPolicy');

const handle = (fn) => (req, res) => {
  try {
    fn(req, res);
  } catch (error) {
    if (error instanceof policy.PolicyError) return res.status(error.status).json({ error: error.message });
    throw error;
  }
};

const requireManageChannels = (req, res, next) => (hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)
  ? next() : res.status(403).json({ error: 'Missing permission: manage_channels' }));

// GET /api/policy/channels/:id -> { channel, own, category, effective }
router.get('/channels/:id', requireManageChannels, (req, res) => {
  const result = policy.channelPolicy(db, req.params.id);
  if (!result) return res.status(404).json({ error: 'Channel not found' });
  res.json(result);
});

// PATCH /api/policy/channels/:id { threadSlowmode?, threadAutoHideMinutes?, media?: { spoiler?, nsfw?, lewd?, blood?, gore? } }
// threadSlowmode: null = use the category's, -1 = same as the channel's slowmode, else seconds.
// threadAutoHideMinutes: null = use the category's, 0 = never, else minutes of inactivity.
router.patch('/channels/:id', requireManageChannels, handle((req, res) => {
  res.json(policy.writeChannelPolicy(db, req.params.id, req.body ?? {}));
}));

router.get('/categories/:id', requireManageChannels, (req, res) => {
  const result = policy.categoryPolicy(db, req.params.id);
  if (!result) return res.status(404).json({ error: 'Category not found' });
  res.json(result);
});

// PATCH /api/policy/categories/:id — same body. Here threadSlowmode null or -1 both mean
// "each channel's own slowmode", and a null auto-hide means the 48-hour default.
router.patch('/categories/:id', requireManageChannels, handle((req, res) => {
  res.json(policy.writeCategoryPolicy(db, req.params.id, req.body ?? {}));
}));

const loadThread = (req, res, next) => {
  const result = policy.threadPolicy(db, req.params.id);
  if (!result) return res.status(404).json({ error: 'Thread not found' });
  if (!hasChannelPermission(req.user, result.channelId, PERMISSIONS.VIEW_CHANNELS, db)
    || !hasChannelPermission(req.user, result.channelId, PERMISSIONS.READ_CHAT_HISTORY, db)) {
    return res.status(403).json({ error: 'Missing permission: view_channels' });
  }
  req.threadPolicy = result;
  next();
};

// GET /api/policy/threads/:id -> { own, channel, effective } — anyone who can read the channel.
router.get('/threads/:id', loadThread, (req, res) => res.json(req.threadPolicy));

// PATCH /api/policy/threads/:id { slowmode?, autoHideMinutes? } — null = use the channel's. Staff only.
router.patch('/threads/:id', loadThread, handle((req, res) => {
  if (!hasChannelPermission(req.user, req.threadPolicy.channelId, PERMISSIONS.MANAGE_POSTS, db)) {
    return res.status(403).json({ error: 'Missing permission: manage_posts' });
  }
  res.json(policy.writeThreadSettings(db, req.params.id, req.body ?? {}));
}));

module.exports = router;
