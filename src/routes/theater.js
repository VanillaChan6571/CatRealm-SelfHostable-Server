const router = require('express').Router();
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const axios = require('axios');
const { randomUUID } = require('crypto');
const db = require('../db');
const {
  PERMISSIONS,
  hasChannelPermission,
  hasPermission,
} = require('../permissions');
const {
  isDomainAllowed,
  isYtDlpAvailable,
  getVideoMetadata,
  downloadVideo,
  deleteChannelCache,
  channelCacheDir,
  ensureCacheDir,
  THEATER_BASE_DIR,
} = require('../lib/theaterDownload');
const { broadcastTheaterQueueUpdate } = require('../socket/handler');

// ── YouTube helpers ───────────────────────────────────────────────────────────

function extractYouTubeId(url) {
  try {
    const u = new URL(url);
    if (u.hostname === 'youtu.be') {
      return u.pathname.slice(1).split('?')[0] || null;
    }
    if (u.hostname === 'www.youtube.com' || u.hostname === 'youtube.com' || u.hostname === 'm.youtube.com') {
      if (u.pathname === '/watch') return u.searchParams.get('v');
      const match = u.pathname.match(/^\/(?:embed|v|shorts)\/([A-Za-z0-9_-]{11})/);
      if (match) return match[1];
    }
    return null;
  } catch {
    return null;
  }
}

async function fetchYouTubeOEmbed(videoId) {
  try {
    const resp = await axios.get(
      `https://www.youtube.com/oembed?url=https://www.youtube.com/watch%3Fv%3D${videoId}&format=json`,
      { timeout: 5000 }
    );
    return resp.data || null;
  } catch {
    return null;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getChannel(channelId) {
  return db.prepare('SELECT * FROM channels WHERE id = ?').get(channelId);
}

function requireTheaterChannel(req, res) {
  const channel = getChannel(req.params.channelId);
  if (!channel) { res.status(404).json({ error: 'Channel not found' }); return null; }
  if (channel.type !== 'theater') { res.status(400).json({ error: 'Not a theater channel' }); return null; }
  return channel;
}

function requireViewChannels(req, res, channelId) {
  if (!hasChannelPermission(req.user, channelId, PERMISSIONS.VIEW_CHANNELS, db)) {
    res.status(403).json({ error: 'Missing permission: view_channels' });
    return false;
  }
  return true;
}

function canControlTheater(user, channelId) {
  if (!user) return false;
  if (user.is_owner || user.role === 'owner') return true;
  if (hasPermission(user, PERMISSIONS.MANAGE_CHANNELS)) return true;
  if (hasPermission(user, PERMISSIONS.ADMINISTRATOR)) return true;
  if (hasChannelPermission(user, channelId, PERMISSIONS.PLAY_IN_THEATER, db)) return true;
  // Also allow the delegated theater host (set via theater:host:grant socket event)
  const state = db.prepare('SELECT host_user_id FROM theater_state WHERE channel_id = ?').get(channelId);
  return !!(state?.host_user_id && state.host_user_id === user.id);
}

function getTheaterSettings(channelId) {
  return db.prepare(`
    SELECT theater_max_duration_seconds, theater_open_queuing, theater_auto_advance,
           theater_reactions_enabled, theater_skip_voting_enabled, theater_queue_voting_enabled
    FROM channel_settings WHERE channel_id = ?
  `).get(channelId) || {
    theater_max_duration_seconds: 14400,
    theater_open_queuing: 1,
    theater_auto_advance: 1,
    theater_reactions_enabled: 0,
    theater_skip_voting_enabled: 0,
    theater_queue_voting_enabled: 0,
  };
}

function getQueue(channelId) {
  return db.prepare(`
    SELECT tq.*, u.username as added_by_username
    FROM theater_queue tq
    LEFT JOIN users u ON u.id = tq.added_by
    WHERE tq.channel_id = ?
    ORDER BY tq.position ASC, tq.created_at ASC
  `).all(channelId);
}

function getState(channelId) {
  return db.prepare('SELECT * FROM theater_state WHERE channel_id = ?').get(channelId);
}

function getVideoUrl(cachedPath, channelId) {
  if (!cachedPath) return null;
  if (cachedPath.startsWith('youtube:')) return cachedPath;
  const basename = path.basename(cachedPath);
  return `/ugc/temp-theater/${channelId}/${basename}`;
}

// ── Upload handler ─────────────────────────────────────────────────────────────

const ALLOWED_VIDEO_MIMES = [
  'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime',
  'video/x-matroska', 'video/avi', 'video/x-msvideo',
];

const videoUpload = multer({
  storage: multer.diskStorage({
    destination: (req, _file, cb) => {
      const dir = ensureCacheDir(req.params.channelId);
      cb(null, dir);
    },
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase() || '.mp4';
      cb(null, `${randomUUID()}${ext}`);
    },
  }),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_VIDEO_MIMES.includes(file.mimetype)) {
      return cb(new Error('Invalid file type — only video files allowed'));
    }
    cb(null, true);
  },
});

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /:channelId/queue
router.get('/:channelId/queue', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!requireViewChannels(req, res, channel.id)) return;

  const items = getQueue(channel.id);
  const state = getState(channel.id);
  const userId = req.user.id;
  const settings = getTheaterSettings(channel.id);

  const enriched = items.map((item) => {
    const myVote = settings.theater_queue_voting_enabled
      ? !!db.prepare('SELECT 1 FROM theater_queue_votes WHERE queue_item_id = ? AND user_id = ?').get(item.id, userId)
      : false;
    return {
      ...item,
      videoUrl: item.cached_path ? getVideoUrl(item.cached_path, channel.id) : null,
      myVote,
    };
  });

  const skipVote = state?.current_item_id
    ? !!db.prepare('SELECT 1 FROM theater_skip_votes WHERE channel_id = ? AND user_id = ?').get(channel.id, userId)
    : false;

  res.json({
    items: enriched,
    state: state
      ? { ...state, videoUrl: state.current_item_id ? getVideoUrl(
          items.find((i) => i.id === state.current_item_id)?.cached_path, channel.id
        ) : null }
      : null,
    mySkipVote: skipVote,
    settings,
  });
});

// POST /:channelId/queue — add URL to queue
router.post('/:channelId/queue', async (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!requireViewChannels(req, res, channel.id)) return;

  const settings = getTheaterSettings(channel.id);
  if (!canControlTheater(req.user, channel.id) && !settings.theater_open_queuing) {
    return res.status(403).json({ error: 'Missing permission: play_in_theater' });
  }

  const { url } = req.body;
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'url required' });

  // Validate URL
  let parsedUrl;
  try { parsedUrl = new URL(url); } catch { return res.status(400).json({ error: 'Invalid URL' }); }
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return res.status(400).json({ error: 'URL must be http or https' });
  }

  const youtubeId = extractYouTubeId(url);

  // Domain allowlist — YouTube bypasses it so yt-dlp can handle it without
  // requiring admins to explicitly allow youtube.com
  if (!youtubeId) {
    const allowlist = db.prepare('SELECT domain FROM theater_domain_allowlist WHERE channel_id = ?').all(channel.id).map((r) => r.domain);
    if (!isDomainAllowed(url, allowlist)) {
      return res.status(403).json({ error: 'Domain not in allowlist' });
    }
  }

  // YouTube without yt-dlp — embed via iframe (no file download possible)
  if (youtubeId && !isYtDlpAvailable()) {
    const itemId = randomUUID();
    const maxPos = db.prepare('SELECT MAX(position) as m FROM theater_queue WHERE channel_id = ?').get(channel.id)?.m ?? -1;
    db.prepare(`
      INSERT INTO theater_queue (id, channel_id, added_by, title, source_url, source_type, cached_path, cache_status, cache_progress, position)
      VALUES (?, ?, ?, ?, ?, 'url', ?, 'ready', 100, ?)
    `).run(itemId, channel.id, req.user.id, url, url, `youtube:${youtubeId}`, maxPos + 1);
    broadcastTheaterQueueUpdate(channel.id);
    res.status(201).json({ id: itemId, status: 'pending' });

    fetchYouTubeOEmbed(youtubeId).then((meta) => {
      if (meta) {
        db.prepare('UPDATE theater_queue SET title = ?, thumbnail_url = ? WHERE id = ?')
          .run(meta.title || url, meta.thumbnail_url || null, itemId);
      }
      const state = getState(channel.id);
      const tsettings = getTheaterSettings(channel.id);
      if (tsettings.theater_auto_advance && (!state || !state.current_item_id)) {
        db.prepare(`
          INSERT INTO theater_state (channel_id, current_item_id, position_ms, playing, updated_at)
          VALUES (?, ?, 0, 0, unixepoch())
          ON CONFLICT(channel_id) DO UPDATE SET
            current_item_id = excluded.current_item_id,
            position_ms = 0, playing = 0, updated_at = unixepoch()
        `).run(channel.id, itemId);
      }
      broadcastTheaterQueueUpdate(channel.id);
    }).catch(() => broadcastTheaterQueueUpdate(channel.id));
    return;
  }

  // Start download in background, insert item as pending
  const itemId = randomUUID();
  const maxPos = db.prepare('SELECT MAX(position) as m FROM theater_queue WHERE channel_id = ?').get(channel.id)?.m ?? -1;

  // Get metadata (best-effort, don't block)
  getVideoMetadata(url).then((meta) => {
    // Max duration check
    if (settings.theater_max_duration_seconds > 0 && meta.durationSeconds && meta.durationSeconds > settings.theater_max_duration_seconds) {
      db.prepare('UPDATE theater_queue SET cache_status = ?, cached_path = NULL WHERE id = ?').run('error', itemId);
      broadcastTheaterQueueUpdate(channel.id);
      return;
    }
    db.prepare('UPDATE theater_queue SET title = ?, duration_seconds = ?, thumbnail_url = ?, cache_status = ? WHERE id = ?')
      .run(meta.title || url, meta.durationSeconds || null, meta.thumbnailUrl || null, 'downloading', itemId);
    broadcastTheaterQueueUpdate(channel.id);

    downloadVideo(url, channel.id, (progress) => {
      db.prepare('UPDATE theater_queue SET cache_progress = ? WHERE id = ?').run(progress, itemId);
      if (progress % 10 === 0) broadcastTheaterQueueUpdate(channel.id);
    }).then(({ filename, durationSeconds }) => {
      db.prepare(`
        UPDATE theater_queue
        SET cached_path = ?, duration_seconds = COALESCE(?, duration_seconds), cache_status = 'ready', cache_progress = 100
        WHERE id = ?
      `).run(filename, durationSeconds, itemId);
      // Auto-play if nothing is currently playing
      const state = getState(channel.id);
      const tsettings = getTheaterSettings(channel.id);
      if (tsettings.theater_auto_advance && (!state || !state.current_item_id)) {
        db.prepare(`
          INSERT INTO theater_state (channel_id, current_item_id, position_ms, playing, updated_at)
          VALUES (?, ?, 0, 0, unixepoch())
          ON CONFLICT(channel_id) DO UPDATE SET
            current_item_id = excluded.current_item_id,
            position_ms = 0, playing = 0, updated_at = unixepoch()
        `).run(channel.id, itemId);
      }
      broadcastTheaterQueueUpdate(channel.id);
    }).catch((err) => {
      if (err.code !== 'ENOENT') {
        db.prepare('UPDATE theater_queue SET cache_status = ? WHERE id = ?').run('error', itemId);
        broadcastTheaterQueueUpdate(channel.id);
      }
    });
  }).catch(() => {
    // If metadata fetch fails, still try to download
    db.prepare('UPDATE theater_queue SET cache_status = ? WHERE id = ?').run('downloading', itemId);
    broadcastTheaterQueueUpdate(channel.id);
    downloadVideo(url, channel.id, (progress) => {
      db.prepare('UPDATE theater_queue SET cache_progress = ? WHERE id = ?').run(progress, itemId);
    }).then(({ filename, durationSeconds }) => {
      db.prepare(`
        UPDATE theater_queue
        SET cached_path = ?, duration_seconds = ?, cache_status = 'ready', cache_progress = 100, title = COALESCE(NULLIF(title, ?), title)
        WHERE id = ?
      `).run(filename, durationSeconds, url, itemId);
      broadcastTheaterQueueUpdate(channel.id);
    }).catch(() => {
      db.prepare('UPDATE theater_queue SET cache_status = ? WHERE id = ?').run('error', itemId);
      broadcastTheaterQueueUpdate(channel.id);
    });
  });

  db.prepare(`
    INSERT INTO theater_queue (id, channel_id, added_by, title, source_url, source_type, cache_status, position)
    VALUES (?, ?, ?, ?, ?, 'url', 'pending', ?)
  `).run(itemId, channel.id, req.user.id, url, url, maxPos + 1);

  broadcastTheaterQueueUpdate(channel.id);
  res.status(201).json({ id: itemId, status: 'pending' });
});

// POST /:channelId/queue/upload — upload video file
router.post('/:channelId/queue/upload', videoUpload.single('video'), async (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!requireViewChannels(req, res, channel.id)) return;

  const settings = getTheaterSettings(channel.id);
  if (!canControlTheater(req.user, channel.id) && !settings.theater_open_queuing) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(403).json({ error: 'Missing permission: play_in_theater' });
  }
  if (!req.file) return res.status(400).json({ error: 'Video file required' });

  const maxPos = db.prepare('SELECT MAX(position) as m FROM theater_queue WHERE channel_id = ?').get(channel.id)?.m ?? -1;
  const itemId = randomUUID();
  const title = req.body.title?.trim() || path.basename(req.file.originalname, path.extname(req.file.originalname)) || 'Upload';

  db.prepare(`
    INSERT INTO theater_queue (id, channel_id, added_by, title, source_url, source_type, cached_path, cache_status, cache_progress, position)
    VALUES (?, ?, ?, ?, ?, 'upload', ?, 'ready', 100, ?)
  `).run(itemId, channel.id, req.user.id, title, req.file.filename, req.file.path, maxPos + 1);

  // Auto-play if nothing is currently playing
  const state = getState(channel.id);
  if (settings.theater_auto_advance && (!state || !state.current_item_id)) {
    db.prepare(`
      INSERT INTO theater_state (channel_id, current_item_id, position_ms, playing, updated_at)
      VALUES (?, ?, 0, 0, unixepoch())
      ON CONFLICT(channel_id) DO UPDATE SET
        current_item_id = excluded.current_item_id,
        position_ms = 0, playing = 0, updated_at = unixepoch()
    `).run(channel.id, itemId);
  }

  broadcastTheaterQueueUpdate(channel.id);
  res.status(201).json({ id: itemId, status: 'ready' });
});

// DELETE /:channelId/queue/:itemId
router.delete('/:channelId/queue/:itemId', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!requireViewChannels(req, res, channel.id)) return;

  const item = db.prepare('SELECT * FROM theater_queue WHERE id = ? AND channel_id = ?').get(req.params.itemId, channel.id);
  if (!item) return res.status(404).json({ error: 'Queue item not found' });

  const isOwnItem = item.added_by === req.user.id;
  if (!isOwnItem && !canControlTheater(req.user, channel.id)) {
    return res.status(403).json({ error: 'Missing permission' });
  }

  // Delete cached file
  if (item.cached_path) {
    fs.unlink(item.cached_path, () => {});
  }

  // If this was the current item, clear state
  const state = getState(channel.id);
  if (state?.current_item_id === item.id) {
    db.prepare('UPDATE theater_state SET current_item_id = NULL, position_ms = 0, playing = 0 WHERE channel_id = ?').run(channel.id);
  }

  db.prepare('DELETE FROM theater_queue WHERE id = ?').run(item.id);
  broadcastTheaterQueueUpdate(channel.id);
  res.json({ success: true });
});

// PATCH /:channelId/queue/:itemId/position
router.patch('/:channelId/queue/:itemId/position', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!canControlTheater(req.user, channel.id)) {
    return res.status(403).json({ error: 'Missing permission: play_in_theater' });
  }
  const { position } = req.body;
  if (typeof position !== 'number') return res.status(400).json({ error: 'position required' });

  const item = db.prepare('SELECT id FROM theater_queue WHERE id = ? AND channel_id = ?').get(req.params.itemId, channel.id);
  if (!item) return res.status(404).json({ error: 'Queue item not found' });

  db.prepare('UPDATE theater_queue SET position = ? WHERE id = ?').run(position, item.id);
  broadcastTheaterQueueUpdate(channel.id);
  res.json({ success: true });
});

// POST /:channelId/queue/:itemId/vote
router.post('/:channelId/queue/:itemId/vote', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!requireViewChannels(req, res, channel.id)) return;

  const settings = getTheaterSettings(channel.id);
  if (!settings.theater_queue_voting_enabled) return res.status(403).json({ error: 'Queue voting is disabled' });

  const item = db.prepare('SELECT id FROM theater_queue WHERE id = ? AND channel_id = ?').get(req.params.itemId, channel.id);
  if (!item) return res.status(404).json({ error: 'Queue item not found' });

  try {
    db.prepare('INSERT INTO theater_queue_votes (queue_item_id, user_id) VALUES (?, ?)').run(item.id, req.user.id);
    db.prepare('UPDATE theater_queue SET votes = votes + 1 WHERE id = ?').run(item.id);
  } catch { /* already voted */ }
  broadcastTheaterQueueUpdate(channel.id);
  res.json({ success: true });
});

// DELETE /:channelId/queue/:itemId/vote
router.delete('/:channelId/queue/:itemId/vote', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!requireViewChannels(req, res, channel.id)) return;

  const settings = getTheaterSettings(channel.id);
  if (!settings.theater_queue_voting_enabled) return res.status(403).json({ error: 'Queue voting is disabled' });

  const item = db.prepare('SELECT id FROM theater_queue WHERE id = ? AND channel_id = ?').get(req.params.itemId, channel.id);
  if (!item) return res.status(404).json({ error: 'Queue item not found' });

  const deleted = db.prepare('DELETE FROM theater_queue_votes WHERE queue_item_id = ? AND user_id = ?').run(item.id, req.user.id);
  if (deleted.changes > 0) {
    db.prepare('UPDATE theater_queue SET votes = MAX(0, votes - 1) WHERE id = ?').run(item.id);
  }
  broadcastTheaterQueueUpdate(channel.id);
  res.json({ success: true });
});

// POST /:channelId/skip-vote
router.post('/:channelId/skip-vote', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!requireViewChannels(req, res, channel.id)) return;

  const settings = getTheaterSettings(channel.id);
  if (!settings.theater_skip_voting_enabled) return res.status(403).json({ error: 'Skip voting is disabled' });

  const state = getState(channel.id);
  if (!state?.current_item_id) return res.status(400).json({ error: 'Nothing is playing' });

  try {
    db.prepare('INSERT INTO theater_skip_votes (channel_id, user_id, item_id) VALUES (?, ?, ?)').run(channel.id, req.user.id, state.current_item_id);
  } catch { /* already voted */ }

  res.json({ success: true });
});

// GET /:channelId/state
router.get('/:channelId/state', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!requireViewChannels(req, res, channel.id)) return;

  const state = getState(channel.id);
  if (!state) return res.json({ state: null });

  const currentItem = state.current_item_id
    ? db.prepare('SELECT * FROM theater_queue WHERE id = ?').get(state.current_item_id)
    : null;

  res.json({
    state: {
      ...state,
      videoUrl: currentItem ? getVideoUrl(currentItem.cached_path, channel.id) : null,
    },
  });
});

// PATCH /:channelId/state — control playback
router.patch('/:channelId/state', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!canControlTheater(req.user, channel.id)) {
    const state = getState(channel.id);
    if (!state || state.host_user_id !== req.user.id) {
      return res.status(403).json({ error: 'Missing permission: play_in_theater' });
    }
  }

  const { playing, positionMs, currentItemId } = req.body;
  const fields = [];
  const values = [];
  if (typeof playing === 'boolean') { fields.push('playing = ?'); values.push(playing ? 1 : 0); }
  if (typeof positionMs === 'number') { fields.push('position_ms = ?'); values.push(Math.max(0, positionMs)); }
  if (currentItemId !== undefined) { fields.push('current_item_id = ?'); values.push(currentItemId || null); }
  fields.push('updated_at = unixepoch()');
  values.push(channel.id);

  db.prepare(`
    INSERT INTO theater_state (channel_id, position_ms, playing, updated_at) VALUES (?, 0, 0, unixepoch())
    ON CONFLICT(channel_id) DO NOTHING
  `).run(channel.id);
  db.prepare(`UPDATE theater_state SET ${fields.join(', ')} WHERE channel_id = ?`).run(...values);

  const { broadcastTheaterSync } = require('../socket/handler');
  broadcastTheaterSync(channel.id);
  res.json({ success: true });
});

// POST /:channelId/skip
router.post('/:channelId/skip', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!canControlTheater(req.user, channel.id)) {
    return res.status(403).json({ error: 'Missing permission: play_in_theater' });
  }

  const { advanceTheaterQueue } = require('../socket/handler');
  advanceTheaterQueue(channel.id);
  res.json({ success: true });
});

// GET /:channelId/settings
router.get('/:channelId/settings', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!requireViewChannels(req, res, channel.id)) return;

  const domains = db.prepare('SELECT domain FROM theater_domain_allowlist WHERE channel_id = ?').all(channel.id).map((r) => r.domain);
  res.json({ ...getTheaterSettings(channel.id), domains });
});

// PATCH /:channelId/settings
router.patch('/:channelId/settings', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }

  // Ensure channel_settings row exists
  db.prepare('INSERT OR IGNORE INTO channel_settings (channel_id) VALUES (?)').run(channel.id);

  const allowed = [
    'theater_max_duration_seconds', 'theater_open_queuing', 'theater_auto_advance',
    'theater_reactions_enabled', 'theater_skip_voting_enabled', 'theater_queue_voting_enabled',
  ];
  const fields = [];
  const values = [];
  for (const key of allowed) {
    if (req.body[key] !== undefined) {
      const val = typeof req.body[key] === 'boolean' ? (req.body[key] ? 1 : 0) : Number(req.body[key]);
      fields.push(`${key} = ?`);
      values.push(val);
    }
  }
  if (fields.length > 0) {
    values.push(channel.id);
    db.prepare(`UPDATE channel_settings SET ${fields.join(', ')} WHERE channel_id = ?`).run(...values);
  }

  const domains = db.prepare('SELECT domain FROM theater_domain_allowlist WHERE channel_id = ?').all(channel.id).map((r) => r.domain);
  res.json({ ...getTheaterSettings(channel.id), domains });
});

// GET /:channelId/domains
router.get('/:channelId/domains', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  const domains = db.prepare('SELECT domain, created_at FROM theater_domain_allowlist WHERE channel_id = ? ORDER BY created_at').all(channel.id);
  res.json(domains);
});

// POST /:channelId/domains
router.post('/:channelId/domains', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  const { domain } = req.body;
  if (!domain || typeof domain !== 'string') return res.status(400).json({ error: 'domain required' });
  const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
  if (!clean) return res.status(400).json({ error: 'Invalid domain' });

  try {
    db.prepare('INSERT INTO theater_domain_allowlist (channel_id, domain) VALUES (?, ?)').run(channel.id, clean);
  } catch { /* already exists */ }
  res.status(201).json({ domain: clean });
});

// DELETE /:channelId/domains/:domain
router.delete('/:channelId/domains/:domain', (req, res) => {
  const channel = requireTheaterChannel(req, res);
  if (!channel) return;
  if (!hasPermission(req.user, PERMISSIONS.MANAGE_CHANNELS)) {
    return res.status(403).json({ error: 'Missing permission: manage_channels' });
  }
  db.prepare('DELETE FROM theater_domain_allowlist WHERE channel_id = ? AND domain = ?').run(channel.id, req.params.domain);
  res.json({ success: true });
});

module.exports = router;
