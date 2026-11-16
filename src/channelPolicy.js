'use strict';

// Thread settings and media settings that staff set on a category, a channel or a
// single thread, and the rules for combining them:
//
//   Thread slowmode   thread → channel → category → the channel's own slowmode
//   Thread auto-hide  thread → channel → category → 48 hours
//   Media auto-marks  on if the channel OR its category turns it on (a category is a
//                     floor its channels cannot lower). NSFW marks only apply in
//                     channels marked NSFW, and the Lewd/Blood/Gore marks need Auto NSFW.
//
// "Auto-hide" is computed, not stored: a thread drops out of the channel's thread list
// once it has been quiet for the configured time, and returns when someone writes in it.

const SYNC_WITH_CHANNEL = -1;
const SLOWMODE_MAX_SECONDS = 21600;
const AUTO_HIDE_DEFAULT_MINUTES = 2880; // 48 hours
const AUTO_HIDE_MAX_MINUTES = 525600; // 1 year
const MEDIA_FLAGS = ['spoiler', 'nsfw', 'lewd', 'blood', 'gore'];
const MEDIA_COLUMNS = MEDIA_FLAGS.map((flag) => `media_auto_${flag}`);
// Tags a message can carry. 'nsfw' is the plain "this is NSFW" mark with no sub-category.
const MEDIA_TAGS = ['blood', 'gore', 'violence', 'lewd', 'sexual', 'disturbing', 'spoiler', 'nsfw'];

class PolicyError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

function migrate(db) {
  const columnsOf = (table) => db.prepare(`PRAGMA table_info(${table})`).all().map((column) => column.name);
  const add = (table, column, definition) => {
    if (!columnsOf(table).includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  };

  // NULL = use the category's setting; -1 = same as the channel's slowmode; otherwise seconds.
  add('channel_settings', 'thread_slowmode', 'INTEGER');
  // NULL = use the category's setting; 0 = never hide; otherwise minutes of inactivity.
  add('channel_settings', 'thread_auto_hide_minutes', 'INTEGER');
  for (const column of MEDIA_COLUMNS) add('channel_settings', column, 'INTEGER NOT NULL DEFAULT 0');

  db.exec(`
    CREATE TABLE IF NOT EXISTS category_settings (
      category_id TEXT PRIMARY KEY REFERENCES categories(id) ON DELETE CASCADE,
      thread_slowmode INTEGER,
      thread_auto_hide_minutes INTEGER,
      ${MEDIA_COLUMNS.map((column) => `${column} INTEGER NOT NULL DEFAULT 0`).join(',\n      ')}
    );
  `);

  // Per-thread overrides; NULL = use the channel's setting.
  add('thread_settings', 'slowmode', 'INTEGER');
  add('thread_settings', 'auto_hide_minutes', 'INTEGER');

  // The tag table's CHECK predates 'spoiler' and 'nsfw', so those tags were dropped on
  // insert and a spoiler lost its cover after a reload. Rebuild it with the full list.
  const tagTable = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'message_nsfw_tags'").get();
  if (tagTable && !/'nsfw'/.test(tagTable.sql)) {
    db.transaction(() => {
      db.exec(`
        CREATE TABLE message_nsfw_tags_next (
          message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
          tag TEXT NOT NULL CHECK(tag IN (${MEDIA_TAGS.map((tag) => `'${tag}'`).join(', ')})),
          PRIMARY KEY (message_id, tag)
        );
        INSERT INTO message_nsfw_tags_next (message_id, tag) SELECT message_id, tag FROM message_nsfw_tags;
        DROP TABLE message_nsfw_tags;
        ALTER TABLE message_nsfw_tags_next RENAME TO message_nsfw_tags;
        CREATE INDEX IF NOT EXISTS idx_message_nsfw ON message_nsfw_tags(message_id);
      `);
    })();
  }
}

const emptyMedia = () => Object.fromEntries(MEDIA_FLAGS.map((flag) => [flag, false]));
const mediaFromRow = (row) => Object.fromEntries(MEDIA_FLAGS.map((flag) => [flag, !!row?.[`media_auto_${flag}`]]));

function categoryPolicy(db, categoryId) {
  if (!categoryId) return null;
  const category = db.prepare('SELECT id, name FROM categories WHERE id = ?').get(categoryId);
  if (!category) return null;
  const row = db.prepare('SELECT * FROM category_settings WHERE category_id = ?').get(categoryId);
  return {
    id: category.id,
    name: category.name,
    threadSlowmode: row?.thread_slowmode ?? null,
    threadAutoHideMinutes: row?.thread_auto_hide_minutes ?? null,
    media: row ? mediaFromRow(row) : emptyMedia(),
  };
}

/** A channel's own settings, its category's, and what actually applies. Null if the channel is gone. */
function channelPolicy(db, channelId) {
  const channel = db.prepare('SELECT id, type, nsfw, category_id FROM channels WHERE id = ?').get(channelId);
  if (!channel) return null;
  const row = db.prepare('SELECT * FROM channel_settings WHERE channel_id = ?').get(channelId);
  const category = categoryPolicy(db, channel.category_id);
  const own = {
    threadSlowmode: row?.thread_slowmode ?? null,
    threadAutoHideMinutes: row?.thread_auto_hide_minutes ?? null,
    media: row ? mediaFromRow(row) : emptyMedia(),
  };
  const channelSlowmode = row?.slowmode ?? 0;

  const slowmodeChoice = own.threadSlowmode ?? category?.threadSlowmode ?? SYNC_WITH_CHANNEL;
  const media = {};
  for (const flag of MEDIA_FLAGS) media[flag] = own.media[flag] || !!category?.media[flag];
  media.nsfw = media.nsfw && !!channel.nsfw;
  for (const flag of ['lewd', 'blood', 'gore']) media[flag] = media[flag] && media.nsfw;

  return {
    channel: { id: channel.id, type: channel.type, nsfw: !!channel.nsfw, categoryId: channel.category_id ?? null, slowmode: channelSlowmode },
    own,
    category,
    effective: {
      threadSlowmode: slowmodeChoice === SYNC_WITH_CHANNEL ? channelSlowmode : slowmodeChoice,
      threadAutoHideMinutes: own.threadAutoHideMinutes ?? category?.threadAutoHideMinutes ?? AUTO_HIDE_DEFAULT_MINUTES,
      media,
    },
  };
}

/** What applies to one thread: its own overrides, falling back to its channel. */
function threadPolicy(db, threadId) {
  const thread = db.prepare('SELECT id, channel_id FROM threads WHERE id = ?').get(threadId);
  if (!thread) return null;
  const row = db.prepare('SELECT slowmode, auto_hide_minutes FROM thread_settings WHERE thread_id = ?').get(threadId);
  const channel = channelPolicy(db, thread.channel_id);
  const own = { slowmode: row?.slowmode ?? null, autoHideMinutes: row?.auto_hide_minutes ?? null };
  return {
    threadId: thread.id,
    channelId: thread.channel_id,
    own,
    channel: { slowmode: channel?.effective.threadSlowmode ?? 0, autoHideMinutes: channel?.effective.threadAutoHideMinutes ?? AUTO_HIDE_DEFAULT_MINUTES },
    effective: {
      slowmode: own.slowmode ?? channel?.effective.threadSlowmode ?? 0,
      autoHideMinutes: own.autoHideMinutes ?? channel?.effective.threadAutoHideMinutes ?? AUTO_HIDE_DEFAULT_MINUTES,
    },
  };
}

/** True once a thread has been quiet for longer than its auto-hide time (0 = never hides). */
function isThreadHidden(lastActivityAt, autoHideMinutes, now = Math.floor(Date.now() / 1000)) {
  return autoHideMinutes > 0 && now - lastActivityAt > autoHideMinutes * 60;
}

/** The tags a media message ends up with once the channel's auto-marks are applied. */
function enforceMediaTags(media, tags = []) {
  const result = new Set(tags.filter((tag) => MEDIA_TAGS.includes(tag)));
  if (media?.spoiler) result.add('spoiler');
  if (media?.nsfw) result.add('nsfw');
  for (const flag of ['lewd', 'blood', 'gore']) if (media?.[flag]) result.add(flag);
  return [...result];
}

/** Applies the channel's auto-marks to a message that has media and stores its tags. Returns them. */
function tagMediaMessage(db, messageId, channelId, tags = []) {
  const policy = channelPolicy(db, channelId);
  const finalTags = enforceMediaTags(policy?.effective.media, tags);
  const insert = db.prepare('INSERT OR IGNORE INTO message_nsfw_tags (message_id, tag) VALUES (?, ?)');
  for (const tag of finalTags) insert.run(messageId, tag);
  return finalTags;
}

// ── Validation and writes ───────────────────────────────────────────────────
function slowmodeValue(value, { allowSync, label = 'Thread slowmode' }) {
  if (value === null) return null;
  if (allowSync && value === SYNC_WITH_CHANNEL) return SYNC_WITH_CHANNEL;
  if (!Number.isInteger(value) || value < 0 || value > SLOWMODE_MAX_SECONDS) {
    throw new PolicyError(`${label} must be between 0 and ${SLOWMODE_MAX_SECONDS} seconds`);
  }
  return value;
}

function autoHideValue(value) {
  if (value === null) return null;
  if (!Number.isInteger(value) || value < 0 || value > AUTO_HIDE_MAX_MINUTES) {
    throw new PolicyError(`Auto-hide must be between 0 and ${AUTO_HIDE_MAX_MINUTES} minutes`);
  }
  return value;
}

// Sub-marks cannot be on without Auto NSFW; clear them rather than store a combination that means nothing.
function mediaValues(input, current) {
  const next = { ...current };
  for (const flag of MEDIA_FLAGS) if (input?.[flag] !== undefined) next[flag] = !!input[flag];
  if (!next.nsfw) for (const flag of ['lewd', 'blood', 'gore']) next[flag] = false;
  return next;
}

function settingsFromBody(body, current, { allowSync }) {
  const sets = {};
  if (body?.threadSlowmode !== undefined) sets.thread_slowmode = slowmodeValue(body.threadSlowmode, { allowSync });
  if (body?.threadAutoHideMinutes !== undefined) sets.thread_auto_hide_minutes = autoHideValue(body.threadAutoHideMinutes);
  if (body?.media !== undefined) {
    const media = mediaValues(body.media, current.media);
    for (const flag of MEDIA_FLAGS) sets[`media_auto_${flag}`] = media[flag] ? 1 : 0;
  }
  return sets;
}

function update(db, table, keyColumn, id, sets) {
  const columns = Object.keys(sets);
  if (columns.length === 0) return;
  db.transaction(() => {
    db.prepare(`INSERT OR IGNORE INTO ${table} (${keyColumn}) VALUES (?)`).run(id);
    db.prepare(`UPDATE ${table} SET ${columns.map((column) => `${column} = ?`).join(', ')} WHERE ${keyColumn} = ?`)
      .run(...columns.map((column) => sets[column]), id);
  })();
}

function writeChannelPolicy(db, channelId, body) {
  const current = channelPolicy(db, channelId);
  if (!current) throw new PolicyError('Channel not found', 404);
  const sets = settingsFromBody(body, current.own, { allowSync: true });
  if (sets.media_auto_nsfw === 1 && !current.channel.nsfw) {
    throw new PolicyError('Mark the channel as NSFW before turning on Auto Mark NSFW');
  }
  update(db, 'channel_settings', 'channel_id', channelId, sets);
  return channelPolicy(db, channelId);
}

function writeCategoryPolicy(db, categoryId, body) {
  const current = categoryPolicy(db, categoryId);
  if (!current) throw new PolicyError('Category not found', 404);
  update(db, 'category_settings', 'category_id', categoryId, settingsFromBody(body, current, { allowSync: true }));
  return categoryPolicy(db, categoryId);
}

function writeThreadSettings(db, threadId, body) {
  const current = threadPolicy(db, threadId);
  if (!current) throw new PolicyError('Thread not found', 404);
  const sets = {};
  if (body?.slowmode !== undefined) sets.slowmode = slowmodeValue(body.slowmode, { allowSync: false });
  if (body?.autoHideMinutes !== undefined) sets.auto_hide_minutes = autoHideValue(body.autoHideMinutes);
  update(db, 'thread_settings', 'thread_id', threadId, sets);
  return threadPolicy(db, threadId);
}

module.exports = {
  SYNC_WITH_CHANNEL, SLOWMODE_MAX_SECONDS, AUTO_HIDE_DEFAULT_MINUTES, AUTO_HIDE_MAX_MINUTES, MEDIA_FLAGS, MEDIA_TAGS,
  PolicyError, migrate, categoryPolicy, channelPolicy, threadPolicy, isThreadHidden, enforceMediaTags, tagMediaMessage,
  writeChannelPolicy, writeCategoryPolicy, writeThreadSettings,
};
