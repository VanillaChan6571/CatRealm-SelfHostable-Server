'use strict';

// A message posted in a thread or forum post only reaches the sockets that have
// that thread open. This records the activity on the thread (so forums can sort
// by latest activity) and builds the notice sent to everyone in the channel, so
// members who are elsewhere still get an unread badge and a notification.

/**
 * Stamps the thread's last activity and returns the `thread:activity` payload,
 * or null if the message is not in a thread or the thread no longer exists.
 */
function recordThreadActivity(db, message) {
  if (!message?.thread_id) return null;
  const thread = db.prepare(`
    SELECT t.id, t.name, t.channel_id, c.type AS channel_type
    FROM threads t JOIN channels c ON c.id = t.channel_id
    WHERE t.id = ?
  `).get(message.thread_id);
  if (!thread) return null;

  const at = Number.isInteger(message.created_at) ? message.created_at : Math.floor(Date.now() / 1000);
  // Activity never moves a thread backwards (a scheduled message can publish out of order).
  db.prepare(`
    INSERT INTO thread_settings (thread_id, last_message_at) VALUES (?, ?)
    ON CONFLICT(thread_id) DO UPDATE SET last_message_at = MAX(last_message_at, excluded.last_message_at)
  `).run(thread.id, at);
  const settings = db.prepare('SELECT last_message_at FROM thread_settings WHERE thread_id = ?').get(thread.id);
  const replyCount = db.prepare('SELECT COUNT(*) AS c FROM messages WHERE thread_id = ?').get(thread.id).c;

  return {
    channelId: thread.channel_id,
    threadId: thread.id,
    threadName: thread.name,
    isForumPost: thread.channel_type === 'forum',
    lastMessageAt: settings.last_message_at,
    replyCount,
    message,
  };
}

/**
 * Threads created before activity was recorded kept their creation time as
 * "last activity". Brings them up to their newest message; safe to run every start.
 */
function backfillThreadActivity(db) {
  return db.prepare(`
    UPDATE thread_settings
    SET last_message_at = (SELECT MAX(m.created_at) FROM messages m WHERE m.thread_id = thread_settings.thread_id AND m.scheduled_at IS NULL)
    WHERE EXISTS (
      SELECT 1 FROM messages m
      WHERE m.thread_id = thread_settings.thread_id AND m.scheduled_at IS NULL AND m.created_at > thread_settings.last_message_at
    )
  `).run().changes;
}

module.exports = { recordThreadActivity, backfillThreadActivity };
