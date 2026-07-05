const db = require('./db');

const MAX_REACTION_TOKEN_LENGTH = 512;

// Accepts unicode emoji and custom emote/sticker tokens (same rules as central DMs).
function normalizeReactionToken(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_REACTION_TOKEN_LENGTH) return null;
  return trimmed;
}

// Batched summary: { [messageId]: [{ emoji, count, users }] }.
// `reacted` is intentionally omitted — payloads fan out to whole channels, so
// each client derives it from `users` and its own user id.
function summarizeMessageReactions(messageIds) {
  const uniqueIds = [...new Set((messageIds || []).filter(Boolean))];
  if (uniqueIds.length === 0) return {};

  const placeholders = uniqueIds.map(() => '?').join(', ');
  const rows = db.prepare(`
    SELECT message_id, emoji, user_id
    FROM message_reactions
    WHERE message_id IN (${placeholders})
    ORDER BY created_at ASC
  `).all(...uniqueIds);

  const byMessage = new Map();
  for (const row of rows) {
    let byEmoji = byMessage.get(row.message_id);
    if (!byEmoji) {
      byEmoji = new Map();
      byMessage.set(row.message_id, byEmoji);
    }
    let entry = byEmoji.get(row.emoji);
    if (!entry) {
      entry = { emoji: row.emoji, users: [] };
      byEmoji.set(row.emoji, entry);
    }
    entry.users.push(row.user_id);
  }

  const result = {};
  for (const messageId of uniqueIds) {
    const byEmoji = byMessage.get(messageId);
    result[messageId] = byEmoji
      ? Array.from(byEmoji.values()).map((entry) => ({
          emoji: entry.emoji,
          count: entry.users.length,
          users: entry.users,
        }))
      : [];
  }
  return result;
}

// Toggle one (message, user, emoji) row. Returns the message's fresh summary.
function toggleMessageReaction(messageId, userId, emoji) {
  const existing = db.prepare(
    'SELECT 1 FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?'
  ).get(messageId, userId, emoji);
  if (existing) {
    db.prepare('DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?')
      .run(messageId, userId, emoji);
  } else {
    db.prepare('INSERT INTO message_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)')
      .run(messageId, userId, emoji);
  }
  return {
    reacted: !existing,
    reactions: summarizeMessageReactions([messageId])[messageId] || [],
  };
}

function attachReactionsToMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return messages;
  const summary = summarizeMessageReactions(messages.map((m) => m.id));
  return messages.map((m) => ({ ...m, reactions: summary[m.id] || [] }));
}

module.exports = {
  normalizeReactionToken,
  summarizeMessageReactions,
  toggleMessageReaction,
  attachReactionsToMessages,
};
