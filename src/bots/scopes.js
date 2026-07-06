// Consent scopes a bot can request from individual users. These are per-user
// privacy gates — server-level powers (send/delete messages, etc.) come from
// the roles admins assign to the bot user, same as any member.
const BOT_SCOPES = Object.freeze({
  // Invoking the bot's slash commands. Always requested implicitly.
  INTERACTIONS: 'interactions',
  // Bot may read the user's bio/pronouns/status/activity via the profile API.
  PROFILE: 'profile',
  // Bot may @mention/ping the user (mention highlight + push).
  MENTIONS: 'mentions',
  // Bot may message the user in the Bot DMs channel.
  PRIVATE_MESSAGES: 'private_messages',
});

const ALL_BOT_SCOPES = Object.freeze(Object.values(BOT_SCOPES));

function normalizeRequestedScopes(scopes) {
  const list = Array.isArray(scopes) ? scopes : [];
  const normalized = list
    .map((s) => String(s).toLowerCase().trim())
    .filter((s) => ALL_BOT_SCOPES.includes(s));
  // Interactions is the baseline scope every bot requests.
  if (!normalized.includes(BOT_SCOPES.INTERACTIONS)) normalized.unshift(BOT_SCOPES.INTERACTIONS);
  return Array.from(new Set(normalized));
}

function parseJsonSafe(value, fallback) {
  if (typeof value !== 'string' || !value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

// Returns { decision: 'allowed'|'denied', scopes: {scope: bool} } or null when
// the user has never answered the consent prompt for this bot.
function getBotConsent(db, botId, userId) {
  const row = db.prepare('SELECT decision, scopes, updated_at FROM bot_user_consents WHERE bot_id = ? AND user_id = ?').get(botId, userId);
  if (!row) return null;
  return {
    decision: row.decision === 'allowed' ? 'allowed' : 'denied',
    scopes: parseJsonSafe(row.scopes, {}),
    updated_at: row.updated_at,
  };
}

function botHasScope(db, botId, userId, scope) {
  const consent = getBotConsent(db, botId, userId);
  if (!consent || consent.decision !== 'allowed') return false;
  return consent.scopes?.[scope] === true;
}

function saveBotConsent(db, botId, userId, decision, scopes) {
  const normalizedDecision = decision === 'allowed' ? 'allowed' : 'denied';
  const normalizedScopes = {};
  for (const scope of ALL_BOT_SCOPES) {
    normalizedScopes[scope] = normalizedDecision === 'allowed' && scopes?.[scope] === true;
  }
  db.prepare(`
    INSERT INTO bot_user_consents (bot_id, user_id, decision, scopes, updated_at)
    VALUES (?, ?, ?, ?, unixepoch())
    ON CONFLICT(bot_id, user_id) DO UPDATE SET
      decision = excluded.decision,
      scopes = excluded.scopes,
      updated_at = excluded.updated_at
  `).run(botId, userId, normalizedDecision, JSON.stringify(normalizedScopes));
  return { decision: normalizedDecision, scopes: normalizedScopes };
}

module.exports = {
  BOT_SCOPES,
  ALL_BOT_SCOPES,
  normalizeRequestedScopes,
  getBotConsent,
  botHasScope,
  saveBotConsent,
  parseJsonSafe,
};
