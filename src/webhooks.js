const crypto = require('crypto');
const axios = require('axios');
const { randomUUID } = require('crypto');
const db = require('./db');
const { encryptMessageContent } = require('./messageCrypto');
const pteroLog = require('./logger');

const WEBHOOK_SCOPE_CHANNEL = 'channel';
const WEBHOOK_SCOPE_CATEGORY = 'category';
const WEBHOOK_AUTH_SECURED = 'secured';
const WEBHOOK_AUTH_SIMPLE = 'simple';
const WEBHOOK_EVENT_MESSAGE_CREATED = 'message.created';
const WEBHOOK_EVENT_CHANNEL_CREATED = 'channel.created';
const WEBHOOK_EVENT_CHANNEL_DELETED = 'channel.deleted';
const WEBHOOK_SYSTEM_USERNAME = '__catrealm_webhook__';
const DELIVERY_PENDING = 'pending';
const DELIVERY_DELIVERED = 'delivered';
const DELIVERY_FAILED = 'failed';
const DELIVERY_RETRYING = 'retrying';

let workerTimer = null;
let workerRunning = false;

function getWebhookCryptoKey() {
  return crypto.createHash('sha256')
    .update(String(process.env.JWT_SECRET || 'catrealm-webhook-fallback'), 'utf8')
    .digest();
}

function encryptSecret(secret) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', getWebhookCryptoKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(secret), 'utf8'), cipher.final()]);
  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
}

function decryptSecret(encryptedSecret) {
  if (typeof encryptedSecret !== 'string' || !encryptedSecret.includes(':')) return '';
  const [ivHex, bodyHex] = encryptedSecret.split(':');
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    getWebhookCryptoKey(),
    Buffer.from(ivHex, 'hex')
  );
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(bodyHex, 'hex')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

function hashSecret(secret) {
  return crypto.createHash('sha256').update(String(secret), 'utf8').digest('hex');
}

function generateSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function buildSecretPreview(secret) {
  const normalized = String(secret || '');
  return normalized.length <= 8 ? normalized : `${normalized.slice(0, 4)}...${normalized.slice(-4)}`;
}

function normalizeScopeType(scopeType) {
  return scopeType === WEBHOOK_SCOPE_CATEGORY ? WEBHOOK_SCOPE_CATEGORY : WEBHOOK_SCOPE_CHANNEL;
}

function normalizeBoolean(value) {
  return value === true || value === 1 || value === '1';
}

function validateCallbackUrl(callbackUrl) {
  if (callbackUrl === null || callbackUrl === undefined || callbackUrl === '') return null;
  try {
    const parsed = new URL(String(callbackUrl));
    if (!['http:', 'https:'].includes(parsed.protocol)) return 'Callback URL must use http or https';
    return null;
  } catch (_err) {
    return 'Callback URL must be a valid URL';
  }
}

function buildInboundUrl(req, scopeType, webhookId, authMode = WEBHOOK_AUTH_SECURED, secret = null) {
  const proto = req.get('x-forwarded-proto')?.split(',')[0]?.trim() || req.protocol || 'http';
  const host = req.get('x-forwarded-host')?.split(',')[0]?.trim() || req.get('host') || 'localhost';
  if (authMode === WEBHOOK_AUTH_SIMPLE && secret) {
    return `${proto}://${host}/api/webhooks/simple/${scopeType}/${webhookId}/${secret}`;
  }
  return `${proto}://${host}/api/webhooks/${scopeType}/${webhookId}`;
}

function parseActionFlags(raw, scopeType) {
  const defaults = scopeType === WEBHOOK_SCOPE_CATEGORY
    ? { allowConversationUpsert: true }
    : { allowMessageCreate: true };
  if (!raw) return defaults;
  try {
    const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (!parsed || typeof parsed !== 'object') return defaults;
    return {
      allowMessageCreate: parsed.allowMessageCreate !== false,
      allowConversationUpsert: parsed.allowConversationUpsert !== false,
    };
  } catch (_err) {
    return defaults;
  }
}

function normalizeAuthMode(value) {
  return value === WEBHOOK_AUTH_SIMPLE ? WEBHOOK_AUTH_SIMPLE : WEBHOOK_AUTH_SECURED;
}

function mapWebhookRow(row, req) {
  if (!row) return null;
  const authMode = normalizeAuthMode(row.auth_mode);
  const secret = req ? decryptSecret(row.secret_encrypted) : null;
  return {
    id: row.id,
    name: row.name,
    scopeType: row.scope_type,
    scopeId: row.scope_id,
    authMode,
    inboundEnabled: !!row.inbound_enabled,
    outboundEnabled: !!row.outbound_enabled,
    actionFlags: parseActionFlags(row.action_flags, row.scope_type),
    ipLockEnabled: !!row.ip_lock_enabled,
    lockedIp: row.locked_ip || null,
    callbackUrl: row.callback_url || null,
    enabled: !!row.enabled,
    secretPreview: row.secret_preview || null,
    inboundUrl: row.inbound_enabled ? buildInboundUrl(req, row.scope_type, row.id, authMode, secret) : null,
    lastDeliveryAt: row.last_delivery_at || null,
    lastDeliveryStatus: row.last_delivery_status || null,
    lastDeliveryError: row.last_delivery_error || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function getSystemWebhookUser() {
  return db.prepare(`
    SELECT id, username, avatar, display_name
    FROM users
    WHERE username = ? AND COALESCE(is_member, 1) = 0
    LIMIT 1
  `).get(WEBHOOK_SYSTEM_USERNAME);
}

function listWebhooks(scopeType, scopeId, req) {
  return db.prepare(`
    SELECT *
    FROM webhooks
    WHERE scope_type = ? AND scope_id = ?
    ORDER BY created_at DESC, name COLLATE NOCASE ASC
  `).all(scopeType, scopeId).map((row) => mapWebhookRow(row, req));
}

function getWebhookById(scopeType, scopeId, webhookId) {
  return db.prepare(`
    SELECT *
    FROM webhooks
    WHERE id = ? AND scope_type = ? AND scope_id = ?
    LIMIT 1
  `).get(webhookId, scopeType, scopeId);
}

function getWebhookByIdAny(webhookId) {
  return db.prepare(`
    SELECT *
    FROM webhooks
    WHERE id = ?
    LIMIT 1
  `).get(webhookId);
}

function getPublicWebhook(scopeType, webhookId) {
  return db.prepare(`
    SELECT *
    FROM webhooks
    WHERE id = ? AND scope_type = ?
    LIMIT 1
  `).get(webhookId, scopeType);
}

function normalizeActionFlags(scopeType, actionFlags) {
  const current = parseActionFlags(actionFlags, scopeType);
  if (scopeType === WEBHOOK_SCOPE_CATEGORY) {
    return {
      allowConversationUpsert: current.allowConversationUpsert !== false,
    };
  }
  return {
    allowMessageCreate: current.allowMessageCreate !== false,
  };
}

function assertWebhookConfig({ name, authMode, inboundEnabled, outboundEnabled, callbackUrl, actionFlags, scopeType }) {
  if (typeof name !== 'string' || name.trim().length < 2) {
    return 'Webhook name required';
  }
  const normalizedAuthMode = normalizeAuthMode(authMode);
  if (!inboundEnabled && !outboundEnabled) {
    return 'Enable inbound or outbound delivery';
  }
  if (normalizedAuthMode === WEBHOOK_AUTH_SIMPLE && outboundEnabled) {
    return 'Simple webhooks do not support outbound callbacks';
  }
  if (normalizedAuthMode === WEBHOOK_AUTH_SIMPLE && !inboundEnabled) {
    return 'Simple webhooks require inbound enabled';
  }
  const normalizedFlags = normalizeActionFlags(scopeType, actionFlags);
  if (scopeType === WEBHOOK_SCOPE_CHANNEL && !normalizedFlags.allowMessageCreate) {
    return 'Enable at least one channel action';
  }
  if (scopeType === WEBHOOK_SCOPE_CATEGORY && !normalizedFlags.allowConversationUpsert) {
    return 'Enable at least one category action';
  }
  const callbackError = validateCallbackUrl(callbackUrl);
  if (callbackError) return callbackError;
  if (outboundEnabled && (!callbackUrl || !String(callbackUrl).trim())) {
    return 'Callback URL required when outbound is enabled';
  }
  return null;
}

function createWebhook({ req, scopeType, scopeId, authMode, name, inboundEnabled, outboundEnabled, actionFlags, callbackUrl, ipLockEnabled, createdBy }) {
  const normalizedAuthMode = normalizeAuthMode(authMode);
  const normalizedFlags = normalizeActionFlags(scopeType, actionFlags);
  const normalizedIpLockEnabled = normalizedAuthMode === WEBHOOK_AUTH_SIMPLE
    ? (ipLockEnabled === undefined ? true : normalizeBoolean(ipLockEnabled))
    : false;
  const validationError = assertWebhookConfig({
    name,
    authMode: normalizedAuthMode,
    inboundEnabled,
    outboundEnabled,
    callbackUrl,
    actionFlags: normalizedFlags,
    scopeType,
  });
  if (validationError) {
    const error = new Error(validationError);
    error.status = 400;
    throw error;
  }
  const now = Math.floor(Date.now() / 1000);
  const id = randomUUID();
  const secret = generateSecret();
  db.prepare(`
    INSERT INTO webhooks (
      id, name, scope_type, scope_id, auth_mode, inbound_enabled, outbound_enabled, action_flags,
      ip_lock_enabled, locked_ip, callback_url, secret_hash, secret_encrypted, secret_preview,
      created_by, created_at, updated_at, enabled
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, 1)
  `).run(
    id,
    name.trim(),
    scopeType,
    scopeId,
    normalizedAuthMode,
    inboundEnabled ? 1 : 0,
    outboundEnabled ? 1 : 0,
    JSON.stringify(normalizedFlags),
    normalizedIpLockEnabled ? 1 : 0,
    callbackUrl ? String(callbackUrl).trim() : null,
    hashSecret(secret),
    encryptSecret(secret),
    buildSecretPreview(secret),
    createdBy,
    now,
    now
  );
  const row = getWebhookById(scopeType, scopeId, id);
  return {
    webhook: mapWebhookRow(row, req),
    signingSecret: secret,
  };
}

function updateWebhook({ req, scopeType, scopeId, webhookId, body }) {
  const row = getWebhookById(scopeType, scopeId, webhookId);
  if (!row) {
    const error = new Error('Webhook not found');
    error.status = 404;
    throw error;
  }
  const nextName = typeof body.name === 'string' ? body.name.trim() : row.name;
  const nextAuthMode = body.authMode === undefined ? normalizeAuthMode(row.auth_mode) : normalizeAuthMode(body.authMode);
  const nextInboundEnabled = body.inboundEnabled === undefined ? !!row.inbound_enabled : !!body.inboundEnabled;
  const nextOutboundEnabled = body.outboundEnabled === undefined ? !!row.outbound_enabled : !!body.outboundEnabled;
  const nextActionFlags = body.actionFlags === undefined ? parseActionFlags(row.action_flags, scopeType) : normalizeActionFlags(scopeType, body.actionFlags);
  const nextCallbackUrl = body.callbackUrl === undefined ? row.callback_url : (body.callbackUrl ? String(body.callbackUrl).trim() : null);
  const nextEnabled = body.enabled === undefined ? !!row.enabled : !!body.enabled;
  const nextIpLockEnabled = nextAuthMode === WEBHOOK_AUTH_SIMPLE
    ? (
      body.ipLockEnabled === undefined
        ? (normalizeAuthMode(row.auth_mode) === WEBHOOK_AUTH_SIMPLE ? !!row.ip_lock_enabled : true)
        : normalizeBoolean(body.ipLockEnabled)
    )
    : false;
  const nextLockedIp = body.resetIpLock === true
    ? null
    : (nextAuthMode === WEBHOOK_AUTH_SIMPLE && nextIpLockEnabled ? (row.locked_ip || null) : null);
  const validationError = assertWebhookConfig({
    name: nextName,
    authMode: nextAuthMode,
    inboundEnabled: nextInboundEnabled,
    outboundEnabled: nextOutboundEnabled,
    callbackUrl: nextCallbackUrl,
    actionFlags: nextActionFlags,
    scopeType,
  });
  if (validationError) {
    const error = new Error(validationError);
    error.status = 400;
    throw error;
  }
  const now = Math.floor(Date.now() / 1000);
  db.prepare(`
    UPDATE webhooks
    SET name = ?, auth_mode = ?, inbound_enabled = ?, outbound_enabled = ?, action_flags = ?, ip_lock_enabled = ?, locked_ip = ?, callback_url = ?, enabled = ?, updated_at = ?
    WHERE id = ?
  `).run(
    nextName,
    nextAuthMode,
    nextInboundEnabled ? 1 : 0,
    nextOutboundEnabled ? 1 : 0,
    JSON.stringify(nextActionFlags),
    nextIpLockEnabled ? 1 : 0,
    nextLockedIp,
    nextCallbackUrl,
    nextEnabled ? 1 : 0,
    now,
    webhookId
  );
  return mapWebhookRow(getWebhookById(scopeType, scopeId, webhookId), req);
}

function regenerateWebhookSecret({ req, scopeType, scopeId, webhookId }) {
  const row = getWebhookById(scopeType, scopeId, webhookId);
  if (!row) {
    const error = new Error('Webhook not found');
    error.status = 404;
    throw error;
  }
  const secret = generateSecret();
  const now = Math.floor(Date.now() / 1000);
  db.prepare(`
    UPDATE webhooks
    SET secret_hash = ?, secret_encrypted = ?, secret_preview = ?, updated_at = ?
    WHERE id = ?
  `).run(hashSecret(secret), encryptSecret(secret), buildSecretPreview(secret), now, webhookId);
  return {
    webhook: mapWebhookRow(getWebhookById(scopeType, scopeId, webhookId), req),
    signingSecret: secret,
  };
}

function deleteWebhook(scopeType, scopeId, webhookId) {
  const row = getWebhookById(scopeType, scopeId, webhookId);
  if (!row) return false;
  db.prepare('DELETE FROM webhooks WHERE id = ?').run(webhookId);
  return true;
}

function listAllWebhooks(req) {
  return db.prepare(`
    SELECT
      w.*,
      c.name AS channel_name,
      cat.name AS category_name
    FROM webhooks w
    LEFT JOIN channels c
      ON w.scope_type = 'channel' AND c.id = w.scope_id
    LEFT JOIN categories cat
      ON w.scope_type = 'category' AND cat.id = w.scope_id
    ORDER BY w.created_at DESC, w.name COLLATE NOCASE ASC
  `).all().map((row) => ({
    ...mapWebhookRow(row, req),
    scopeName: row.scope_type === WEBHOOK_SCOPE_CHANNEL ? (row.channel_name || 'Unknown Channel') : (row.category_name || 'Unknown Category'),
  }));
}

function updateWebhookById({ req, webhookId, body }) {
  const row = getWebhookByIdAny(webhookId);
  if (!row) {
    const error = new Error('Webhook not found');
    error.status = 404;
    throw error;
  }
  return updateWebhook({
    req,
    scopeType: row.scope_type,
    scopeId: row.scope_id,
    webhookId,
    body,
  });
}

function regenerateWebhookSecretById({ req, webhookId }) {
  const row = getWebhookByIdAny(webhookId);
  if (!row) {
    const error = new Error('Webhook not found');
    error.status = 404;
    throw error;
  }
  return regenerateWebhookSecret({
    req,
    scopeType: row.scope_type,
    scopeId: row.scope_id,
    webhookId,
  });
}

function deleteWebhookById(webhookId) {
  const row = getWebhookByIdAny(webhookId);
  if (!row) return false;
  db.prepare('DELETE FROM webhooks WHERE id = ?').run(webhookId);
  return true;
}

function timingSafeEqualHex(a, b) {
  const left = Buffer.from(String(a || ''), 'hex');
  const right = Buffer.from(String(b || ''), 'hex');
  if (left.length === 0 || right.length === 0 || left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function timingSafeEqualString(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  if (left.length === 0 || right.length === 0 || left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function verifyRequestSignature(req, webhook) {
  const timestampHeader = String(req.get('x-catrealm-timestamp') || '').trim();
  const signatureHeader = String(req.get('x-catrealm-signature') || '').trim();
  if (!timestampHeader || !signatureHeader) return 'Missing signature headers';
  const timestamp = Number(timestampHeader);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > 300) {
    return 'Stale or invalid timestamp';
  }
  const provided = signatureHeader.replace(/^sha256=/i, '');
  const secret = decryptSecret(webhook.secret_encrypted);
  if (!secret) return 'Webhook secret unavailable';
  const rawBody = typeof req.rawBody === 'string' ? req.rawBody : JSON.stringify(req.body || {});
  const expected = crypto.createHmac('sha256', secret)
    .update(`${timestampHeader}.${rawBody}`, 'utf8')
    .digest('hex');
  if (!timingSafeEqualHex(provided, expected)) return 'Invalid signature';
  return null;
}

function verifySimpleToken(token, webhook) {
  const secret = decryptSecret(webhook.secret_encrypted);
  if (!secret) return 'Webhook secret unavailable';
  if (!timingSafeEqualString(token, secret)) return 'Invalid webhook token';
  return null;
}

function normalizeIpValue(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (raw.startsWith('::ffff:')) return raw.slice(7);
  return raw;
}

function extractRequestIp(req) {
  const forwarded = String(req.get('x-forwarded-for') || '').split(',')[0].trim();
  if (forwarded) return normalizeIpValue(forwarded);
  if (req.ip) return normalizeIpValue(req.ip);
  if (req.socket?.remoteAddress) return normalizeIpValue(req.socket.remoteAddress);
  return '';
}

function verifyOrBindSimpleIp(req, webhook) {
  if (!webhook?.ip_lock_enabled) return null;
  const requestIp = extractRequestIp(req);
  if (!requestIp) return 'Unable to determine caller IP';
  const lockedIp = normalizeIpValue(webhook.locked_ip);
  if (!lockedIp) {
    db.prepare(`
      UPDATE webhooks
      SET locked_ip = ?, updated_at = ?
      WHERE id = ?
    `).run(requestIp, Math.floor(Date.now() / 1000), webhook.id);
    webhook.locked_ip = requestIp;
    return null;
  }
  if (lockedIp !== requestIp) return 'Caller IP does not match the locked webhook IP';
  return null;
}

function markWebhookOrigin(entityType, entityId, webhookId) {
  if (!entityType || !entityId || !webhookId) return;
  db.prepare(`
    INSERT OR REPLACE INTO webhook_origins (entity_type, entity_id, webhook_id, created_at)
    VALUES (?, ?, ?, ?)
  `).run(entityType, entityId, webhookId, Math.floor(Date.now() / 1000));
}

function isWebhookOrigin(entityType, entityId) {
  if (!entityType || !entityId) return false;
  return !!db.prepare(`
    SELECT 1
    FROM webhook_origins
    WHERE entity_type = ? AND entity_id = ?
    LIMIT 1
  `).get(entityType, entityId);
}

function sanitizeChannelName(name, fallback) {
  const base = String(name || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9\s-_]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
  return (base || fallback || 'webhook-channel').slice(0, 64);
}

function createChannelForCategoryWebhook({ webhookId, categoryId, externalKey, channelName, channelDescription }) {
  const existingLink = db.prepare(`
    SELECT l.channel_id, c.name
    FROM webhook_channel_links l
    JOIN channels c ON c.id = l.channel_id
    WHERE l.webhook_id = ? AND l.external_key = ?
    LIMIT 1
  `).get(webhookId, externalKey);
  if (existingLink) {
    return {
      channelId: existingLink.channel_id,
      channelName: existingLink.name,
      created: false,
    };
  }
  const id = randomUUID();
  const maxPos = db.prepare('SELECT MAX(position) AS m FROM channels').get().m || 0;
  const fallbackName = `ticket-${String(externalKey).slice(0, 10).toLowerCase()}`;
  const normalizedName = sanitizeChannelName(channelName, fallbackName);
  db.prepare(`
    INSERT INTO channels (id, name, description, type, position, category_id)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, normalizedName, channelDescription || null, 'basic', maxPos + 1, categoryId);
  db.prepare(`
    INSERT INTO webhook_channel_links (webhook_id, external_key, channel_id, external_label, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    webhookId,
    externalKey,
    id,
    channelName ? String(channelName).trim() : null,
    Math.floor(Date.now() / 1000),
    Math.floor(Date.now() / 1000)
  );
  markWebhookOrigin('channel', id, webhookId);
  return {
    channelId: id,
    channelName: normalizedName,
    created: true,
  };
}

function buildWebhookMessageContent(content, authorName) {
  const trimmed = String(content || '').trim();
  if (!trimmed) return '';
  const author = typeof authorName === 'string' && authorName.trim() ? authorName.trim() : '';
  return author ? `[${author}] ${trimmed}` : trimmed;
}

function emitRealtimeMessage(channelId, message) {
  const handler = require('./socket/handler');
  if (typeof handler.emitMessage === 'function') {
    handler.emitMessage(channelId, message);
  }
}

function emitChannelUpdate() {
  const handler = require('./socket/handler');
  if (typeof handler.broadcastChannelUpdate === 'function') {
    handler.broadcastChannelUpdate();
  }
}

function createInboundMessage({ webhookId, channelId, content, authorName }) {
  const systemUser = getSystemWebhookUser();
  if (!systemUser) {
    const error = new Error('Webhook system user unavailable');
    error.status = 500;
    throw error;
  }
  const channel = db.prepare('SELECT id FROM channels WHERE id = ?').get(channelId);
  if (!channel) {
    const error = new Error('Channel not found');
    error.status = 404;
    throw error;
  }
  const finalContent = buildWebhookMessageContent(content, authorName);
  if (!finalContent) {
    const error = new Error('Message content required');
    error.status = 400;
    throw error;
  }
  const id = randomUUID();
  const now = Math.floor(Date.now() / 1000);
  db.prepare(`
    INSERT INTO messages (
      id, channel_id, user_id, content, created_at, message_type, embeds_enabled
    )
    VALUES (?, ?, ?, ?, ?, 'user', 1)
  `).run(id, channelId, systemUser.id, encryptMessageContent(finalContent), now);
  markWebhookOrigin('message', id, webhookId);
  emitRealtimeMessage(channelId, {
    id,
    channel_id: channelId,
    user_id: systemUser.id,
    username: systemUser.username,
    avatar: systemUser.avatar || null,
    display_name: systemUser.display_name || 'Webhook',
    content: finalContent,
    edited: 0,
    is_owner: 0,
    role_color: null,
    attachment_url: null,
    attachment_type: null,
    attachment_size: null,
    attachments: [],
    nsfw_tags: [],
    message_type: 'user',
    created_at: now,
    embeds_enabled: 1,
    verified: false,
  });
  return { messageId: id, content: finalContent, createdAt: now };
}

function queueDeliveriesForRows(rows, eventType, data) {
  const now = Math.floor(Date.now() / 1000);
  const insert = db.prepare(`
    INSERT INTO webhook_deliveries (
      id, webhook_id, event_type, payload_json, attempt_count, next_attempt_at,
      status, response_code, last_error, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, 0, ?, ?, NULL, NULL, ?, ?)
  `);
  const payload = JSON.stringify({
    id: randomUUID(),
    eventType,
    occurredAt: now,
    data,
  });
  for (const row of rows) {
    insert.run(randomUUID(), row.id, eventType, payload, now, DELIVERY_PENDING, now, now);
    db.prepare(`
      UPDATE webhooks
      SET last_delivery_status = ?, last_delivery_error = NULL, updated_at = ?
      WHERE id = ?
    `).run(DELIVERY_PENDING, now, row.id);
  }
}

function getOutboundChannelWebhooks(channelId) {
  return db.prepare(`
    SELECT *
    FROM webhooks
    WHERE scope_type = 'channel' AND scope_id = ? AND enabled = 1 AND outbound_enabled = 1 AND auth_mode = 'secured'
  `).all(channelId);
}

function getOutboundCategoryWebhooksByChannel(channelId) {
  return db.prepare(`
    SELECT w.*
    FROM webhooks w
    JOIN channels c ON c.category_id = w.scope_id
    WHERE w.scope_type = 'category'
      AND c.id = ?
      AND w.enabled = 1
      AND w.outbound_enabled = 1
      AND w.auth_mode = 'secured'
  `).all(channelId);
}

function queueChannelCreatedEvent(channel) {
  if (!channel?.id || !channel.category_id || isWebhookOrigin('channel', channel.id)) return;
  const hooks = getOutboundCategoryWebhooksByChannel(channel.id);
  if (hooks.length === 0) return;
  queueDeliveriesForRows(hooks, WEBHOOK_EVENT_CHANNEL_CREATED, {
    channelId: channel.id,
    categoryId: channel.category_id,
    name: channel.name,
    type: channel.type,
    description: channel.description || null,
  });
}

function queueChannelDeletedEvent(channel) {
  if (!channel?.id || !channel.category_id || isWebhookOrigin('channel', channel.id)) return;
  const hooks = db.prepare(`
    SELECT *
    FROM webhooks
    WHERE scope_type = 'category' AND scope_id = ? AND enabled = 1 AND outbound_enabled = 1 AND auth_mode = 'secured'
  `).all(channel.category_id);
  if (hooks.length === 0) return;
  queueDeliveriesForRows(hooks, WEBHOOK_EVENT_CHANNEL_DELETED, {
    channelId: channel.id,
    categoryId: channel.category_id,
    name: channel.name,
    type: channel.type,
  });
}

function queueMessageCreatedEvent(message) {
  if (!message?.id || !message.channel_id) return;
  if (message.message_type && message.message_type !== 'user') return;
  if (isWebhookOrigin('message', message.id)) return;
  const hooks = [
    ...getOutboundChannelWebhooks(message.channel_id),
    ...getOutboundCategoryWebhooksByChannel(message.channel_id),
  ];
  if (hooks.length === 0) return;
  const uniqueHooks = Array.from(new Map(hooks.map((row) => [row.id, row])).values());
  queueDeliveriesForRows(uniqueHooks, WEBHOOK_EVENT_MESSAGE_CREATED, {
    messageId: message.id,
    channelId: message.channel_id,
    userId: message.user_id,
    username: message.username || null,
    displayName: message.display_name || null,
    content: message.content || '',
    createdAt: message.created_at || Math.floor(Date.now() / 1000),
  });
}

function nextRetrySeconds(attemptCount) {
  return Math.min(900, 15 * (2 ** Math.max(0, attemptCount)));
}

async function processPendingDeliveries() {
  if (workerRunning) return;
  workerRunning = true;
  try {
    const now = Math.floor(Date.now() / 1000);
    const rows = db.prepare(`
      SELECT d.*, w.callback_url, w.secret_encrypted, w.enabled, w.outbound_enabled
      FROM webhook_deliveries d
      JOIN webhooks w ON w.id = d.webhook_id
      WHERE d.next_attempt_at <= ?
        AND d.status IN (?, ?)
        AND w.enabled = 1
        AND w.outbound_enabled = 1
      ORDER BY d.next_attempt_at ASC, d.created_at ASC
      LIMIT 20
    `).all(now, DELIVERY_PENDING, DELIVERY_RETRYING);
    for (const row of rows) {
      const payload = typeof row.payload_json === 'string' ? row.payload_json : '{}';
      const timestamp = String(Math.floor(Date.now() / 1000));
      const secret = decryptSecret(row.secret_encrypted);
      const signature = crypto.createHmac('sha256', secret)
        .update(`${timestamp}.${payload}`, 'utf8')
        .digest('hex');
      const nextAttemptCount = Number(row.attempt_count || 0) + 1;
      const markBase = db.prepare(`
        UPDATE webhook_deliveries
        SET attempt_count = ?, updated_at = ?
        WHERE id = ?
      `);
      markBase.run(nextAttemptCount, now, row.id);
      try {
        const response = await axios.post(row.callback_url, JSON.parse(payload), {
          timeout: 10_000,
          headers: {
            'Content-Type': 'application/json',
            'X-CatRealm-Timestamp': timestamp,
            'X-CatRealm-Signature': `sha256=${signature}`,
          },
        });
        db.prepare(`
          UPDATE webhook_deliveries
          SET status = ?, response_code = ?, last_error = NULL, updated_at = ?
          WHERE id = ?
        `).run(DELIVERY_DELIVERED, response.status, now, row.id);
        db.prepare(`
          UPDATE webhooks
          SET last_delivery_at = ?, last_delivery_status = ?, last_delivery_error = NULL, updated_at = ?
          WHERE id = ?
        `).run(now, DELIVERY_DELIVERED, now, row.webhook_id);
      } catch (err) {
        const isFinal = nextAttemptCount >= 5;
        const nextRunAt = now + nextRetrySeconds(nextAttemptCount);
        const errorText = err?.response?.data?.error || err?.message || 'Delivery failed';
        db.prepare(`
          UPDATE webhook_deliveries
          SET status = ?, response_code = ?, last_error = ?, next_attempt_at = ?, updated_at = ?
          WHERE id = ?
        `).run(
          isFinal ? DELIVERY_FAILED : DELIVERY_RETRYING,
          err?.response?.status || null,
          String(errorText).slice(0, 500),
          nextRunAt,
          now,
          row.id
        );
        db.prepare(`
          UPDATE webhooks
          SET last_delivery_at = ?, last_delivery_status = ?, last_delivery_error = ?, updated_at = ?
          WHERE id = ?
        `).run(
          now,
          isFinal ? DELIVERY_FAILED : DELIVERY_RETRYING,
          String(errorText).slice(0, 500),
          now,
          row.webhook_id
        );
      }
    }
  } finally {
    workerRunning = false;
  }
}

function startWebhookWorker() {
  if (workerTimer) return;
  workerTimer = setInterval(() => {
    void processPendingDeliveries().catch((err) => {
      pteroLog(`[CatRealm] Webhook worker error: ${err.message}`);
    });
  }, 5000);
  workerTimer.unref?.();
}

function stopWebhookWorker() {
  if (!workerTimer) return;
  clearInterval(workerTimer);
  workerTimer = null;
}

function handleChannelWebhookRequest(req) {
  const webhook = getPublicWebhook(WEBHOOK_SCOPE_CHANNEL, req.params.webhookId);
  if (!webhook || !webhook.enabled || !webhook.inbound_enabled) {
    const error = new Error('Webhook not found');
    error.status = 404;
    throw error;
  }
  const signatureError = verifyRequestSignature(req, webhook);
  if (signatureError) {
    const error = new Error(signatureError);
    error.status = 401;
    throw error;
  }
  if (req.body?.event !== 'message.create') {
    const error = new Error('Unsupported event');
    error.status = 400;
    throw error;
  }
  const channel = db.prepare('SELECT id, name FROM channels WHERE id = ?').get(webhook.scope_id);
  if (!channel) {
    const error = new Error('Channel not found');
    error.status = 404;
    throw error;
  }
  const created = createInboundMessage({
    webhookId: webhook.id,
    channelId: channel.id,
    content: req.body?.content,
    authorName: req.body?.author?.name,
  });
  return {
    ok: true,
    channelId: channel.id,
    channelName: channel.name,
    created: false,
    messageId: created.messageId,
  };
}

function handleSimpleChannelWebhookRequest(req) {
  const webhook = getPublicWebhook(WEBHOOK_SCOPE_CHANNEL, req.params.webhookId);
  if (!webhook || !webhook.enabled || !webhook.inbound_enabled || normalizeAuthMode(webhook.auth_mode) !== WEBHOOK_AUTH_SIMPLE) {
    const error = new Error('Webhook not found');
    error.status = 404;
    throw error;
  }
  const tokenError = verifySimpleToken(req.params.token, webhook);
  if (tokenError) {
    const error = new Error(tokenError);
    error.status = 401;
    throw error;
  }
  const ipLockError = verifyOrBindSimpleIp(req, webhook);
  if (ipLockError) {
    const error = new Error(ipLockError);
    error.status = 403;
    throw error;
  }
  const flags = parseActionFlags(webhook.action_flags, WEBHOOK_SCOPE_CHANNEL);
  if (!flags.allowMessageCreate) {
    const error = new Error('Action not allowed');
    error.status = 403;
    throw error;
  }
  const channel = db.prepare('SELECT id, name FROM channels WHERE id = ?').get(webhook.scope_id);
  if (!channel) {
    const error = new Error('Channel not found');
    error.status = 404;
    throw error;
  }
  const created = createInboundMessage({
    webhookId: webhook.id,
    channelId: channel.id,
    content: req.body?.content ?? req.body?.message ?? req.body?.text,
    authorName: req.body?.author?.name ?? req.body?.username ?? req.body?.authorName,
  });
  return {
    ok: true,
    channelId: channel.id,
    channelName: channel.name,
    created: false,
    messageId: created.messageId,
  };
}

function handleCategoryWebhookRequest(req) {
  const webhook = getPublicWebhook(WEBHOOK_SCOPE_CATEGORY, req.params.webhookId);
  if (!webhook || !webhook.enabled || !webhook.inbound_enabled) {
    const error = new Error('Webhook not found');
    error.status = 404;
    throw error;
  }
  const signatureError = verifyRequestSignature(req, webhook);
  if (signatureError) {
    const error = new Error(signatureError);
    error.status = 401;
    throw error;
  }
  if (req.body?.event !== 'conversation.upsert') {
    const error = new Error('Unsupported event');
    error.status = 400;
    throw error;
  }
  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(webhook.scope_id);
  if (!category) {
    const error = new Error('Category not found');
    error.status = 404;
    throw error;
  }
  const externalKey = String(req.body?.externalKey || '').trim();
  if (!externalKey) {
    const error = new Error('externalKey required');
    error.status = 400;
    throw error;
  }
  const result = createChannelForCategoryWebhook({
    webhookId: webhook.id,
    categoryId: category.id,
    externalKey,
    channelName: req.body?.channelName,
    channelDescription: req.body?.channelDescription,
  });
  if (result.created) {
    emitChannelUpdate();
  }
  let messageId = null;
  const messagePayload = req.body?.message;
  if (messagePayload?.content) {
    const createdMessage = createInboundMessage({
      webhookId: webhook.id,
      channelId: result.channelId,
      content: messagePayload.content,
      authorName: messagePayload?.author?.name || req.body?.author?.name,
    });
    messageId = createdMessage.messageId;
  }
  return {
    ok: true,
    channelId: result.channelId,
    channelName: result.channelName,
    created: result.created,
    messageId,
  };
}

function handleSimpleCategoryWebhookRequest(req) {
  const webhook = getPublicWebhook(WEBHOOK_SCOPE_CATEGORY, req.params.webhookId);
  if (!webhook || !webhook.enabled || !webhook.inbound_enabled || normalizeAuthMode(webhook.auth_mode) !== WEBHOOK_AUTH_SIMPLE) {
    const error = new Error('Webhook not found');
    error.status = 404;
    throw error;
  }
  const tokenError = verifySimpleToken(req.params.token, webhook);
  if (tokenError) {
    const error = new Error(tokenError);
    error.status = 401;
    throw error;
  }
  const ipLockError = verifyOrBindSimpleIp(req, webhook);
  if (ipLockError) {
    const error = new Error(ipLockError);
    error.status = 403;
    throw error;
  }
  const flags = parseActionFlags(webhook.action_flags, WEBHOOK_SCOPE_CATEGORY);
  if (!flags.allowConversationUpsert) {
    const error = new Error('Action not allowed');
    error.status = 403;
    throw error;
  }
  const category = db.prepare('SELECT id FROM categories WHERE id = ?').get(webhook.scope_id);
  if (!category) {
    const error = new Error('Category not found');
    error.status = 404;
    throw error;
  }
  const externalKey = String(
    req.body?.externalKey
    || req.body?.externalId
    || req.body?.conversationId
    || req.body?.userId
    || ''
  ).trim();
  if (!externalKey) {
    const error = new Error('externalKey required');
    error.status = 400;
    throw error;
  }
  const result = createChannelForCategoryWebhook({
    webhookId: webhook.id,
    categoryId: category.id,
    externalKey,
    channelName: req.body?.channelName ?? req.body?.name,
    channelDescription: req.body?.channelDescription ?? req.body?.description,
  });
  if (result.created) emitChannelUpdate();
  let messageId = null;
  const messageContent = req.body?.message?.content ?? req.body?.content ?? req.body?.message ?? req.body?.text;
  if (messageContent) {
    const createdMessage = createInboundMessage({
      webhookId: webhook.id,
      channelId: result.channelId,
      content: messageContent,
      authorName: req.body?.message?.author?.name ?? req.body?.author?.name ?? req.body?.username ?? req.body?.authorName,
    });
    messageId = createdMessage.messageId;
  }
  return {
    ok: true,
    channelId: result.channelId,
    channelName: result.channelName,
    created: result.created,
    messageId,
  };
}

module.exports = {
  WEBHOOK_SCOPE_CHANNEL,
  WEBHOOK_SCOPE_CATEGORY,
  WEBHOOK_AUTH_SECURED,
  WEBHOOK_AUTH_SIMPLE,
  listWebhooks,
  listAllWebhooks,
  createWebhook,
  updateWebhook,
  updateWebhookById,
  regenerateWebhookSecret,
  regenerateWebhookSecretById,
  deleteWebhook,
  deleteWebhookById,
  handleChannelWebhookRequest,
  handleSimpleChannelWebhookRequest,
  handleCategoryWebhookRequest,
  handleSimpleCategoryWebhookRequest,
  queueChannelCreatedEvent,
  queueChannelDeletedEvent,
  queueMessageCreatedEvent,
  startWebhookWorker,
  stopWebhookWorker,
};
