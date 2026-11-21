'use strict';

const { randomBytes } = require('crypto');
const db = require('../db');

const sessions = new Map();
const RESERVATION_MS = 10 * 60 * 1000;
const EMPTY_GRACE_MS = 10 * 1000;

function normalizeRegion(value) {
  return value === 'eu' || value === 'us-central' ? value : null;
}

function getOverride(channelId) {
  const row = db.prepare('SELECT voice_region_override FROM channel_settings WHERE channel_id = ?').get(channelId);
  return normalizeRegion(row?.voice_region_override);
}

function assignVoiceRegion(channelId, preferredRegion) {
  const now = Date.now();
  let session = sessions.get(channelId);
  if (session && (session.occupied || session.expiresAt > now)) {
    if (!session.occupied) {
      session.expiresAt = now + RESERVATION_MS;
      if (session.emptyTimer) clearTimeout(session.emptyTimer);
      session.emptyTimer = null;
    }
    return { region: session.region, generation: session.generation };
  }
  if (session?.emptyTimer) clearTimeout(session.emptyTimer);
  session = {
    region: getOverride(channelId) || normalizeRegion(preferredRegion) || 'eu',
    generation: randomBytes(16).toString('hex'),
    occupied: false,
    expiresAt: now + RESERVATION_MS,
    emptyTimer: null,
  };
  sessions.set(channelId, session);
  return { region: session.region, generation: session.generation };
}

function markVoiceOccupied(channelId) {
  const session = sessions.get(channelId);
  if (!session) return;
  if (session.emptyTimer) clearTimeout(session.emptyTimer);
  session.emptyTimer = null;
  session.occupied = true;
}

function markVoiceEmpty(channelId) {
  const session = sessions.get(channelId);
  if (!session) return;
  session.occupied = false;
  session.expiresAt = Date.now() + EMPTY_GRACE_MS;
  if (session.emptyTimer) clearTimeout(session.emptyTimer);
  session.emptyTimer = setTimeout(() => {
    if (sessions.get(channelId) === session && !session.occupied) sessions.delete(channelId);
  }, EMPTY_GRACE_MS);
  session.emptyTimer.unref?.();
}

function resetEmptyVoiceRegion(channelId) {
  const session = sessions.get(channelId);
  if (!session || session.occupied) return false;
  if (session.emptyTimer) clearTimeout(session.emptyTimer);
  sessions.delete(channelId);
  return true;
}

function getVoiceRegionSession(channelId) {
  const session = sessions.get(channelId);
  if (!session || (!session.occupied && session.expiresAt <= Date.now())) return null;
  return { region: session.region, generation: session.generation, occupied: session.occupied };
}

function switchOccupiedVoiceRegion(channelId, region) {
  const session = sessions.get(channelId);
  const normalized = normalizeRegion(region);
  if (!session?.occupied || !normalized) return null;
  if (session.region === normalized) return { region: session.region, generation: session.generation, changed: false };
  session.region = normalized;
  session.generation = randomBytes(16).toString('hex');
  session.expiresAt = Date.now() + RESERVATION_MS;
  return { region: session.region, generation: session.generation, changed: true };
}

function reconcileVoiceRegion(channelId, generation, region) {
  const session = sessions.get(channelId);
  const normalized = normalizeRegion(region);
  if (!session || session.generation !== generation || !normalized) return false;
  session.region = normalized;
  return true;
}

// A live switch commits once any member reports a successful reconnect. If none
// does before the deadline, or every current member reports failure, the
// channel returns to its previous region (with a fresh generation).
const SWITCH_VERIFY_MS = 20 * 1000;
const pendingSwitches = new Map();

function clearRegionSwitch(channelId) {
  const pending = pendingSwitches.get(channelId);
  if (pending) clearTimeout(pending.timer);
  pendingSwitches.delete(channelId);
}

function revertRegionSwitch(channelId, pending) {
  if (pendingSwitches.get(channelId) !== pending) return;
  clearRegionSwitch(channelId);
  if (sessions.get(channelId)?.generation !== pending.generation) return;
  const restored = switchOccupiedVoiceRegion(channelId, pending.previousRegion);
  if (restored?.changed) pending.onRevert(restored);
}

function trackRegionSwitch(channelId, { previousRegion, generation, onRevert, timeoutMs = SWITCH_VERIFY_MS }) {
  clearRegionSwitch(channelId);
  const pending = { previousRegion, generation, onRevert, failed: new Set(), timer: null };
  pending.timer = setTimeout(() => revertRegionSwitch(channelId, pending), timeoutMs);
  pending.timer.unref?.();
  pendingSwitches.set(channelId, pending);
}

function reportRegionSwitchResult(channelId, userId, { generation, ok }, memberIds) {
  const pending = pendingSwitches.get(channelId);
  if (!pending || pending.generation !== generation || !memberIds.includes(userId)) return null;
  if (ok === true) { clearRegionSwitch(channelId); return 'committed'; }
  pending.failed.add(userId);
  if (memberIds.every((id) => pending.failed.has(id))) { revertRegionSwitch(channelId, pending); return 'reverted'; }
  return 'pending';
}

module.exports = { trackRegionSwitch, reportRegionSwitchResult, clearRegionSwitch,
  normalizeRegion, assignVoiceRegion, markVoiceOccupied, markVoiceEmpty,
  resetEmptyVoiceRegion, getVoiceRegionSession, switchOccupiedVoiceRegion, reconcileVoiceRegion, getOverride };
