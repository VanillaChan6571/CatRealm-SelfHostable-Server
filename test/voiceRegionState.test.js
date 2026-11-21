'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModule } = require('./helpers');

test('a channel keeps one regional room while occupied and takes an override after it empties', () => {
  let override = null;
  const db = { prepare: () => ({ get: () => ({ voice_region_override: override }) }) };
  const state = loadModule('src/lib/voiceRegionState.js', { '../db': db });
  const first = state.assignVoiceRegion('lobby', 'us-central');
  assert.equal(first.region, 'us-central');
  assert.match(first.generation, /^[a-f0-9]{32}$/);
  state.markVoiceOccupied('lobby');
  override = 'eu';
  assert.equal(state.resetEmptyVoiceRegion('lobby'), false);
  assert.deepEqual(state.assignVoiceRegion('lobby', 'eu'), first);
  state.markVoiceEmpty('lobby');
  assert.equal(state.resetEmptyVoiceRegion('lobby'), true);
  const next = state.assignVoiceRegion('lobby', 'us-central');
  assert.equal(next.region, 'eu');
  assert.notEqual(next.generation, first.generation);
});

test('an occupied room changes generation when its region is switched', () => {
  const db = { prepare: () => ({ get: () => ({ voice_region_override: null }) }) };
  const state = loadModule('src/lib/voiceRegionState.js', { '../db': db });
  const first = state.assignVoiceRegion('music', 'eu');
  state.markVoiceOccupied('music');
  const switched = state.switchOccupiedVoiceRegion('music', 'us-central');
  assert.equal(switched.region, 'us-central');
  assert.equal(switched.changed, true);
  assert.notEqual(switched.generation, first.generation);
  assert.equal(state.assignVoiceRegion('music', 'eu').generation, switched.generation);
  assert.equal(state.reconcileVoiceRegion('music', first.generation, 'eu'), false);
  assert.equal(state.reconcileVoiceRegion('music', switched.generation, 'eu'), true);
  assert.equal(state.assignVoiceRegion('music', 'us-central').region, 'eu');
});

function switchedChannel(name) {
  const db = { prepare: () => ({ get: () => ({ voice_region_override: null }) }) };
  const state = loadModule('src/lib/voiceRegionState.js', { '../db': db });
  const first = state.assignVoiceRegion(name, 'eu');
  state.markVoiceOccupied(name);
  const switched = state.switchOccupiedVoiceRegion(name, 'us-central');
  const reverts = [];
  state.trackRegionSwitch(name, {
    previousRegion: first.region, generation: switched.generation,
    onRevert: (restored) => reverts.push(restored), timeoutMs: 60_000,
  });
  return { state, switched, reverts };
}

test('a live voice switch commits when one member reconnects', () => {
  const { state, switched, reverts } = switchedChannel('ok-room');
  assert.equal(state.reportRegionSwitchResult('ok-room', 'stranger', { generation: switched.generation, ok: true }, ['a', 'b']), null);
  assert.equal(state.reportRegionSwitchResult('ok-room', 'a', { generation: 'stale', ok: true }, ['a', 'b']), null);
  assert.equal(state.reportRegionSwitchResult('ok-room', 'a', { generation: switched.generation, ok: true }, ['a', 'b']), 'committed');
  assert.equal(state.getVoiceRegionSession('ok-room').region, 'us-central');
  assert.equal(reverts.length, 0);
});

test('a live voice switch reverts once every member reports failure', () => {
  const { state, switched, reverts } = switchedChannel('bad-room');
  assert.equal(state.reportRegionSwitchResult('bad-room', 'a', { generation: switched.generation, ok: false }, ['a', 'b']), 'pending');
  assert.equal(state.reportRegionSwitchResult('bad-room', 'b', { generation: switched.generation, ok: false }, ['a', 'b']), 'reverted');
  assert.equal(reverts.length, 1);
  assert.equal(reverts[0].region, 'eu');
  assert.notEqual(reverts[0].generation, switched.generation);
  assert.equal(state.getVoiceRegionSession('bad-room').region, 'eu');
});
