'use strict';

// TEMPORARY dev helper (remove when WHIP screen-share testing is done).
// When CATREALM_DEV_WHIP_INGRESS is truthy, ensures a single *reusable* WHIP
// ingress exists at startup and logs its stable endpoint, so load tests
// (tools/native-whip-debug/whip-client-sim.cjs) can publish to a fixed URL
// without driving the GUI client to mint one each time. No-op unless the flag
// is set, so it is safe to ship and trivial to delete (this file + one call in
// src/index.js + the env flag).

const { getIngressClient, readLiveKitIngressConfig } = require('./mediaConfig');

const WHIP_INPUT = 1; // @livekit/protocol IngressInput.WHIP_INPUT
const DEV_NAME = (process.env.CATREALM_DEV_WHIP_INGRESS_NAME || 'catrealm-dev-sim').trim();

function isTruthy(value) {
  return /^(1|true|yes|on)$/i.test(String(value ?? '').trim());
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function ensureDevWhipIngress({ log = console.log } = {}) {
  if (!isTruthy(process.env.CATREALM_DEV_WHIP_INGRESS)) return null;

  const ingressCfg = readLiveKitIngressConfig();
  if (!ingressCfg.enabled || !ingressCfg.publicWhipUrl) {
    log('[CatRealm][dev-whip] skipped: WHIP ingress is not enabled on this server.');
    return null;
  }
  const whipBase = ingressCfg.publicWhipUrl.replace(/\/+$/, '');
  const opts = {
    name: DEV_NAME,
    roomName: DEV_NAME,
    participantIdentity: DEV_NAME,
    participantName: 'CatRealm dev sim',
    enableTranscoding: false, // passthrough, same as production native WHIP
    reusable: true,           // stable streamKey across republishes
  };

  // LiveKit/ingress may take a few seconds to accept API calls after spawn.
  const maxAttempts = 20;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const client = getIngressClient();
    if (!client) {
      await sleep(2000);
      continue;
    }
    try {
      const items = await client.listIngress({}).catch(() => []);
      let info = items.find((it) => (
        it.name === DEV_NAME && it.reusable === true && it.inputType === WHIP_INPUT && it.streamKey
      ));
      const reused = !!info;
      if (!info) info = await client.createIngress(WHIP_INPUT, opts);
      const endpoint = `${whipBase}/${info.streamKey}`;
      log('[CatRealm][dev-whip] ──────────────────────────────────────────────────────');
      log(`[CatRealm][dev-whip] ${reused ? 'Reusing' : 'Created'} reusable dev WHIP ingress (CATREALM_DEV_WHIP_INGRESS).`);
      log(`[CatRealm][dev-whip] ENDPOINT=${endpoint}`);
      log(`[CatRealm][dev-whip] ingressId=${info.ingressId} streamKey=${info.streamKey}`);
      log(`[CatRealm][dev-whip] test: node tools/native-whip-debug/whip-client-sim.cjs --endpoint "${endpoint}" --source testsrc2 --duration 60 --verbose`);
      log('[CatRealm][dev-whip] ──────────────────────────────────────────────────────');
      return endpoint;
    } catch (err) {
      if (attempt === maxAttempts) {
        log(`[CatRealm][dev-whip] failed to ensure dev ingress: ${err && err.message ? err.message : err}`);
        return null;
      }
      await sleep(2000);
    }
  }
  return null;
}

module.exports = { ensureDevWhipIngress };
