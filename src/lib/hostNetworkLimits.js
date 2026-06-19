'use strict';

// Detects whether the kernel UDP socket buffers are large enough for LiveKit /
// WHIP ingress to receive high-bitrate (1080p/1440p) screen-share without packet
// loss. On a stock Linux box `net.core.rmem_max` defaults to 212992 (208 KiB); a
// 14 Mbps 1440p keyframe burst overflows that socket, drops packets, and the WHIP
// video track dies with "i/o timeout" → ~2-5 fps.
//
// IMPORTANT: we do NOT read /proc/sys/net/core/rmem_max. CatRealm runs inside a
// (Pterodactyl) container as a non-root user, and the host-global net.core sysctls
// are NOT exposed in the container's /proc — the file is simply absent there. So
// instead we *measure the effective limit*: open a UDP socket, ask for a huge
// SO_RCVBUF, and read back what the kernel actually granted. Linux returns
// 2 × min(requested, rmem_max), so effectiveMax = granted / 2. This needs no /proc
// and no privileges, and is exactly how LiveKit/Pion derives its own warning.
//
// When the host is constrained we cap native screen-share to a safe height
// (default 720p) so bursts stay small enough to fit, and tell the operator how to
// fix it. Linux-only; on other platforms (dev) the probe is a no-op (no cap).

const dgram = require('dgram');

// Stock Linux net.core.{r,w}mem_max. Hosts at or below this are "limited".
const STOCK_LIMIT_BYTES = 212992; // 208 KiB
// Value LiveKit/ingress logs as "suggested" for a production set-up.
const LIVEKIT_SUGGESTED_BYTES = 5_000_000;
// Safe native screen-share height when the host buffer is at the stock limit.
const LIMITED_MAX_HEIGHT = 720;
// Requested far above any sane rmem_max so the kernel caps us at 2 × rmem_max.
const PROBE_REQUEST_BYTES = 64 * 1024 * 1024;

function envInt(name, fallback) {
  const n = Number.parseInt(String(process.env[name] ?? '').trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

// Pure: given the measured effective net.core.{r,w}mem_max (bytes, or null when
// unknown/unmeasurable), decide whether we're constrained and what to cap to.
function computeLimit(recvMaxBytes, sendMaxBytes) {
  if (recvMaxBytes === null && sendMaxBytes === null) {
    return {
      available: false,
      rmemMax: null,
      wmemMax: null,
      effectiveBytes: null,
      limitBytes: null,
      suggestedBytes: LIVEKIT_SUGGESTED_BYTES,
      constrained: false,
      belowRecommended: false,
      maxHeight: null,
    };
  }
  const effectiveBytes = Math.min(
    recvMaxBytes ?? Number.MAX_SAFE_INTEGER,
    sendMaxBytes ?? Number.MAX_SAFE_INTEGER,
  );
  const limitBytes = envInt('CATREALM_WHIP_HOST_MIN_RMEM', STOCK_LIMIT_BYTES);
  const maxHeightWhenLimited = envInt('CATREALM_WHIP_MAX_HEIGHT_WHEN_LIMITED', LIMITED_MAX_HEIGHT);
  const constrained = effectiveBytes <= limitBytes;
  return {
    available: true,
    rmemMax: recvMaxBytes,
    wmemMax: sendMaxBytes,
    effectiveBytes,
    limitBytes,
    suggestedBytes: LIVEKIT_SUGGESTED_BYTES,
    constrained,
    belowRecommended: effectiveBytes < LIVEKIT_SUGGESTED_BYTES,
    maxHeight: constrained ? maxHeightWhenLimited : null,
  };
}

// Measures the actual net.core.{r,w}mem_max by reading back the kernel-granted
// SO_{RCV,SND}BUF when requesting a large value. Resolves to bytes, or null when
// it can't be measured (non-Linux, sandboxed socket, etc.). Linux-only.
function probeKernelBufferMax(kind /* 'recv' | 'send' */) {
  return new Promise((resolve) => {
    if (process.platform !== 'linux') return resolve(null);
    let socket = null;
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      try { if (socket) socket.close(); } catch { /* ignore */ }
      resolve(value);
    };
    try {
      socket = dgram.createSocket('udp4');
    } catch {
      return finish(null);
    }
    socket.once('error', () => finish(null));
    const timer = setTimeout(() => finish(null), 1500);
    try {
      // setRecvBufferSize / getRecvBufferSize require a bound socket.
      socket.bind(0, '127.0.0.1', () => {
        try {
          if (kind === 'send') socket.setSendBufferSize(PROBE_REQUEST_BYTES);
          else socket.setRecvBufferSize(PROBE_REQUEST_BYTES);
          const granted = kind === 'send' ? socket.getSendBufferSize() : socket.getRecvBufferSize();
          clearTimeout(timer);
          // Linux stores 2 × the (capped) value, so effective max = granted / 2.
          finish(Number.isFinite(granted) && granted > 0 ? Math.floor(granted / 2) : null);
        } catch {
          clearTimeout(timer);
          finish(null);
        }
      });
    } catch {
      clearTimeout(timer);
      finish(null);
    }
  });
}

let _result = null;
let _initPromise = null;

// Runs the probe once and caches the result. Idempotent; pass forceRefresh to
// re-measure (e.g. after the operator raises the sysctl + restarts).
function initHostUdpBufferLimit({ forceRefresh = false } = {}) {
  if (_initPromise && !forceRefresh) return _initPromise;
  _initPromise = Promise.all([probeKernelBufferMax('recv'), probeKernelBufferMax('send')])
    .then(([recvMax, sendMax]) => {
      _result = computeLimit(recvMax, sendMax);
      return _result;
    })
    .catch(() => {
      _result = computeLimit(null, null);
      return _result;
    });
  return _initPromise;
}

// Synchronous accessor. Returns the cached measurement; if the probe hasn't run
// yet it kicks it off (fire-and-forget) and reports "unknown" (no cap) until it
// settles a moment later.
function getHostUdpBufferLimit() {
  if (_result) return _result;
  initHostUdpBufferLimit();
  return computeLimit(null, null);
}

function formatKiB(bytes) {
  if (bytes === null || bytes === undefined) return 'unknown';
  return `${Math.round(bytes / 1024)} KiB`;
}

// Multi-line operator warning, returned as an array so the caller can log them
// through whatever logger it uses. Empty array when not constrained.
function getHostUdpBufferWarningLines(limit = _result || computeLimit(null, null)) {
  if (!limit.available || !limit.constrained) return [];
  return [
    `[CatRealm] ⚠ Host UDP buffer is limited by the host itself: net.core.rmem_max≈${formatKiB(limit.rmemMax)}, wmem_max≈${formatKiB(limit.wmemMax)} (LiveKit suggests ${formatKiB(limit.suggestedBytes)}).`,
    `[CatRealm] ⚠ Native screen-share is being capped to ${limit.maxHeight}p on this host to avoid packet loss / frozen video.`,
    '[CatRealm]   Fix on the HOST (not the container): sudo sysctl -w net.core.rmem_max=16777216 net.core.wmem_max=16777216',
    "[CatRealm]   Persist: printf 'net.core.rmem_max=16777216\\nnet.core.wmem_max=16777216\\n' | sudo tee /etc/sysctl.d/99-livekit-udp.conf",
    '[CatRealm]   Then restart this server so LiveKit/ingress recreate their sockets, and the 720p cap lifts automatically.',
  ];
}

module.exports = {
  STOCK_LIMIT_BYTES,
  LIVEKIT_SUGGESTED_BYTES,
  LIMITED_MAX_HEIGHT,
  computeLimit,
  probeKernelBufferMax,
  initHostUdpBufferLimit,
  getHostUdpBufferLimit,
  getHostUdpBufferWarningLines,
};
