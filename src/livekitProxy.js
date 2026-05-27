const http = require('http');
const net = require('net');

function isTruthy(value, fallback = false) {
  if (value == null || value === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(value).trim());
}

function isBundledLiveKitProxyEnabled() {
  return isTruthy(process.env.MEDIA_LIVEKIT_PROXY_ENABLED, false);
}

function getLiveKitHttpTarget() {
  const raw = (process.env.MEDIA_LIVEKIT_URL || process.env.LIVEKIT_URL || '').trim();
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    parsed.protocol = parsed.protocol === 'wss:' ? 'https:' : 'http:';
    return parsed;
  } catch {
    return null;
  }
}

function stripHopByHopHeaders(headers) {
  const next = { ...headers };
  for (const header of [
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
  ]) {
    delete next[header];
  }
  return next;
}

function createLiveKitHttpProxy(logger = console.log) {
  return function liveKitHttpProxy(req, res, next) {
    if (!isBundledLiveKitProxyEnabled()) return next();

    const target = getLiveKitHttpTarget();
    if (!target) {
      res.status(503).send('LiveKit proxy target unavailable');
      return;
    }

    const proxyReq = http.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 80,
      method: req.method,
      path: req.originalUrl || req.url,
      headers: {
        ...stripHopByHopHeaders(req.headers),
        host: target.host,
      },
    }, (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 502, stripHopByHopHeaders(proxyRes.headers));
      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      logger(`[CatRealm] LiveKit HTTP proxy error: ${err.message}`);
      if (!res.headersSent) res.status(502).send('LiveKit proxy unavailable');
      else res.end();
    });

    req.pipe(proxyReq);
  };
}

function attachLiveKitUpgradeProxy(server, logger = console.log) {
  server.on('upgrade', (req, socket, head) => {
    let pathname = '';
    try {
      pathname = new URL(req.url || '/', 'http://localhost').pathname;
    } catch {
      socket.destroy();
      return;
    }

    if (!pathname.startsWith('/rtc')) return;
    if (!isBundledLiveKitProxyEnabled()) {
      socket.destroy();
      return;
    }

    const target = getLiveKitHttpTarget();
    if (!target) {
      socket.destroy();
      return;
    }

    const upstream = net.connect({
      host: target.hostname,
      port: Number(target.port || 80),
    });

    upstream.on('connect', () => {
      const headers = [];
      headers.push(`${req.method} ${req.url} HTTP/${req.httpVersion}`);
      for (const [name, value] of Object.entries(req.headers)) {
        if (name.toLowerCase() === 'host') {
          headers.push(`host: ${target.host}`);
          continue;
        }
        if (Array.isArray(value)) {
          for (const item of value) headers.push(`${name}: ${item}`);
        } else if (value != null) {
          headers.push(`${name}: ${value}`);
        }
      }
      upstream.write(`${headers.join('\r\n')}\r\n\r\n`);
      if (head?.length) upstream.write(head);
      socket.pipe(upstream).pipe(socket);
    });

    upstream.on('error', (err) => {
      logger(`[CatRealm] LiveKit WebSocket proxy error: ${err.message}`);
      socket.destroy();
    });

    socket.on('error', () => {
      upstream.destroy();
    });
  });
}

module.exports = {
  attachLiveKitUpgradeProxy,
  createLiveKitHttpProxy,
};
