const router = require('express').Router();
const crypto = require('crypto');

// Central TURN is intentionally baked into the server (not exposed in egg/.env).
// Set the secret here for internal distributions.
const CENTRAL_TURN = {
  host: 'catrealm.app',
  port: '3478',
  tlsPort: '5349',
  secret: '686a0bb7eae0a0f33080cf98ffb3d6164cbd8529aeb7518b3fe10de6bad17dd5b92ee8751628d6b7039b831f5cab5776',
};

function getCentralTurnConfig() {
  return { ...CENTRAL_TURN };
}

function buildFallbackIceServers() {
  return [
    { urls: 'stun:stun.l.google.com:19302' },
    {
      urls: 'turn:openrelay.metered.ca:80?transport=tcp',
      username: 'openrelayproject',
      credential: 'openrelayproject',
    },
    {
      urls: 'turn:openrelay.metered.ca:443?transport=tcp',
      username: 'openrelayproject',
      credential: 'openrelayproject',
    },
    {
      urls: 'turns:openrelay.metered.ca:443?transport=tcp',
      username: 'openrelayproject',
      credential: 'openrelayproject',
    },
  ];
}

// GET /api/turn/credentials
// Returns TURN server credentials for WebRTC
router.get('/credentials', (req, res) => {
  const modeRaw = (process.env.TURN_MODE || '').trim().toLowerCase();
  const mode = modeRaw || 'central';
  const forceTcp = /^(1|true|yes|on)$/i.test((process.env.TURN_FORCE_TCP || '').trim());

  const requestHost = req.get('host')?.split(':')[0] || 'localhost';
  let turnSecret = '';
  let turnPort = '3478';
  let turnTlsPort = '';
  let serverHost = requestHost;

  if (mode === 'fallback') {
    return res.json({
      iceServers: buildFallbackIceServers(),
      ttl: 86400,
      usingFallback: true,
      mode,
    });
  }

  if (mode === 'central') {
    turnSecret = CENTRAL_TURN.secret.trim();
    turnPort = CENTRAL_TURN.port.trim();
    turnTlsPort = CENTRAL_TURN.tlsPort.trim();
    serverHost = CENTRAL_TURN.host.trim();
  } else {
    // custom mode (self-hosted TURN)
    turnSecret = (process.env.TURN_SECRET || '').trim();
    turnPort = (process.env.TURN_PORT || '3478').trim();
    turnTlsPort = (process.env.TURN_TLS_PORT || '').trim();
    serverHost = (process.env.TURN_HOST || requestHost).trim();
  }

  if (!turnSecret || !serverHost) {
    return res.json({
      iceServers: buildFallbackIceServers(),
      ttl: 86400,
      usingFallback: true,
      mode: 'fallback',
      reason: `missing_${mode}_turn_config`,
    });
  }

  // Generate time-limited TURN credentials
  // Format: timestamp:username
  // Password: HMAC-SHA1(username, secret) in base64
  const timestamp = Math.floor(Date.now() / 1000) + 86400; // Valid for 24 hours
  const username = `${timestamp}:catrealm`;

  const hmac = crypto.createHmac('sha1', turnSecret);
  hmac.update(username);
  const credential = hmac.digest('base64');

  const iceServers = [
      // STUN servers
      { urls: `stun:${serverHost}:${turnPort}` },
      { urls: 'stun:stun.l.google.com:19302' }, // Fallback

      // TURN TCP endpoint (more reliable on restrictive networks)
      {
        urls: `turn:${serverHost}:${turnPort}?transport=tcp`,
        username,
        credential,
      },
    ];

  // Optional UDP TURN endpoint
  if (!forceTcp) {
    iceServers.splice(2, 0, {
      urls: `turn:${serverHost}:${turnPort}`,
      username,
      credential,
    });
  }

  if (turnTlsPort) {
    iceServers.push({
      urls: `turns:${serverHost}:${turnTlsPort}?transport=tcp`,
      username,
      credential,
    });
  }

  res.json({
    iceServers,
    ttl: 86400, // Credentials valid for 24 hours
    usingFallback: false,
    mode,
  });
});

module.exports = router;
module.exports.getCentralTurnConfig = getCentralTurnConfig;
