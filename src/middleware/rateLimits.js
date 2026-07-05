const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

// Buckets keyed by authenticated user when possible so users behind a shared
// proxy/NAT don't exhaust each other's quota; falls back to IP.
function getAuthenticatedRateLimitKey(req) {
  const authHeader = req.headers?.authorization;
  const token = typeof authHeader === 'string' && authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : '';
  if (token) {
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      const subject = payload?.sub || payload?.id || payload?.userId;
      if (subject) return `user:${subject}`;
    } catch (_err) {
      // Invalid token: fall back to IP bucket.
    }
  }
  return `ip:${req.ip || req.connection?.remoteAddress || 'unknown'}`;
}

// General API limiter — generous; protects against unauthenticated floods and
// runaway clients without throttling normal use (message loads, presence, etc).
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 600,
  message: { error: 'Too many requests, please slow down' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getAuthenticatedRateLimitKey,
});

// Auth endpoints — brute-force protection (IP-keyed: no valid token yet).
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many auth attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Message search — secure-mode search decrypts in bulk, so keep this tight.
const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Too many searches, please slow down' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getAuthenticatedRateLimitKey,
});

module.exports = { apiLimiter, authLimiter, searchLimiter };
