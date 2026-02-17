const router = require('express').Router();
const axios = require('axios');
const { verifyEmbedProxyToken, isAllowedEmbedProxyHost } = require('../embedProxyToken');

const MAX_REDIRECTS = 3;

async function fetchProxyStream(url, rangeHeader, depth = 0) {
  const response = await axios.get(url, {
    timeout: 12000,
    responseType: 'stream',
    maxRedirects: 0,
    validateStatus: (status) => status >= 200 && status < 400,
    headers: {
      'User-Agent': 'CatRealm-EmbedProxy/1.0',
      Accept: 'video/*,image/*,audio/*,*/*;q=0.8',
      ...(rangeHeader ? { Range: rangeHeader } : {}),
    },
  });

  if (response.status >= 300 && response.status < 400) {
    if (depth >= MAX_REDIRECTS) {
      throw new Error('Too many redirects');
    }
    const location = response.headers.location;
    if (!location) {
      throw new Error('Redirect without location');
    }
    const nextUrl = new URL(location, url);
    if (!isAllowedEmbedProxyHost(nextUrl.hostname)) {
      throw new Error('Redirect target not allowed');
    }
    return fetchProxyStream(nextUrl.toString(), rangeHeader, depth + 1);
  }

  return response;
}

function applyResponseHeaders(res, headers) {
  const passThrough = [
    'content-type',
    'content-length',
    'accept-ranges',
    'content-range',
    'etag',
    'last-modified',
    'expires',
    'cache-control',
  ];

  for (const name of passThrough) {
    const value = headers?.[name];
    if (value !== undefined && value !== null && value !== '') {
      res.setHeader(name, value);
    }
  }

  if (!headers?.['cache-control']) {
    res.setHeader('cache-control', 'public, max-age=3600');
  }
  res.setHeader('x-content-type-options', 'nosniff');
}

async function handleProxyRequest(req, res, headOnly = false) {
  const token = String(req.query.token || '').trim();
  if (!token) {
    return res.status(400).json({ error: 'token query is required' });
  }

  const verified = verifyEmbedProxyToken(token);
  if (!verified) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }

  try {
    const upstream = await fetchProxyStream(verified.url, req.headers.range ? String(req.headers.range) : null);
    res.status(upstream.status || 200);
    applyResponseHeaders(res, upstream.headers);

    if (headOnly) {
      if (upstream.data && typeof upstream.data.destroy === 'function') {
        upstream.data.destroy();
      }
      return res.end();
    }

    upstream.data.on('error', () => {
      if (!res.headersSent) {
        res.status(502);
      }
      res.end();
    });
    upstream.data.pipe(res);
    return undefined;
  } catch {
    return res.status(502).json({ error: 'Unable to fetch media' });
  }
}

router.get('/', async (req, res) => handleProxyRequest(req, res, false));
router.head('/', async (req, res) => handleProxyRequest(req, res, true));

module.exports = router;
