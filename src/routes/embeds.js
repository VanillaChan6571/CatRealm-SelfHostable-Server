const router = require('express').Router();
const axios = require('axios');
const dns = require('dns').promises;
const net = require('net');
const { createEmbedProxyToken } = require('../embedProxyToken');

const MAX_REDIRECTS = 5;
const MAX_HTML_BYTES = 1024 * 1024;

function isPrivateOrLocalIp(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const [a, b] = address.split('.').map((x) => Number(x));
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true;
    return false;
  }
  if (family === 6) {
    const n = address.toLowerCase();
    if (n === '::1') return true;
    if (n.startsWith('fc') || n.startsWith('fd')) return true;
    if (n.startsWith('fe8') || n.startsWith('fe9') || n.startsWith('fea') || n.startsWith('feb')) return true;
    return false;
  }
  return true;
}

async function isSafePublicHost(hostname) {
  if (!hostname) return false;
  const raw = String(hostname).trim().toLowerCase();
  if (!raw) return false;
  if (raw === 'localhost') return false;

  if (net.isIP(raw)) {
    return !isPrivateOrLocalIp(raw);
  }

  try {
    const records = await dns.lookup(raw, { all: true, verbatim: true });
    if (!records || records.length === 0) return false;
    return records.every((r) => !isPrivateOrLocalIp(r.address));
  } catch {
    return false;
  }
}

function extractMetaTag(html, key, attr = 'property') {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`<meta[^>]+${attr}=["']${escaped}["'][^>]*content=["']([^"']+)["'][^>]*>`, 'i');
  const reInverse = new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]*${attr}=["']${escaped}["'][^>]*>`, 'i');
  const m = html.match(re) || html.match(reInverse);
  return m?.[1]?.trim() || null;
}

function extractTitle(html) {
  const m = html.match(/<title[^>]*>([^<]{1,400})<\/title>/i);
  return m?.[1]?.trim() || null;
}

function resolveMaybeRelative(base, target) {
  if (!target) return null;
  try {
    return new URL(target, base).toString();
  } catch {
    return null;
  }
}

function parseTwitterLikeStatusUrl(urlObj) {
  const host = String(urlObj.hostname || '').toLowerCase();
  const supportedHost =
    host.includes('twitter.com') ||
    host === 'x.com' ||
    host.endsWith('.x.com') ||
    host.includes('vxtwitter.com') ||
    host.includes('fxtwitter.com') ||
    host.includes('fixupx.com') ||
    host.includes('fixvx.com');

  if (!supportedHost) return null;

  const segments = String(urlObj.pathname || '').split('/').filter(Boolean);
  const statusIndex = segments.findIndex((segment) => segment.toLowerCase() === 'status');
  if (statusIndex < 0 || statusIndex >= segments.length - 1) return null;

  const tweetId = segments[statusIndex + 1];
  if (!/^\d+$/.test(tweetId)) return null;

  const username = statusIndex > 0 ? segments[statusIndex - 1] : null;
  return {
    tweetId,
    username: username && !['i', 'status'].includes(username.toLowerCase()) ? username : null,
  };
}

function sanitizeTextValue(value, max = 600) {
  if (typeof value !== 'string') return null;
  const normalized = value.replace(/\s+/g, ' ').trim();
  if (!normalized) return null;
  return normalized.slice(0, max);
}

function isLikelyVideoUrl(value) {
  if (typeof value !== 'string') return false;
  const lower = value.toLowerCase();
  return lower.endsWith('.mp4') || lower.includes('.mp4?') || lower.includes('/vid/');
}

function isLikelyImageUrl(value) {
  if (typeof value !== 'string') return false;
  const lower = value.toLowerCase();
  return (
    lower.endsWith('.png') ||
    lower.endsWith('.jpg') ||
    lower.endsWith('.jpeg') ||
    lower.endsWith('.webp') ||
    lower.endsWith('.gif') ||
    lower.includes('.png?') ||
    lower.includes('.jpg?') ||
    lower.includes('.jpeg?') ||
    lower.includes('.webp?') ||
    lower.includes('.gif?')
  );
}

function toEmbedMediaProxyUrl(mediaUrl) {
  const token = createEmbedProxyToken(mediaUrl);
  if (!token) return mediaUrl;
  return `/api/embed-media?token=${encodeURIComponent(token)}`;
}

async function fetchTwitterLikePreview(tweetRef, fallbackUrl) {
  const candidates = [];
  if (tweetRef.username) {
    candidates.push(`https://api.vxtwitter.com/${encodeURIComponent(tweetRef.username)}/status/${tweetRef.tweetId}`);
  }
  candidates.push(`https://api.vxtwitter.com/status/${tweetRef.tweetId}`);

  for (const endpoint of candidates) {
    try {
      const response = await axios.get(endpoint, {
        timeout: 6000,
        responseType: 'json',
        validateStatus: (status) => status >= 200 && status < 300,
        headers: {
          'User-Agent': 'CatRealm-EmbedFetcher/1.0',
          Accept: 'application/json',
        },
      });

      const data = response.data && typeof response.data === 'object' ? response.data : null;
      if (!data) {
        continue;
      }

      const titleName = sanitizeTextValue(data.user_name, 180);
      const titleHandle = sanitizeTextValue(data.user_screen_name, 120);
      const title = titleName && titleHandle ? `${titleName} (@${titleHandle})` : (titleName || (titleHandle ? `@${titleHandle}` : null));
      const description = sanitizeTextValue(data.text, 600);

      if (Array.isArray(data.media_extended)) {
        for (const media of data.media_extended) {
          if (!media || typeof media !== 'object') continue;
          const mediaType = sanitizeTextValue(media.type, 40);
          const mediaUrl = sanitizeTextValue(media.url, 400);
          if (!mediaUrl) continue;
          if (mediaType === 'video' || mediaType === 'gif' || isLikelyVideoUrl(mediaUrl)) {
            return {
              type: 'media',
              url: toEmbedMediaProxyUrl(mediaUrl),
              mime: 'video/mp4',
              siteName: 'X',
              title,
              description,
            };
          }
        }
      }

      let image = null;
      if (Array.isArray(data.media_extended)) {
        for (const media of data.media_extended) {
          if (!media || typeof media !== 'object') continue;
          const mediaType = sanitizeTextValue(media.type, 40);
          if (mediaType && mediaType !== 'photo' && mediaType !== 'image') continue;
          const candidate = sanitizeTextValue(media.url, 400) || sanitizeTextValue(media.thumbnail_url, 400);
          if (candidate && isLikelyImageUrl(candidate)) {
            image = candidate;
            break;
          }
        }
      }
      if (!image && Array.isArray(data.mediaURLs)) {
        for (const mediaUrl of data.mediaURLs) {
          const candidate = sanitizeTextValue(mediaUrl, 400);
          if (candidate && isLikelyImageUrl(candidate)) {
            image = candidate;
            break;
          }
        }
      }
      if (!image && Array.isArray(data.media_extended)) {
        for (const media of data.media_extended) {
          if (!media || typeof media !== 'object') continue;
          const thumb = sanitizeTextValue(media.thumbnail_url, 400);
          if (thumb && isLikelyImageUrl(thumb)) {
            image = thumb;
            break;
          }
        }
      }

      const canonicalUrl = sanitizeTextValue(data.tweetURL, 400) || fallbackUrl;

      return {
        type: 'link',
        url: canonicalUrl,
        siteName: 'X',
        title,
        description,
        image: image || null,
      };
    } catch {
      // Try the next candidate endpoint.
    }
  }

  return null;
}

async function fetchWithSafeRedirects(url, depth = 0) {
  const response = await axios.get(url, {
    timeout: 6000,
    maxRedirects: 0,
    responseType: 'text',
    maxContentLength: MAX_HTML_BYTES,
    validateStatus: (status) => status >= 200 && status < 400,
    headers: {
      'User-Agent': 'CatRealm-EmbedFetcher/1.0',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
  });

  if (response.status >= 300 && response.status < 400) {
    if (depth >= MAX_REDIRECTS) {
      throw new Error('Too many redirects');
    }
    const loc = response.headers.location;
    if (!loc) {
      throw new Error('Redirect without location');
    }
    const next = new URL(loc, url).toString();
    const parsed = new URL(next);
    const safe = await isSafePublicHost(parsed.hostname);
    if (!safe) {
      throw new Error('Unsafe redirect target');
    }
    return fetchWithSafeRedirects(next, depth + 1);
  }

  return response;
}

router.get('/', async (req, res) => {
  const rawUrl = String(req.query.url || '').trim();
  if (!rawUrl) {
    return res.status(400).json({ error: 'url query is required' });
  }

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return res.status(400).json({ error: 'Only http/https URLs are supported' });
  }

  const safe = await isSafePublicHost(parsed.hostname);
  if (!safe) {
    return res.status(400).json({ error: 'Blocked host' });
  }

  const twitterRef = parseTwitterLikeStatusUrl(parsed);
  if (twitterRef) {
    const twitterPreview = await fetchTwitterLikePreview(twitterRef, parsed.toString());
    if (twitterPreview) {
      return res.json({ embed: twitterPreview });
    }
  }

  try {
    const response = await fetchWithSafeRedirects(parsed.toString());
    const finalUrl = response.request?.res?.responseUrl || parsed.toString();
    const contentTypeRaw = String(response.headers['content-type'] || '').toLowerCase();
    const contentType = contentTypeRaw.split(';')[0].trim();

    if (contentType.startsWith('image/') || contentType.startsWith('video/') || contentType.startsWith('audio/')) {
      return res.json({
        embed: {
          type: 'media',
          url: finalUrl,
          mime: contentType,
          siteName: new URL(finalUrl).hostname,
        },
      });
    }

    const html = typeof response.data === 'string' ? response.data.slice(0, MAX_HTML_BYTES) : '';
    const ogTitle = extractMetaTag(html, 'og:title', 'property');
    const ogDescription = extractMetaTag(html, 'og:description', 'property');
    const ogImage = extractMetaTag(html, 'og:image', 'property');
    const ogSiteName = extractMetaTag(html, 'og:site_name', 'property');
    const twTitle = extractMetaTag(html, 'twitter:title', 'name');
    const twDescription = extractMetaTag(html, 'twitter:description', 'name');
    const twImage = extractMetaTag(html, 'twitter:image', 'name');
    const description = extractMetaTag(html, 'description', 'name');

    const title = ogTitle || twTitle || extractTitle(html);
    const summary = ogDescription || twDescription || description;
    const image = resolveMaybeRelative(finalUrl, ogImage || twImage);
    const siteName = ogSiteName || new URL(finalUrl).hostname;

    return res.json({
      embed: {
        type: 'link',
        url: finalUrl,
        siteName,
        title: title || null,
        description: summary || null,
        image: image || null,
      },
    });
  } catch (err) {
    return res.status(200).json({ embed: null, error: err.message || 'Unable to fetch preview' });
  }
});

module.exports = router;
