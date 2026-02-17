const router = require('express').Router();
const axios = require('axios');
const dns = require('dns').promises;
const net = require('net');
const { createEmbedProxyToken } = require('../embedProxyToken');

const MAX_REDIRECTS = 5;
const MAX_HTML_BYTES = 2 * 1024 * 1024;

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
  return decodeHtmlEntities(m?.[1]?.trim() || null);
}

function extractTitle(html) {
  const m = html.match(/<title[^>]*>([^<]{1,400})<\/title>/i);
  return decodeHtmlEntities(m?.[1]?.trim() || null);
}

function decodeHtmlEntities(value) {
  if (typeof value !== 'string' || value.length === 0) return value || null;
  return value
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>');
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

function parseKickUrl(urlObj) {
  const host = String(urlObj.hostname || '').toLowerCase();
  if (!(host === 'kick.com' || host === 'www.kick.com' || host.endsWith('.kick.com'))) {
    return null;
  }

  const segments = String(urlObj.pathname || '').split('/').filter(Boolean);
  if (segments.length === 0) return null;

  const channelSlug = sanitizeTextValue(segments[0], 120);
  if (!channelSlug) return null;

  const videosIndex = segments.findIndex((segment) => segment.toLowerCase() === 'videos');
  if (videosIndex >= 0 && videosIndex < segments.length - 1) {
    const vodUuid = sanitizeTextValue(segments[videosIndex + 1], 120);
    if (!vodUuid) return null;
    return { channelSlug, vodUuid };
  }

  return { channelSlug, vodUuid: null };
}

function parseInstagramPostUrl(urlObj) {
  const host = String(urlObj.hostname || '').toLowerCase();
  const supportedHost =
    host === 'instagram.com' ||
    host === 'www.instagram.com' ||
    host.endsWith('.instagram.com');
  if (!supportedHost) return null;

  const segments = String(urlObj.pathname || '').split('/').filter(Boolean);
  if (segments.length < 2) return null;

  const kind = segments[0].toLowerCase();
  if (!['p', 'reel', 'tv'].includes(kind)) return null;

  const shortcode = sanitizeTextValue(segments[1], 120);
  if (!shortcode || !/^[a-zA-Z0-9_-]+$/.test(shortcode)) return null;

  return { kind, shortcode };
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

function normalizeKickProfilePic(url) {
  const value = sanitizeTextValue(url, 600);
  if (!value) return null;
  if (value.startsWith('http://') || value.startsWith('https://')) return value;
  if (value.startsWith('//')) return `https:${value}`;
  if (value.startsWith('/')) return `https://kick.com${value}`;
  return `https://kick.com/${value.replace(/^\/+/, '')}`;
}

function toEmbedMediaProxyUrl(mediaUrl) {
  const token = createEmbedProxyToken(mediaUrl);
  if (!token) return mediaUrl;
  return `/api/embed-media?token=${encodeURIComponent(token)}`;
}

async function fetchKickPreview(kickRef, fallbackUrl) {
  const channelSlug = sanitizeTextValue(kickRef.channelSlug, 120);
  if (!channelSlug) return null;

  let channelData = null;
  try {
    const channelResp = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(channelSlug)}`, {
      timeout: 7000,
      responseType: 'json',
      validateStatus: (status) => status >= 200 && status < 300,
      headers: {
        'User-Agent': 'CatRealm-EmbedFetcher/1.0',
        Accept: 'application/json',
      },
    });
    channelData = channelResp.data && typeof channelResp.data === 'object' ? channelResp.data : null;
  } catch {
    channelData = null;
  }

  let authorName =
    sanitizeTextValue(channelData?.user?.username, 120) ||
    sanitizeTextValue(channelData?.slug, 120) ||
    channelSlug;
  let authorAvatar = normalizeKickProfilePic(channelData?.user?.profile_pic);

  if (kickRef.vodUuid) {
    const vodUuid = sanitizeTextValue(kickRef.vodUuid, 120);
    if (!vodUuid) return null;

    let vodTitle = null;
    let vodChannelSlug = null;
    try {
      const vodResp = await axios.get(`https://kick.com/api/v1/video/${encodeURIComponent(vodUuid)}`, {
        timeout: 7000,
        responseType: 'json',
        validateStatus: (status) => status >= 200 && status < 300,
        headers: {
          'User-Agent': 'CatRealm-EmbedFetcher/1.0',
          Accept: 'application/json',
        },
      });
      const vodData = vodResp.data && typeof vodResp.data === 'object' ? vodResp.data : null;
      const livestream = vodData?.livestream;
      vodTitle = sanitizeTextValue(livestream?.session_title, 600);
      vodChannelSlug = sanitizeTextValue(livestream?.channel?.slug, 120);
      const vodAuthorName = sanitizeTextValue(livestream?.channel?.user?.username, 120);
      const vodAuthorAvatar = normalizeKickProfilePic(livestream?.channel?.user?.profilepic);
      if (vodAuthorName) authorName = vodAuthorName;
      if (vodAuthorAvatar) authorAvatar = vodAuthorAvatar;
    } catch {
      // ignore and fallback below
    }

    if (!vodTitle) {
      try {
        const videosResp = await axios.get(`https://kick.com/api/v2/channels/${encodeURIComponent(channelSlug)}/videos`, {
          timeout: 7000,
          responseType: 'json',
          validateStatus: (status) => status >= 200 && status < 300,
          headers: {
            'User-Agent': 'CatRealm-EmbedFetcher/1.0',
            Accept: 'application/json',
          },
        });
        const videos = Array.isArray(videosResp.data) ? videosResp.data : [];
        const match = videos.find((entry) => sanitizeTextValue(entry?.video?.uuid, 120) === vodUuid);
        vodTitle = sanitizeTextValue(match?.session_title, 600) || vodTitle;
      } catch {
        // ignore
      }
    }

    const resolvedSlug = vodChannelSlug || channelSlug;
    const vodUrl = `https://kick.com/${encodeURIComponent(resolvedSlug)}/videos/${encodeURIComponent(vodUuid)}`;
    return {
      type: 'kick',
      url: vodUrl || fallbackUrl,
      siteName: 'Kick.com - VOD',
      title: `${authorName} - Watch the VOD on Kick`,
      description: vodTitle || null,
      image: authorAvatar || null,
      authorName,
      authorAvatar: authorAvatar || null,
    };
  }

  const channelUrl = `https://kick.com/${encodeURIComponent(channelSlug)}`;
  const liveTitle = sanitizeTextValue(channelData?.livestream?.session_title, 600);
  return {
    type: 'kick',
    url: channelUrl || fallbackUrl,
    siteName: 'Kick.com',
    title: `${authorName} - Watch on Kick`,
    description: liveTitle || null,
    image: authorAvatar || null,
    authorName,
    authorAvatar: authorAvatar || null,
  };
}

async function fetchInstagramPreview(instaRef, fallbackUrl) {
  const canonicalUrl = `https://www.instagram.com/${encodeURIComponent(instaRef.kind)}/${encodeURIComponent(instaRef.shortcode)}/`;
  const endpoint = `https://www.instagram.com/api/v1/oembed/?url=${encodeURIComponent(canonicalUrl)}`;

  try {
    const response = await axios.get(endpoint, {
      timeout: 7000,
      responseType: 'json',
      validateStatus: (status) => status >= 200 && status < 300,
      headers: {
        'User-Agent': 'CatRealm-EmbedFetcher/1.0',
        Accept: 'application/json',
      },
    });

    const data = response.data && typeof response.data === 'object' ? response.data : null;
    if (!data) return null;

    const title = sanitizeTextValue(decodeHtmlEntities(data.title), 600);
    const authorName = sanitizeTextValue(decodeHtmlEntities(data.author_name), 120);
    const thumbnailUrl = sanitizeTextValue(decodeHtmlEntities(data.thumbnail_url), 1400);

    return {
      type: 'link',
      url: canonicalUrl || fallbackUrl,
      siteName: 'Instagram',
      title: title || null,
      description: authorName ? `By ${authorName}` : null,
      image: resolveMaybeRelative(canonicalUrl, thumbnailUrl),
      authorName: authorName || null,
      authorAvatar: null,
    };
  } catch {
    return null;
  }
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

      const imageCandidates = [];
      const seenImages = new Set();
      const addImageCandidate = (value) => {
        const candidate = sanitizeTextValue(value, 400);
        if (!candidate || !isLikelyImageUrl(candidate)) return;
        if (seenImages.has(candidate)) return;
        seenImages.add(candidate);
        imageCandidates.push(candidate);
      };

      if (Array.isArray(data.media_extended)) {
        for (const media of data.media_extended) {
          if (!media || typeof media !== 'object') continue;
          const mediaType = sanitizeTextValue(media.type, 40);
          if (mediaType && mediaType !== 'photo' && mediaType !== 'image') continue;
          addImageCandidate(media.url);
          addImageCandidate(media.thumbnail_url);
        }
      }
      if (Array.isArray(data.mediaURLs)) {
        for (const mediaUrl of data.mediaURLs) {
          addImageCandidate(mediaUrl);
        }
      }
      if (imageCandidates.length === 0 && Array.isArray(data.media_extended)) {
        for (const media of data.media_extended) {
          if (!media || typeof media !== 'object') continue;
          addImageCandidate(media.thumbnail_url);
        }
      }

      const images = imageCandidates.slice(0, 4);
      const image = images[0] || null;

      const canonicalUrl = sanitizeTextValue(data.tweetURL, 400) || fallbackUrl;

      return {
        type: 'link',
        url: canonicalUrl,
        siteName: 'X',
        title,
        description,
        image: image || null,
        images,
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

  let instagramOembedPreview = null;
  const instagramRef = parseInstagramPostUrl(parsed);
  if (instagramRef) {
    const instagramPreview = await fetchInstagramPreview(instagramRef, parsed.toString());
    if (instagramPreview && instagramPreview.image) {
      return res.json({ embed: instagramPreview });
    }
    instagramOembedPreview = instagramPreview;
  }

  const kickRef = parseKickUrl(parsed);
  if (kickRef) {
    const kickPreview = await fetchKickPreview(kickRef, parsed.toString());
    if (kickPreview) {
      return res.json({ embed: kickPreview });
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
    const ogImageSecure = extractMetaTag(html, 'og:image:secure_url', 'property');
    const ogSiteName = extractMetaTag(html, 'og:site_name', 'property');
    const twTitle = extractMetaTag(html, 'twitter:title', 'name');
    const twDescription = extractMetaTag(html, 'twitter:description', 'name');
    const twImage = extractMetaTag(html, 'twitter:image', 'name');
    const description = extractMetaTag(html, 'description', 'name');

    const title = ogTitle || twTitle || extractTitle(html) || instagramOembedPreview?.title || null;
    const summary = ogDescription || twDescription || description || instagramOembedPreview?.description || null;
    const image = resolveMaybeRelative(finalUrl, ogImageSecure || ogImage || twImage) || instagramOembedPreview?.image || null;
    const siteName = ogSiteName || instagramOembedPreview?.siteName || new URL(finalUrl).hostname;

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
