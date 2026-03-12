const express = require('express');
const router = express.Router();
const db = require('../db');
const { getSetting } = require('../settings');

function getServerInfo(req) {
  const name = getSetting('server_name', process.env.SERVER_NAME || 'CatRealm Server');
  const description = getSetting(
    'server_description',
    process.env.SERVER_DESCRIPTION || 'A self-hosted CatRealm server'
  );
  const registrationOpen =
    getSetting('registration_open', process.env.REGISTRATION_OPEN !== 'false' ? 'true' : 'false') === 'true';
  const memberCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const serverIcon = getSetting('server_icon', null);
  const serverBanner = getSetting('server_banner', null);

  const proto = req.get('x-forwarded-proto') || req.protocol || 'http';
  const host = req.get('x-forwarded-host') || req.get('host');
  const origin = `${proto}://${host}`;

  return {
    name,
    description,
    registrationOpen,
    memberCount,
    iconUrl: serverIcon ? `${origin}${serverIcon}` : null,
    bannerUrl: serverBanner ? `${origin}${serverBanner}` : null,
    serverUrl: process.env.SERVER_URL || origin,
  };
}

function renderLandingPage(info) {
  const { name, description, registrationOpen, memberCount, iconUrl, bannerUrl, serverUrl } = info;

  const escapedName = name.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const escapedDesc = description.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const escapedServerUrl = serverUrl.replace(/"/g, '&quot;');

  const bannerHtml = bannerUrl
    ? `<div class="banner" style="background-image:url('${bannerUrl.replace(/'/g, "\\'")}')"></div>`
    : `<div class="banner banner-placeholder"></div>`;

  const iconHtml = iconUrl
    ? `<img class="icon" src="${iconUrl.replace(/"/g, '&quot;')}" alt="${escapedName} icon">`
    : `<div class="icon icon-placeholder"><span>🐱</span></div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapedName} — CatRealm Server</title>
  <meta name="description" content="${escapedDesc}">
  <meta property="og:title" content="${escapedName}">
  <meta property="og:description" content="${escapedDesc}">
  ${iconUrl ? `<meta property="og:image" content="${iconUrl.replace(/"/g, '&quot;')}">` : ''}
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f0f14;
      color: #e0e0e8;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
    }

    .card {
      background: #1a1a24;
      border: 1px solid #2a2a38;
      border-radius: 16px;
      overflow: hidden;
      width: 100%;
      max-width: 460px;
      box-shadow: 0 8px 40px rgba(0,0,0,0.5);
    }

    .banner {
      width: 100%;
      height: 140px;
      background-size: cover;
      background-position: center;
    }
    .banner-placeholder {
      background: linear-gradient(135deg, #2d1f4e 0%, #1a2d4e 50%, #1f3d2d 100%);
    }

    .header {
      padding: 0 24px 20px;
      position: relative;
    }

    .icon {
      width: 80px;
      height: 80px;
      border-radius: 20px;
      border: 4px solid #1a1a24;
      margin-top: -40px;
      display: block;
      object-fit: cover;
      background: #2a2a38;
    }
    .icon-placeholder {
      width: 80px;
      height: 80px;
      border-radius: 20px;
      border: 4px solid #1a1a24;
      margin-top: -40px;
      background: #2a2a38;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 36px;
    }

    .server-name {
      font-size: 22px;
      font-weight: 700;
      color: #f0f0f8;
      margin-top: 12px;
    }

    .server-description {
      color: #9090a8;
      font-size: 14px;
      line-height: 1.5;
      margin-top: 6px;
    }

    .stats {
      display: flex;
      gap: 16px;
      margin-top: 14px;
    }

    .stat {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
      color: #7878a0;
    }
    .stat-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }
    .dot-green { background: #3ba55c; }
    .dot-gray  { background: #72767d; }

    .divider {
      border: none;
      border-top: 1px solid #2a2a38;
      margin: 0 24px;
    }

    .url-section {
      padding: 16px 24px;
    }

    .url-label {
      font-size: 11px;
      font-weight: 600;
      color: #6060a0;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 8px;
    }

    .url-row {
      display: flex;
      align-items: center;
      background: #12121a;
      border: 1px solid #2a2a38;
      border-radius: 8px;
      overflow: hidden;
    }

    .url-text {
      flex: 1;
      padding: 9px 12px;
      font-size: 13px;
      font-family: 'SF Mono', 'Fira Code', monospace;
      color: #a0a0c8;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .copy-btn {
      padding: 9px 14px;
      background: #2a2a3a;
      border: none;
      border-left: 1px solid #2a2a38;
      color: #9090b8;
      font-size: 12px;
      cursor: pointer;
      transition: background 0.15s, color 0.15s;
      white-space: nowrap;
    }
    .copy-btn:hover { background: #33334a; color: #c0c0e0; }
    .copy-btn.copied { color: #3ba55c; }

    .actions {
      padding: 0 24px 24px;
    }

    .btn-join {
      display: block;
      width: 100%;
      padding: 13px;
      background: #5865f2;
      color: #fff;
      font-size: 15px;
      font-weight: 600;
      text-align: center;
      text-decoration: none;
      border-radius: 10px;
      transition: background 0.15s, transform 0.1s;
    }
    .btn-join:hover { background: #4752c4; transform: translateY(-1px); }
    .btn-join:active { transform: translateY(0); }

    .hint {
      text-align: center;
      font-size: 12px;
      color: #50507a;
      margin-top: 10px;
    }
    .hint a { color: #6868a8; text-decoration: none; }
    .hint a:hover { text-decoration: underline; }

    .footer {
      text-align: center;
      padding: 16px;
      font-size: 11px;
      color: #404060;
      border-top: 1px solid #1e1e2a;
    }
    .footer a { color: #505080; text-decoration: none; }
    .footer a:hover { color: #7070a8; }
  </style>
</head>
<body>
  <div class="card">
    ${bannerHtml}
    <div class="header">
      ${iconHtml}
      <div class="server-name">${escapedName}</div>
      <div class="server-description">${escapedDesc}</div>
      <div class="stats">
        <div class="stat">
          <div class="stat-dot dot-green"></div>
          <span>${memberCount} member${memberCount !== 1 ? 's' : ''}</span>
        </div>
        <div class="stat">
          <div class="stat-dot ${registrationOpen ? 'dot-green' : 'dot-gray'}"></div>
          <span>Registration ${registrationOpen ? 'open' : 'closed'}</span>
        </div>
      </div>
    </div>

    <hr class="divider">

    <div class="url-section">
      <div class="url-label">Server Address</div>
      <div class="url-row">
        <div class="url-text" id="serverUrl">${escapedServerUrl}</div>
        <button class="copy-btn" id="copyBtn" onclick="copyUrl()">Copy</button>
      </div>
    </div>

    <div class="actions">
      <a class="btn-join" href="https://catrealm.app" target="_blank" rel="noopener">
        Open CatRealm
      </a>
      <div class="hint">
        Open <a href="https://catrealm.app" target="_blank" rel="noopener">catrealm.app</a>,
        then paste the server address above to connect.
      </div>
    </div>
  </div>

  <div style="position:fixed;bottom:14px;width:100%;text-align:center;font-size:11px;color:#30304a;">
    Powered by <a href="https://github.com/VanillaChan6571/CatRealm-SelfHostable-Server" target="_blank" rel="noopener" style="color:#40407a;text-decoration:none;">CatRealm Self-Hosted</a>
  </div>

  <script>
    function copyUrl() {
      const url = document.getElementById('serverUrl').textContent;
      const btn = document.getElementById('copyBtn');
      navigator.clipboard.writeText(url).then(() => {
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
      }).catch(() => {
        // Fallback for non-secure contexts
        const ta = document.createElement('textarea');
        ta.value = url;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
      });
    }
  </script>
</body>
</html>`;
}

// GET / — Server landing page
router.get('/', (req, res) => {
  const info = getServerInfo(req);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderLandingPage(info));
});

module.exports = router;
