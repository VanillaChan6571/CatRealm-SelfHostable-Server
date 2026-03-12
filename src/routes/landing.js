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
    ? `<div style="width:100%;height:128px;background:url('${bannerUrl.replace(/'/g, "\\'")}') center/cover no-repeat;"></div>`
    : `<div style="width:100%;height:128px;background:linear-gradient(135deg,#2d1f4e 0%,#1a2d4e 50%,#1f3d2d 100%);"></div>`;

  const iconHtml = iconUrl
    ? `<img src="${iconUrl.replace(/"/g, '&quot;')}" alt="${escapedName}" style="width:96px;height:96px;border-radius:50%;border:4px solid #1e1b2e;object-fit:cover;background:#2a2438;">`
    : `<div style="width:96px;height:96px;border-radius:50%;border:4px solid #1e1b2e;background:#3d2f6e;display:flex;align-items:center;justify-content:center;font-size:42px;">🐱</div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/png" href="https://catrealm.app/app/CatRealm.png">
  <title>${escapedName} — CatRealm Server</title>
  <meta name="description" content="${escapedDesc}">
  <meta property="og:title" content="${escapedName}">
  <meta property="og:description" content="${escapedDesc}">
  ${iconUrl ? `<meta property="og:image" content="${iconUrl.replace(/"/g, '&quot;')}">` : ''}
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #e0e0f0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px 16px 48px;
      overflow-x: hidden;
    }

    /* ── Backdrop (exact match to client) ── */
    .invite-backdrop {
      background:
        radial-gradient(1200px 560px at 12% -10%, rgba(124, 92, 255, 0.18), transparent 60%),
        radial-gradient(900px 460px at 92% 8%, rgba(103, 232, 249, 0.08), transparent 60%),
        #171225;
    }

    /* ── Orbs ── */
    .invite-orb-a {
      background: radial-gradient(circle at 35% 35%, rgba(124, 92, 255, 0.34), rgba(124, 92, 255, 0.08) 55%, transparent 72%);
      animation: inviteDriftOrbA 20s ease-in-out infinite alternate;
    }
    .invite-orb-b {
      background: radial-gradient(circle at 45% 45%, rgba(103, 232, 249, 0.2), rgba(103, 232, 249, 0.06) 54%, transparent 74%);
      animation: inviteDriftOrbB 23s ease-in-out infinite alternate;
    }

    /* ── Stars ── */
    .invite-stars {
      opacity: 0.86;
      mix-blend-mode: screen;
      background-image:
        radial-gradient(1.4px 1.4px at 14px 26px, rgba(255,255,255,0.9), transparent 62%),
        radial-gradient(1px 1px at 42px 82px, rgba(222,229,255,0.84), transparent 60%),
        radial-gradient(1.8px 1.8px at 88px 36px, rgba(214,195,255,0.78), transparent 64%),
        radial-gradient(2.8px 2.8px at 110px 18px, rgba(255,255,255,0.78), transparent 68%),
        radial-gradient(1.2px 1.2px at 124px 104px, rgba(197,241,255,0.74), transparent 62%),
        radial-gradient(1px 1px at 168px 60px, rgba(255,255,255,0.84), transparent 60%),
        radial-gradient(1.6px 1.6px at 202px 20px, rgba(215,201,255,0.74), transparent 64%),
        radial-gradient(2.4px 2.4px at 228px 72px, rgba(198,239,255,0.76), transparent 67%),
        radial-gradient(1px 1px at 236px 96px, rgba(186,245,255,0.76), transparent 60%),
        radial-gradient(1.4px 1.4px at 264px 52px, rgba(255,255,255,0.8), transparent 62%);
      background-size: 280px 140px;
      animation: inviteTwinkle1 7.4s ease-in-out infinite;
    }
    .invite-stars::before,
    .invite-stars::after {
      content: '';
      position: absolute;
      inset: 0;
      pointer-events: none;
      background-repeat: repeat;
    }
    .invite-stars::before {
      opacity: 0.84;
      background-image:
        radial-gradient(1.4px 1.4px at 22px 48px, rgba(255,255,255,0.78), transparent 62%),
        radial-gradient(1px 1px at 58px 20px, rgba(189,168,255,0.72), transparent 60%),
        radial-gradient(1.8px 1.8px at 102px 84px, rgba(194,240,255,0.8), transparent 64%),
        radial-gradient(2.6px 2.6px at 132px 26px, rgba(213,198,255,0.76), transparent 68%),
        radial-gradient(1px 1px at 144px 56px, rgba(255,255,255,0.72), transparent 60%),
        radial-gradient(1.6px 1.6px at 182px 10px, rgba(205,188,255,0.72), transparent 64%),
        radial-gradient(2.3px 2.3px at 214px 92px, rgba(189,239,255,0.74), transparent 67%),
        radial-gradient(1px 1px at 226px 72px, rgba(194,240,255,0.7), transparent 60%),
        radial-gradient(1.2px 1.2px at 268px 38px, rgba(255,255,255,0.72), transparent 62%);
      background-size: 300px 120px;
      animation: inviteTwinkle2 6.1s ease-in-out infinite reverse;
    }
    .invite-stars::after {
      opacity: 0.72;
      background-image:
        radial-gradient(1.2px 1.2px at 34px 18px, rgba(255,255,255,0.74), transparent 62%),
        radial-gradient(1.7px 1.7px at 74px 68px, rgba(179,154,255,0.72), transparent 64%),
        radial-gradient(2.5px 2.5px at 96px 42px, rgba(255,255,255,0.72), transparent 67%),
        radial-gradient(1px 1px at 114px 42px, rgba(197,232,255,0.68), transparent 60%),
        radial-gradient(1.4px 1.4px at 154px 90px, rgba(255,255,255,0.7), transparent 62%),
        radial-gradient(2.2px 2.2px at 176px 14px, rgba(198,237,255,0.7), transparent 67%),
        radial-gradient(1px 1px at 198px 28px, rgba(197,232,255,0.66), transparent 60%),
        radial-gradient(1.6px 1.6px at 234px 78px, rgba(179,154,255,0.68), transparent 64%),
        radial-gradient(2.4px 2.4px at 254px 96px, rgba(201,186,255,0.68), transparent 68%),
        radial-gradient(1px 1px at 272px 50px, rgba(255,255,255,0.72), transparent 60%);
      background-size: 290px 110px;
      animation: inviteTwinkle3 8.9s ease-in-out infinite;
    }

    /* ── Card breathe ── */
    .invite-card-breathe {
      animation: inviteCardBreathe 3.2s ease-in-out infinite;
    }

    /* ── Keyframes ── */
    @keyframes inviteDriftOrbA {
      0%   { transform: translate3d(0,0,0) scale(1); }
      100% { transform: translate3d(32px,-34px,0) scale(1.08); }
    }
    @keyframes inviteDriftOrbB {
      0%   { transform: translate3d(0,0,0) scale(1); }
      100% { transform: translate3d(-30px,26px,0) scale(1.06); }
    }
    @keyframes inviteTwinkle1 {
      0%,100% { opacity:0.62; filter:none; transform:scale(1); }
      26%     { opacity:0.82; filter:drop-shadow(0 0 4px rgba(212,198,255,0.2)); }
      34%     { opacity:0.98; filter:drop-shadow(0 0 7px rgba(186,245,255,0.28)); transform:scale(1.01); }
      64%     { opacity:0.76; }
      81%     { opacity:0.92; filter:drop-shadow(0 0 6px rgba(255,255,255,0.26)); transform:scale(1.005); }
    }
    @keyframes inviteTwinkle2 {
      0%,100% { opacity:0.56; transform:scale(1); }
      22%     { opacity:0.74; }
      28%     { opacity:0.9; transform:scale(1.012); }
      64%     { opacity:0.7; }
      86%     { opacity:0.84; transform:scale(1.006); }
    }
    @keyframes inviteTwinkle3 {
      0%,100% { opacity:0.5; transform:scale(1); }
      18%     { opacity:0.62; }
      45%     { opacity:0.84; transform:scale(1.01); }
      70%     { opacity:0.64; }
      91%     { opacity:0.78; transform:scale(1.004); }
    }
    @keyframes inviteCardBreathe {
      0%,100% {
        border-color: rgba(255,255,255,0.20);
        box-shadow: 0 0 0 1px rgba(255,255,255,0.05), 0 18px 38px rgba(0,0,0,0.38);
      }
      50% {
        border-color: rgba(255,255,255,0.62);
        box-shadow: 0 0 0 1px rgba(255,255,255,0.32), 0 0 24px rgba(255,255,255,0.28), 0 20px 44px rgba(0,0,0,0.42);
      }
    }
    @media (prefers-reduced-motion: reduce) {
      .invite-orb-a, .invite-orb-b,
      .invite-stars, .invite-stars::before, .invite-stars::after,
      .invite-card-breathe { animation: none !important; }
    }

    /* ── Card ── */
    .card {
      background: #1e1b2e;
      border: 1px solid rgba(255,255,255,0.20);
      border-radius: 12px;
      overflow: hidden;
      width: 100%;
      max-width: 480px;
    }

    .card-body { padding: 32px; }

    .icon-wrap {
      display: flex;
      justify-content: center;
      margin-top: -48px;
      margin-bottom: 24px;
    }

    .server-name {
      text-align: center;
      font-size: 24px;
      font-weight: 700;
      color: #f0eeff;
      margin-bottom: 8px;
    }
    .server-desc {
      text-align: center;
      font-size: 14px;
      color: #9090b8;
      line-height: 1.5;
      margin-bottom: 8px;
    }
    .server-tagline {
      text-align: center;
      font-size: 14px;
      color: #9090b8;
      margin-bottom: 24px;
    }

    .stats-box {
      background: #171225;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 14px;
      color: #9090b8;
    }
    .stat { display: flex; align-items: center; gap: 6px; }
    .stat-dot { width: 8px; height: 8px; border-radius: 50%; }
    .dot-green { background: #3ba55c; }
    .dot-gray  { background: #72767d; }

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
      background: #0f0d1a;
      border: 1px solid #2a2448;
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 20px;
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
      background: #2a2448;
      border: none;
      border-left: 1px solid #2a2448;
      color: #9090b8;
      font-size: 12px;
      cursor: pointer;
      transition: background 0.15s, color 0.15s;
      white-space: nowrap;
    }
    .copy-btn:hover { background: #332d5a; color: #c0c0e0; }
    .copy-btn.copied { color: #3ba55c; }

    .btn-join {
      display: block;
      width: 100%;
      padding: 13px;
      background: #7c5cff;
      color: #fff;
      font-size: 15px;
      font-weight: 600;
      text-align: center;
      text-decoration: none;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      transition: background 0.15s, transform 0.1s;
      margin-bottom: 10px;
    }
    .btn-join:hover { background: #6a4de0; transform: translateY(-1px); }
    .btn-join:active { transform: translateY(0); }

    .hint {
      text-align: center;
      font-size: 12px;
      color: #50507a;
      margin-top: 2px;
    }
    .hint a { color: #6868a8; text-decoration: none; }
    .hint a:hover { text-decoration: underline; }

    .powered-by {
      position: fixed;
      bottom: 14px;
      width: 100%;
      text-align: center;
      font-size: 11px;
      color: rgba(255,255,255,0.18);
    }
    .powered-by a { color: rgba(255,255,255,0.26); text-decoration: none; }
    .powered-by a:hover { color: rgba(255,255,255,0.5); }
  </style>
</head>
<body class="invite-backdrop">
  <!-- Orbs -->
  <div aria-hidden="true" class="invite-orb-a" style="pointer-events:none;position:fixed;left:-160px;bottom:-190px;height:460px;width:460px;border-radius:50%;opacity:0.80;filter:blur(8px);"></div>
  <div aria-hidden="true" class="invite-orb-b" style="pointer-events:none;position:fixed;right:-130px;top:88px;height:390px;width:390px;border-radius:50%;opacity:0.70;filter:blur(7px);"></div>
  <!-- Stars -->
  <div aria-hidden="true" class="invite-stars" style="pointer-events:none;position:fixed;inset:0;background-repeat:repeat;"></div>

  <!-- Card -->
  <div style="position:relative;z-index:10;width:100%;display:flex;align-items:center;justify-content:center;">
    <div class="card invite-card-breathe">
      ${bannerHtml}
      <div class="card-body">
        <div class="icon-wrap">${iconHtml}</div>
        <div class="server-name">${escapedName}</div>
        ${description ? `<div class="server-desc">${escapedDesc}</div>` : ''}
        <div class="server-tagline">🐱 You've found a self-hosted CatRealm server</div>

        <div class="stats-box">
          <div class="stat">
            <div class="stat-dot dot-green"></div>
            <span>${memberCount} member${memberCount !== 1 ? 's' : ''}</span>
          </div>
          <div class="stat">
            <div class="stat-dot ${registrationOpen ? 'dot-green' : 'dot-gray'}"></div>
            <span>Registration ${registrationOpen ? 'open' : 'closed'}</span>
          </div>
        </div>

        <div class="url-label">Server Address</div>
        <div class="url-row">
          <div class="url-text" id="serverUrl">${escapedServerUrl}</div>
          <button class="copy-btn" id="copyBtn" onclick="copyUrl()">Copy</button>
        </div>

        <a class="btn-join" href="https://catrealm.app" target="_blank" rel="noopener">Open CatRealm</a>
        <div class="hint">
          Open <a href="https://catrealm.app" target="_blank" rel="noopener">catrealm.app</a>,
          then paste the server address above to connect.
        </div>
      </div>
    </div>
  </div>

  <div class="powered-by">
    Powered by <a href="https://github.com/VanillaChan6571/CatRealm-SelfHostable-Server" target="_blank" rel="noopener">CatRealm Self-Hosted</a>
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
        const ta = document.createElement('textarea');
        ta.value = url;
        ta.style.cssText = 'position:fixed;opacity:0';
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
