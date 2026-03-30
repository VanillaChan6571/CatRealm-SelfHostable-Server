# CatRealm Egg Repository

Use this URL in Pterodactyl's **Import Egg from URL** flow:

`https://raw.githubusercontent.com/VanillaChan6571/CatRealm-SelfHostable-Server/main/pterodactyl-egg/egg-cat-realm-server.json`

This egg includes:
- Git-based install from `CatRealm-SelfHostable-Server`
- Runtime startup via `node scripts/pterodactyl-bootstrap.js`
- Runtime dependency bootstrap with `npm_config_libc=musl` when `node_modules` or the `better-sqlite3` native binding is missing
- Install-time OS prerequisites via `curl git python3 make g++ ffmpeg yt-dlp`
- Optional custom runtime images published from this repo:
  - `ghcr.io/vanillachan6571/catrealm-selfhostable-server-yolk:nodejs_20`
- Safe-directory handling for `/mnt/server` during git install/update
- Auto-update controls:
  - `AUTO_UPDATE`
  - `GIT_REPO`
  - `GIT_BRANCH`

Default repository:

`https://github.com/VanillaChan6571/CatRealm-SelfHostable-Server.git`

Notes:
- The startup path is a direct Node process, which lets Pterodactyl attach console input to CatRealm correctly.
- `scripts/pterodactyl-bootstrap.js` installs dependencies only when they are missing, then loads `src/index.js`.
- `npm_config_libc=musl` is intentional. It helps Pterodactyl environments that need the musl variant of `better-sqlite3`.
- Dependencies are installed in the runtime container only when `node_modules` or the `better-sqlite3` native binding is missing.
- The custom runtime image is the recommended way to guarantee Theater runtime tools like `ffmpeg` and `yt-dlp` are present after deployment.
- If a host requires glibc instead, admins can edit the egg and change `npm_config_libc=musl` to `npm_config_libc=glibc`, or remove the override entirely.
- The install script runs in the installer container; runtime startup uses the selected Pterodactyl Node image.
- Existing deployed servers do not switch images automatically. After updating the egg, change the server image in the panel and rebuild or reinstall the server.
- Reinstall preserves the previous `.env` as `/mnt/server/backup-before-reinstall/.env-YYYYMMDD-HHMMSS` before writing the new one.
- `AUTO_UPDATE_RESTART_ON_START=false` is written by the egg so startup update checks do not intentionally stop the managed process during boot.
- If panel stdin is still limited on a host, CatRealm also exposes `/api/admin/console-command` as a fallback for supported diagnostic commands.
