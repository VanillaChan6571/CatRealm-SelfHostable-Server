# CatRealm Egg Repository

Use this URL in Pterodactyl's **Import Egg from URL** flow:

`https://raw.githubusercontent.com/VanillaChan6571/CatRealm-SelfHostable-Server/refs/heads/main/pterodactyl-egg/egg-cat-realm-server.json`

This egg includes:
- Git-based install from `CatRealm-SelfHostable-Server`
- Runtime startup via `if missing deps -> npm_config_libc=musl npm install --production; exec node src/index.js`
- Install-time OS prerequisites via `curl git python3 make g++`
- Safe-directory handling for `/mnt/server` during git install/update
- Auto-update controls:
  - `AUTO_UPDATE`
  - `GIT_REPO`
  - `GIT_BRANCH`

Default repository:

`https://github.com/VanillaChan6571/CatRealm-SelfHostable-Server.git`

Notes:
- The startup path ends with `exec node src/index.js` so Pterodactyl attaches console input to the real server process after any one-time dependency bootstrap.
- `npm_config_libc=musl` is intentional. It helps Pterodactyl environments that need the musl variant of `better-sqlite3`.
- Dependencies are installed in the runtime container only when `node_modules` or the `better-sqlite3` native binding is missing.
- If a host requires glibc instead, admins can edit the egg and change `npm_config_libc=musl` to `npm_config_libc=glibc`, or remove the override entirely.
- The install script runs in the installer container; runtime startup uses the selected Pterodactyl Node image.
- If panel stdin is still limited on a host, CatRealm also exposes `/api/admin/console-command` as a fallback for supported diagnostic commands.
