# Multi-Realm Hosting

Multi-realm mode lets one CatRealm install run **several independent realms on one machine**, each on its own port with its own database, while sharing the heavy infrastructure:

```
10.0.0.19:34959 = Frank's Realm        (data/34959.db)
10.0.0.19:34960 = Cherries Music Realm (data/34960.db)
10.0.0.19:34961 = Dolphin The Yard     (data/34961.db)
```

| Per realm | Shared by all realms |
|---|---|
| HTTP/WS port | One bundled LiveKit (one set of media ports) |
| SQLite database (`data/<port>.db`) | `data/uploads` and `data/ugc/*` folders |
| `JWT_SECRET`, secure-mode key | TLS certificate (one domain, many ports) |
| Realm identity, roles, users, messages | The repo checkout / node_modules |

The feature is **off by default**. `MULTI_REALM=false` (or unset) behaves exactly like a normal single-realm server.

## Enabling

1. Stop the server.
2. Set `MULTI_REALM=true` in `.env`.
3. Start the server as usual (`Start.sh`, `node src/index.js`, Docker, ...).

On the first multi-realm boot:

- Your existing database is **safely copied** to `data/<PORT>.db` (using the SQLite backup API — WAL-safe). The original is kept as `data/catrealm.db.pre-multirealm.bak`.
- `data/realms.json` is created with your current server as realm #1.
- Your current `JWT_SECRET` (and `SECURE_MODE_KEY`, if set) are copied to `data/realms/<PORT>.env`, so existing logins and encrypted messages keep working.

### Rolling back

Set `MULTI_REALM=false` and rename `data/catrealm.db.pre-multirealm.bak` back to `data/catrealm.db` (note: anything that happened while multi-realm was on stays in the per-port db).

## Adding / removing realms

Edit `data/realms.json` and restart:

```json
{
  "version": 1,
  "realms": [
    { "port": 34959, "name": "Frank's Realm", "dbFile": "34959.db", "enabled": true },
    { "port": 34960, "name": "Cherries Music Realm", "dbFile": "34960.db", "enabled": true }
  ]
}
```

- `port` — unique per realm; this is what players connect to.
- `dbFile` — relative to `data/`; defaults to `<port>.db` if omitted. A brand-new file is created automatically on first boot. You can rename a db file to move a realm to a new port (rename the file, update `port`/`dbFile`, restart).
- `enabled: false` — keeps the realm's data but doesn't start it.

Each realm gets `data/realms/<port>.env` (created automatically, mode 0600) holding its auto-generated `JWT_SECRET`. You can add per-realm overrides there, e.g. `SERVER_NAME`, `SERVER_DESCRIPTION`, `REGISTRATION_OPEN=false`, `CLIENT_URL`. Removing a realm from `realms.json` never deletes its `.db` file.

## LiveKit (voice / theater / streaming)

Set up LiveKit exactly as for a single server (`HOST_LIVEKIT_MEDIA=true` with the runtime image, or external `MEDIA_LIVEKIT_*` settings). The supervisor starts **one** LiveKit and every realm shares it. Rooms are automatically namespaced per realm, so voice channels on different realms never collide.

Do **not** set `CATREALM_SERVER_ID`/`SERVER_ID` in multi-realm mode — it is ignored (a shared id would merge the room namespaces).

## TLS

- **Auto-SSL** (`SSL_DOMAIN` + `SSL_EMAIL`): obtained once by the supervisor; all realms serve HTTPS for that domain on their own ports. On renewal, realms are rolling-restarted to pick up the new certificate.
- **Manual certs** (`SSL_CERT_PATH`/`SSL_KEY_PATH`): shared by all realms.
- **Reverse proxy** (nginx/caddy) in front of plain-HTTP realms also works and is recommended for many realms.

## Notes & caveats

- The shared `.env` is never modified while multi-realm is on; per-realm generated secrets go to `data/realms/<port>.env`. Back up that folder — losing a realm's `JWT_SECRET` logs everyone out, and losing a `SECURE_MODE_KEY` makes that realm's encrypted messages unrecoverable.
- Uploads/UGC are one shared pool. Files are unguessable UUIDs, so realms can't enumerate each other's files, but a leaked URL is readable from any realm.
- The in-process git auto-updater is disabled inside realm children. `Start.sh` / `auto-update-start.sh` still updates the install at boot.
- Console diagnostic commands are not available per-realm in this version (the supervisor owns the terminal).
