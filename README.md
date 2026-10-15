# CatRealm Self-Hosted Server 🐱

Welcome to CatRealm Self-Hosted Server!

We have moved the Server Guide to https://catrealm.app/docs/#home

Any Server/Client Bugs can be issued at https://github.com/VanillaChan6571/CatRealm/issues/new/choose

## Central account sign-in

For central accounts to join a realm, run server version 1.8.8 or newer and set
`PUBLIC_URL` to the realm's exact external HTTPS origin (for example,
`https://realm.example.com`). Existing `PUBLIC_SERVER_URL` settings are also
accepted. When `SERVER_URL` is already that public origin, no override is needed.
The client obtains a realm-bound sign-in assertion from central; the server
verifies it with central before issuing a realm-local session.

## Multi-Realm Hosting (optional)

Run several independent realms from one install — each on its own port with its own database, sharing LiveKit and the uploads/UGC folders. Set `MULTI_REALM=true` in `.env` and see [docs/MULTI_REALM.md](docs/MULTI_REALM.md).

## Bots (optional)

Create bot accounts from Realm Settings → Bots (token shown once, regenerable), or drop plugin bots into `realm-plugins/<name>/` to run them with the server. Bots register slash commands, and users individually Allow/Deny what each bot may do to them. See [docs/BOTS.md](docs/BOTS.md).

## Push Notification Relay (optional)

When a CatRealm mobile user is @mentioned in a channel, your server can relay a push notification to their device via the central CatRealm server.

**Requirements:** The mentioned user must have a CatRealm central account (not a local-only account). Local account users do not have push tokens and will not receive push notifications.

Users authorize notification grants when linking their central account. The
server signs each notification request with its realm identity, and central
checks the recipient's grant. The old `PUSH_RELAY_SECRET` self-registration
flow is retired; do not configure it for new installations.
