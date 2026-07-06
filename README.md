# CatRealm Self-Hosted Server 🐱

Welcome to CatRealm Self-Hosted Server!

We have moved the Server Guide to https://catrealm.app/docs/#home

Any Server/Client Bugs can be issued at https://github.com/VanillaChan6571/CatRealm/issues/new/choose

## Multi-Realm Hosting (optional)

Run several independent realms from one install — each on its own port with its own database, sharing LiveKit and the uploads/UGC folders. Set `MULTI_REALM=true` in `.env` and see [docs/MULTI_REALM.md](docs/MULTI_REALM.md).

## Push Notification Relay (optional)

When a CatRealm mobile user is @mentioned in a channel, your server can relay a push notification to their device via the central CatRealm server.

**Requirements:** The mentioned user must have a CatRealm central account (not a local-only account). Local account users do not have push tokens and will not receive push notifications.

**Setup:**
1. Generate your own relay secret — no coordination with CatRealm required:
   ```
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
2. Add to your `.env`:
   ```
   PUSH_RELAY_SECRET=<your generated secret>
   ```

Your server self-registers with the central CatRealm server automatically on startup using your `SERVER_URL`. No further setup is needed. Leave `PUSH_RELAY_SECRET` unset to disable push relay entirely.
