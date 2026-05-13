# CatRealm Self-Hosted Server 🐱

Welcome to CatRealm Self-Hosted Server!

We have moved the Server Guide to https://catrealm.app/docs/#home

Any Server/Client Bugs can be issued at https://github.com/VanillaChan6571/CatRealm/issues/new/choose

## Push Notification Relay (optional)

When a CatRealm mobile user is @mentioned in a channel, your server can relay a push notification to their device via the central CatRealm server.

**Requirements:** The recipient must have a CatRealm central account (not local-only).

**Setup:**
1. Get a shared secret from your central server admin (or generate one):
   ```
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
2. Add to your `.env`:
   ```
   PUSH_RELAY_SECRET=<the shared secret>
   ```
3. The central server admin adds the same value as `PUSH_RELAY_SECRET` on their end.

That's it. The relay target is `AUTH_SERVER_URL` (defaults to `https://auth.catrealm.app`) — no extra URL config needed. Leave `PUSH_RELAY_SECRET` unset to disable push relay entirely.
