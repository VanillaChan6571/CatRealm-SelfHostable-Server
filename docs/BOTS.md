# Bots

CatRealm Self-Hosted Server supports two kinds of bots. Both are real member
accounts on your realm: they show up in the member list with a **BOT** badge,
and their server powers (sending messages, managing messages, etc.) come from
the **roles you assign them** — exactly like human members.

| | Token bot | Plugin bot |
|---|---|---|
| Created by | Realm Settings → **Bots** tab | Dropping code into `realm-plugins/<name>/` |
| Runs | Anywhere you want (your own process/host) | As a child process of the server |
| Credential | Token shown once at creation (regenerable) | Auto-generated fresh on every server boot |
| Private storage | Bring your own | `data/bot-<username>.db` path handed to the process |

## User consent (privacy gates)

Server permissions say what a bot can do *to the realm*. Consent scopes say
what a bot can do *to an individual user*. Each bot declares which scopes it
wants; each user gets an **Allow / Deny** prompt the first time they invoke one
of the bot's commands, and can change their choice anytime from the bot's
profile ("Bot Settings").

| Scope | Gates |
|---|---|
| `interactions` | Invoking the bot's slash commands (always requested) |
| `profile` | Bot reading the user's bio/pronouns/status/activity |
| `mentions` | Bot @mentioning the user (highlight + push notification) |
| `private_messages` | Bot messaging the user in their **Bot DMs** channel |

Enforcement is server-side: a bot mentioning a non-consenting user still sends
the message, but the mention triggers no push or highlight for that user; a
bot reading a non-consenting user's profile gets a stripped payload; a bot
private message without consent is rejected.

## Token bots (quickstart)

1. Realm Settings → **Bots** → **Create Bot** (requires the *Manage Bots*
   permission). Pick a username and the consent scopes the bot will ask for.
2. Copy the token — it is shown **once**. `Regenerate` kills the old token
   instantly and disconnects the bot.
3. Assign the bot roles (Members tab) for whatever server permissions it needs
   (at minimum View Channels + Send Messages to chat).
4. Connect like a client:

```js
const { io } = require('socket.io-client');
const socket = io('https://your-realm.example:3000', {
  auth: { token: 'crbt_...' },
});
socket.on('message:new', (msg) => { /* the bot sees what its roles allow */ });
```

The token also works as a Bearer token on the REST API
(`Authorization: Bearer crbt_...`).

## Plugin bots

Create `realm-plugins/<name>/bot.json`:

```json
{
  "name": "greeter",
  "username": "GreeterBot",
  "entry": "index.js",
  "scopes": ["interactions", "mentions"],
  "commands": [
    { "name": "greet", "description": "Say hello", "options": [] }
  ]
}
```

On boot the server provisions the bot account, generates a fresh token, and
forks `entry` with these environment variables:

- `CATREALM_SERVER_URL` — `http://127.0.0.1:<port>` for this realm
- `CATREALM_BOT_TOKEN` — the bot's token (never stored on disk)
- `CATREALM_BOT_DB` — a reserved path for the bot's own sqlite database
- `CATREALM_BOT_NAME` — the plugin name

Crashed plugins are restarted with backoff (1s → 60s, giving up after 10
consecutive crashes — status shows in the Bots tab). Logs are prefixed
`[bot:<name>]`. Toggle a plugin off/on from the Bots tab; set
`BOTS_PLUGINS_ENABLED=false` in `.env` to disable the plugin loader entirely.

A complete example lives in [`examples/bots/ping`](../examples/bots/ping) —
copy it to `realm-plugins/ping` and restart the server — dependencies are
installed automatically on first start —
and type `/ping` in any channel.

> **Security note:** plugin processes run with the same filesystem rights as
> the server user. Process isolation protects the server from crashes, not
> from malicious code — only install plugins you trust.

## Slash commands & interactions

Bots register commands with `PUT /api/bots/self/commands` (or pre-declare them
in `bot.json`). Typing `/` in the desktop composer suggests commands; invoking
one sends the bot an `interaction:create` socket event:

```js
socket.on('interaction:create', (interaction) => {
  // { id, command, options, channelId, threadId, user: {id, username, displayName, ...}, respondBy }
  socket.emit('interaction:respond', {
    id: interaction.id,
    content: 'pong!',
    // ephemeral: true  → only the invoker sees the reply, nothing persisted
  }, (ack) => { /* ack.status === 'ok' */ });
});
```

A non-ephemeral response becomes a normal bot message in the channel with a
"used /command" header. Bots have 60 seconds to respond before the interaction
expires. Bot socket traffic is throttled (~30 events / 10s).

## Bot DMs

With the `private_messages` scope granted, a bot can message a user privately:

```js
socket.emit('bot:dm:send', { userId, content: 'hello!' }, (ack) => {});
socket.on('bot:dm:incoming', (msg) => { /* the user replied */ });
```

Users see these in the pinned **Bot DMs** channel at the top of the channel
list (below Realm Rules) and can reply. Conversations are stored in the realm
database (encrypted at rest when secure mode is on).

## API reference (summary)

Bot-token endpoints:
- `GET /api/bots/self` — the bot's own record
- `PUT /api/bots/self/commands` — replace the bot's command set
- Everything a member of equal roles can call (profile customization via
  `/api/profile/me`, message history, uploads, ...)

Admin endpoints (Manage Bots):
- `GET /api/bots`, `POST /api/bots`, `PATCH /api/bots/:id`,
  `DELETE /api/bots/:id`, `POST /api/bots/:id/regenerate-token`,
  `PATCH /api/bots/:id/profile`, `POST /api/bots/:id/avatar|banner`

User endpoints:
- `GET /api/bots/commands` — command list for the composer
- `GET/PUT /api/bots/:id/consent` — the caller's consent for a bot
- `GET /api/bots/dms`, `GET /api/bots/dms/:botId`, `POST /api/bots/dms/:botId/read`

Socket events:
- user → server: `interaction:invoke`, `bot:dm:reply`
- bot → server: `interaction:respond`, `bot:dm:send`
- server → bot: `interaction:create`, `bot:dm:incoming`
- server → user: `interaction:failed`, `bot:ephemeral`, `bot:dm`,
  `bots:commands_updated`

## Notes & limits

- Deleting a bot keeps its past messages (the account is soft-removed).
- Multi-realm: each realm has its own bots; plugin bots live in each realm's
  own plugins and connect to that realm's port.
- Real DMs (the Central-hosted, end-to-end-encrypted kind) are not available
  to realm bots — Bot DMs are realm-local.
- Mobile client support for bot UIs (commands, Bot DMs) is not included yet;
  bot messages and badges still display.
