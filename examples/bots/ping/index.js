// Minimal CatRealm plugin bot. The server forks this file with:
//   CATREALM_SERVER_URL — this realm's local URL (http://127.0.0.1:<port>)
//   CATREALM_BOT_TOKEN  — the bot's API token (fresh every boot)
//   CATREALM_BOT_DB     — path reserved for this bot's private sqlite db
//   CATREALM_BOT_NAME   — the plugin name from bot.json
// Run `npm install` in this directory once so socket.io-client resolves.
const { io } = require('socket.io-client');

const SERVER_URL = process.env.CATREALM_SERVER_URL;
const TOKEN = process.env.CATREALM_BOT_TOKEN;
if (!SERVER_URL || !TOKEN) {
  console.error('CATREALM_SERVER_URL and CATREALM_BOT_TOKEN are required');
  process.exit(1);
}

async function registerCommands() {
  // Commands can also be pre-declared in bot.json; this shows the API path.
  const res = await fetch(`${SERVER_URL}/api/bots/self/commands`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${TOKEN}`,
    },
    body: JSON.stringify({
      commands: [
        { name: 'ping', description: 'Replies with pong and the round-trip time', options: [] },
      ],
    }),
  });
  if (!res.ok) throw new Error(`Command registration failed: ${res.status} ${await res.text()}`);
  console.log('Registered /ping');
}

const socket = io(SERVER_URL, { auth: { token: TOKEN } });

socket.on('connect', () => {
  console.log('Connected to realm');
  registerCommands().catch((err) => console.error(err.message));
});

socket.on('interaction:create', (interaction) => {
  const started = Date.now();
  socket.emit('interaction:respond', {
    id: interaction.id,
    content: `pong! (${Date.now() - started}ms) — hi ${interaction.user.displayName || interaction.user.username}`,
  }, (ack) => {
    if (ack?.status !== 'ok') console.error('Respond failed:', ack);
  });
});

socket.on('connect_error', (err) => console.error(`Connection error: ${err.message}`));
socket.on('disconnect', (reason) => console.log(`Disconnected: ${reason}`));
