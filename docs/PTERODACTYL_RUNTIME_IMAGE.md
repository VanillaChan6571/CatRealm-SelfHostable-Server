# Pterodactyl Runtime Image

CatRealm now includes a public Pterodactyl runtime image definition that adds the OS tools the server expects at runtime:

- `ffmpeg`
- `yt-dlp`
- `git`
- `python3`
- `make`
- `g++`

The Dockerfile lives at:

- `docker/pterodactyl-yolk/Dockerfile`

The GitHub Actions workflow publishes these tags to GHCR:

- `ghcr.io/vanillachan6571/catrealm-selfhostable-server-yolk:nodejs_20`

## Why this exists

Pterodactyl runs the egg install script in an installer container, but your server actually runs in a separate runtime image.

That means adding `apt-get install ffmpeg` to the egg install script alone does not guarantee `ffmpeg` exists in the runtime container after deployment.

Using a custom runtime image fixes that permanently.

## New servers

Import the CatRealm egg and pick one of the `CatRealm Runtime` image options from the egg image list.

## LiveKit Sidecar

The CatRealm egg now exposes optional LiveKit media variables. These do not run LiveKit inside the CatRealm process; they connect CatRealm to a separate LiveKit media server that carries voice/video media.

Recommended layout:

- CatRealm server: this existing egg and runtime image.
- LiveKit media server: a separate Pterodactyl server, VPS service, Docker Compose service, or LiveKit Cloud project.
- Public media URL: a real TLS hostname such as `wss://media.example.com`.

CatRealm egg variables:

- `MEDIA_LIVEKIT_ENABLED`: set to `true` to enable LiveKit token/capability plumbing.
- `MEDIA_LIVEKIT_URL`: CatRealm-to-LiveKit URL. Use the same value as public URL unless CatRealm can reach LiveKit over an internal address.
- `MEDIA_LIVEKIT_PUBLIC_WS_URL`: client-facing URL, usually `wss://media.example.com`.
- `MEDIA_LIVEKIT_API_KEY`: LiveKit API key.
- `MEDIA_LIVEKIT_API_SECRET`: LiveKit API secret.
- `MEDIA_FALLBACK_TO_LEGACY`: keep `true` while testing, so clients can fall back to legacy voice if the media sidecar is unavailable.
- `MEDIA_TOKEN_TTL_SECONDS`: token lifetime, default `600`.

Pterodactyl note: LiveKit needs WebRTC media ports exposed on the LiveKit server, not the CatRealm server. For small hosts, configure a smaller UDP range on LiveKit, then allocate that same UDP range in the panel/firewall. A typical LiveKit deployment also needs its signaling port reachable through HTTPS/WSS.

Do not put the LiveKit API secret in client-side config. CatRealm mints participant tokens server-side.

## Existing deployed servers

Existing servers will keep using their current runtime image until you change it in the panel.

To move an existing server:

1. Update or re-import the CatRealm egg.
2. Change the server Docker image to one of the CatRealm runtime tags above.
3. Rebuild or reinstall the server so Pterodactyl recreates the container on that image.
4. Start the server and confirm startup logs show both `yt-dlp` and `ffmpeg` detected.

## Manual build

If you want to publish your own image instead of using GHCR:

```bash
docker build \
  -f docker/pterodactyl-yolk/Dockerfile \
  --build-arg BASE_IMAGE=ghcr.io/pterodactyl/yolks:nodejs_20 \
  -t your-registry/catrealm-selfhostable-server-yolk:nodejs_20 \
  .
```

Then push that image and point your egg at it.
