# Pterodactyl Runtime Image

CatRealm now includes a public Pterodactyl runtime image definition that adds the OS tools the server expects at runtime:

- `ffmpeg`
- `livekit-server`
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

## Bundled LiveKit

The CatRealm runtime image includes `livekit-server`, so one Pterodactyl server can run CatRealm plus LiveKit media together. LiveKit still runs as a sidecar process; it is not embedded into the CatRealm Node process.

Set these visible egg variables for bundled mode:

- `HOST_LIVEKIT_MEDIA=true`
- `LIVEKIT_PUBLIC_HOST`: public hostname clients use for LiveKit. Leave empty to reuse `SSL_DOMAIN`; only set it when media uses a different hostname.
- `LIVEKIT_SIGNALING_PORT`: default `7880/tcp`.
- `LIVEKIT_RTC_TCP_PORT`: default `7881/tcp`.
- `LIVEKIT_RTC_UDP_PORT_START`: default `50000/udp`.
- `LIVEKIT_RTC_UDP_PORT_END`: default `50100/udp`.
- `MEDIA_FALLBACK_TO_LEGACY=true`: recommended while testing.

When bundled mode starts, `scripts/pterodactyl-bootstrap.js` writes `data/livekit.yaml`, starts `livekit-server --config data/livekit.yaml`, and sets CatRealm's `MEDIA_LIVEKIT_*` environment variables automatically.

The external LiveKit URL, API key, API secret, and token TTL variables remain in the egg for advanced deployments, but they are hidden from regular server users. In bundled mode CatRealm generates and persists the LiveKit API secret automatically.

Pterodactyl port requirements for bundled mode:

- Allocate `LIVEKIT_SIGNALING_PORT` as TCP.
- Allocate `LIVEKIT_RTC_TCP_PORT` as TCP.
- Allocate the full UDP range from `LIVEKIT_RTC_UDP_PORT_START` through `LIVEKIT_RTC_UDP_PORT_END`.

For small hosts, `50000-50100/udp` is a reasonable test range. Larger servers need a wider UDP range. LiveKit's official port guidance is at https://docs.livekit.io/home/self-hosting/ports-firewall/.

Do not put the LiveKit API secret in client-side config. CatRealm mints participant tokens server-side.

## Existing deployed servers

Existing servers will keep using their current runtime image until you change it in the panel.

To move an existing server:

1. Update or re-import the CatRealm egg.
2. Change the server Docker image to one of the CatRealm runtime tags above.
3. Rebuild or reinstall the server so Pterodactyl recreates the container on that image.
4. Start the server and confirm startup logs show `yt-dlp`, `ffmpeg`, and `livekit-server` detected.

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
