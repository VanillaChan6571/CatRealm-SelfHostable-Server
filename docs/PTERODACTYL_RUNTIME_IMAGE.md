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
- `ghcr.io/vanillachan6571/catrealm-selfhostable-server-yolk:nodejs_24`

## Why this exists

Pterodactyl runs the egg install script in an installer container, but your server actually runs in a separate runtime image.

That means adding `apt-get install ffmpeg` to the egg install script alone does not guarantee `ffmpeg` exists in the runtime container after deployment.

Using a custom runtime image fixes that permanently.

## New servers

Import the CatRealm egg and pick one of the `CatRealm Runtime` image options from the egg image list.

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
  --build-arg BASE_IMAGE=ghcr.io/pterodactyl/yolks:nodejs_24 \
  -t your-registry/catrealm-selfhostable-server-yolk:nodejs_24 \
  .
```

Then push that image and point your egg at it.

