ARG BASE_IMAGE=ghcr.io/pterodactyl/yolks:nodejs_20
ARG LIVEKIT_VERSION=1.11.0
FROM ${BASE_IMAGE}

ARG LIVEKIT_VERSION

USER root

SHELL ["/bin/sh", "-c"]

RUN set -eux; \
  if command -v apk >/dev/null 2>&1; then \
    apk add --no-cache \
      bash \
      ca-certificates \
      curl \
      ffmpeg \
      g++ \
      git \
      make \
      python3 \
      tini; \
  elif command -v apt-get >/dev/null 2>&1; then \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      ffmpeg \
      g++ \
      git \
      make \
      python3 \
      tini; \
    rm -rf /var/lib/apt/lists/*; \
  else \
    echo "Unsupported base image: no apk or apt-get available"; \
    exit 1; \
  fi; \
  curl -fsSL "https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp" -o /usr/local/bin/yt-dlp; \
  chmod 0755 /usr/local/bin/yt-dlp; \
  arch="$(uname -m)"; \
  case "$arch" in \
    x86_64|amd64) livekit_arch="amd64" ;; \
    aarch64|arm64) livekit_arch="arm64" ;; \
    armv7l|armv7) livekit_arch="armv7" ;; \
    *) echo "Unsupported LiveKit architecture: $arch"; exit 1 ;; \
  esac; \
  curl -fsSL "https://github.com/livekit/livekit/releases/download/v${LIVEKIT_VERSION}/livekit_${LIVEKIT_VERSION}_linux_${livekit_arch}.tar.gz" -o /tmp/livekit.tar.gz; \
  tar -xzf /tmp/livekit.tar.gz -C /usr/local/bin livekit-server; \
  rm -f /tmp/livekit.tar.gz; \
  chmod 0755 /usr/local/bin/livekit-server; \
  /usr/local/bin/yt-dlp --version; \
  /usr/local/bin/livekit-server --version; \
  ffmpeg -version | head -n 1

USER container

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/bin/ash", "/entrypoint.sh"]
