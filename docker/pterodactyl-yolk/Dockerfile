ARG BASE_IMAGE=ghcr.io/pterodactyl/yolks:nodejs_20
FROM ${BASE_IMAGE}

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
  /usr/local/bin/yt-dlp --version; \
  ffmpeg -version | head -n 1

USER container

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/bin/ash", "/entrypoint.sh"]
