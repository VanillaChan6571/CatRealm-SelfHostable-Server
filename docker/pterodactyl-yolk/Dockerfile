# Built straight from the official Node image: upstream pterodactyl/yolks stops
# at nodejs_20, so the user, packages and entrypoint it provided live here now.
ARG NODE_VERSION=24.22.2
ARG BASE_IMAGE=node:${NODE_VERSION}-alpine
ARG LIVEKIT_VERSION=1.13.11
ARG LIVEKIT_INGRESS_VERSION=1.5.0
FROM ${BASE_IMAGE}

ARG LIVEKIT_VERSION
ARG LIVEKIT_INGRESS_VERSION

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
      go \
      gst-libav \
      gst-plugins-bad \
      gst-plugins-bad-dev \
      gst-plugins-base \
      gst-plugins-base-dev \
      gst-plugins-good \
      gst-plugins-ugly \
      gstreamer \
      gstreamer-dev \
      make \
      openssl \
      pkgconf \
      python3 \
      redis \
      sqlite \
      tar \
      tini \
      tzdata; \
    id container >/dev/null 2>&1 || adduser -D -h /home/container container; \
  elif command -v apt-get >/dev/null 2>&1; then \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      ffmpeg \
      g++ \
      gstreamer1.0-libav \
      gstreamer1.0-plugins-bad \
      gstreamer1.0-plugins-base \
      gstreamer1.0-plugins-good \
      gstreamer1.0-plugins-ugly \
      gstreamer1.0-tools \
      git \
      golang-go \
      libgstreamer-plugins-bad1.0-dev \
      libgstreamer-plugins-base1.0-dev \
      libgstreamer1.0-dev \
      make \
      pkg-config \
      openssl \
      python3 \
      redis-server \
      sqlite3 \
      tini \
      tzdata; \
    id container >/dev/null 2>&1 || useradd -m -d /home/container container; \
    ln -sf /usr/bin/tini /sbin/tini; \
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
  git clone --depth 1 --branch "v${LIVEKIT_INGRESS_VERSION}" https://github.com/livekit/ingress.git /tmp/livekit-ingress; \
  (cd /tmp/livekit-ingress && CGO_ENABLED=1 GO111MODULE=on go build -a -o /usr/local/bin/ingress ./cmd/server); \
  rm -rf /tmp/livekit-ingress; \
  chmod 0755 /usr/local/bin/ingress; \
  /usr/local/bin/yt-dlp --version; \
  /usr/local/bin/livekit-server --version; \
  /usr/local/bin/ingress --help >/dev/null; \
  redis-server --version; \
  node --version; \
  ffmpeg -version | head -n 1

# Pterodactyl entrypoint (vendored from pterodactyl/yolks, MIT).
COPY docker/pterodactyl-yolk/entrypoint.sh /entrypoint.sh

USER container
ENV USER=container HOME=/home/container
WORKDIR /home/container

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/bin/sh", "/entrypoint.sh"]
