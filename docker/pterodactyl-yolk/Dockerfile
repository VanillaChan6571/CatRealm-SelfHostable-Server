ARG BASE_IMAGE=ghcr.io/pterodactyl/yolks:nodejs_20
ARG LIVEKIT_VERSION=1.11.0
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
      gst-plugins-base \
      gst-plugins-base-dev \
      gst-plugins-good \
      gst-plugins-ugly \
      gstreamer \
      gstreamer-dev \
      make \
      pkgconf \
      python3 \
      redis \
      tini; \
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
      libgstreamer-plugins-base1.0-dev \
      libgstreamer1.0-dev \
      make \
      pkg-config \
      python3 \
      redis-server \
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
  git clone --depth 1 --branch "v${LIVEKIT_INGRESS_VERSION}" https://github.com/livekit/ingress.git /tmp/livekit-ingress; \
  (cd /tmp/livekit-ingress && CGO_ENABLED=1 GO111MODULE=on go build -a -o /usr/local/bin/ingress ./cmd/server); \
  rm -rf /tmp/livekit-ingress; \
  chmod 0755 /usr/local/bin/ingress; \
  /usr/local/bin/yt-dlp --version; \
  /usr/local/bin/livekit-server --version; \
  /usr/local/bin/ingress --help >/dev/null; \
  redis-server --version; \
  ffmpeg -version | head -n 1

USER container

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/bin/ash", "/entrypoint.sh"]
