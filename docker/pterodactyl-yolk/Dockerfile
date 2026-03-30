ARG BASE_IMAGE=ghcr.io/pterodactyl/yolks:nodejs_24
FROM ${BASE_IMAGE}

USER root

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    ffmpeg \
    g++ \
    git \
    make \
    python3 \
 && curl -fsSL "https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp" -o /usr/local/bin/yt-dlp \
 && chmod 0755 /usr/local/bin/yt-dlp \
 && /usr/local/bin/yt-dlp --version \
 && ffmpeg -version | head -n 1 \
 && rm -rf /var/lib/apt/lists/*

USER container

