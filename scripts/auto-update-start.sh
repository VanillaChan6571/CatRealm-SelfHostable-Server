#!/usr/bin/env bash
set -euo pipefail

# CatRealm self-hosted startup with optional git auto-update.
# Safe defaults:
# - AUTO_UPDATE=true
# - GIT_BRANCH=main
# - GIT_REPO can be omitted; origin remote is used when available.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AUTO_UPDATE="${AUTO_UPDATE:-true}"
GIT_REPO="${GIT_REPO:-}"
GIT_BRANCH="${GIT_BRANCH:-main}"

echo "[CatRealm] Startup launcher"
echo "[CatRealm] Root: $ROOT_DIR"

normalize_bool() {
  case "${1,,}" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

if normalize_bool "$AUTO_UPDATE"; then
  if command -v git >/dev/null 2>&1 && [ -d ".git" ]; then
    echo "[CatRealm] Auto-update enabled (branch: $GIT_BRANCH)"

    if [ -z "$GIT_REPO" ]; then
      if git remote get-url origin >/dev/null 2>&1; then
        GIT_REPO="$(git remote get-url origin)"
      fi
    fi

    if [ -n "$GIT_REPO" ]; then
      git remote set-url origin "$GIT_REPO" || true
    fi

    git fetch --all --prune || true
    if git show-ref --verify --quiet "refs/remotes/origin/$GIT_BRANCH"; then
      LOCAL_SHA="$(git rev-parse HEAD)"
      REMOTE_SHA="$(git rev-parse "origin/$GIT_BRANCH")"
      if [ "$LOCAL_SHA" != "$REMOTE_SHA" ]; then
        echo "[CatRealm] New commit detected. Updating to origin/$GIT_BRANCH..."
        git reset --hard "origin/$GIT_BRANCH"
      else
        echo "[CatRealm] Already up-to-date."
      fi
    else
      echo "[CatRealm] Branch origin/$GIT_BRANCH not found. Skipping update."
    fi
  else
    echo "[CatRealm] Auto-update skipped (git missing or repository not initialized)."
  fi
else
  echo "[CatRealm] Auto-update disabled."
fi

if [ ! -d "node_modules" ]; then
  echo "[CatRealm] Installing dependencies..."
  npm install --omit=dev
fi

echo "[CatRealm] Starting server..."
exec node src/index.js
