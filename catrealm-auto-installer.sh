#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PRIMARY_SERVER_DIR="$SCRIPT_DIR/CatRealm-SelfHostable-Server"
FALLBACK_SERVER_DIR="$SCRIPT_DIR/CatRealm-SelfHostableServer"
REPO_URL="https://github.com/VanillaChan6571/CatRealm-SelfHostable-Server.git"

SERVER_DIR=""
INSTALLER_DONE_FILE=""
DEPS_DONE_FILE=""
PID_FILE=""
LOG_FILE=""
SCREEN_SESSION=""
NAVIGATE_BACK=0

RED="$(printf '\033[0;31m')"
GREEN="$(printf '\033[0;32m')"
YELLOW="$(printf '\033[1;33m')"
CYAN="$(printf '\033[0;36m')"
DIM="$(printf '\033[2m')"
BOLD="$(printf '\033[1m')"
NC="$(printf '\033[0m')"

CATREALM_ASCII=(
'  ██████╗ █████╗ ████████╗██████╗ ███████╗ █████╗ ██╗     ███╗   ███╗'
' ██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔══██╗██║     ████╗ ████║'
' ██║     ███████║   ██║   ██████╔╝█████╗  ███████║██║     ██╔████╔██║'
' ██║     ██╔══██║   ██║   ██╔══██╗██╔══╝  ██╔══██║██║     ██║╚██╔╝██║'
' ╚██████╗██║  ██║   ██║   ██║  ██║███████╗██║  ██║███████╗██║ ╚═╝ ██║'
'  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝'
)

resolve_server_dir() {
  if [[ -d "$PRIMARY_SERVER_DIR" ]]; then
    SERVER_DIR="$PRIMARY_SERVER_DIR"
  elif [[ -d "$FALLBACK_SERVER_DIR" ]]; then
    SERVER_DIR="$FALLBACK_SERVER_DIR"
  else
    SERVER_DIR="$PRIMARY_SERVER_DIR"
  fi

  INSTALLER_DONE_FILE="$SERVER_DIR/.installer-done"
  DEPS_DONE_FILE="$SERVER_DIR/.installer-deps-done"
  PID_FILE="$SERVER_DIR/.installer-server.pid"
  LOG_FILE="$SERVER_DIR/.installer-server.log"
  SCREEN_SESSION="catrealm-$(basename "$SERVER_DIR" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-')"
}

clear_screen() {
  clear
}

redraw_screen() {
  if command -v tput >/dev/null 2>&1; then
    tput cup 0 0
    tput ed
  else
    printf '\033[H\033[J'
  fi
}

restore_terminal() {
  if command -v tput >/dev/null 2>&1; then
    tput cnorm
  fi
}

handle_interrupt() {
  NAVIGATE_BACK=1
  printf '\n'
}

pause() {
  printf "\nPress Enter to continue..."
  read -r || true
}

load_nvm() {
  if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
    # shellcheck disable=SC1090
    . "$HOME/.nvm/nvm.sh"
    return 0
  fi

  return 1
}

version_gte() {
  local left="$1"
  local right="$2"
  [[ "$(printf '%s\n%s\n' "$right" "$left" | sort -V | tail -n 1)" == "$left" ]]
}

get_glibc_version() {
  local version=""

  if command -v getconf >/dev/null 2>&1; then
    version="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
  fi

  if [[ -z "$version" ]] && command -v ldd >/dev/null 2>&1; then
    version="$(ldd --version 2>/dev/null | head -n 1 | grep -oE '[0-9]+\.[0-9]+' | head -n 1)"
  fi

  printf '%s\n' "$version"
}

activate_node_prefix() {
  local prefix="$1"

  if [[ -d "$prefix/bin" ]]; then
    export PATH="$prefix/bin:$PATH"
    hash -r
    return 0
  fi

  return 1
}

install_glibc217_node() {
  local arch version install_root archive_name archive_path extract_dir

  if ! command -v curl >/dev/null 2>&1; then
    printf "%bcurl is required to install the glibc-compatible Node.js fallback.%b\n" "$RED" "$NC"
    return 1
  fi

  arch="$(uname -m)"
  if [[ "$arch" != "x86_64" ]]; then
    printf "%bAutomatic old-glibc fallback currently supports x86_64 only. Detected: %s%b\n" "$RED" "$arch" "$NC"
    return 1
  fi

  version="$(curl -fsSL https://unofficial-builds.nodejs.org/download/release/index.json | grep -o '"version":"v20\.[^"]*"' | head -n 1 | cut -d'"' -f4)"
  if [[ -z "$version" ]]; then
    printf "%bUnable to determine the latest Node 20 unofficial build.%b\n" "$RED" "$NC"
    return 1
  fi

  install_root="$HOME/.local/catrealm-node-$version-glibc217"
  if activate_node_prefix "$install_root"; then
    return 0
  fi

  archive_name="node-$version-linux-x64-glibc-217.tar.xz"
  archive_path="/tmp/$archive_name"
  extract_dir="/tmp/node-$version-linux-x64-glibc-217"

  mkdir -p "$HOME/.local"
  curl -fsSL "https://unofficial-builds.nodejs.org/download/release/$version/$archive_name" -o "$archive_path"
  rm -rf "$extract_dir" "$install_root"
  tar -xJf "$archive_path" -C /tmp
  mv "$extract_dir" "$install_root"
  rm -f "$archive_path"

  activate_node_prefix "$install_root"
}

ensure_node_runtime() {
  local node_major install_script glibc_version

  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 && node -v >/dev/null 2>&1 && npm -v >/dev/null 2>&1; then
    node_major="$(node -v | sed 's/^v//' | cut -d. -f1)"
    if [[ "$node_major" =~ ^[0-9]+$ ]] && (( node_major >= 20 )); then
      return 0
    fi
  fi

  glibc_version="$(get_glibc_version)"
  if [[ -n "$glibc_version" ]] && ! version_gte "$glibc_version" "2.28"; then
    printf "%bDetected glibc %s. Official Node 20+/24 Linux binaries need glibc 2.28+.%b\n" "$YELLOW" "$glibc_version" "$NC"
    printf "%bInstalling a glibc-compatible Node 20 build for older systems...%b\n\n" "$YELLOW" "$NC"

    install_glibc217_node

    if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 && node -v >/dev/null 2>&1 && npm -v >/dev/null 2>&1; then
      return 0
    fi

    printf "%bFailed to install the glibc-compatible Node.js fallback.%b\n" "$RED" "$NC"
    return 1
  fi

  printf "%bNode.js 20+ with npm is required. Installing Node.js 24...%b\n\n" "$YELLOW" "$NC"

  if load_nvm || command -v nvm >/dev/null 2>&1; then
    load_nvm || true
  else
    if ! command -v curl >/dev/null 2>&1; then
      printf "%bcurl is required to install nvm automatically.%b\n" "$RED" "$NC"
      printf "Install curl, then rerun the installer.\n"
      return 1
    fi

    install_script="$(mktemp)"
    curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh -o "$install_script"
    bash "$install_script"
    rm -f "$install_script"

    if ! load_nvm; then
      printf "%bFailed to load nvm after installation.%b\n" "$RED" "$NC"
      return 1
    fi
  fi

  nvm install 24
  nvm use 24
  nvm alias default 24

  if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1 || ! node -v >/dev/null 2>&1 || ! npm -v >/dev/null 2>&1; then
    printf "%bNode.js installation did not complete successfully.%b\n" "$RED" "$NC"
    return 1
  fi

  return 0
}

ensure_native_build_tools() {
  local missing=0

  for cmd in make gcc g++ python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing=1
      break
    fi
  done

  if (( missing == 0 )); then
    return 0
  fi

  printf "%bNative build tools are required for some npm packages. Installing build prerequisites...%b\n\n" "$YELLOW" "$NC"
  sudo apt update
  sudo apt install -y build-essential python3
}

ensure_theater_media_tools() {
  local missing=0

  for cmd in ffmpeg yt-dlp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing=1
      break
    fi
  done

  if (( missing == 0 )); then
    return 0
  fi

  printf "%bInstalling Theater media tools (ffmpeg, yt-dlp)...%b\n\n" "$YELLOW" "$NC"
  sudo apt update
  sudo apt install -y ffmpeg yt-dlp
}

compiler_supports_cpp20() {
  local compiler="${1:-g++}"
  local test_src test_bin

  if ! command -v "$compiler" >/dev/null 2>&1; then
    return 1
  fi

  test_src="$(mktemp /tmp/catrealm-cxx20-XXXXXX.cpp)"
  test_bin="$(mktemp /tmp/catrealm-cxx20-bin-XXXXXX)"
  printf 'int main() { return 0; }\n' > "$test_src"

  if "$compiler" -std=c++20 "$test_src" -o "$test_bin" >/dev/null 2>&1; then
    rm -f "$test_src" "$test_bin"
    return 0
  fi

  rm -f "$test_src" "$test_bin"
  return 1
}

use_compiler_pair() {
  local gcc_bin="$1"
  local gxx_bin="$2"

  export CC="$gcc_bin"
  export CXX="$gxx_bin"
}

ensure_modern_cpp_compiler() {
  if compiler_supports_cpp20 "${CXX:-g++}"; then
    return 0
  fi

  local candidate
  for candidate in g++-14 g++-13 g++-12 g++-11 g++-10 g++-9; do
    if compiler_supports_cpp20 "$candidate"; then
      use_compiler_pair "${candidate/g++/gcc}" "$candidate"
      return 0
    fi
  done

  printf "%bA C++20-capable compiler is required for better-sqlite3. Installing a newer GCC toolchain...%b\n\n" "$YELLOW" "$NC"

  sudo apt update
  sudo apt install -y software-properties-common

  if ! apt-cache policy g++-10 2>/dev/null | grep -q 'Candidate:' || apt-cache policy g++-10 2>/dev/null | grep -q 'Candidate: (none)'; then
    sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
    sudo apt update
  fi

  sudo apt install -y gcc-10 g++-10
  use_compiler_pair "gcc-10" "g++-10"

  if ! compiler_supports_cpp20 "$CXX"; then
    printf "%bFailed to provision a C++20-capable compiler.%b\n" "$RED" "$NC"
    return 1
  fi
}

ensure_screen() {
  if command -v screen >/dev/null 2>&1; then
    return 0
  fi

  printf "%bInstalling screen for live console support...%b\n\n" "$YELLOW" "$NC"
  sudo apt update
  sudo apt install -y screen
}

ensure_certbot() {
  if command -v certbot >/dev/null 2>&1; then
    return 0
  fi

  printf "%bInstalling certbot...%b\n\n" "$YELLOW" "$NC"
  sudo apt update
  sudo apt install -y certbot
}

slow_println() {
  local text="$1"
  local delay="${2:-0.03}"
  local i char

  for ((i = 0; i < ${#text}; i++)); do
    char="${text:i:1}"
    printf '%s' "$char"
    sleep "$delay"
  done
  printf '\n'
}

show_boot_sequence() {
  clear_screen
  printf "%b" "$CYAN"
  local line
  for line in "${CATREALM_ASCII[@]}"; do
    slow_println "$line" 0.002
    sleep 0.08
  done
  printf "%b" "$NC"
  sleep 0.8
  clear_screen
}

ensure_bootstrap() {
  resolve_server_dir

  if [[ -f "$INSTALLER_DONE_FILE" ]]; then
    return
  fi

  clear_screen
  printf "%bCatRealm bootstrap%b\n\n" "$BOLD$CYAN" "$NC"
  printf "Preparing self-hosted server in %s\n\n" "$SERVER_DIR"

  echo "Running system package refresh..."
  sudo apt update
  sudo apt upgrade -y

  if [[ ! -d "$SERVER_DIR" ]]; then
    echo
    echo "Cloning CatRealm self-hosted server..."
    git clone "$REPO_URL" "$SERVER_DIR"
  else
    echo
    echo "Server directory already exists, skipping clone."
  fi

  if [[ -f "$SERVER_DIR/Start.sh" ]]; then
    chmod +x "$SERVER_DIR/Start.sh"
  fi

  touch "$INSTALLER_DONE_FILE"
  echo
  printf "%bBootstrap complete.%b\n" "$GREEN" "$NC"
  sleep 1
}

is_server_online() {
  local port
  port="$(get_server_port)"

  if lsof -iTCP:"$port" -sTCP:LISTEN -nP 2>/dev/null | awk 'NR > 1 && $1 == "node" { found = 1 } END { exit(found ? 0 : 1) }'; then
    return 0
  fi

  return 1
}

get_running_pid() {
  local port
  port="$(get_server_port)"
  lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null | head -n 1 || true
}

get_server_name() {
  local env_file example_file name
  env_file="$SERVER_DIR/.env"
  example_file="$SERVER_DIR/.env.example"
  name=""

  if [[ -f "$env_file" ]]; then
    name="$(awk -F= '/^SERVER_NAME=/{sub(/^[^=]*=/, ""); print; exit}' "$env_file")"
  fi

  if [[ -z "$name" && -f "$example_file" ]]; then
    name="$(awk -F= '/^SERVER_NAME=/{sub(/^[^=]*=/, ""); print; exit}' "$example_file")"
  fi

  if [[ -z "$name" ]]; then
    name="CatRealm Server"
  fi

  printf '%s\n' "$name"
}

get_server_url() {
  local env_file example_file value
  env_file="$SERVER_DIR/.env"
  example_file="$SERVER_DIR/.env.example"
  value=""

  if [[ -f "$env_file" ]]; then
    value="$(awk -F= '/^SERVER_URL=/{sub(/^[^=]*=/, ""); print; exit}' "$env_file")"
  fi

  if [[ -z "$value" && -f "$example_file" ]]; then
    value="$(awk -F= '/^SERVER_URL=/{sub(/^[^=]*=/, ""); print; exit}' "$example_file")"
  fi

  if [[ -z "$value" ]]; then
    value="http://localhost:$(get_server_port)"
  fi

  printf '%s\n' "$value"
}

get_registration_status() {
  local env_file example_file value
  env_file="$SERVER_DIR/.env"
  example_file="$SERVER_DIR/.env.example"
  value=""

  if [[ -f "$env_file" ]]; then
    value="$(awk -F= '/^REGISTRATION_OPEN=/{sub(/^[^=]*=/, ""); print; exit}' "$env_file" | tr '[:upper:]' '[:lower:]')"
  fi

  if [[ -z "$value" && -f "$example_file" ]]; then
    value="$(awk -F= '/^REGISTRATION_OPEN=/{sub(/^[^=]*=/, ""); print; exit}' "$example_file" | tr '[:upper:]' '[:lower:]')"
  fi

  if [[ "$value" == "false" ]]; then
    printf 'Closed\n'
  else
    printf 'Open\n'
  fi
}

get_pid_uptime() {
  local pid="$1"

  if [[ -z "$pid" ]]; then
    return 0
  fi

  ps -p "$pid" -o etime= 2>/dev/null | xargs || true
}

get_server_port() {
  local env_file example_file port
  env_file="$SERVER_DIR/.env"
  example_file="$SERVER_DIR/.env.example"
  port=""

  if [[ -f "$env_file" ]]; then
    port="$(awk -F= '/^PORT=/{print $2; exit}' "$env_file" | tr -d '[:space:]')"
  fi

  if [[ -z "$port" && -f "$example_file" ]]; then
    port="$(awk -F= '/^PORT=/{print $2; exit}' "$example_file" | tr -d '[:space:]')"
  fi

  if [[ -z "$port" ]]; then
    port="40500"
  fi

  printf '%s\n' "$port"
}

get_db_path() {
  local db_path
  db_path="$(get_env_value "DB_PATH")"

  if [[ -z "$db_path" ]]; then
    db_path="$(get_example_value "DB_PATH")"
  fi

  if [[ -z "$db_path" ]]; then
    db_path="./data/catrealm.db"
  fi

  if [[ "$db_path" != /* ]]; then
    db_path="$SERVER_DIR/${db_path#./}"
  fi

  printf '%s\n' "$db_path"
}

db_already_exists() {
  [[ -f "$(get_db_path)" ]]
}

get_env_value() {
  local key="$1"
  local env_file="${2:-$SERVER_DIR/.env}"

  if [[ ! -f "$env_file" ]]; then
    return 0
  fi

  awk -F= -v search_key="$key" '$1 == search_key {sub(/^[^=]*=/, ""); print; exit}' "$env_file"
}

get_example_value() {
  local key="$1"
  get_env_value "$key" "$SERVER_DIR/.env.example"
}

set_env_value() {
  local key="$1"
  local value="$2"
  local file="$SERVER_DIR/.env"
  local tmp_file

  tmp_file="$(mktemp)"

  if [[ -f "$file" ]]; then
    awk -v search_key="$key" -v replacement="$key=$value" '
      BEGIN { replaced = 0 }
      $0 ~ ("^" search_key "=") {
        if (!replaced) {
          print replacement
          replaced = 1
        }
        next
      }
      { print }
      END {
        if (!replaced) {
          print replacement
        }
      }
    ' "$file" > "$tmp_file"
  else
    printf '%s=%s\n' "$key" "$value" > "$tmp_file"
  fi

  mv "$tmp_file" "$file"
}

unset_env_value() {
  local key="$1"
  local file="$SERVER_DIR/.env"
  local tmp_file

  if [[ ! -f "$file" ]]; then
    return 0
  fi

  tmp_file="$(mktemp)"
  awk -v search_key="$key" '$0 !~ ("^" search_key "=")' "$file" > "$tmp_file"
  mv "$tmp_file" "$file"
}

prompt_env_value() {
  local key="$1"
  local prompt="$2"
  local hint="$3"
  local mode="${4:-required}"
  local current default value

  current="$(get_env_value "$key")"
  default="$(get_example_value "$key")"

  clear_screen
  printf "%bConfigure A Server%b\n\n" "$BOLD$CYAN" "$NC"
  printf "%s\n" "$prompt"
  if [[ -n "$hint" ]]; then
    printf "%b%s%b\n" "$DIM" "$hint" "$NC"
  fi
  if [[ "$key" == "SERVER_NAME" || "$key" == "SERVER_DESCRIPTION" || "$key" == "REGISTRATION_OPEN" || "$key" == "MENTION_ALIAS" ]]; then
    if db_already_exists; then
      printf "%bDatabase already exists at %s. This value may already be stored in server_settings, so changing .env alone may not change the live server setting.%b\n" "$YELLOW" "$(get_db_path)" "$NC"
    fi
  fi
  if [[ "$key" == "DB_PATH" ]]; then
    printf "%bChanging DB_PATH to an empty location will create a fresh database there.%b\n" "$YELLOW" "$NC"
  fi
  printf "\nKey: %s\n" "$key"
  if [[ -n "$current" ]]; then
    printf "Current: %s\n" "$current"
  elif [[ -n "$default" ]]; then
    printf "Default: %s\n" "$default"
  fi

  if [[ "$mode" == "optional" ]]; then
    printf "Enter a value, press Enter to keep current/default, or type %bNONE%b to clear it.\n\n" "$BOLD" "$NC"
  else
    printf "Press Enter to keep current/default.\n\n"
  fi

  while true; do
    printf "> "
    IFS= read -r value || {
      if (( NAVIGATE_BACK )); then
        NAVIGATE_BACK=0
        return 130
      fi
      continue
    }

    case "${value,,}" in
      cancel|exit|back)
        return 130
        ;;
    esac

    if [[ -z "$value" ]]; then
      if [[ -n "$current" ]]; then
        value="$current"
      else
        value="$default"
      fi
    fi

    if [[ "$mode" == "optional" && "$value" == "NONE" ]]; then
      unset_env_value "$key"
      return 0
    fi

    if [[ "$mode" == "required" && -z "$value" ]]; then
      printf "%bA value is required for %s.%b\n" "$YELLOW" "$key" "$NC"
      continue
    fi

    if [[ -z "$value" && "$mode" == "optional" ]]; then
      unset_env_value "$key"
    else
      set_env_value "$key" "$value"
    fi
    return 0
  done
}

ensure_env_file() {
  if [[ -f "$SERVER_DIR/.env" ]]; then
    return
  fi

  if [[ -f "$SERVER_DIR/.env.example" ]]; then
    cp "$SERVER_DIR/.env.example" "$SERVER_DIR/.env"
    printf "%bCreated .env from .env.example%b\n" "$GREEN" "$NC"
    printf "%bReview %s before exposing the server publicly.%b\n" "$YELLOW" "$SERVER_DIR/.env" "$NC"
  else
    printf "%bNo .env.example was found. Create %s manually.%b\n" "$RED" "$SERVER_DIR/.env" "$NC"
  fi
}

configure_server() {
  local selected=0 key
  local options=("Basic Config" "Auto SSL" "Back")
  local actions=("configure_server_basic" "configure_server_ssl" "back")

  while true; do
    redraw_screen
    printf "%bConfigure A Server%b\n\n" "$BOLD$CYAN" "$NC"
    printf "Choose a configuration area.\n\n"

    local idx
    for idx in "${!options[@]}"; do
      if [[ "$idx" -eq "$selected" ]]; then
        printf "%b> %s%b\n" "$BOLD$CYAN" "${options[$idx]}" "$NC"
      else
        printf "  %s\n" "${options[$idx]}"
      fi
    done

    IFS= read -rsn1 key || {
      if (( NAVIGATE_BACK )); then
        NAVIGATE_BACK=0
        return
      fi
      continue
    }
    if [[ "$key" == $'\x1b' ]]; then
      IFS= read -rsn1 key || true
      if [[ "$key" == "[" ]]; then
        IFS= read -rsn1 key || true
        case "$key" in
          A)
            selected=$((selected - 1))
            if (( selected < 0 )); then
              selected=$((${#options[@]} - 1))
            fi
            ;;
          B)
            selected=$((selected + 1))
            if (( selected >= ${#options[@]} )); then
              selected=0
            fi
            ;;
        esac
      fi
    elif [[ "$key" == "" || "$key" == $'\n' ]]; then
      case "${actions[$selected]}" in
        configure_server_basic) configure_server_basic ;;
        configure_server_ssl) configure_server_ssl ;;
        back) return ;;
      esac
      selected=0
    fi
  done
}

configure_server_basic() {
  local item key prompt hint mode
  local -a config_items=(
    "PORT|Server port|Port the CatRealm server listens on.|required"
    "SERVER_URL|Server URL|Public URL clients should use to connect, including http:// or https://.|required"
    "SERVER_NAME|Server name|Displayed to users in the CatRealm client.|required"
    "SERVER_DESCRIPTION|Server description|Short description for your realm.|required"
    "REGISTRATION_OPEN|Registration open|Use true to allow signups or false for invite-only.|required"
    "DB_PATH|Database path|SQLite database file path.|required"
    "CLIENT_URL|Client URL|Use * for open access or set your web/client origin.|required"
    "UPLOADS_DIR|Uploads directory|Path for general uploads.|required"
    "UGC_IMAGES_DIR|UGC images directory|Path for uploaded image assets.|required"
    "DEFAULT_AVATAR_URL|Default avatar URL|Optional URL for new user avatars.|optional"
    "SERVER_MODE|Server mode|Optional: decentral_only, mixed, or central_only.|optional"
    "MEDIA_MAX_MB|Media upload limit (MB)|Optional overall media upload limit in megabytes.|optional"
    "COMPRESS_MEDIA|Compress media|Optional: 1 to enable compression, 0 to disable.|optional"
    "LEVEL_OF_COMPRESSION|Compression level|Optional 0-9. Higher means more compression and more CPU.|optional"
    "AVATAR_MAX_MB|Avatar upload limit (MB)|Optional avatar upload limit in megabytes.|optional"
    "MAX_PINS|Max pins|Optional maximum pinned messages per channel/thread.|optional"
    "MENTION_ALIAS|Mention alias|Optional alias for global mention behavior.|optional"
  )

  clear_screen
  resolve_server_dir
  ensure_env_file

  if ! db_already_exists; then
    prompt_env_value "SECURE_MODE" "Secure mode" "Use 1 to keep message-at-rest secure mode enabled and locked, or 0 to disable." "required" || return 0
  fi

  for item in "${config_items[@]}"; do
    IFS='|' read -r key prompt hint mode <<< "$item"
    prompt_env_value "$key" "$prompt" "$hint" "$mode" || return 0
  done

  clear_screen
  printf "%bServer configuration updated.%b\n" "$GREEN" "$NC"
  if is_server_online; then
    printf "Restart the server to apply changed environment settings.\n"
  fi
  pause
}

configure_server_ssl() {
  local selected=0 key
  local options=("Use Certbot" "Cloudflare DNS Challenge" "Clear SSL Config" "Back")
  local actions=("configure_ssl_certbot" "configure_ssl_cloudflare" "clear_ssl_config" "back")

  while true; do
    redraw_screen
    printf "%bAuto SSL%b\n\n" "$BOLD$CYAN" "$NC"
    printf "Choose how you want to configure SSL.\n\n"

    local idx
    for idx in "${!options[@]}"; do
      if [[ "$idx" -eq "$selected" ]]; then
        printf "%b> %s%b\n" "$BOLD$CYAN" "${options[$idx]}" "$NC"
      else
        printf "  %s\n" "${options[$idx]}"
      fi
    done

    IFS= read -rsn1 key || {
      if (( NAVIGATE_BACK )); then
        NAVIGATE_BACK=0
        return
      fi
      continue
    }
    if [[ "$key" == $'\x1b' ]]; then
      IFS= read -rsn1 key || true
      if [[ "$key" == "[" ]]; then
        IFS= read -rsn1 key || true
        case "$key" in
          A)
            selected=$((selected - 1))
            if (( selected < 0 )); then
              selected=$((${#options[@]} - 1))
            fi
            ;;
          B)
            selected=$((selected + 1))
            if (( selected >= ${#options[@]} )); then
              selected=0
            fi
            ;;
        esac
      fi
    elif [[ "$key" == "" || "$key" == $'\n' ]]; then
      case "${actions[$selected]}" in
        configure_ssl_certbot) configure_ssl_certbot ;;
        configure_ssl_cloudflare) configure_ssl_cloudflare ;;
        clear_ssl_config) clear_ssl_config ;;
        back) return ;;
      esac
      selected=0
    fi
  done
}

configure_ssl_certbot() {
  local ssl_domain ssl_email cert_path key_path

  clear_screen
  resolve_server_dir
  ensure_env_file
  ensure_certbot

  prompt_env_value "SSL_DOMAIN" "Certbot domain" "Domain name certbot should request a certificate for." "required"
  prompt_env_value "SSL_EMAIL" "Certbot email" "Email address for Let's Encrypt notices." "required"

  ssl_domain="$(get_env_value "SSL_DOMAIN")"
  ssl_email="$(get_env_value "SSL_EMAIL")"
  cert_path="/etc/letsencrypt/live/$ssl_domain/fullchain.pem"
  key_path="/etc/letsencrypt/live/$ssl_domain/privkey.pem"

  clear_screen
  printf "%bCertbot setup%b\n\n" "$BOLD$CYAN" "$NC"
  printf "This will run certbot in standalone mode.\n"
  printf "Requirements:\n"
  printf "  - %s must point to this server\n" "$ssl_domain"
  printf "  - port 80 must be reachable and not blocked\n"
  printf "  - nothing else should be using port 80 during validation\n\n"
  printf "Continue? [y/N]: "

  local confirm
  read -r confirm || {
    if (( NAVIGATE_BACK )); then
      NAVIGATE_BACK=0
    fi
    return
  }
  case "${confirm,,}" in
    cancel|exit|back)
      return
      ;;
  esac
  if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    return
  fi

  sudo certbot certonly --standalone -d "$ssl_domain" -m "$ssl_email" --agree-tos --non-interactive

  set_env_value "SSL_CERT_PATH" "$cert_path"
  set_env_value "SSL_KEY_PATH" "$key_path"
  unset_env_value "SSL_DNS_PROVIDER"
  unset_env_value "SSL_DNS_API_TOKEN"

  clear_screen
  printf "%bCertbot SSL configuration updated.%b\n" "$GREEN" "$NC"
  printf "Cert path: %s\n" "$cert_path"
  printf "Key path: %s\n" "$key_path"
  printf "Restart the server to apply SSL changes.\n"
  pause
}

configure_ssl_cloudflare() {
  clear_screen
  resolve_server_dir
  ensure_env_file

  prompt_env_value "SSL_DOMAIN" "Cloudflare SSL domain" "Domain name CatRealm should request a certificate for." "required" || return 0
  prompt_env_value "SSL_EMAIL" "Cloudflare SSL email" "Email address used for Let's Encrypt registration notices." "required" || return 0
  set_env_value "SSL_DNS_PROVIDER" "cloudflare"
  prompt_env_value "SSL_DNS_API_TOKEN" "Cloudflare API token" "API token used for DNS challenge automation." "required" || return 0
  unset_env_value "SSL_CERT_PATH"
  unset_env_value "SSL_KEY_PATH"

  clear_screen
  printf "%bCloudflare DNS challenge configuration updated.%b\n" "$GREEN" "$NC"
  printf "CatRealm will use its built-in Auto-SSL flow with Cloudflare DNS validation.\n"
  printf "Restart the server to apply SSL changes.\n"
  pause
}

clear_ssl_config() {
  clear_screen
  resolve_server_dir
  ensure_env_file

  unset_env_value "SSL_DOMAIN"
  unset_env_value "SSL_EMAIL"
  unset_env_value "SSL_DNS_PROVIDER"
  unset_env_value "SSL_DNS_API_TOKEN"
  unset_env_value "SSL_CERT_PATH"
  unset_env_value "SSL_KEY_PATH"

  printf "%bSSL configuration cleared.%b\n" "$GREEN" "$NC"
  printf "Restart the server to apply SSL changes.\n"
  pause
}

install_dependencies() {
  clear_screen
  printf "%bCatRealm dependency install%b\n\n" "$BOLD$CYAN" "$NC"

  resolve_server_dir
  ensure_env_file
  ensure_node_runtime
  ensure_native_build_tools
  ensure_theater_media_tools
  ensure_modern_cpp_compiler

  (
    cd "$SERVER_DIR"
    npm install --omit=dev
  )

  touch "$DEPS_DONE_FILE"
  printf "\n%bDependencies installed.%b\n" "$GREEN" "$NC"
  pause
}

start_server() {
  local session_pid node_bin

  clear_screen
  resolve_server_dir

  if [[ ! -f "$DEPS_DONE_FILE" ]]; then
    printf "%bInstall dependencies first.%b\n" "$YELLOW" "$NC"
    pause
    return
  fi

  if is_server_online; then
    printf "%bServer is already online on port %s.%b\n" "$GREEN" "$(get_server_port)" "$NC"
    pause
    return
  fi

  ensure_env_file
  ensure_node_runtime
  ensure_screen
  node_bin="$(command -v node)"

  if [[ -z "$node_bin" ]]; then
    printf "%bNode.js runtime could not be resolved.%b\n" "$RED" "$NC"
    pause
    return
  fi

  (
    cd "$SERVER_DIR"
    : > "$LOG_FILE"
    screen -L -Logfile "$LOG_FILE" -h 5000 -dmS "$SCREEN_SESSION" bash -lc "cd \"$SERVER_DIR\" && exec \"$node_bin\" src/index.js"
  )

  sleep 2

  if is_server_online; then
    session_pid="$(screen -ls | awk '/[[:space:]][0-9]+\.'"$SCREEN_SESSION"'[[:space:]]/ {print $1; exit}' | cut -d. -f1)"
    if [[ -n "$session_pid" ]]; then
      printf '%s\n' "$session_pid" > "$PID_FILE"
    fi
    printf "%bServer started in the background on port %s.%b\n" "$GREEN" "$(get_server_port)" "$NC"
    printf "Log file: %s\n" "$LOG_FILE"
    printf "Live console session: %s\n" "$SCREEN_SESSION"
  else
    printf "%bServer did not come online. Check %s.%b\n" "$RED" "$LOG_FILE" "$NC"
  fi

  pause
}

stop_server() {
  clear_screen
  resolve_server_dir

  if ! is_server_online && ! has_live_console; then
    printf "%bServer is not currently running.%b\n" "$YELLOW" "$NC"
    pause
    return
  fi

  stop_server_if_running

  if is_server_online || has_live_console; then
    printf "%bServer stop requested, but it still appears to be running.%b\n" "$RED" "$NC"
    printf "Check %s for shutdown details.\n" "$LOG_FILE"
  else
    printf "%bServer stopped.%b\n" "$GREEN" "$NC"
  fi

  pause
}

stop_server_if_running() {
  local pid

  if has_live_console; then
    screen -S "$SCREEN_SESSION" -X stuff $'\003'
    sleep 2
    if has_live_console; then
      screen -S "$SCREEN_SESSION" -X quit || true
      sleep 1
    fi
  fi

  pid="$(get_running_pid)"

  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    sleep 2
  fi

  if [[ -f "$PID_FILE" ]]; then
    rm -f "$PID_FILE"
  fi
}

has_live_console() {
  command -v screen >/dev/null 2>&1 && screen -list | grep -Eq "[[:space:]][0-9]+\\.${SCREEN_SESSION}[[:space:]]"
}

view_server() {
  local selected=0 key
  local options=("View Mode" "Console Mode" "Back")
  local actions=("view_server_status" "live_console" "back")

  if ! has_live_console; then
    options=("View Mode" "Back")
    actions=("view_server_status" "back")
  fi

  while true; do
    redraw_screen
    printf "%bCatRealm server view%b\n\n" "$BOLD$CYAN" "$NC"
    printf "Choose how you want to open the server view.\n\n"

    local idx
    for idx in "${!options[@]}"; do
      if [[ "$idx" -eq "$selected" ]]; then
        printf "%b> %s%b\n" "$BOLD$CYAN" "${options[$idx]}" "$NC"
      else
        printf "  %s\n" "${options[$idx]}"
      fi
    done

    IFS= read -rsn1 key || {
      if (( NAVIGATE_BACK )); then
        NAVIGATE_BACK=0
        return
      fi
      continue
    }
    if [[ "$key" == $'\x1b' ]]; then
      IFS= read -rsn1 key || true
      if [[ "$key" == "[" ]]; then
        IFS= read -rsn1 key || true
        case "$key" in
          A)
            selected=$((selected - 1))
            if (( selected < 0 )); then
              selected=$((${#options[@]} - 1))
            fi
            ;;
          B)
            selected=$((selected + 1))
            if (( selected >= ${#options[@]} )); then
              selected=0
            fi
            ;;
        esac
      fi
    elif [[ "$key" == "" || "$key" == $'\n' ]]; then
      case "${actions[$selected]}" in
        view_server_status) view_server_status ;;
        live_console) live_console ;;
        back) return ;;
      esac
      selected=0
    fi
  done
}

view_server_status() {
  local port pid uptime server_name server_url registration_status log_lines live_console_status

  clear_screen
  resolve_server_dir
  port="$(get_server_port)"
  pid="$(get_running_pid)"
  uptime="$(get_pid_uptime "$pid")"
  server_name="$(get_server_name)"
  server_url="$(get_server_url)"
  registration_status="$(get_registration_status)"
  log_lines=20
  if has_live_console; then
    live_console_status="Available"
  else
    live_console_status="Unavailable"
  fi

  printf "%bCatRealm server status%b\n\n" "$BOLD$CYAN" "$NC"
  printf "Server name: %s\n" "$server_name"
  printf "Directory: %s\n" "$SERVER_DIR"
  printf "Port: %s\n" "$port"
  printf "URL: %s\n" "$server_url"
  printf "Registration: %s\n" "$registration_status"
  printf ".env present: %s\n" "$([[ -f "$SERVER_DIR/.env" ]] && printf 'Yes' || printf 'No')"
  printf "Dependencies ready: %s\n" "$([[ -f "$DEPS_DONE_FILE" ]] && printf 'Yes' || printf 'No')"
  printf "node_modules present: %s\n" "$([[ -d "$SERVER_DIR/node_modules" ]] && printf 'Yes' || printf 'No')"
  printf "Log file: %s\n" "$LOG_FILE"
  printf "Live console: %s\n" "$live_console_status"

  if is_server_online; then
    printf "Status: %bONLINE%b\n" "$GREEN" "$NC"
    if [[ -n "$pid" ]]; then
      printf "PID: %s\n" "$pid"
    fi
    if [[ -n "$uptime" ]]; then
      printf "Uptime: %s\n" "$uptime"
    fi
  else
    printf "Status: %bOFFLINE%b\n" "$RED" "$NC"
    if [[ -f "$PID_FILE" ]]; then
      printf "Saved PID file: %s\n" "$PID_FILE"
    fi
  fi

  if [[ -f "$LOG_FILE" ]]; then
    printf "\nRecent log lines (%s):\n" "$log_lines"
    tail -n "$log_lines" "$LOG_FILE" || true
  else
    printf "\nNo log file has been created yet.\n"
  fi

  if has_live_console; then
    printf "\nDetach live console with %bCtrl+A%b then %bD%b.\n" "$BOLD" "$NC" "$BOLD" "$NC"
  fi

  pause
}

live_console() {
  clear_screen
  resolve_server_dir

  if ! has_live_console; then
    printf "%bNo live console session is available for the current server.%b\n" "$YELLOW" "$NC"
    pause
    return
  fi

  printf "%bAttaching to live console...%b\n" "$CYAN" "$NC"
  printf "Detach and return here with %bCtrl+A%b then %bD%b.\n" "$BOLD" "$NC" "$BOLD" "$NC"
  sleep 1

  restore_terminal
  screen -r "$SCREEN_SESSION"

  if command -v tput >/dev/null 2>&1; then
    tput civis
  fi
}

backup_server() {
  local backup_root backup_dir

  clear_screen
  resolve_server_dir
  backup_root="$HOME/CatRealm-backups"
  backup_dir="$backup_root/backup-$(date +%Y%m%d-%H%M%S)"

  mkdir -p "$backup_dir"

  if [[ -f "$SERVER_DIR/.env" ]]; then
    cp "$SERVER_DIR/.env" "$backup_dir/.env"
  fi

  if [[ -d "$SERVER_DIR/data" ]]; then
    cp -a "$SERVER_DIR/data" "$backup_dir/data"
  fi

  printf "%bBackup created at %s%b\n" "$GREEN" "$backup_dir" "$NC"
  pause
}

clone_fresh_server() {
  rm -rf "$SERVER_DIR"
  git clone "$REPO_URL" "$SERVER_DIR"
  chmod +x "$SERVER_DIR/Start.sh"
  resolve_server_dir
}

reinstall_server() {
  local backup_root backup_dir temp_env temp_data

  clear_screen
  resolve_server_dir
  backup_root="$HOME/CatRealm-backups"
  backup_dir="$backup_root/reinstall-$(date +%Y%m%d-%H%M%S)"
  temp_env=""
  temp_data=""

  mkdir -p "$backup_dir"

  if [[ -f "$SERVER_DIR/.env" ]]; then
    cp "$SERVER_DIR/.env" "$backup_dir/.env"
    temp_env="$backup_dir/.env"
  fi

  if [[ -d "$SERVER_DIR/data" ]]; then
    cp -a "$SERVER_DIR/data" "$backup_dir/data"
    temp_data="$backup_dir/data"
  fi

  stop_server_if_running
  clone_fresh_server

  if [[ -n "$temp_env" && -f "$temp_env" ]]; then
    cp "$temp_env" "$SERVER_DIR/.env"
  fi

  if [[ -n "$temp_data" && -d "$temp_data" ]]; then
    cp -a "$temp_data" "$SERVER_DIR/data"
  fi

  rm -f "$DEPS_DONE_FILE"
  install_dependencies
}

nuke_server() {
  clear_screen
  resolve_server_dir

  printf "%bThis will delete the server directory, database, uploads, and .env.%b\n" "$RED" "$NC"
  printf "Type %bNUKE%b to continue: " "$BOLD" "$NC"

  local confirmation
  read -r confirmation

  if [[ "$confirmation" != "NUKE" ]]; then
    printf "\n%bNuke cancelled.%b\n" "$YELLOW" "$NC"
    pause
    return
  fi

  stop_server_if_running
  clone_fresh_server
  rm -f "$INSTALLER_DONE_FILE" "$DEPS_DONE_FILE"
  touch "$INSTALLER_DONE_FILE"
  install_dependencies
}

create_virtual_server() {
  clear_screen
  printf "%bLayered virtual servers are coming soon.%b\n" "$YELLOW" "$NC"
  pause
}

build_menu_options() {
  MENU_LABELS=()
  MENU_ACTIONS=()

  if [[ -f "$DEPS_DONE_FILE" ]]; then
    MENU_LABELS+=("Start Server")
    MENU_ACTIONS+=("start_server")
  else
    MENU_LABELS+=("Install Dependencies")
    MENU_ACTIONS+=("install_dependencies")
  fi

  if is_server_online; then
    MENU_LABELS+=("View A Server")
    MENU_ACTIONS+=("view_server")
    MENU_LABELS+=("Stop Server")
    MENU_ACTIONS+=("stop_server")
  fi

  if [[ -d "$SERVER_DIR" ]]; then
    MENU_LABELS+=("Configure A Server")
    MENU_ACTIONS+=("configure_server")
  fi

  if [[ -f "$DEPS_DONE_FILE" ]]; then
    MENU_LABELS+=("Create A New Virtual Server")
    MENU_ACTIONS+=("create_virtual_server")
    MENU_LABELS+=("Backup Server")
    MENU_ACTIONS+=("backup_server")
    MENU_LABELS+=("Reinstall Server")
    MENU_ACTIONS+=("reinstall_server")
    MENU_LABELS+=("Nuke Server")
    MENU_ACTIONS+=("nuke_server")
  fi

  MENU_LABELS+=("Exit")
  MENU_ACTIONS+=("exit_menu")
}

draw_menu() {
  local selected="$1"
  local port idx line

  redraw_screen
  port="$(get_server_port)"

  printf "%b" "$BOLD$CYAN"
  for line in "${CATREALM_ASCII[@]}"; do
    printf "%s\n" "$line"
  done
  printf "%b" "$NC"
  printf "%b%s%b\n\n" "$DIM" "Use arrow keys to move and Enter to select." "$NC"
  printf "Server directory: %s\n" "$SERVER_DIR"
  printf "Port: %s\n" "$port"

  if is_server_online; then
    printf "Status: %bONLINE%b\n\n" "$GREEN" "$NC"
  else
    printf "Status: %bOFFLINE%b\n\n" "$RED" "$NC"
  fi

  for idx in "${!MENU_LABELS[@]}"; do
    if [[ "$idx" -eq "$selected" ]]; then
      printf "%b> %s%b\n" "$BOLD$CYAN" "${MENU_LABELS[$idx]}" "$NC"
    else
      printf "  %s\n" "${MENU_LABELS[$idx]}"
    fi
  done
}

run_menu() {
  local selected=0 key

  trap restore_terminal EXIT
  trap handle_interrupt INT TERM

  if command -v tput >/dev/null 2>&1; then
    tput civis
  fi

  while true; do
    resolve_server_dir
    build_menu_options
    draw_menu "$selected"

    IFS= read -rsn1 key || {
      if (( NAVIGATE_BACK )); then
        NAVIGATE_BACK=0
        selected=0
        continue
      fi
      continue
    }
    if [[ "$key" == $'\x1b' ]]; then
      IFS= read -rsn1 key || true
      if [[ "$key" == "[" ]]; then
        IFS= read -rsn1 key || true
        case "$key" in
          A)
            selected=$((selected - 1))
            if (( selected < 0 )); then
              selected=$((${#MENU_LABELS[@]} - 1))
            fi
            ;;
          B)
            selected=$((selected + 1))
            if (( selected >= ${#MENU_LABELS[@]} )); then
              selected=0
            fi
            ;;
        esac
      fi
    elif [[ "$key" == "" || "$key" == $'\n' ]]; then
      case "${MENU_ACTIONS[$selected]}" in
        install_dependencies) install_dependencies ;;
        start_server) start_server ;;
        view_server) view_server ;;
        stop_server) stop_server ;;
        configure_server) configure_server ;;
        create_virtual_server) create_virtual_server ;;
        backup_server) backup_server ;;
        reinstall_server) reinstall_server ;;
        nuke_server) nuke_server ;;
        exit_menu)
          clear_screen
          exit 0
          ;;
      esac
      selected=0
    fi
  done
}

main() {
  resolve_server_dir
  ensure_bootstrap
  show_boot_sequence
  run_menu
}

main "$@"
