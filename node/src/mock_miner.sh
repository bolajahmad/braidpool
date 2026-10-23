#!/bin/bash
#
# Build the cpuminer CPU miner (`minerd`) used as a downstream mining device
# for the node's Stratum port on mainnet, testnet4 and signet.
#
# cpuminer cannot mine `cpunet` (different block-header hash). For cpunet use
# https://github.com/braidpool/rust_cpunet_miner instead.
#
# Supported systems:
#   - Debian/Ubuntu (apt)
#   - macOS (Xcode command line tools + Homebrew)
# Any other system: install the tools in REQUIRED_TOOLS below (plus the libcurl
# development files) yourself, then run this script again.
#
# Environment:
#   CPUMINER_DIR  directory to clone and build in
#                 (default: a `cpuminer` directory next to this script)
#
# The built binary is printed at the end: <CPUMINER_DIR>/minerd

set -euo pipefail

REPO_URL="https://github.com/pooler/cpuminer.git"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CPUMINER_DIR="${CPUMINER_DIR:-$SCRIPT_DIR/cpuminer}"
REQUIRED_TOOLS="git automake autoconf make perl cc curl-config"

log() {
  printf '==> %s\n' "$*"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

# Print the tools from REQUIRED_TOOLS that are not on PATH.
missing_tools() {
  local missing="" tool
  for tool in $REQUIRED_TOOLS; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing="$missing $tool"
    fi
  done
  printf '%s' "${missing# }"
}

unsupported_system() {
  die "$1
Install these yourself, then run this script again: $REQUIRED_TOOLS
(curl-config comes with the libcurl development package.)"
}

install_dependencies_linux() {
  local missing
  missing="$(missing_tools)"
  if [ -z "$missing" ]; then
    log "Build tools already installed, skipping package installation"
    return
  fi
  log "Missing build tools: $missing"

  if ! command -v apt-get >/dev/null 2>&1; then
    unsupported_system "No supported package manager found (only apt is handled)."
  fi

  local sudo_cmd=""
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "sudo is required to install packages. Run as root or install sudo."
    sudo_cmd="sudo"
  fi

  log "Installing build dependencies with apt"
  $sudo_cmd apt-get update
  $sudo_cmd apt-get install -y git automake autoconf build-essential libcurl4-openssl-dev
}

# Homebrew's curl is keg-only. It is the only place libcurl.m4 is installed,
# which cpuminer's configure.ac needs (LIBCURL_CHECK_CONFIG). The build links
# against Apple's libcurl.
macos_aclocal_dir() {
  printf '%s/share/aclocal' "$(brew --prefix curl)"
}

install_dependencies_macos() {
  if ! xcode-select -p >/dev/null 2>&1; then
    die "Xcode command line tools are required. Run: xcode-select --install"
  fi
  # Apple ships git, make, perl, cc and libcurl with the command line tools.
  # automake, autoconf and libcurl.m4 come from Homebrew.
  command -v brew >/dev/null 2>&1 || die "Homebrew is required to install automake, autoconf and curl. See https://brew.sh"

  local packages="" tool
  for tool in automake autoconf; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      packages="$packages $tool"
    fi
  done
  if [ ! -f "$(macos_aclocal_dir)/libcurl.m4" ]; then
    packages="$packages curl"
  fi

  if [ -z "$packages" ]; then
    log "Build tools already installed, skipping package installation"
    return
  fi
  log "Installing build dependencies with Homebrew:$packages"
  # shellcheck disable=SC2086 # intentional word splitting of the package list
  brew install $packages
}

install_dependencies() {
  case "$(uname -s)" in
    Linux) install_dependencies_linux ;;
    Darwin) install_dependencies_macos ;;
    *)
      if [ -n "$(missing_tools)" ]; then
        unsupported_system "Unsupported system: $(uname -s). Missing: $(missing_tools)."
      fi
      ;;
  esac

  if [ -n "$(missing_tools)" ]; then
    die "Still missing after installation: $(missing_tools)"
  fi
}

build_cpuminer() {
  if [ -d "$CPUMINER_DIR/.git" ]; then
    log "Using existing checkout in $CPUMINER_DIR"
  elif [ -e "$CPUMINER_DIR" ]; then
    die "$CPUMINER_DIR exists but is not a cpuminer checkout. Remove it or set CPUMINER_DIR."
  else
    log "Cloning cpuminer into $CPUMINER_DIR"
    git clone "$REPO_URL" "$CPUMINER_DIR"
  fi

  cd "$CPUMINER_DIR"
  if [ "$(uname -s)" = "Darwin" ]; then
    # autogen.sh calls a bare `aclocal`, which honors ACLOCAL_PATH.
    export ACLOCAL_PATH="$(macos_aclocal_dir)${ACLOCAL_PATH:+:$ACLOCAL_PATH}"
  fi
  ./autogen.sh
  ./nomacro.pl
  ./configure CFLAGS="-O3"
  make
}

install_dependencies
build_cpuminer

log "Built: $CPUMINER_DIR/minerd"
log "Run it against the node's Stratum port, for example:"
log "  $CPUMINER_DIR/minerd -a sha256d -o stratum+tcp://localhost:3333 -q -D -P"
