#!/usr/bin/env sh
set -eu

REPO="${KEELWAY_REPO:-creova-gif/keelway-mcp-gateway}"
INSTALL_DIR="${KEELWAY_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${KEELWAY_VERSION:-latest}"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS-$ARCH" in
  Darwin-arm64) TARGET="aarch64-apple-darwin" ;;
  Linux-x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
  *)
    echo "Unsupported platform: $OS-$ARCH (use: cargo install --path crates/keelway-cli)" >&2
    exit 1
    ;;
esac

ARCHIVE="keelway-${TARGET}.tar.gz"
if [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fsSL "${BASE_URL}/${ARCHIVE}" -o "${TMP_DIR}/${ARCHIVE}"
curl -fsSL "${BASE_URL}/${ARCHIVE}.sha256" -o "${TMP_DIR}/${ARCHIVE}.sha256"

(cd "$TMP_DIR" && shasum -a 256 -c "${ARCHIVE}.sha256")

mkdir -p "$INSTALL_DIR"
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "$INSTALL_DIR"
chmod +x "${INSTALL_DIR}/keelway"

echo "Installed keelway to ${INSTALL_DIR}/keelway"
