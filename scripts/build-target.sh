#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-"$ROOT_DIR/dist"}"
VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo none)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
PACKAGE="github.com/whitedns/wdns-wizard/internal/cli"
CGO_ENABLED="${CGO_ENABLED:-0}"

: "${GOOS:?GOOS is required}"
: "${GOARCH:?GOARCH is required}"
: "${LABEL:?LABEL is required}"
GOARM="${GOARM:--}"

mkdir -p "$DIST_DIR"

binary="whitedns"
archive_ext="tar.gz"
if [[ "$GOOS" == "windows" ]]; then
  binary="whitedns.exe"
  archive_ext="zip"
fi

package_name="whitedns_${VERSION}_${LABEL}"
staging="$DIST_DIR/$package_name"
rm -rf "$staging"
mkdir -p "$staging"

ldflags="-s -w -X ${PACKAGE}.version=${VERSION} -X ${PACKAGE}.commit=${COMMIT} -X ${PACKAGE}.date=${BUILD_DATE}"

echo "Building WhiteDNS ${VERSION} (${COMMIT}) for ${LABEL}"
build_env=(
  "CGO_ENABLED=$CGO_ENABLED"
  "GOOS=$GOOS"
  "GOARCH=$GOARCH"
)
if [[ "$GOARM" != "-" ]]; then
  build_env+=("GOARM=$GOARM")
fi

(
  cd "$ROOT_DIR"
  env "${build_env[@]}" go build -trimpath -ldflags "$ldflags" -o "$staging/$binary" ./cmd/whitedns
)

cp "$ROOT_DIR/README.md" "$staging/README.md"

(
  cd "$DIST_DIR"
  if [[ "$archive_ext" == "zip" ]]; then
    zip -qr "$package_name.zip" "$package_name"
    rm -rf "$package_name"
  else
    tar -czf "$package_name.tar.gz" "$package_name"
    rm -rf "$package_name"
  fi
)

echo "Built ${DIST_DIR}/${package_name}.${archive_ext}"
