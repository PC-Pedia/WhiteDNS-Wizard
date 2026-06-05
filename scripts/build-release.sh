#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-"$ROOT_DIR/dist"}"
TARGETS_FILE="${TARGETS_FILE:-"$ROOT_DIR/scripts/release-targets.txt"}"
VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo none)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
PACKAGE="github.com/whitedns/wdns-wizard/internal/cli"
CGO_ENABLED="${CGO_ENABLED:-0}"

mkdir -p "$DIST_DIR"
rm -rf "$DIST_DIR"/whitedns_* "$DIST_DIR"/checksums.txt

ldflags="-s -w -X ${PACKAGE}.version=${VERSION} -X ${PACKAGE}.commit=${COMMIT} -X ${PACKAGE}.date=${BUILD_DATE}"

echo "Building WhiteDNS ${VERSION} (${COMMIT})"
echo "Output: ${DIST_DIR}"

checksum_file="$DIST_DIR/whitedns_${VERSION}_checksums.txt"
: > "$checksum_file"

while read -r goos goarch goarm label; do
  case "${goos:-}" in
    ""|"#") continue ;;
  esac

  binary="whitedns"
  archive_ext="tar.gz"
  if [[ "$goos" == "windows" ]]; then
    binary="whitedns.exe"
    archive_ext="zip"
  fi

  package_name="whitedns_${VERSION}_${label}"
  staging="$DIST_DIR/$package_name"
  rm -rf "$staging"
  mkdir -p "$staging"

  echo "-> ${label}"
  build_env=(
    "CGO_ENABLED=$CGO_ENABLED"
    "GOOS=$goos"
    "GOARCH=$goarch"
  )
  if [[ "$goarm" != "-" ]]; then
    build_env+=("GOARM=$goarm")
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
done < "$TARGETS_FILE"

(
  cd "$DIST_DIR"
  for artifact in whitedns_"$VERSION"_*.tar.gz whitedns_"$VERSION"_*.zip; do
    [[ -e "$artifact" ]] || continue
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$artifact"
    else
      shasum -a 256 "$artifact"
    fi
  done
) > "$checksum_file"

echo "Checksums: $checksum_file"
echo "Done."
