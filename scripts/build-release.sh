#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-"$ROOT_DIR/dist"}"
TARGETS_FILE="${TARGETS_FILE:-"$ROOT_DIR/scripts/release-targets.txt"}"
VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo none)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
CGO_ENABLED="${CGO_ENABLED:-0}"

mkdir -p "$DIST_DIR"
rm -rf "$DIST_DIR"/whitedns_* "$DIST_DIR"/checksums.txt

echo "Building WhiteDNS ${VERSION} (${COMMIT})"
echo "Output: ${DIST_DIR}"

checksum_file="$DIST_DIR/whitedns_${VERSION}_checksums.txt"

while read -r goos goarch goarm label; do
  case "${goos:-}" in
    ""|"#") continue ;;
  esac

  echo "-> ${label}"
  GOOS="$goos" \
    GOARCH="$goarch" \
    GOARM="$goarm" \
    LABEL="$label" \
    VERSION="$VERSION" \
    COMMIT="$COMMIT" \
    BUILD_DATE="$BUILD_DATE" \
    DIST_DIR="$DIST_DIR" \
    CGO_ENABLED="$CGO_ENABLED" \
    "$ROOT_DIR/scripts/build-target.sh"
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
