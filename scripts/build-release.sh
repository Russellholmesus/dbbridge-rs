#!/usr/bin/env bash
set -euo pipefail

RUST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$RUST_DIR"
OUT_DIR="${OUT_DIR:-$RUST_DIR/dist}"

while (($#)); do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || { echo '--output requires a directory' >&2; exit 2; }
      OUT_DIR="$2"
      shift 2
      ;;
    --help|-h)
      cat <<'USAGE'
Usage: build-release.sh [--output DIR]

Build reproducible static Linux/musl release packages for x86_64 and aarch64.
Set SOURCE_DATE_EPOCH to pin archive timestamps and embedded build date.
USAGE
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)"
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
fi
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || { echo 'SOURCE_DATE_EPOCH must be a non-negative integer' >&2; exit 2; }
export SOURCE_DATE_EPOCH

VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)"/\1/p' "$RUST_DIR/Cargo.toml" | head -n 1)"
[[ -n "$VERSION" ]] || { echo 'could not read package version from Cargo.toml' >&2; exit 1; }
COMMIT="$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || true)"
COMMIT="${COMMIT:-unknown}"
BUILD_DATE="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
RUSTC_VERSION="$(rustc --version)"
command -v readelf >/dev/null || { echo 'readelf is required to verify static linkage' >&2; exit 1; }
RUST_LLDDIR="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
if [[ -x "$RUST_LLDDIR/rust-lld" ]]; then
  PATH="$RUST_LLDDIR:$PATH"
  export PATH
fi
command -v rust-lld >/dev/null || { echo 'rust-lld is required for static musl release builds' >&2; exit 1; }

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/dbbridge-release.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT
umask 022
export LC_ALL=C TZ=UTC CARGO_INCREMENTAL=0

for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  case "$target" in
    x86_64-unknown-linux-musl)
      arch=amd64
      cc_env=CC_x86_64_unknown_linux_musl
      cc=musl-gcc
      ;;
    aarch64-unknown-linux-musl)
      arch=arm64
      cc_env=CC_aarch64_unknown_linux_musl
      cc=aarch64-linux-gnu-gcc
      ;;
  esac
  command -v "$cc" >/dev/null || { echo "$cc is required to compile target C dependencies" >&2; exit 1; }
  if ! rustup target list --installed | grep -Fxq "$target"; then
    rustup target add "$target"
  fi

  target_tmp="$TMP_ROOT/$target"
  stage="$target_tmp/package"
  mkdir -p "$stage"
  remap="--remap-path-prefix=$RUST_DIR=/usr/src/dbbridge"
  flags="-C linker=rust-lld -C link-self-contained=yes $remap ${RUSTFLAGS:-}"
  (
    cd "$RUST_DIR"
    env "$cc_env=$cc" \
      CARGO_TARGET_DIR="$target_tmp/cargo-target" \
      RUSTFLAGS="$flags" \
      DBBRIDGE_VERSION="$VERSION" \
      DBBRIDGE_COMMIT="$COMMIT" \
      DBBRIDGE_BUILD_DATE="$BUILD_DATE" \
      cargo build --release --target "$target"
  )

  binary="$target_tmp/cargo-target/$target/release/dbbridge"
  [[ -x "$binary" ]] || { echo "missing build output: $binary" >&2; exit 1; }
  if readelf -l "$binary" 2>/dev/null | grep -q 'INTERP'; then
    echo "dynamic interpreter found in supposed static binary: $binary" >&2
    exit 1
  fi
  if readelf -d "$binary" 2>/dev/null | grep -q '(NEEDED)'; then
    echo "dynamic dependency found in supposed static binary: $binary" >&2
    exit 1
  fi
  if [[ "$target" == x86_64-unknown-linux-musl && "$(uname -m)" == x86_64 ]]; then
    version_output="$("$binary" version)"
    for expected in "dbbridge version $VERSION" "commit: $COMMIT" "built: $BUILD_DATE"; do
      grep -Fq "$expected" <<<"$version_output" || {
        echo "version output is missing '$expected': $version_output" >&2
        exit 1
      }
    done
  fi

  package="$OUT_DIR/dbbridge-$VERSION-linux-$arch"
  cp "$binary" "$package"
  cp "$binary" "$stage/dbbridge"
  cp "$RUST_DIR/README.md" "$RUST_DIR/README.zh-CN.md" "$stage/"
  cp -a "$ROOT/testdata/configs" "$stage/configs"
  cp "$ROOT/LICENSE" "$stage/LICENSE"

  cat >"$stage/BUILD-INFO.txt" <<INFO
DBBridge Rust release build
Version: $VERSION
Commit: $COMMIT
Build date (UTC): $BUILD_DATE
SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH
Rust compiler: $RUSTC_VERSION
Target: $target
Linkage: static musl
INFO
  (cd "$stage" && sha256sum dbbridge > SHA256SUMS)

  archive="$OUT_DIR/dbbridge-$VERSION-linux-$arch.tar.gz"
  tar --sort=name --format=gnu --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 --group=0 --numeric-owner -cf - -C "$stage" . | gzip -n >"$archive"
  printf 'Built %s\n' "$package"
  printf 'Built %s\n' "$archive"
done

cat >"$OUT_DIR/BUILD-INFO.txt" <<INFO
DBBridge Rust release set
Version: $VERSION
Commit: $COMMIT
Build date (UTC): $BUILD_DATE
SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH
Rust compiler: $RUSTC_VERSION
Targets: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl
INFO

(
  cd "$OUT_DIR"
  sha256sum "dbbridge-$VERSION-linux-amd64" "dbbridge-$VERSION-linux-arm64" \
    "dbbridge-$VERSION-linux-amd64.tar.gz" "dbbridge-$VERSION-linux-arm64.tar.gz" \
    BUILD-INFO.txt > SHA256SUMS
)
printf 'Release metadata: %s\n' "$OUT_DIR/BUILD-INFO.txt"
printf 'Checksums: %s\n' "$OUT_DIR/SHA256SUMS"
