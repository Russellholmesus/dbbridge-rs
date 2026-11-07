#!/usr/bin/env bash
set -euo pipefail

RUST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$RUST_DIR"
cd "$RUST_DIR"

BIN_RS="${BIN_RS:-$RUST_DIR/target/release/dbbridge}"
export BIN_RS
export DBB_TOKEN_TO_HQ="${DBB_TOKEN_TO_HQ:-configuration-check-current}"
export DBB_TOKEN_FROM_PLANT_CURRENT="${DBB_TOKEN_FROM_PLANT_CURRENT:-configuration-check-current}"

step() { printf '\n==> %s\n' "$*"; }

step 'cargo fmt --check'
cargo fmt -- --check

step 'cargo clippy --all-targets -- -D warnings'
cargo clippy --all-targets -- -D warnings

step 'cargo test --all-targets'
cargo test --all-targets

step 'native release build (no default features)'
cargo build --release --no-default-features

step 'native release build (default TLS/H2 features)'
cargo build --release

step 'ensure musl targets are installed'
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  if ! rustup target list --installed | grep -Fxq "$target"; then
    rustup target add "$target"
  fi
done

RUST_LLDDIR="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
if [[ -x "$RUST_LLDDIR/rust-lld" ]]; then
  PATH="$RUST_LLDDIR:$PATH"
  export PATH
fi
command -v rust-lld >/dev/null || { echo 'rust-lld is required for static musl verification' >&2; exit 1; }
command -v readelf >/dev/null || { echo 'readelf is required to verify static musl linkage' >&2; exit 1; }

step 'static release builds for x86_64 and aarch64 musl'
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  case "$target" in
    x86_64-unknown-linux-musl)
      cc_env=CC_x86_64_unknown_linux_musl
      cc=musl-gcc
      ;;
    aarch64-unknown-linux-musl)
      cc_env=CC_aarch64_unknown_linux_musl
      cc=aarch64-linux-gnu-gcc
      ;;
  esac
  command -v "$cc" >/dev/null || { echo "$cc is required to compile target C dependencies" >&2; exit 1; }
  target_dir="$RUST_DIR/target/verify-$target"
  remap="--remap-path-prefix=$RUST_DIR=/usr/src/dbbridge"
  flags="-C linker=rust-lld -C link-self-contained=yes $remap ${RUSTFLAGS:-}"
  env "$cc_env=$cc" CARGO_TARGET_DIR="$target_dir" RUSTFLAGS="$flags" \
    cargo build --release --target "$target"
  binary="$target_dir/$target/release/dbbridge"
  if readelf -l "$binary" 2>/dev/null | grep -q 'INTERP'; then
    echo "dynamic interpreter found in supposed static binary: $binary" >&2
    exit 1
  fi
  if readelf -d "$binary" 2>/dev/null | grep -q '(NEEDED)'; then
    echo "dynamic dependency found in supposed static binary: $binary" >&2
    exit 1
  fi
done

step 'configuration examples: online and offline check-config'
for config_path in "$ROOT"/testdata/configs/*.yaml; do
  "$BIN_RS" check-config --config "$config_path"
done
for config_path in "$ROOT"/testdata/configs/production/peer-*.yaml; do
  "$BIN_RS" check-config --offline --config "$config_path"
done

step 'config-check corpus'
python3 "$RUST_DIR/scripts/config-check.py" --bin "$BIN_RS"

step 'end-to-end matrix'
python3 "$ROOT/e2e/e2e.py"

printf '\nAll Rust verification steps passed.\n'
