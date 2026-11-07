#!/usr/bin/env bash
# DBBridge Rust CI gate. Runs every step, then prints a summary; exit 1 when
# any step failed.
#
#   fmt         cargo fmt -- --check
#   clippy      cargo clippy --all-targets -- -D warnings   (default features)
#   clippy-nd   same with --no-default-features
#   test        cargo test --all-targets (default features)
#   test-nd     cargo test --all-targets --no-default-features
#   release     cargo build --release (BIN_RS for the scripts below)
#   e2e         e2e/e2e.py ws                (quick)
#   config      scripts/config-check.py      (recorded check-config corpus)
#
# env: CI_STEPS="fmt clippy ..." to run a subset; CARGO_TARGET_DIR / CI_TARGET_ND (target dir
# for no-default-features, default "$CARGO_TARGET_DIR-nd" or target-nd);
# JOBS (cargo -j, default 2). Tests run with HOME/TMPDIR from CI_HOME/CI_TMP
# (default $HOME and /tmp).
set -uo pipefail

RUST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$RUST_DIR"
cd "$RUST_DIR"

JOBS="${JOBS:-2}"
TARGET="${CARGO_TARGET_DIR:-$RUST_DIR/target}"
TARGET_ND="${CI_TARGET_ND:-${TARGET}-nd}"
export BIN_RS="${BIN_RS:-$TARGET/release/dbbridge}"
export CFG_DIR="${CFG_DIR:-$ROOT/e2e/configs}"
CI_HOME="${CI_HOME:-$HOME}"
CI_TMP="${CI_TMP:-/tmp}"
STEPS="${CI_STEPS:-fmt clippy clippy-nd test test-nd release e2e config}"

RESULTS=()
FAILURES=0
run_step() {
  local label="$1"
  shift
  printf '\n==> %s\n' "$label"
  local t0=$SECONDS
  if "$@"; then
    RESULTS+=("PASS  $label ($((SECONDS - t0))s)")
  else
    local rc=$?
    RESULTS+=("FAIL  $label (exit $rc, $((SECONDS - t0))s)")
    FAILURES=$((FAILURES + 1))
  fi
}
want() { [[ " $STEPS " == *" $1 "* ]]; }
nd() { CARGO_TARGET_DIR="$TARGET_ND" "$@"; }
tests() { HOME="$CI_HOME" TMPDIR="$CI_TMP" "$@"; }

want fmt && run_step "cargo fmt --check" cargo fmt -- --check
want clippy && run_step "clippy -D warnings (default features)" \
  cargo clippy -j "$JOBS" --all-targets -- -D warnings
want clippy-nd && run_step "clippy -D warnings (--no-default-features)" \
  nd cargo clippy -j "$JOBS" --all-targets --no-default-features -- -D warnings
want test && run_step "cargo test (default features)" \
  tests cargo test -j "$JOBS" --all-targets
want test-nd && run_step "cargo test (--no-default-features)" \
  tests nd cargo test -j "$JOBS" --all-targets --no-default-features
want release && run_step "release build" cargo build -j "$JOBS" --release
want e2e && run_step "e2e quick (rs:rs ws)" python3 "$ROOT/e2e/e2e.py" ws
want config && run_step "config-check" python3 "$RUST_DIR/scripts/config-check.py" --bin "$BIN_RS"

printf '\n===== CI summary =====\n'
for result in "${RESULTS[@]}"; do
  printf '%s\n' "$result"
done
printf '%d/%d steps passed\n' "$(( ${#RESULTS[@]} - FAILURES ))" "${#RESULTS[@]}"
(( FAILURES == 0 ))
