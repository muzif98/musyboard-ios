#!/usr/bin/env bash
# Build the WebAssembly module and copy it to dist/.
#
#   ./build-wasm.sh           build and update dist/musyboard_wasm.wasm
#   ./build-wasm.sh --check   build and fail if dist/ differs (changes nothing)
#
# Absolute paths of the build machine (cargo registry, source checkouts) end
# up in panic location strings inside the binary. They are remapped to fixed
# names, so the module reveals nothing about the machine that built it and the
# same toolchain produces the same bytes everywhere.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$(cd "$HERE/../musyboard-core" && pwd)"
REGISTRY="${CARGO_HOME:-$HOME/.cargo}/registry/src"
BUILT="${CARGO_TARGET_DIR:-$HERE/target}/wasm32-unknown-unknown/release/musyboard_wasm.wasm"

export RUSTFLAGS="${RUSTFLAGS:-} \
--remap-path-prefix=$REGISTRY=/registry \
--remap-path-prefix=$CORE=/musyboard-core \
--remap-path-prefix=$HERE=/musyboard-ios"

cd "$HERE"
cargo build --release --target wasm32-unknown-unknown

if [ "${1:-}" = "--check" ]; then
  if cmp -s "$BUILT" dist/musyboard_wasm.wasm; then
    echo "dist/musyboard_wasm.wasm matches the source"
    exit 0
  fi
  echo "dist/musyboard_wasm.wasm is not the binary just built. Run ./build-wasm.sh"
  exit 1
fi

cp "$BUILT" dist/
echo "dist/musyboard_wasm.wasm updated ($(wc -c < dist/musyboard_wasm.wasm) bytes)"
