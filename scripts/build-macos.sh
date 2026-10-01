#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Local development build. No services are registered and no credentials read.
# This script packages the native host architecture only.
if [[ -n "${CARGO_BUILD_TARGET:-}" || -n "${CARGO_TARGET_DIR:-}" ]]; then
  echo "Use the default Cargo target directory for native bundle packaging" >&2; exit 2
fi
arch="$(uname -m)"
mkdir -p build/module-cache
rustup run 1.97.1 cargo build --locked
signal_manifest="${DARKSIGNAL_MANIFEST:-../darksignal/Cargo.toml}"
rustup run 1.97.1 cargo build --locked --manifest-path "$signal_manifest"
signal_dir="$(dirname "$signal_manifest")"
xcrun swiftc -swift-version 5 -module-cache-path build/module-cache -target "$arch-apple-macosx13.0" native/EndpointSensor/main.swift -lEndpointSecurity -o build/EndpointSensor
xcrun swiftc -swift-version 5 -module-cache-path build/module-cache -target "$arch-apple-macosx13.0" -parse-as-library native/App/DarkappleApp.swift -o build/Darkapple
python3 scripts/package-macos.py "${DARKSIGNAL_BINARY:-$signal_dir/target/debug/darksignal}"
