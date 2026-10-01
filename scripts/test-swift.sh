#!/bin/bash
# Typechecks the Swift sources and runs the Endpoint Security-free output test.
# No signing, entitlements or services are needed.
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(mktemp -d "${TMPDIR:-/private/tmp}/darkapple-swift.XXXXXX")"
trap 'rm -rf "$out"' EXIT
swiftc=(xcrun swiftc -swift-version 5 -module-cache-path "$out/module-cache")
"${swiftc[@]}" -typecheck native/EndpointSensor/main.swift native/EndpointSensor/Emit.swift
"${swiftc[@]}" -typecheck -parse-as-library native/App/DarkappleApp.swift
"${swiftc[@]}" native/EndpointSensorTests/main.swift native/EndpointSensor/Emit.swift -o "$out/emit-test"
"$out/emit-test" >/dev/null
