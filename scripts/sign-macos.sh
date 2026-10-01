#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${SIGNING_IDENTITY:?Set a Developer ID Application signing identity}"
: "${ENDPOINT_PROFILE:?Set the path to the approved Endpoint Security provisioning profile}"
app=build/Darkapple.app
helper="$app/Contents/Helpers/EndpointSensor.app"
cp "$ENDPOINT_PROFILE" "$helper/Contents/embedded.provisionprofile"
codesign --force --options runtime --timestamp --sign "$SIGNING_IDENTITY" "$app/Contents/MacOS/darkappled"
codesign --force --options runtime --timestamp --sign "$SIGNING_IDENTITY" "$app/Contents/MacOS/darksignal"
codesign --force --options runtime --timestamp --entitlements native/EndpointSensor/entitlements.plist --sign "$SIGNING_IDENTITY" "$helper"
codesign --force --options runtime --timestamp --sign "$SIGNING_IDENTITY" "$app"
codesign --verify --deep --strict "$app"
# Notarization needs the operator's Apple account/keychain profile; see README.
