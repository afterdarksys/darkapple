# Local verification — 2026-10-01

Validated on this Intel macOS development host with the repository's Rust
1.97.1 toolchain and Xcode 26.3 / Swift 6.2.4 (Swift 5 language mode).

| Check | Result |
| --- | --- |
| Darkapple Rust tests | 9 passed |
| Darksignal Rust tests including existing producers | 84 passed |
| Darkapple and Darksignal Clippy, all targets, warnings denied | Passed |
| Rust formatting | Passed |
| Swift Endpoint Security executable build | Passed |
| SwiftUI application build, warnings denied | Passed |
| Actual executable -> authenticated Darksignal -> local HTTP receiver | Passed |
| Wrong executable copy refused | Passed |
| Socket outage/restart retains original event identity | Passed |
| ACK/commit crash simulation does not duplicate Darksignal record | Passed |
| Live read-only collection with delivery unavailable | Passed |
| Swift helper without entitlements reports unavailable | Passed |
| Graceful daemon shutdown | Passed |
| Launchd property list validation | Passed |
| Development app bundle deep/strict ad-hoc signature verification | Passed |

The live test observed process/launchd partial coverage and available posture
checks. Partial means incomplete collection, not a clean host. Test state was
disposable; no services were installed or registered.

Not qualified: Apple Silicon runtime; Developer ID provisioning/notarization;
live entitled Endpoint Security delivery; Full Disk Access/MDM enrollment;
production darkapi acceptance; sustained fleet load. Network Extension is not
part of this implementation. The ad-hoc development bundle is not a production
release.

Darksignal's modified source files were compared byte-for-byte with the tested
staging sources, and the sibling repository was built after patch application.
The patch is retained at `integration/darksignal.patch`. It applies to the
pre-change Darksignal checkout, not to the already modified sibling tree.
