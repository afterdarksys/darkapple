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

The Darksignal integration is now on Darksignal main (commit d573028), so the
former `integration/darksignal.patch` was removed.

## 3-way acknowledgement re-verification — 2026-10-01

Same host and toolchain, Darksignal built from its HEAD d573028.

| Check | Result |
| --- | --- |
| Darkapple Rust tests (`cargo test --locked`) | 18 passed (1 unit, 17 integration) |
| Clippy, all targets and features, warnings denied; rustfmt check | Passed |
| `cargo deny check` | Passed |
| `scripts/test-swift.sh` (typecheck, helper output-loss test) | Passed |
| `scripts/build-macos.sh` with ad-hoc bundle verification | Passed |
| `scripts/test-integration.py` against Darksignal d573028, and `--bundle` | Passed |
| Real Darksignal `0x00` for a wrong executable and an unknown rule: record kept as `refused`, never resent, exit 3, other records unaffected | Passed |
| Scripted `0x02`, unknown byte and no byte: record retained, exit 2 | Passed |
| `run` with a refused health frame leaves events pending and unattempted | Passed |

Each fix was mutation-checked: reverting it made its test fail.

## `ship` stop-on-refusal and `requeue-refused` — 2026-10-01

Same host and toolchain, Darksignal d573028.

| Check | Result |
| --- | --- |
| Darkapple Rust tests (`cargo test --locked`) | 22 passed (1 unit, 21 integration) |
| Clippy, all targets and features, warnings denied; rustfmt check; `cargo deny check` | Passed |
| `scripts/test-swift.sh` | Passed |
| `scripts/test-integration.py` against Darksignal d573028 | Passed |
| Wrong executable `ship` against the real Darksignal: first record refused, the other two pending with attempts unchanged, exit 3 | Passed |
| `requeue-refused --all` then `ship` with the correct executable: all three delivered, one signal per event_id, resend deduplicated | Passed |
| `requeue-refused` without a selector, with a non-refused ID (exit 2), and while `run` holds the writer lock (exit 2) | Passed |
| Unknown-rule refusal stops `ship`; the next record is delivered by the next `ship`, the refused one is never resent | Passed |

Mutation checks: continuing after a refusal, continuing after a retry, not
counting unattempted records, not resetting attempts, requeueing rows in any
state, skipping event-ID validation, not counting `requeued`, accepting
`--all` with `--event-id`, exit 0 for unrequeued IDs, and bypassing the writer
lock each made a test fail.

## CLI output contract — 2026-10-01

Same host and toolchain, Darksignal d573028. See
[the output contract](output-contract.md) and the README section
"CLI output and exit codes".

| Check | Result |
| --- | --- |
| Darkapple Rust tests (`cargo test --locked`) | 27 passed (1 unit, 26 integration; `tests/cli.rs` adds 5) |
| Clippy, all targets and features, warnings denied; rustfmt check; `cargo deny check` | Passed |
| `scripts/test-swift.sh` | Passed |
| `scripts/test-integration.py` against Darksignal d573028 (all calls with `--json`) | Passed |
| `scripts/test-live.py` (status file carries the envelope) | Passed |
| Every subcommand with `--json`, including `run` as a daemon (no stdout, envelope in `status.json`): one line, envelope fields first, documented exit code | Passed |
| JSON errors (usage, config, io): one stderr line with the six fields, empty stdout, exit 2; control and bidi characters escaped | Passed |
| `status --json` while a writer holds the lock; `stale` for old, future and missing `updated_at_ms` | Passed |
| `--help`/`-h`/`help` on the binary and every command: exit 0, every command and its exit codes listed | Passed |

Mutation checks: stdout envelope omitted, `status.json` envelope omitted, JSON
error written to stdout, JSON mode ignored for errors, `schema_version`
dropped from the error, failure exit code 1 instead of 2, `ship` always
exiting 0, and staleness ignoring future/missing timestamps each made a test
fail.
