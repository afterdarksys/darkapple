# Darkapple

Continuous macOS observation and signal delivery for the After Dark ecosystem.
Rust owns collection, detection, SQLite state and the Darksignal outbox. A Swift
Endpoint Security helper supplies real-time process events when authorized. A
SwiftUI application registers the bundled launch daemons through SMAppService.

Development version 0.1.0. No service is installed by building. The macOS minimum
for the native application is 13. Intel builds are exercised locally; Apple
Silicon runtime qualification is still required.

## Project documentation

- [Future work and release planning](TODO.md)
- [Security model, macOS privileges and ecosystem integration](SECURITY.md)
- [Wire protocol and rule mappings](docs/protocol.md)
- [Local verification and qualification limits](docs/verification.md)

## Implemented

- Native libproc process snapshots with PID plus start-time identity and checks
  around executable lookup. No argv or environment capture.
- Launchd plist content-hash baselines in configured directories. Changes raise
  low-severity signals; additions after a complete directory baseline do too.
  Initial inventory is quiet. No file contents leave the collector. Deletions are not inferred from incomplete scans.
- SIP and Gatekeeper posture checks with fixed executables, bounded output and
  timeouts. Unrecognized output is incomplete coverage, never an assumed pass.
- Swift Endpoint Security `NOTIFY_EXEC`, `NOTIFY_FORK`, `NOTIFY_EXIT` collector,
  copied metadata, bounded asynchronous output, kernel sequence-loss detection
  and heartbeats. No AUTH subscriptions or blocking actions.
- Atomic observation/baseline/outbox commits; owner-only SQLite state; exclusive
  writer lock; stable event IDs across retries. Pending events are not evicted.
  Full capacity counts loss. Completed journal rows can expire or be evicted.
- A separate delivery thread, length-prefixed Unix IPC, bounded I/O, exponential
  per-record backoff capped at five minutes. ACK 0 and transport failure retain
  the original event. ACK 1 means handled by Darksignal, not delivered upstream.
- Explicit source coverage and delivery counters in `status.json`. Darksignal
  records authenticated Darkapple health and includes available/degraded/silent/
  unseen status in its own heartbeat. Silence threshold is 90 seconds.
- First-class `darkapple` Darksignal producer, fixed rule classification, event
  source references, dedupe, standard entity joins and `/v1/darksignal/darkapple`.

## Build and test

Use the pinned rustup toolchain; Homebrew cargo may shadow it.

```sh
rustup run 1.97.1 cargo test --locked
rustup run 1.97.1 cargo clippy --locked --all-targets -- -D warnings
bash scripts/build-macos.sh
DARKSIGNAL_BINARY=../darksignal/target/debug/darksignal python3 scripts/test-integration.py
python3 scripts/test-integration.py --bundle
python3 scripts/test-live.py
```

The integration test runs the actual binaries against local Unix and HTTP
listeners. It tests wrong-executable refusal, socket outage/restart, retained
record identity, classification, deduplication and the outgoing HTTP payload.
It never uses the configured production API or its credentials.

`build/Darkapple.app` is an ad-hoc-signed development bundle. It contains
`darkappled` (the CLI is named `darkapple` outside the app), `darksignal`, the Swift application, the embedded EndpointSensor
app and two daemon property lists. Do not treat ad-hoc signing as an Endpoint
Security entitlement or a distribution signature.

## CLI

```sh
darkapple version
darkapple check --config /absolute/path/config.json
darkapple once --config /absolute/path/config.json
darkapple run --config /absolute/path/config.json
darkapple status --config /absolute/path/config.json
darkapple replay --config /absolute/path/config.json --input fixtures/observations.jsonl
darkapple ship --config /absolute/path/config.json
```

`check` validates configuration and helper-path trust without collecting,
creating state or sending. `once` collects and journals without shipment.
`run` collects continuously and ships independently. `replay` is an explicit
fixture/import operation, not live evidence; it validates all input before
inserting. `ship` attempts up to 32 currently due records; exit 2 means some
attempts failed/refused and were retained. Records still in backoff are not
attempted; inspect `pending` rather than treating exit 0 as a drained queue.

`status` reads the last published snapshot even while the daemon is running.
Always check `updated_at_ms`; a stopped process cannot update its status. Exit
2 indicates configuration, I/O, delivery or validation failure, with stderr
explaining the reason.

The JSON config rejects unknown fields. Paths must be absolute, without `..`.
Use canonical `/private/tmp` rather than `/tmp` for a local lab. Config must be
owned by the service uid and not group/world writable. State directory is
0700; state files are 0600. The parent directory must exist. Only root or the
service uid may own trusted helper/socket ancestors; writable non-sticky
ancestors are refused. A configured helper must be an executable regular file.

See [the example](deploy/config.example.json). Set `endpoint_helper` to `null`
for polling-only operation. Per-user launch agents require explicitly adding
that user's LaunchAgents directory; the default covers only the two system
`/Library` directories. Directory access failures are reported as partial.

## Connect to Darksignal

Use [darksignal.example.json](deploy/darksignal.example.json) with the matching
host name, absolute installed producer path and service uid. Other producers
can remain in the same host-mode config. Socket directory ownership must
match Darksignal's configuration. Both bundled daemons run as root in this
version because Endpoint Security requires it; unprivileged polling is also
supported with a configuration owned by that uid.

The sibling Darksignal change is also retained as
[integration/darksignal.patch](integration/darksignal.patch) for review and
application to compatible checkouts. Do not apply it twice. Darksignal's
existing nocved, aftercve and cveguard schemas remain supported.

No new direct cveguard enforcement or nocve-store event-chain format is
introduced. AfterCVE can investigate the host independently; the local
`events.db` is a standard SQLite artifact with `records`, `baseline` and `meta`
tables. An event's `source_ref.id` identifies its retained `records.event`
JSON event_id. Retention can remove acknowledged evidence, so export evidence
for an investigation before that window expires.

## Packaging and operation

For a production installation, build and sign the bundle, install it with root-owned contents at
`/Applications/Darkapple.app`, and provision root-owned configuration under
`/Library/Application Support/Darkapple`. The examples assume that location.
Create that parent directory before registering; the daemon creates its own
private state child. Create Darksignal's `ipc` directory with mode 0700.
Provision `config.json`, `darksignal.json` and a 0600 `api.key` separately.
Do not overwrite existing fleet credentials during an upgrade.

Open the native application to register Darksignal and Darkapple. Approve the
background services in System Settings when requested. Disabling monitoring
unregisters Darkapple; Darksignal stays registered because it can serve other
producers. To remove it too, unregister its SMAppService or use the matching
launchd service controls, then remove the application. Preserve evidence
before explicitly deleting the state directory.

Endpoint Security requires an Apple-approved provisioning profile, the
`com.apple.developer.endpoint-security.client` entitlement, root, and Full Disk
Access. The helper is packaged as an embedded app-like daemon so a profile can
be attached. Configure its approval according to your deployment/MDM policy.
Missing permission is reported as unavailable; Darkapple continues polling.
A helper that exits is visible in status; restart Darkapple after changing its
permissions in this version.

```sh
SIGNING_IDENTITY='Developer ID Application: YOUR ORGANIZATION (TEAMID)' \
ENDPOINT_PROFILE=/secure/path/endpoint.provisionprofile \
  bash scripts/sign-macos.sh
```

The signing script does not notarize or install. Submit the signed bundle
through your existing notarization process and staple its ticket before
fleet distribution. Apple references:
[ES client requirements](https://developer.apple.com/documentation/endpointsecurity/client),
[daemon provisioning](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement),
[SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice).

Local results and unqualified environments are recorded in [verification.md](docs/verification.md).

## Coverage and trust limits

Polling can miss short-lived processes. Endpoint Security v1 subscribes only
to process events, not filesystem or authentication events. Network Extension,
DNS/flow telemetry, Unified Logging ingestion, Secure Enclave identity,
automated response and native system-extension activation are not implemented.
The Swift helper uses Apple's supported ES client API in an app-wrapped child
process, not an installed system extension.

The journal is bounded local evidence, not a cryptographically authenticated
off-host archive. Root can falsify it. The SQLite allocation cap is 65,536
pages (normally 256 MiB), with a separate configurable row/baseline limit.
Pending events never expire; they can fill the cap during a prolonged outage.
Check counters, coverage and queue size. Deleting state resets baselines and
record IDs. Snapshot detections are emitted on change, not every poll.

The darkapi receiving routes are outside these four sensor repositories and
remain a separate deployment dependency. Local integration uses a test
receiver; a successful test is not proof of production fleet delivery.
