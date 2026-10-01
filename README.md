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
  per-record backoff capped at five minutes. ACK `0x02`, an unknown byte and any
  transport failure retain the original event for retry. ACK `0x00` is a
  permanent refusal: the record moves to the `refused` state, stays in the
  journal as evidence, is counted and logged, and is never resent unless an
  operator runs `requeue-refused`. ACK `0x01` means handled by Darksignal, not
  delivered upstream. See [the protocol](docs/protocol.md#acknowledgement).
- Explicit source coverage and delivery counters in `status.json`. Darksignal
  records authenticated Darkapple health and includes available/degraded/silent/
  unseen status in its heartbeat's `producers.darkapple` entry. Silence
  threshold is 90 seconds.
- First-class `darkapple` Darksignal producer, fixed rule classification, event
  source references, dedupe, standard entity joins and `/v1/darksignal/darkapple`.

## Build and test

Use the pinned rustup toolchain; Homebrew cargo may shadow it.

```sh
rustup run 1.97.1 cargo test --locked
rustup run 1.97.1 cargo clippy --locked --all-targets --all-features -- -D warnings
cargo deny check
bash scripts/test-swift.sh
bash scripts/build-macos.sh
DARKSIGNAL_BINARY=../darksignal/target/debug/darksignal python3 scripts/test-integration.py
python3 scripts/test-integration.py --bundle
python3 scripts/test-live.py
```

The integration test runs the actual binaries against local Unix and HTTP
listeners. It tests wrong-executable and unknown-rule refusal by the real
Darksignal (`0x00`, record kept as `refused`, exit 3, `ship` stops and leaves
the rest pending), `requeue-refused` recovery and its writer-lock refusal while
`run` is active, `0x02`/unknown-byte/
no-byte retention against a scripted socket (exit 2), socket outage/restart,
retained record identity, the `run` health-frame guard, classification,
deduplication and the outgoing HTTP payload. It never uses the configured
production API or its credentials. `scripts/test-swift.sh` typechecks the Swift
sources and runs the helper's output-loss test without Endpoint Security.
CI (`.github/workflows/ci.yml`) runs formatting, Clippy, tests, cargo-deny,
gitleaks and the Swift check on macOS.

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
darkapple requeue-refused --config /absolute/path/config.json --event-id ID [--event-id ID ...]
darkapple requeue-refused --config /absolute/path/config.json --all
```

`check` validates configuration and helper-path trust without collecting,
creating state or sending. `once` collects and journals without shipment.
`run` collects continuously and ships independently. `replay` is an explicit
fixture/import operation, not live evidence; it validates all input before
inserting. `ship` sends up to 32 currently due records in order and stops at
the first one that is not accepted; the later due records stay pending and
unattempted (not sent, attempts and backoff unchanged) and stderr reports how
many. Stopping matters because `ship` sends no health frame and Darksignal
answers `0x00` to a wrong producer executable or uid exactly as to a bad
record: a misconfigured `ship` refuses at most one record per run instead of
the whole queue. Exit 0: every due record was accepted. Exit 3: a record was
permanently refused (`0x00`) and moved to state `refused`. Exit 2: a record was
retained for retry (`0x02` or transport failure), or another error. Records
still in backoff are not attempted; inspect `pending` rather than treating
exit 0 as a drained queue.

`requeue-refused` is the operator recovery for refused records. It moves the
matching `refused` rows back to `pending` with attempts reset and due
immediately, keeping the stored event and its `event_id`, so Darksignal still
deduplicates a record it had already handled. Name records with one or more
`--event-id` (canonical lowercase UUIDs, at most 256), or requeue every refused
row with `--all`; one of the two is required and they cannot be combined. Rows
in any other state are never touched. It runs in one transaction under the
exclusive writer lock, so it refuses (exit 2) while `run`, `ship` or another
writer holds the state directory. It reports the requeued count and the IDs
not requeued (`--json`: `"requeued":N,"not_requeued":[...]` in the envelope) and updates `status.json` (counter
`requeued`). Exit 0: every named ID was requeued (or `--all`). Exit 2: an
event ID was unknown or not in state `refused` (listed on stderr), or an
error.

`status.json` reports `store.pending`, `store.refused` (rows kept as refused
evidence) and counters including `acknowledged`, `refused`, `retried`,
`transport_errors`, `requeued`, `refused_evicted`, `refused_expired`, `lost`, the
`health_*` counters and `worker_failures`. Refused rows are terminal like
completed rows: they expire after `retention_days`, and when the journal is
full the oldest completed row is evicted first, then the oldest refused row.
Both are counted. Pending rows are never evicted. A refusal is usually a
configuration fault (wrong host, uid or executable in Darksignal's producer
config). After fixing it, stop the daemon, requeue the retained evidence with
`darkapple requeue-refused --config PATH --all` (or `--event-id ID` for
specific records) and start it again; do not edit `events.db` by hand.
If the delivery thread fails, `run` records `delivery` coverage as unavailable,
counts `worker_failures` and exits 2.

`status` reads the last published snapshot even while the daemon is running
(it never takes the writer lock) and reports `stale` when `updated_at_ms` is
older than 3 x `interval_seconds`, missing, or that far in the future; a
stopped process cannot update its status. Exit 2 indicates configuration, I/O,
delivery or validation failure, with stderr explaining the reason.

## CLI output and exit codes

Darkapple follows the suite [output contract](docs/output-contract.md). Every
command prints human text by default; `--json` (alias `--format json`, also
accepted before the command) prints exactly one compact JSON line on stdout
that starts with the envelope
`{"schema_version":1,"kind":"darkapple.<command>","tool":"darkapple","tool_version":"0.1.0",...}`
followed by the command's payload. No command is machine-primary. `run` is a
daemon: it writes nothing to stdout and publishes the envelope to
`status.json` instead. Diagnostics (refusal and retry explanations) always go
to stderr as text lines.

| Command | Default | `kind` | Exit codes |
| --- | --- | --- | --- |
| `version` (also `--version`) | human | `darkapple.version` | 0; 2 failure |
| `check` | human | `darkapple.check` | 0; 2 failure |
| `once` | human | `darkapple.once` | 0; 2 failure |
| `run` | daemon (no stdout) | `darkapple.status` in `status.json` | 0 clean shutdown; 2 failure, including a delivery-worker failure |
| `status` | human | `darkapple.status` (+ `stale`, `stale_after_ms`, `age_ms`) | 0; 2 failure (for example no `status.json` yet) |
| `replay` | human | `darkapple.replay` (+ `replayed`) | 0; 2 failure |
| `ship` | human | `darkapple.ship` (+ `tally`) | 0 all due records accepted; 2 retained for retry, or failure; 3 permanently refused |
| `requeue-refused` | human | `darkapple.requeue_refused` | 0 all named IDs requeued (or `--all`); 2 an ID not requeued, or failure |
| `help`, `-h`, `--help` (any command) | human | none | 0 |

Existing payload fields keep their names; `status` keeps
`"schema":"darkapple.status.v1"` as an extra field. A `ship` exit 2/3 and a
`requeue-refused` exit 2 with unrequeued IDs are delivery outcomes, not
errors: the envelope still goes to stdout and the reason to stderr.

Errors: in text mode one stderr line `darkapple: <message>`. With `--json`
every failure, including usage errors, writes one JSON line to stderr and
nothing to stdout:
`{"schema_version":1,"kind":"error","tool":"darkapple","command":"<command or null>","category":"usage|config|io|internal","message":"...","exit_code":2}`.
Control and bidi characters in messages are escaped.

Every failure exits 2. The suite contract assigns 1 to runtime failures and 2
to usage/configuration errors; darkapple's documented and tested 2 for every
failure is kept and not renumbered, as are `ship`'s 2 (retained) and 3
(refused).

Status file: `STATE_DIR/status.json` (0600, written atomically via
`status.tmp` + rename), published by `run` every `interval_seconds` (at most
30) and on shutdown, and by `replay`, `ship` and `requeue-refused` after they
change state. It carries the envelope with `kind` `darkapple.status`, plus
`schema`, `host`, `updated_at_ms`, `store`, `coverage` and `delivery`.

The JSON config rejects unknown fields. Paths must be absolute, without `..`.
Use canonical `/private/tmp` rather than `/tmp` for a local lab. Config must be
owned by the service uid and not group/world writable. State directory is
0700; state files are 0600. The parent directory must exist. Only root or the
service uid may own trusted helper/socket ancestors; writable non-sticky
ancestors are refused. A configured helper must be an executable regular file.

`hidden_dir_allowlist` (optional) lists dot-directory names directly under a
user home (`/Users/<name>/`, never `/Users/Shared`) whose executables do not
raise `macos.process.hidden_executable`. The default is `.bun`, `.cargo`,
`.docker`, `.local`, `.npm`, `.nvm`, `.pyenv`, `.rustup`, `.vscode`. Only the
first hidden component is excused: `~/.cargo/.x/tool` still fires, as do
`/opt/.cache/...`, `/tmp/.x` (temporary-executable rule) and `~/.anything-else`.
Each entry is one component starting with `.` (at most 64 entries of 64
bytes); `[]` disables the exception.

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

Darksignal main already contains the darkapple producer (tool, classifier,
health tracking and the 3-way ack); no patch is needed. Darksignal's existing
nocved, aftercve and cveguard schemas remain supported.

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
