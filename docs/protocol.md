# Darkapple / Darksignal protocol v1

One AF_UNIX connection per frame. Four-byte little-endian JSON length, at most
65,536 bytes, then an envelope with `v:1`, `tool:"darkapple"`, configured `host`,
`sent_at_ms`, and `body`. Darksignal authenticates the actual connecting Rust
executable and uid. The Swift helper never connects to Darksignal.

Event body example:

```json
{"schema":"darkapple.event.v1","event_id":"00000000-0000-4000-8000-000000000001","observed_at_ms":1780000000000,"source":"process","kind":"process.observed","rule_id":"macos.process.hidden_executable","severity":"medium","summary":"Process executable in hidden directory","pid":4242,"exe":"/opt/.cache/example"}
```

Optional subject fields are `pid`, `exe`, `path`. Unknown rules, invalid IDs,
incorrect severity, invalid timestamps or invalid paths are refused. Class is
chosen by Darksignal, not supplied by the client. Paths are bounded to 4096
bytes; the existing Darksignal join format only retains printable ASCII tokens
up to 256 bytes, so longer/Unicode paths remain in local evidence but may have
no upstream path join.

| Rule | Class | Severity |
| --- | --- | --- |
| macos.process.hidden_executable | threat | medium |
| macos.process.temporary_executable | threat | medium |
| macos.persistence.launchd_changed | threat | low |
| macos.posture.sip_disabled | vuln | high |
| macos.posture.gatekeeper_disabled | vuln | medium |
| macos.sensor.events_dropped | breach | high |
| macos.sensor.coverage_degraded | threat | medium |

Heuristics are indicators for investigation, not declarations of compromise.
A changed launchd file can be a legitimate update. Coverage loss is not proof
of an attacker.

Health body is `{"schema":"darkapple.health.v1","observed_at_ms":1780000000000,
"status":"available"}`; status can also be `degraded`. A valid authenticated
health frame refreshes receiver-side health, without producing a threat signal.
The Darksignal heartbeat carries a `producers` map that is present only when a
darkapple producer is configured on that host:
`"producers":{"darkapple":{"last_health_ms":...,"status":...}}`. Status is
`unseen` before the first health frame, `silent` after 90 seconds (or a backward
receiver clock), otherwise `available`/`degraded` as reported. A host without
darkapple configured sends no `producers` key. `unseen` alone does not establish
whether Darkapple was expected on that host. No backend liveness alarm is
implemented by this local change.

## Acknowledgement

The ack is one byte (Darksignal `src/ingest.rs` `Outcome::ack`):

| Byte | Meaning | Darkapple action |
| --- | --- | --- |
| `0x01` ACCEPTED | stored, a duplicate, stored after an eviction, or classified as not a signal (including a health frame) | record `done`; counter `acknowledged` |
| `0x00` REFUSED | permanent, the producer's fault: bad frame or envelope, tool not allowed, host mismatch, classifier error (unknown rule, bad field), peer uid/exe mismatch. Resending the same bytes never succeeds. | record moves to the `refused` state, stays in the journal as evidence and is never resent (unless an operator runs `requeue-refused`); counter `refused`; one stderr line with `event_id` and `rule` only (no body); `ship` stops and exits 3 |
| `0x02` RETRY | transient on Darksignal's side: peer identity unreadable, queue full, SQLite error, socket setup failure | record stays `pending` with per-record backoff (1 s doubling, capped at 5 minutes); counter `retried`; `ship` stops and exits 2 |
| other byte, no byte, I/O error, timeout, missing or untrusted socket | treated exactly like `0x02` | as `0x02`, counter `transport_errors` |

A refused record never blocks other records later: it leaves the outbox, and
in the `run` loop only a transient failure stops the current batch. The
exception is the health frame, sent first in each `run` batch: its body is
always valid, so a refusal of it means the envelope or producer identity is
refused (wrong host, uid or executable). That batch's events are then left
pending and unattempted rather than refused one by one. A health ack is only
counted (`health_acknowledged`, `health_refused`, `health_retried`,
`health_transport_errors`); health frames are regenerated and never resent, and
a refused one is also logged.

`ship` sends no health frame, so it cannot tell a bad record from a refused
producer identity. It therefore stops at the first ack other than `0x01`
(refusal or transient failure): the later due records stay pending and
unattempted, with attempts and backoff unchanged. A `ship` run by a
misconfigured or wrong executable refuses at most one record.

Recovery: after fixing the cause, `darkapple requeue-refused --config PATH
--event-id ID ...` or `--all` moves `refused` rows back to `pending` (attempts
0, due now) in one transaction under the writer lock, keeping the stored body
and `event_id`. A record Darksignal had already handled is deduplicated on
resend. Requeues are counted (`requeued`).

A body whose frame would exceed 64 KiB can never be accepted and is refused
locally without connecting. After an ack, a crash before the local commit
replays the identical event. Darksignal includes event_id in dedupe and exposes
`source_ref:{kind:"darkapple.event",id}`.

Swift -> Rust uses bounded JSONL on a private child stdout pipe. Messages are
`{type:"event",observation:{...}}` or `{type:"health",status,detail}`. No public
sensor ingress socket exists. The reader caps line size at 65,536 bytes and its
queue at 1,024 messages; the Swift writer caps outstanding writes at 512. Loss
is explicitly counted. An ES record's borrowed pointers never cross the
callback boundary. No argv, environment, file bytes or network payloads are
included.
