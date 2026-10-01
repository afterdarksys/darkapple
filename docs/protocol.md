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
Darksignal heartbeat adds `darkapple:{last_health_ms,status}`. Status is `unseen`
before the first health frame, `silent` after 90 seconds (or backward receiver
clock), otherwise available/degraded. `unseen` alone does not establish whether
Darkapple was expected on that host. No backend liveness alarm is implemented
by this local change.

ACK 1: handled locally (queued/deduplicated event or recognized health frame).
ACK 0: refused, including transient capacity/storage failure. Darkapple keeps
ACK-0 records and retries; an unexpected byte/EOF/timeout is a transport failure.
After an ACK, a crash before commit replays the identical event. Darksignal
includes event_id in dedupe and exposes `source_ref:{kind:"darkapple.event",id}`.

Swift -> Rust uses bounded JSONL on a private child stdout pipe. Messages are
`{type:"event",observation:{...}}` or `{type:"health",status,detail}`. No public
sensor ingress socket exists. The reader caps line size at 65,536 bytes and its
queue at 1,024 messages; the Swift writer caps outstanding writes at 512. Loss
is explicitly counted. An ES record's borrowed pointers never cross the
callback boundary. No argv, environment, file bytes or network payloads are
included.
