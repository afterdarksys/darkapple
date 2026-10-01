# Darkapple development outline

Status: original development outline. The Rust agent, Swift application and Endpoint Security helper, and Darksignal producer integration are now implemented. See ../README.md for actual coverage, build instructions and remaining deployment requirements. Items below remain design context, not a claim that every future collector is implemented.

## First release boundary

A Rust macOS daemon, supervised by launchd, with a CLI for configuration
validation, one-shot collection, continuous operation and delivery status.
Use the ecosystem's Rust conventions and versioned JSON. Native macOS APIs
and distribution requirements must be verified against Apple documentation
when selecting and implementing the collectors.

Initial collection candidates are process snapshots, launchd persistence
changes and host security posture. Keep source permissions, failed reads,
truncation and polling blind spots visible. A snapshot reports an observation,
not proof of an exec event. Do not infer a process exit from a failed scan or
key process identity by PID alone.

Retain a bounded local observation journal and a separate durable signal
outbox. Avoid command arguments, environment values or arbitrary file content
in outbound summaries. Report capacity losses explicitly. Keep observation
time and delivery time distinct, with stable record IDs across retries.

The first release is observation and reporting. Automated process termination,
host isolation, arbitrary remote commands and privileged remediation are not
part of this milestone.

## Integration work

Run Darksignal alongside Darkapple on the Mac. Register `darkapple` as its own
host-mode producer, bound to the installed binary and service uid. Preserve
the existing IPC envelope/framing and define a versioned Darkapple body.

Proposed body fields: `schema`, `event_id`, `observed_at_ms`, `kind`, `source`,
`rule_id`, `severity`, `summary`, and typed optional subject identifiers.
Define an explicit rule-to-class table rather than trusting a caller-provided
class. Keep original producer identity in every resulting signal.

Before implementation, pin:

- The initial rules and severities, including coverage-loss behavior.
- Entity extraction and event-ID deduplication/source references.
- Refusal handling: bounded retry while retaining the record, with separately
  counted connection errors, refusals and acknowledgements. Exhaustion leaves
  a visible retained failure rather than silently advancing a cursor.
- Local health versus signal traffic. Do not manufacture threat signals from
  normal health messages; add explicit per-producer liveness tracking.
- The darkapi route `/v1/darksignal/darkapple` and its receiver requirements.
  Existing receiver readiness is unverified, so use a local test receiver.

Future nocve-store integration is a separate work item: its authenticated
event/heartbeat chain and event schemas need a deliberate macOS mapping.
The Darksignal socket does not provide raw off-host evidence retention.

## Implementation sequence and exit criteria

1. **Contract and executable skeleton.** Versioned config/body schemas, strict
   validation, framed transport, protected state paths, fixture input and
   status output. Tests cover oversized/malformed frames and stable IDs.
2. **Darksignal producer integration.** Add the producer, class table, joins,
   source references and static ship path in the sibling project. Verify the
   real Darkapple executable against the real macOS peer-credential listener.
   Assert the database row and exact payload at a local HTTP test receiver.
3. **First live source.** Implement bounded process observation and one
   fixture-backed detection. Verify same-PID/new-process handling, partial
   snapshots and timeouts. Document coverage honestly.
4. **Durability.** Journal/outbox recovery, restart replay, duplicate ACK,
   refusal/full queue, unavailable socket, unexpected ACK and storage limits.
   Keep collection independent of slow delivery. Verify counters and retained
   records, including interruption between ACK and local commit.
5. **Persistence and posture.** Add launchd changes and selected posture
   checks, baselines and deterministic rules; avoid treating every legitimate
   change as evidence of compromise. Validate both positive and negative cases.
6. **Operations.** launchd packaging, protected configuration, graceful
   shutdown, health and uninstall instructions. Qualify Intel and Apple Silicon
   independently and record untested targets. Fleet shipment requires the
   actual receiving API and its authorization/idempotency tests.

Native event-stream collection, signed distribution and higher-fidelity
network telemetry can follow once the basic contract and delivery behavior
are proven. Their platform permissions and implementation choices remain open.
