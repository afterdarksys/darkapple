# Darkapple future work

This is the development plan after the initial 0.1.0 implementation. Unchecked
items are planned work, not supported capabilities or release commitments.
See [README.md](README.md) for implemented behavior,
[SECURITY.md](SECURITY.md) for trust boundaries, and
[local verification](docs/verification.md) for the qualification record.

## P0 — Qualify the current agent before fleet deployment

- [ ] Obtain and validate the Endpoint Security provisioning profile; exercise
  the Developer ID signing, notarization and stapling workflow.
  **Done when:** a distribution-signed installation receives real exec/fork/exit
  events with SIP enabled, and permission denial/revocation produces accurate
  coverage status without stopping polling.
- [ ] Qualify Intel and Apple Silicon on the supported macOS versions. Establish
  a version matrix and automated Rust, Swift, package and integration checks.
  **Done when:** each claimed target has retained build and runtime results;
  untested combinations are explicitly identified.
- [ ] Implement and deploy the receiving darkapi routes with the API project.
  Include the Darkapple signal route, Darksignal heartbeat field, scoped
  credentials, tenant/host authorization, idempotency and retention policy.
  **Done when:** a staged Mac's signal can be retrieved by the authorized
  operator, cross-tenant access is rejected, and retries do not duplicate it.
- [ ] Implement server-side alerts for expected producers that never report,
  become silent, lose coverage or repeatedly encounter full queues.
  **Done when:** terminating Darkapple while leaving Darksignal running raises
  an alert; terminating both is detected separately through engine silence.
- [ ] Test installation, upgrade, rollback and uninstall on clean Macs, including
  SMAppService approval, Full Disk Access/MDM provisioning and root-owned files.
  **Done when:** upgrade preserves state and identity; uninstall behavior for
  retained evidence and the shared Darksignal service is documented and tested.

## P1 — Delivery, lifecycle and evidence reliability

- [ ] Restart failed or stalled Endpoint Security helpers with bounded backoff;
  handle permission changes without requiring a manual daemon restart.
- [x] Darksignal acknowledgement distinguishes retryable (`0x02`) from
  permanent (`0x00`) failure; Darkapple keeps refused evidence visibly in the
  journal (`refused` state and counters). `ship` stops at the first refusal;
  `requeue-refused` (named event IDs or `--all`) is the operator recovery.
- [ ] Exercise disk-full, database corruption, abrupt power loss, clock jumps,
  prolonged outages, event bursts and sustained workloads. Set measured CPU,
  memory, disk and recovery targets before claiming fleet capacity.
- [ ] Add consistent evidence export with a manifest and documented retention.
  Distinguish evidence eviction, expired history and actual collection loss.
- [ ] Review baseline eviction and reset behavior. Preserve directory-baseline
  meaning across capacity pressure and make intentional rebaselining explicit.
- [ ] Add authenticated off-host evidence retention with nocve-store, using an
  explicitly versioned macOS schema and its chain/heartbeat protocol. Do not
  equate Darksignal signal shipment with raw evidence archival.
- [ ] Add an AfterCVE collection adapter for Darkapple coverage, observations
  and outbox metadata, preserving source IDs and acquisition provenance.

**Acceptance:** recovery and loss scenarios have repeatable fault-injection
coverage; no queue or coverage error is presented as successful delivery or a
clean host.

## P2 — Expand native macOS visibility

- [ ] Evaluate moving the Endpoint Security helper into a native system
  extension, including activation, replacement and MDM lifecycle handling.
- [ ] Add selected Endpoint Security filesystem, authentication and persistence
  events with OS-version checks, privacy limits and per-source coverage.
- [ ] Implement a Swift Network Extension for the selected network-flow/DNS
  use case. Validate permitted metadata reporting and provider sandbox rules
  before designing the Rust interface. Test VPN and other-filter coexistence.
- [ ] Add optional Unified Logging collection after verifying its actual access
  and redaction constraints on each supported OS version.
- [ ] Enrich executable observations with validated signing identity and
  notarization-related evidence where supported; distinguish a valid signature
  from a security verdict.
- [ ] Expand per-user launchd coverage, login/background items and persistence
  monitoring. Detect removals only when complete collection supports the claim.
- [ ] Improve Darksignal joins for long and Unicode macOS paths without exposing
  unnecessary personal data or changing existing producer contracts silently.

**Acceptance:** each collector has bounded work, meaningful positive/negative
fixtures, an explicit permission matrix and truthful degraded-coverage behavior.

## P3 — Harden privilege boundaries and detection quality

- [ ] Separate privileged collection from the journal/detection/delivery worker
  where the platform allows it; review root requirements component by component.
- [ ] Authenticate native peers by signing identity when introducing XPC or
  shared IPC. Harden path validation against replacement races; document the
  remaining macOS process-identity limitations.
- [ ] Review the local socket server-authentication boundary and evaluate
  stronger mutual authentication without weakening existing producer checks.
- [ ] Fuzz configuration, observation, native-message and signal parsers;
  schedule an independent security review of unsafe FFI and privilege boundaries.
- [ ] Add rule versioning, tuning and allowlists with auditable configuration.
  Measure false positives from legitimate temporary executables and updates.
- [ ] Evaluate Secure Enclave device keys and remote verification as a separate
  identity protocol, not a replacement for evidence completeness guarantees.

**Acceptance:** documented adversarial cases fail safely; reducing privileges
must not silently reduce coverage; rule tuning preserves evidence provenance.

## P4 — Optional response capabilities

- [ ] Design macOS response actions with cveguard and AfterCVE before implementing
  any process authorization, termination or network isolation.
- [ ] Specify policy approval, action identity, audit records, rollback/deadman
  behavior and failure policy for each proposed action.
- [ ] Keep any Endpoint Security authorization decision local and within Apple's
  deadlines; never wait for Darksignal or a remote API to make that response.

**Acceptance:** an independent design review and explicit operational approval
precede enabling active response. The current release remains observational.

## Maintenance

- [ ] Automate dependency/security checks and reproducible release artifacts.
- [ ] Establish supported release branches, patch policy and a verified private
  vulnerability-reporting channel for the public repository.
- [ ] Keep README, SECURITY, protocol documentation, examples and tests aligned
  whenever a capability or integration contract changes.
