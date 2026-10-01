import Foundation

// Runs without Endpoint Security: exercises Emit.swift only. Build and run with
// scripts/test-swift.sh. Valid messages go to stdout; the result goes to stderr.
emit(["type": "health", "status": "available", "detail": "ok"])
emit(["type": "event", "observation": ["when": Date()]])            // not JSON-encodable
emit(["type": "event", "value": String(repeating: "a", count: 70_000)]) // over 64 KiB
writer.sync {}
lossLock.lock(); let lost = dropped; let failures = encodeFailures; lossLock.unlock()
guard lost == 2, failures == 2 else {
    fputs("FAIL: dropped=\(lost) encode_failures=\(failures), expected 2 and 2\n", stderr)
    exit(1)
}
fputs("PASS: unencodable and oversized messages are counted as loss\n", stderr)
