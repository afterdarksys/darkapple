import Foundation
import EndpointSecurity
import Darwin

// No AUTH subscriptions: this sensor never blocks execution or filesystem work.
// Copy only bounded metadata during the callback; never retain borrowed ES pointers.
let writer = DispatchQueue(label: "com.afterdark.darkapple.endpoint-writer")
let slots = DispatchSemaphore(value: 512)
let lossLock = NSLock()
var dropped: UInt64 = 0
func emit(_ object: [String: Any]) {
    guard slots.wait(timeout: .now()) == .success else {
        lossLock.lock(); dropped &+= 1; lossLock.unlock(); return
    }
    writer.async {
        defer { slots.signal() }
        guard var data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]), data.count < 65536 else { return }
        data.append(10)
        do { try FileHandle.standardOutput.write(contentsOf: data) } catch { exit(74) }
    }
}
func now() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
func health(_ status: String, _ detail: String) { emit(["type":"health", "status":status, "detail":detail]) }
func token(_ t: es_string_token_t) -> String {
    String(decoding: UnsafeRawBufferPointer(start: t.data, count: min(t.length,4096)), as: UTF8.self)
}
func loss(_ count: UInt64, _ stamp: Int64) {
    emit(["type":"event", "observation":["source":"endpoint_security", "kind":"sensor.loss", "observed_at_ms":stamp, "start_us":UInt64(max(0,stamp)), "value":String(count)]])
}
if CommandLine.arguments.count != 1 {
    fputs("EndpointSensor takes no arguments; launch through darkappled\n", stderr); exit(64)
}
var client: OpaquePointer?
var lastSequence: UInt64?
let result = es_new_client(&client) { _, pointer in
    let message = pointer.pointee
    let stamp = Int64(message.time.tv_sec) * 1000 + Int64(message.time.tv_nsec / 1_000_000)
    if message.version >= 4 {
        if let previous = lastSequence, message.global_seq_num > previous, message.global_seq_num - previous > 1 {
            loss(message.global_seq_num - previous - 1, stamp)
        }
        lastSequence = message.global_seq_num
    }
    let process: UnsafeMutablePointer<es_process_t>
    let kind: String
    switch message.event_type {
    case ES_EVENT_TYPE_NOTIFY_EXEC: process = message.event.exec.target; kind = "process.exec"
    case ES_EVENT_TYPE_NOTIFY_FORK: process = message.event.fork.child; kind = "process.fork"
    case ES_EVENT_TYPE_NOTIFY_EXIT: process = message.process; kind = "process.exit"
    default: return
    }
    let p = process.pointee
    // audit_token slot 5 is the PID; the token also contains pidversion, but we
    // retain start time as the cross-source process identity in this version.
    var observation: [String: Any] = ["source":"endpoint_security", "kind":kind,
        "observed_at_ms":stamp, "pid":p.audit_token.val.5,
        "exe":token(p.executable.pointee.path), "value":String(message.mach_time)]
    if message.version >= 3 {
        observation["start_us"] = UInt64(max(0,p.start_time.tv_sec)) * 1_000_000 + UInt64(max(0,p.start_time.tv_usec))
    }
    emit(["type":"event", "observation":observation])
}
guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let connected = client else {
    health("unavailable", "es_new_client failed (\(result.rawValue)); entitlement, root and Full Disk Access required")
    writer.sync {}; exit(77)
}
let events = [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT]
let subscribed = events.withUnsafeBufferPointer { es_subscribe(connected, $0.baseAddress!, UInt32($0.count)) }
guard subscribed == ES_RETURN_SUCCESS else {
    health("unavailable", "Endpoint Security subscription failed"); writer.sync {}; es_delete_client(connected); exit(78)
}
health("available", "NOTIFY exec/fork/exit; no authorization or file-event subscriptions")
let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
timer.schedule(deadline: .now() + 15, repeating: 15)
timer.setEventHandler {
    lossLock.lock(); let count = dropped; dropped = 0; lossLock.unlock()
    if count > 0 { loss(count, now()) }
    health("available", "NOTIFY exec/fork/exit")
}
timer.resume()
signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
for source in [term, interrupt] {
    source.setEventHandler { es_delete_client(connected); exit(0) }; source.resume()
}
dispatchMain()
