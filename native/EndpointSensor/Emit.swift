import Foundation

// Bounded asynchronous JSONL output to the parent darkapple process.
let writer = DispatchQueue(label: "com.afterdark.darkapple.endpoint-writer")
let slots = DispatchSemaphore(value: 512)
let lossLock = NSLock()
var dropped: UInt64 = 0
var encodeFailures: UInt64 = 0
// Every message that cannot be written is counted: it is reported as a
// sensor.loss event (macos.sensor.events_dropped) and, for encoding failures,
// also as a cumulative count in the health detail. Nothing is dropped silently.
func countLoss(encoding: Bool = false) {
    lossLock.lock(); dropped &+= 1; if encoding { encodeFailures &+= 1 }; lossLock.unlock()
}
func emit(_ object: [String: Any]) {
    guard slots.wait(timeout: .now()) == .success else { countLoss(); return }
    writer.async {
        defer { slots.signal() }
        // isValidJSONObject first: an invalid object raises an Objective-C exception rather than throwing.
        guard JSONSerialization.isValidJSONObject(object) else { countLoss(encoding: true); return }
        var data: Data
        do { data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) } catch { countLoss(encoding: true); return }
        guard data.count < 65536 else { countLoss(encoding: true); return }
        data.append(10)
        do { try FileHandle.standardOutput.write(contentsOf: data) } catch { exit(74) }
    }
}
