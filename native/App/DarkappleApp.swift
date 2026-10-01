import SwiftUI
import ServiceManagement

@main
struct DarkappleApp: App {
    var body: some Scene { WindowGroup { ControlView() }.defaultSize(width: 520, height: 280) }
}
struct ControlView: View {
    @State private var serviceStatus = "Checking service registration…"
    @State private var message = ""
    private let service = SMAppService.daemon(plistName: "com.afterdark.darkapple.plist")
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Darkapple").font(.largeTitle)
            Text("Continuous macOS security observations for After Dark.")
            Text(serviceStatus)
            HStack {
                Button("Enable monitoring") {
                    do { let engine = SMAppService.daemon(plistName: "com.afterdark.darksignal.plist"); if engine.status != .enabled { try engine.register() }; if service.status != .enabled { try service.register() }; message = "Approve the background service in System Settings if requested." }
                    catch { message = error.localizedDescription }
                    refresh()
                }
                Button("Disable monitoring") {
                    service.unregister { error in DispatchQueue.main.async {
                        message = error?.localizedDescription ?? "Darkapple unregistered. Darksignal remains registered for other producers."
                        refresh()
                    } }
                }
                Button("System Settings") { SMAppService.openSystemSettingsLoginItems() }
            }
            Text("Real-time Endpoint Security also requires Full Disk Access and an Apple-approved signed sensor. Polling remains available without it.").font(.caption)
            Text(message).font(.caption).textSelection(.enabled)
        }.padding(24).onAppear { refresh() }
    }
    private func refresh() {
        switch service.status {
        case .enabled: serviceStatus = "Background service registered. Use darkapple status for collection and delivery health."
        case .requiresApproval: serviceStatus = "Background service needs approval in System Settings."
        case .notRegistered: serviceStatus = "Background service is not registered."
        case .notFound: serviceStatus = "Background service bundle is missing."
        @unknown default: serviceStatus = "Unknown registration status."
        }
    }
}
