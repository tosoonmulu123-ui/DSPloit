//
//  DaemonDisableView.swift
//  DSPloit
//
//  Disable/enable system daemons via /var/db/com.apple.xpc.launchd/disabled.plist
//  Auto: read existing plist → add/remove keys → write back as binary plist
//

import SwiftUI

struct DaemonDisableView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var daemons: [DaemonEntry] = []
    @State private var isLoading = false
    @State private var customDaemon = ""
    @State private var statusMessage = ""
    @State private var showCustomAdd = false
    
    private let plistPath = "/var/db/com.apple.xpc.launchd/disabled.plist"
    
    struct DaemonEntry: Identifiable {
        let id = UUID()
        let name: String
        var disabled: Bool
        let category: String
    }
    
    // Common daemons people want to disable
    private let knownDaemons: [(String, String, String)] = [
        ("com.apple.thermalmonitord", "Thermal Monitor", "Performance"),
        ("com.apple.OTAPKIAssetTool", "OTA PKI Updates", "Updates"),
        ("com.apple.mobile.softwareupdated", "Software Update", "Updates"),
        ("com.apple.softwareupdateservicesd", "Update Services", "Updates"),
        ("com.apple.ReportCrash", "Crash Reporter", "Telemetry"),
        ("com.apple.ReportCrash.DirectoryService", "Crash Dir Service", "Telemetry"),
        ("com.apple.diagnosticd", "Diagnostics", "Telemetry"),
        ("com.apple.osanalytics", "OS Analytics", "Telemetry"),
        ("com.apple.symptomsd", "Symptoms", "Telemetry"),
        ("com.apple.tailspind", "Tailspin", "Telemetry"),
        ("com.apple.spindump", "Spindump", "Telemetry"),
        ("com.apple.backboardd.backlight", "Backlight Daemon", "Display"),
        ("com.apple.wifid", "WiFi Daemon", "Network"),
        ("com.apple.bluetoothd", "Bluetooth", "Network"),
        ("com.apple.locationd", "Location Services", "Privacy"),
        ("com.apple.icloud.findmydeviced", "Find My Device", "Privacy"),
        ("com.apple.itunescloudd", "iTunes Cloud", "iCloud"),
        ("com.apple.cloudd", "Cloud Daemon", "iCloud"),
    ]
    
    var body: some View {
        List {
            // Status
            Section {
                HStack(spacing: 12) {
                    Image(systemName: mgr.rcready ? "checkmark.circle.fill" : "xmark.circle")
                        .foregroundStyle(mgr.rcready ? .green : .red)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Root Access")
                            .font(.subheadline.bold())
                        Text(mgr.rcready ? "Ready — can modify daemon plist" : "Run Jailbreak first")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Reload") { loadDisabledPlist() }
                        .font(.caption.bold())
                        .buttonStyle(.bordered)
                        .disabled(!mgr.rcready || isLoading)
                }
                
                if !statusMessage.isEmpty {
                    Text(statusMessage)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(statusMessage.contains("✅") ? .green : (statusMessage.contains("❌") ? .red : .secondary))
                }
            } header: {
                Label("Daemon Control", systemImage: "gearshape.2")
            } footer: {
                Text("Disabling daemons takes effect after respring/reboot. Be careful — disabling critical daemons can cause boot loops.")
            }
            
            // Add custom
            Section {
                HStack {
                    TextField("com.apple.daemon.name", text: $customDaemon)
                        .font(.system(size: 13, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("Disable") {
                        addDaemon(customDaemon, disabled: true)
                    }
                    .font(.caption.bold())
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                    .disabled(customDaemon.isEmpty || !mgr.rcready)
                }
            } header: {
                Label("Custom Daemon", systemImage: "plus.circle")
            }
            
            // Daemon list by category
            let categories = Dictionary(grouping: daemons, by: { $0.category })
            ForEach(categories.keys.sorted(), id: \.self) { category in
                Section(category) {
                    ForEach(categories[category] ?? []) { daemon in
                        daemonRow(daemon)
                    }
                }
            }
            
            // Known daemons not yet in list
            let existingNames = Set(daemons.map { $0.name })
            let available = knownDaemons.filter { !existingNames.contains($0.0) }
            if !available.isEmpty {
                Section {
                    ForEach(available, id: \.0) { name, label, category in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(label)
                                    .font(.subheadline)
                                Text(name)
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Disable") {
                                addDaemon(name, disabled: true)
                            }
                            .font(.caption.bold())
                            .buttonStyle(.bordered)
                            .tint(.red)
                            .disabled(!mgr.rcready)
                        }
                    }
                } header: {
                    Label("Available Daemons", systemImage: "list.bullet")
                }
            }
        }
        .navigationTitle("Daemon Control")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            if mgr.rcready { loadDisabledPlist() }
        }
    }
    
    private func daemonRow(_ daemon: DaemonEntry) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(daemon.name)
                    .font(.system(size: 12, design: .monospaced))
                Text(daemon.disabled ? "Disabled" : "Enabled")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(daemon.disabled ? .red : .green)
            }
            Spacer()
            Button(daemon.disabled ? "Enable" : "Disable") {
                toggleDaemon(daemon.name, disable: !daemon.disabled)
            }
            .font(.caption.bold())
            .buttonStyle(.bordered)
            .tint(daemon.disabled ? .green : .red)
            .disabled(!mgr.rcready)
        }
    }
    
    // MARK: - Actions
    
    private func loadDisabledPlist() {
        isLoading = true
        statusMessage = "Reading plist..."
        
        #if !DISABLE_REMOTECALL
        root.readFileAsRoot(path: plistPath, maxSize: 8192) { data in
            isLoading = false
            guard let data = data else {
                statusMessage = "⚠️ Plist not found or empty — will create new"
                daemons = []
                return
            }
            
            // Parse binary or XML plist
            guard let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Bool] else {
                statusMessage = "⚠️ Could not parse plist (\(data.count) bytes)"
                daemons = []
                return
            }
            
            daemons = plist.map { key, value in
                let category = knownDaemons.first(where: { $0.0 == key })?.2 ?? "Other"
                return DaemonEntry(name: key, disabled: value, category: category)
            }.sorted { $0.name < $1.name }
            
            statusMessage = "✅ Loaded \(daemons.count) entries"
        }
        #endif
    }
    
    private func addDaemon(_ name: String, disabled: Bool) {
        guard !name.isEmpty else { return }
        toggleDaemon(name, disable: disabled)
        customDaemon = ""
    }
    
    private func toggleDaemon(_ name: String, disable: Bool) {
        statusMessage = "\(disable ? "Disabling" : "Enabling") \(name)..."
        
        #if !DISABLE_REMOTECALL
        // Step 1: Read current plist
        root.readFileAsRoot(path: plistPath, maxSize: 8192) { [self] data in
            var dict: [String: Bool] = [:]
            
            if let data = data {
                dict = (try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Bool]) ?? [:]
            }
            
            // Step 2: Modify
            dict[name] = disable
            
            // Step 3: Serialize to binary plist
            guard let newData = try? PropertyListSerialization.data(
                fromPropertyList: dict,
                format: .binary,
                options: 0
            ) else {
                statusMessage = "❌ Failed to serialize plist"
                return
            }
            
            // Step 4: Remove immutable flag + write
            root.executeAsRoot(operation: "daemon_toggle") { rc in
                let pathAddr = remote_alloc_str(rc, self.plistPath)
                
                // chflags(path, 0) — remove immutable/system flags
                RootExecutor.rcall(rc, "chflags", pathAddr, 0)
                
                // chmod 644
                RootExecutor.rcall(rc, "chmod", pathAddr, 0o644)
                
                RootExecutor.rcall(rc, "free", pathAddr)
                return (true, "flags cleared", 0)
            }
            
            // Step 5: Write the new plist (after flags cleared)
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
                self.root.writeFileAsRoot(path: self.plistPath, content: newData)
                
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                    // Verify
                    self.statusMessage = "✅ \(name) → \(disable ? "DISABLED" : "ENABLED") (respring to apply)"
                    
                    // Update local state
                    if let idx = self.daemons.firstIndex(where: { $0.name == name }) {
                        self.daemons[idx] = DaemonEntry(name: name, disabled: disable, category: self.daemons[idx].category)
                    } else {
                        let category = self.knownDaemons.first(where: { $0.0 == name })?.2 ?? "Custom"
                        self.daemons.append(DaemonEntry(name: name, disabled: disable, category: category))
                    }
                    
                    UINotificationFeedbackGenerator().notificationOccurred(.success)
                }
            }
        }
        #endif
    }
}
