//
//  DaemonDisableView.swift
//  DSPloit — Daemon control
//

import SwiftUI

struct DaemonDisableView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var daemons: [DaemonEntry] = []
    @State private var isLoading = false
    @State private var customDaemon = ""
    @State private var statusMessage = ""
    
    private let plistPath = "/var/db/com.apple.xpc.launchd/disabled.plist"
    
    struct DaemonEntry: Identifiable {
        let id = UUID()
        let name: String
        var disabled: Bool
        let category: String
    }
    
    private let knownDaemons: [(String, String, String)] = [
        ("com.apple.thermalmonitord", "Thermal Monitor", "Performance"),
        ("com.apple.OTAPKIAssetTool", "OTA PKI Updates", "Updates"),
        ("com.apple.mobile.softwareupdated", "Software Update", "Updates"),
        ("com.apple.ReportCrash", "Crash Reporter", "Telemetry"),
        ("com.apple.diagnosticd", "Diagnostics", "Telemetry"),
        ("com.apple.osanalytics", "OS Analytics", "Telemetry"),
        ("com.apple.symptomsd", "Symptoms", "Telemetry"),
        ("com.apple.tailspind", "Tailspin", "Telemetry"),
        ("com.apple.locationd", "Location Services", "Privacy"),
        ("com.apple.icloud.findmydeviced", "Find My Device", "Privacy"),
    ]
    
    var body: some View {
        List {
            // Status + reload
            Section {
                HStack {
                    Text(mgr.rcready ? "Ready" : "Need jailbreak")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(mgr.rcready ? .green : .secondary)
                    Spacer()
                    Button("Reload") { loadDisabledPlist() }
                        .font(.system(size: 12, weight: .medium))
                        .disabled(!mgr.rcready || isLoading)
                }
                if !statusMessage.isEmpty {
                    Text(statusMessage)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(statusMessage.contains("✅") ? .green : .secondary)
                }
            }
            
            // Custom add
            Section {
                HStack {
                    TextField("com.apple.daemon", text: $customDaemon)
                        .font(.system(size: 12, design: .monospaced))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("Add") { addDaemon(customDaemon, disabled: true) }
                        .font(.system(size: 12, weight: .semibold))
                        .disabled(customDaemon.isEmpty || !mgr.rcready)
                }
            } header: {
                Text("CUSTOM")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
            }
            
            // Active daemons
            if !daemons.isEmpty {
                let categories = Dictionary(grouping: daemons, by: { $0.category })
                ForEach(categories.keys.sorted(), id: \.self) { cat in
                    Section {
                        ForEach(categories[cat] ?? []) { d in
                            daemonRow(d)
                        }
                    } header: {
                        Text(cat.uppercased())
                            .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    }
                }
            }
            
            // Available (not yet disabled)
            let existing = Set(daemons.map(\.name))
            let available = knownDaemons.filter { !existing.contains($0.0) }
            if !available.isEmpty && !isLoading {
                Section {
                    ForEach(available, id: \.0) { name, label, _ in
                        HStack {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(label).font(.system(size: 13))
                                Text(name).font(.system(size: 9, design: .monospaced)).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Disable") { addDaemon(name, disabled: true) }
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(.red)
                                .disabled(!mgr.rcready)
                        }
                    }
                } header: {
                    Text("AVAILABLE")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Daemons")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { if mgr.rcready { loadDisabledPlist() } }
    }
    
    private func daemonRow(_ d: DaemonEntry) -> some View {
        HStack {
            Text(d.name)
                .font(.system(size: 11, design: .monospaced))
                .lineLimit(1)
            Spacer()
            Text(d.disabled ? "OFF" : "ON")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundStyle(d.disabled ? .red : .green)
            Button(d.disabled ? "Enable" : "Disable") {
                toggleDaemon(d.name, disable: !d.disabled)
            }
            .font(.system(size: 11, weight: .medium))
            .buttonStyle(.bordered)
            .controlSize(.small)
            .tint(d.disabled ? .green : .red)
            .disabled(!mgr.rcready)
        }
    }
    
    // MARK: - Logic
    
    private func loadDisabledPlist() {
        isLoading = true
        statusMessage = "Loading..."
        #if !DISABLE_REMOTECALL
        root.readFileAsRoot(path: plistPath, maxSize: 8192) { data in
            isLoading = false
            guard let data = data,
                  let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Bool] else {
                statusMessage = "Empty or new"
                daemons = []
                return
            }
            daemons = plist.map { k, v in
                DaemonEntry(name: k, disabled: v, category: knownDaemons.first(where: { $0.0 == k })?.2 ?? "Other")
            }.sorted { $0.name < $1.name }
            statusMessage = "✅ \(daemons.count) entries"
        }
        #endif
    }
    
    private func addDaemon(_ name: String, disabled: Bool) {
        guard !name.isEmpty else { return }
        toggleDaemon(name, disable: disabled)
        customDaemon = ""
    }
    
    private func toggleDaemon(_ name: String, disable: Bool) {
        statusMessage = "\(disable ? "Disabling" : "Enabling")..."
        #if !DISABLE_REMOTECALL
        root.readFileAsRoot(path: plistPath, maxSize: 8192) { data in
            var dict: [String: Bool] = [:]
            if let data = data {
                dict = (try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Bool]) ?? [:]
            }
            dict[name] = disable
            guard let newData = try? PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0) else {
                statusMessage = "❌ Serialize failed"
                return
            }
            root.executeAsRoot(operation: "daemon_toggle") { rc in
                let p = remote_alloc_str(rc, self.plistPath)
                RootExecutor.rcall(rc, "chflags", p, 0)
                RootExecutor.rcall(rc, "chmod", p, 0o644)
                RootExecutor.rcall(rc, "free", p)
                return (true, "ok", 0)
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) {
                self.root.writeFileAsRoot(path: self.plistPath, content: newData)
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                    self.statusMessage = "✅ \(name) → \(disable ? "OFF" : "ON") (respring to apply)"
                    if let idx = self.daemons.firstIndex(where: { $0.name == name }) {
                        self.daemons[idx] = DaemonEntry(name: name, disabled: disable, category: self.daemons[idx].category)
                    } else {
                        self.daemons.append(DaemonEntry(name: name, disabled: disable, category: "Custom"))
                    }
                    UINotificationFeedbackGenerator().notificationOccurred(.success)
                }
            }
        }
        #endif
    }
}
