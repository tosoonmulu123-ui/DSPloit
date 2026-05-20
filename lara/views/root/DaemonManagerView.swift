//
//  DaemonManagerView.swift
//  DSPloit
//
//  Daemon Manager — enable/disable iOS system daemons
//  Writes directly to /var/db/com.apple.xpc.launchd/disabled.plist
//  Changes take effect after reboot
//

import SwiftUI

struct DaemonManagerView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var daemonStates: [DaemonEntry] = []
    @State private var isLoading = false
    @State private var statusMessage = ""
    @State private var showApplyConfirm = false
    
    struct DaemonEntry: Identifiable {
        let id = UUID()
        let label: String
        let group: String
        var disabled: Bool
        let safe: Bool  // proven safe to disable
    }
    
    // Safe daemon groups (proven by iOS Daemon Tweaker)
    private let safeDaemons: [(String, String, String)] = [
        // (label, group, description)
        ("com.apple.ReportCrash", "Crash Reports", "Crash reporter"),
        ("com.apple.ReportCrash.Jetsam", "Crash Reports", "Jetsam crash reporter"),
        ("com.apple.DumpPanic", "Crash Reports", "Panic dump"),
        ("com.apple.analyticsd", "Analytics", "Analytics daemon"),
        ("com.apple.OTATaskingAgent", "OTA Updates", "OTA update agent"),
        ("com.apple.mobile.softwareupdated", "OTA Updates", "Software update"),
        ("com.apple.softwareupdateservicesd", "OTA Updates", "Update service"),
        ("com.apple.UsageTrackingAgent", "Tracking", "Usage tracking"),
        ("com.apple.ScreenTimeAgent", "Screen Time", "Screen Time"),
        ("com.apple.osanalytics.osanalyticshelper", "Analytics", "OS analytics"),
        ("com.apple.intelligenceplatformd", "AI", "Apple Intelligence"),
        ("com.apple.photoanalysisd", "AI", "Photo analysis"),
        ("com.apple.siriinferenced", "AI", "Siri inference"),
        ("com.apple.duetactivityschedulerd", "Suggestions", "Duet scheduler"),
        ("com.apple.suggestd", "Suggestions", "Suggestions"),
        ("com.apple.gamed", "Apps", "Game Center"),
        ("com.apple.tipsd", "Apps", "Tips"),
        ("com.apple.thermalmonitord", "Advanced", "Thermal monitor"),
        ("com.apple.spindump", "Diagnostics", "Spindump"),
        ("com.apple.sysdiagnose", "Diagnostics", "Sysdiagnose"),
        ("com.apple.hangtracerd", "Diagnostics", "Hang tracer"),
        ("com.apple.wifianalyticsd", "Analytics", "WiFi analytics"),
        ("com.apple.searchd", "Spotlight", "Spotlight search"),
    ]
    
    var body: some View {
        List {
            // Status
            Section {
                HStack {
                    Image(systemName: "gear.badge")
                        .foregroundStyle(.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Daemon Manager")
                            .font(.subheadline.bold())
                        Text("Changes apply after reboot")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
                
                if !statusMessage.isEmpty {
                    Text(statusMessage)
                        .font(.caption)
                        .foregroundStyle(statusMessage.contains("!") ? .green : .orange)
                }
            }

            // Actions
            Section {
                Button(action: loadCurrentState) {
                    HStack {
                        Label("Read Current State", systemImage: "arrow.down.circle")
                            .foregroundStyle(.blue)
                        Spacer()
                        if isLoading { ProgressView().scaleEffect(0.7) }
                    }
                }
                .disabled(!mgr.rcready || isLoading)
                
                Button(action: { showApplyConfirm = true }) {
                    Label("Apply Changes", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                }
                .disabled(!mgr.rcready || daemonStates.isEmpty)
                
                Button(action: disableAllSafe) {
                    Label("Disable All Safe", systemImage: "bolt.circle")
                        .foregroundStyle(.orange)
                }
                .disabled(daemonStates.isEmpty)
                
                Button(action: enableAll) {
                    Label("Enable All", systemImage: "arrow.uturn.backward")
                        .foregroundStyle(.secondary)
                }
                .disabled(daemonStates.isEmpty)
            } header: {
                Label("Actions", systemImage: "wrench")
            } footer: {
                Text("Only proven-safe daemons shown. Critical system daemons are protected.")
                    .font(.system(size: 9))
            }
            
            // Daemon list
            if !daemonStates.isEmpty {
                let groups = Dictionary(grouping: daemonStates, by: { $0.group })
                ForEach(groups.keys.sorted(), id: \.self) { group in
                    Section {
                        ForEach(groups[group]!.indices, id: \.self) { idx in
                            let daemon = groups[group]![idx]
                            if let stateIdx = daemonStates.firstIndex(where: { $0.label == daemon.label }) {
                                Toggle(isOn: $daemonStates[stateIdx].disabled) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(daemon.label.replacingOccurrences(of: "com.apple.", with: ""))
                                            .font(.system(size: 12, design: .monospaced))
                                        Text(daemon.disabled ? "Will be DISABLED" : "Enabled (normal)")
                                            .font(.system(size: 9))
                                            .foregroundStyle(daemon.disabled ? .orange : .green)
                                    }
                                }
                                .tint(.orange)
                            }
                        }
                    } header: {
                        Label(group, systemImage: groupIcon(group))
                    }
                }
            }
        }
        .navigationTitle("Daemons")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Apply Changes?", isPresented: $showApplyConfirm) {
            Button("Apply & Reboot Later", role: .destructive) { applyChanges() }
            Button("Cancel", role: .cancel) {}
        } message: {
            let disabledCount = daemonStates.filter { $0.disabled }.count
            Text("This will write disabled.plist with \(disabledCount) daemons disabled.\nChanges take effect after reboot.")
        }
        .onAppear { if daemonStates.isEmpty { loadCurrentState() } }
    }
    
    private func groupIcon(_ group: String) -> String {
        switch group {
        case "Crash Reports": return "exclamationmark.triangle"
        case "Analytics": return "chart.bar"
        case "OTA Updates": return "arrow.down.circle"
        case "Tracking": return "eye.slash"
        case "Screen Time": return "hourglass"
        case "AI": return "brain"
        case "Suggestions": return "lightbulb"
        case "Apps": return "app"
        case "Advanced": return "exclamationmark.shield"
        case "Diagnostics": return "stethoscope"
        case "Spotlight": return "magnifyingglass"
        default: return "gear"
        }
    }
    
    private func disableAllSafe() {
        for i in daemonStates.indices {
            if daemonStates[i].safe { daemonStates[i].disabled = true }
        }
    }
    
    private func enableAll() {
        for i in daemonStates.indices {
            daemonStates[i].disabled = false
        }
    }
    
    private func loadCurrentState() {
        isLoading = true
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "read_daemons") { rc in
            let mem = rc.trojanMem
            let plistPath = "/var/db/com.apple.xpc.launchd/disabled.plist"
            let pathAddr = remote_alloc_str(rc, plistPath)
            
            // Read current disabled.plist
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_RDONLY), 0)
            var currentDisabled: Set<String> = []
            
            if fd != UInt64(bitPattern: -1) {
                let size = RootExecutor.rcall(rc, "lseek", fd, 0, 2)
                RootExecutor.rcall(rc, "lseek", fd, 0, 0)
                
                if size > 0 && size < 16000 {
                    let bufAddr = mem + 0x800
                    let n = RootExecutor.rcall(rc, "read", fd, bufAddr, min(size, 15000))
                    if n > 0 {
                        var buf = [UInt8](repeating: 0, count: Int(n))
                        rc.remoteRead(bufAddr, to: &buf, size: n)
                        let content = String(bytes: buf, encoding: .utf8) ?? ""
                        // Parse plist keys that have <true/> after them
                        let lines = content.components(separatedBy: "\n")
                        for (i, line) in lines.enumerated() {
                            if line.contains("<key>"), i + 1 < lines.count, lines[i+1].contains("<true/>") {
                                let key = line.replacingOccurrences(of: "<key>", with: "")
                                    .replacingOccurrences(of: "</key>", with: "")
                                    .trimmingCharacters(in: .whitespaces.union(.init(charactersIn: "\t")))
                                currentDisabled.insert(key)
                            }
                        }
                    }
                }
                RootExecutor.rcall(rc, "close", fd)
            }
            RootExecutor.rcall(rc, "free", pathAddr)
            
            // Build state list
            var entries: [DaemonEntry] = []
            for (label, group, _) in self.safeDaemons {
                entries.append(DaemonEntry(
                    label: label,
                    group: group,
                    disabled: currentDisabled.contains(label),
                    safe: true
                ))
            }
            
            DispatchQueue.main.async {
                self.daemonStates = entries
                self.isLoading = false
                self.statusMessage = "Loaded: \(currentDisabled.count) currently disabled"
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
            }
            return (true, "\(currentDisabled.count) disabled", 0)
        }
        #endif
    }
    
    private func applyChanges() {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "write_daemons") { rc in
            let _ = rc.trojanMem
            
            // Build plist XML
            var plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            plist += "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            plist += "<plist version=\"1.0\">\n<dict>\n"
            
            let disabledDaemons = self.daemonStates.filter { $0.disabled }
            for daemon in disabledDaemons.sorted(by: { $0.label < $1.label }) {
                plist += "\t<key>\(daemon.label)</key>\n\t<true/>\n"
            }
            
            plist += "</dict>\n</plist>\n"
            
            // Write to file
            let plistPath = "/var/db/com.apple.xpc.launchd/disabled.plist"
            let pathAddr = remote_alloc_str(rc, plistPath)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            
            guard fd != UInt64(bitPattern: -1) else {
                RootExecutor.rcall(rc, "free", pathAddr)
                DispatchQueue.main.async { self.statusMessage = "Failed to open file for writing" }
                return (false, "open failed", 0)
            }
            
            let contentAddr = remote_alloc_str(rc, plist)
            RootExecutor.rcall(rc, "write", fd, contentAddr, UInt64(plist.utf8.count))
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "free", contentAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            DispatchQueue.main.async {
                self.statusMessage = "\(disabledDaemons.count) daemons will be disabled after reboot!"
                UINotificationFeedbackGenerator().notificationOccurred(.success)
            }
            return (true, "written \(disabledDaemons.count) entries", 0)
        }
        #endif
    }
}
