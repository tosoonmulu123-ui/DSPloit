//
//  MobileBankingView.swift
//  DSPloit
//
//  Hide jailbreak from banking apps by renaming /var/jb
//

import SwiftUI

struct MobileBankingView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared

    private static let jbPath = "/var/jb"
    private static let hiddenPath = "/var/.dsploit_jb_stash"

    @State private var indicators: [JailbreakIndicator] = []
    @State private var jbHidden = false
    @State private var statusMessage: String?
    @State private var showHideConfirm = false
    @State private var showRestoreConfirm = false
    @State private var jbPathVisible = false
    @State private var stashPathVisible = false
    @State private var isHideRestoreRunning = false

    struct JailbreakIndicator: Identifiable {
        let id = UUID()
        let label: String
        let path: String
        var exists: Bool
        var critical: Bool
    }

    private var criticalCount: Int {
        indicators.filter { $0.exists && $0.critical }.count
    }

    private var hideRestoreDisabled: Bool {
        !mgr.rcready || isHideRestoreRunning
    }

    var body: some View {
        List {
            // Status
            Section {
                HStack(spacing: 12) {
                    Image(systemName: jbHidden ? "eye.slash.fill" : "eye.fill")
                        .font(.title3)
                        .foregroundStyle(jbHidden ? .green : .orange)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(jbHidden ? "Jailbreak Hidden" : "Jailbreak Visible")
                            .font(.subheadline.bold())
                        Text(jbHidden
                             ? "Banking apps should work now. Restore when done."
                             : "Banking apps may detect jailbreak and refuse to open.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 2)

                if let statusMessage, !statusMessage.isEmpty {
                    Text(statusMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            // Actions
            Section {
                if jbHidden {
                    Button {
                        showRestoreConfirm = true
                    } label: {
                        Label("Restore Jailbreak", systemImage: "arrow.uturn.backward")
                    }
                    .disabled(hideRestoreDisabled)
                    .alert("Restore jailbreak files?", isPresented: $showRestoreConfirm) {
                        Button("Cancel", role: .cancel) {}
                        Button("Restore") { restoreJbPath() }
                    } message: {
                        Text("This will make /var/jb visible again. Banking apps may block you.")
                    }
                } else {
                    Button {
                        showHideConfirm = true
                    } label: {
                        Label("Hide Jailbreak", systemImage: "eye.slash")
                    }
                    .disabled(hideRestoreDisabled)
                    .alert("Hide jailbreak files?", isPresented: $showHideConfirm) {
                        Button("Cancel", role: .cancel) {}
                        Button("Hide", role: .destructive) { hideJbPath() }
                    } message: {
                        Text("Moves /var/jb to a hidden location. Root tools won't work until you restore.")
                    }
                }

                Button { scanIndicators() } label: {
                    Label("Scan for Traces", systemImage: "magnifyingglass")
                }
                .disabled(isHideRestoreRunning)

                if isHideRestoreRunning {
                    HStack(spacing: 8) {
                        ProgressView().scaleEffect(0.7)
                        Text("Processing...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } footer: {
                if !mgr.rcready {
                    Text("Run Jailbreak from Main tab first.")
                }
            }

            // Scan results
            if !indicators.isEmpty {
                Section("Scan Results") {
                    ForEach(indicators) { item in
                        HStack(spacing: 10) {
                            Image(systemName: item.exists ? "exclamationmark.circle.fill" : "checkmark.circle.fill")
                                .foregroundStyle(item.exists ? .orange : .green)
                                .font(.caption)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(item.label)
                                    .font(.subheadline)
                                Text(item.path)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                }
            }

            // How to use
            Section("How to Use") {
                VStack(alignment: .leading, spacing: 6) {
                    tipRow("1", "Tap Hide Jailbreak")
                    tipRow("2", "Force-quit your banking app")
                    tipRow("3", "Open the banking app")
                    tipRow("4", "When done, come back and tap Restore")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Banking")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { refreshJbPathsLocal() }
    }

    private func tipRow(_ number: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(number)
                .font(.caption2.bold())
                .frame(width: 16, height: 16)
                .background(Circle().fill(Color.secondary.opacity(0.2)))
            Text(text)
        }
    }

    private func localPathExists(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    private func refreshJbPathsLocal() {
        jbPathVisible = localPathExists(Self.jbPath)
        stashPathVisible = localPathExists(Self.hiddenPath)
        jbHidden = stashPathVisible && !jbPathVisible
    }

    private func scanIndicators() {
        let probes: [(String, String, Bool)] = [
            ("Bootstrap", Self.jbPath, true),
            ("Stash (hidden)", Self.hiddenPath, false),
            ("unc0ver", "/.installed_unc0ver", true),
            ("Cydia", "/Applications/Cydia.app", true),
            ("Sileo", "/Applications/Sileo.app", true),
            ("MobileSubstrate", "/Library/MobileSubstrate", true),
            ("apt", "/etc/apt", true),
            ("Frida", "/usr/sbin/frida-server", true),
            ("checkra1n", "/var/binpack/Applications/loader.app", true),
        ]

        refreshJbPathsLocal()
        indicators = probes.map { label, path, critical in
            JailbreakIndicator(label: label, path: path, exists: localPathExists(path), critical: critical)
        }
    }

    private func hideJbPath() {
        guard mgr.rcready, !isHideRestoreRunning else { return }
        isHideRestoreRunning = true
        statusMessage = "Hiding..."

        #if !DISABLE_REMOTECALL
        mgr.rcinitDaemon(serviceName: "com.apple.launchd", framework: nil, process: "launchd", migbypass: false) { [self] launchdRC in
            guard let rc = launchdRC else {
                DispatchQueue.main.async {
                    self.statusMessage = "❌ Connection failed"
                    self.isHideRestoreRunning = false
                }
                return
            }

            let fromAddr = remote_alloc_str(rc, Self.jbPath)
            let toAddr = remote_alloc_str(rc, Self.hiddenPath)
            let stashExists = RootExecutor.rcall(rc, "access", toAddr, 0) == 0

            if stashExists {
                let trash = "/var/.dsploit_trash_\(Int(Date().timeIntervalSince1970))"
                let trashAddr = remote_alloc_str(rc, trash)
                RootExecutor.rcall(rc, "rename", toAddr, trashAddr)
                RootExecutor.rcall(rc, "free", trashAddr)
            }

            let result = RootExecutor.rcall(rc, "rename", fromAddr, toAddr)
            let ok = result == 0
            let errNo = ok ? 0 : Int(remote_errno(rc))

            RootExecutor.rcall(rc, "free", fromAddr)
            RootExecutor.rcall(rc, "free", toAddr)
            rc.destroy()

            DispatchQueue.main.async {
                self.statusMessage = ok ? "✅ Hidden. Force-quit banking app and reopen." : "❌ Failed (errno=\(errNo))"
                self.isHideRestoreRunning = false
                if ok { self.jbHidden = true }
                else { self.refreshJbPathsLocal() }
            }
        }
        #else
        isHideRestoreRunning = false
        #endif
    }

    private func restoreJbPath() {
        guard mgr.rcready, !isHideRestoreRunning else { return }
        isHideRestoreRunning = true
        statusMessage = "Restoring..."

        #if !DISABLE_REMOTECALL
        mgr.rcinitDaemon(serviceName: "com.apple.launchd", framework: nil, process: "launchd", migbypass: false) { [self] launchdRC in
            guard let rc = launchdRC else {
                DispatchQueue.main.async {
                    self.statusMessage = "❌ Connection failed"
                    self.isHideRestoreRunning = false
                }
                return
            }

            let fromAddr = remote_alloc_str(rc, Self.hiddenPath)
            let toAddr = remote_alloc_str(rc, Self.jbPath)
            let jbExists = RootExecutor.rcall(rc, "access", toAddr, 0) == 0

            if jbExists {
                let trash = "/var/.dsploit_trash_\(Int(Date().timeIntervalSince1970))"
                let trashAddr = remote_alloc_str(rc, trash)
                RootExecutor.rcall(rc, "rename", toAddr, trashAddr)
                RootExecutor.rcall(rc, "free", trashAddr)
            }

            let result = RootExecutor.rcall(rc, "rename", fromAddr, toAddr)
            let ok = result == 0

            RootExecutor.rcall(rc, "free", fromAddr)
            RootExecutor.rcall(rc, "free", toAddr)
            rc.destroy()

            DispatchQueue.main.async {
                self.statusMessage = ok ? "✅ Restored. Jailbreak tools active again." : "❌ Failed"
                self.isHideRestoreRunning = false
                if ok { self.jbHidden = false }
                else { self.refreshJbPathsLocal() }
            }
        }
        #else
        isHideRestoreRunning = false
        #endif
    }
}
