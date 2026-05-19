//
//  MobileBankingView.swift
//  DSPloit
//
//  Hide jailbreak paths (especially /var/jb) so banking apps can open again.
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

    var body: some View {
        List {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: jbHidden ? "eye.slash.fill" : "building.columns.fill")
                        .font(.title2)
                        .foregroundStyle(jbHidden ? .green : (criticalCount > 0 ? .orange : .blue))
                    VStack(alignment: .leading, spacing: 4) {
                        Text(jbHidden ? "/var/jb disembunyikan" : "/var/jb terlihat")
                            .font(.subheadline.bold())
                        Text(jbHidden
                             ? "Folder dipindah ke \(Self.hiddenPath). Restore setelah selesai banking."
                             : "Banyak app perbankan menolak device jika \(Self.jbPath) ada.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 4)

                if let statusMessage, !statusMessage.isEmpty {
                    Text(statusMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Label("Status", systemImage: "shield.lefthalf.filled")
            }

            Section {
                Button {
                    scanIndicators()
                } label: {
                    Label("Scan Jejak Jailbreak", systemImage: "magnifyingglass")
                }
                .disabled(!mgr.rcready || root.isExecuting)

                if jbHidden {
                    Button {
                        showRestoreConfirm = true
                    } label: {
                        Label("Restore /var/jb", systemImage: "arrow.uturn.backward.circle.fill")
                            .foregroundStyle(.blue)
                    }
                    .disabled(!mgr.rcready || root.isExecuting)
                } else {
                    Button {
                        showHideConfirm = true
                    } label: {
                        Label("Sembunyikan /var/jb", systemImage: "eye.slash")
                            .foregroundStyle(.orange)
                    }
                    .disabled(!mgr.rcready || root.isExecuting || !indicatorExists(Self.jbPath))
                }
            } header: {
                Label("Aksi", systemImage: "bolt.fill")
            } footer: {
                Text("Sembunyikan hanya rename folder (aman, bisa dikembalikan). Setelah hide: force-quit app bank, buka lagi. Beberapa bank juga cek file lain — gunakan scan + VarClean.")
            }

            if !indicators.isEmpty {
                Section {
                    ForEach(indicators) { item in
                        HStack(spacing: 10) {
                            Image(systemName: item.exists ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                                .foregroundStyle(item.exists ? (item.critical ? .orange : .yellow) : .green)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.label)
                                    .font(.subheadline)
                                Text(item.path)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                        }
                    }
                } header: {
                    Label("Hasil Scan", systemImage: "list.bullet.rectangle")
                } footer: {
                    Text("\(indicators.filter(\.exists).count) path terdeteksi, \(criticalCount) kritis untuk banking.")
                }
            }

            Section {
                NavigationLink {
                    VarCleanView()
                } label: {
                    Label("VarClean (jejak tambahan)", systemImage: "trash")
                }
                .disabled(!mgr.sbxready)

                Button {
                    mgr.respring()
                } label: {
                    Label("Respring", systemImage: "arrow.clockwise")
                }
                .disabled(!mgr.rcready)
            } header: {
                Label("Lainnya", systemImage: "ellipsis.circle")
            } footer: {
                Text(mgr.sbxready
                     ? "VarClean menghapus sisa Sileo, Dopamine, Filza, dll. dari /var/mobile."
                     : "VarClean butuh sandbox escape (jalankan Jailbreak di Home dulu).")
            }

            Section {
                VStack(alignment: .leading, spacing: 8) {
                    tipRow("1", "Tap Sembunyikan /var/jb")
                    tipRow("2", "Swipe-close app Mobile Banking dari app switcher")
                    tipRow("3", "Buka app bank lagi (jangan buka DSPloit dulu)")
                    tipRow("4", "Setelah selesai → Restore /var/jb agar tweak & root tools normal")
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            } header: {
                Label("Cara Pakai", systemImage: "questionmark.circle")
            }
        }
        .navigationTitle("Mobile Banking")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            refreshHiddenState()
        }
        .alert("Sembunyikan /var/jb?", isPresented: $showHideConfirm) {
            Button("Batal", role: .cancel) {}
            Button("Sembunyikan", role: .destructive) {
                hideJbPath()
            }
        } message: {
            Text("Folder \(Self.jbPath) akan dipindah ke \(Self.hiddenPath). Jailbreak tools di dalamnya tidak bisa dipakai sampai Anda restore.")
        }
        .alert("Restore /var/jb?", isPresented: $showRestoreConfirm) {
            Button("Batal", role: .cancel) {}
            Button("Restore") {
                restoreJbPath()
            }
        } message: {
            Text("Mengembalikan \(Self.jbPath) dari \(Self.hiddenPath). App perbankan mungkin akan blokir lagi.")
        }
    }

    private func tipRow(_ number: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(number)
                .font(.caption2.bold())
                .frame(width: 16, height: 16)
                .background(Circle().fill(Color.secondary.opacity(0.25)))
            Text(text)
        }
    }

    private func indicatorExists(_ path: String) -> Bool {
        indicators.first(where: { $0.path == path })?.exists ?? false
    }

    private func refreshHiddenState() {
        jbHidden = UserDefaults.standard.bool(forKey: "dsploit.jb_hidden")
        if indicators.isEmpty {
            scanIndicators()
        }
    }

    private func scanIndicators() {
        #if !DISABLE_REMOTECALL
        let probes: [(String, String, Bool)] = [
            ("Rootless bootstrap", Self.jbPath, true),
            ("Stash (hidden jb)", Self.hiddenPath, false),
            (".installed_unc0ver", "/.installed_unc0ver", true),
            ("Cydia", "/Applications/Cydia.app", true),
            ("Sileo", "/Applications/Sileo.app", true),
            ("MobileSubstrate", "/Library/MobileSubstrate", true),
            ("apt (etc)", "/etc/apt", true),
            ("apt (var)", "/var/lib/apt", true),
            ("binpack", "/var/binpack", true),
            ("bash", "/bin/bash", false),
            ("sshd", "/usr/sbin/sshd", false),
            ("Frida server", "/usr/sbin/frida-server", true),
            ("checkra1n", "/var/binpack/Applications/loader.app", true),
        ]

        root.executeAsRoot(operation: "banking_scan") { rc in
            var found: [JailbreakIndicator] = []
            var hidden = false
            var visible = false

            for (label, path, critical) in probes {
                let pathAddr = remote_alloc_str(rc, path)
                let exists = RootExecutor.rcall(rc, "access", pathAddr, 0) == 0
                RootExecutor.rcall(rc, "free", pathAddr)
                found.append(JailbreakIndicator(label: label, path: path, exists: exists, critical: critical))
                if path == Self.hiddenPath, exists { hidden = true }
                if path == Self.jbPath, exists { visible = true }
            }

            let resolvedHidden = hidden && !visible

            DispatchQueue.main.async {
                self.indicators = found
                self.jbHidden = resolvedHidden
                UserDefaults.standard.set(resolvedHidden, forKey: "dsploit.jb_hidden")
                let visCount = found.filter(\.exists).count
                self.statusMessage = "Scan selesai — \(visCount) path ada di disk."
            }

            return (true, "Scanned \(probes.count) paths", UInt64(found.filter(\.exists).count))
        }
        #endif
    }

    private func hideJbPath() {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "hide_var_jb") { rc in
            let fromAddr = remote_alloc_str(rc, Self.jbPath)
            let toAddr = remote_alloc_str(rc, Self.hiddenPath)

            let jbExists = RootExecutor.rcall(rc, "access", fromAddr, 0) == 0
            let stashExists = RootExecutor.rcall(rc, "access", toAddr, 0) == 0

            guard jbExists else {
                RootExecutor.rcall(rc, "free", fromAddr)
                RootExecutor.rcall(rc, "free", toAddr)
                return (false, "\(Self.jbPath) tidak ditemukan", 0)
            }

            if stashExists {
                RootExecutor.rcall(rc, "free", fromAddr)
                RootExecutor.rcall(rc, "free", toAddr)
                return (false, "\(Self.hiddenPath) sudah ada — restore dulu atau hapus manual", 0)
            }

            let result = RootExecutor.rcall(rc, "rename", fromAddr, toAddr)
            let err = remote_errno(rc)
            RootExecutor.rcall(rc, "free", fromAddr)
            RootExecutor.rcall(rc, "free", toAddr)

            let ok = result == 0
            if ok {
                DispatchQueue.main.async {
                    self.jbHidden = true
                    UserDefaults.standard.set(true, forKey: "dsploit.jb_hidden")
                    self.statusMessage = "✅ \(Self.jbPath) disembunyikan. Force-quit app bank lalu buka lagi."
                    self.scanIndicators()
                }
            }

            return (ok, ok ? "Hidden \(Self.jbPath)" : "rename failed: errno=\(err)", UInt64(result))
        }
        #endif
    }

    private func restoreJbPath() {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "restore_var_jb") { rc in
            let fromAddr = remote_alloc_str(rc, Self.hiddenPath)
            let toAddr = remote_alloc_str(rc, Self.jbPath)

            let stashExists = RootExecutor.rcall(rc, "access", fromAddr, 0) == 0
            let jbExists = RootExecutor.rcall(rc, "access", toAddr, 0) == 0

            guard stashExists else {
                RootExecutor.rcall(rc, "free", fromAddr)
                RootExecutor.rcall(rc, "free", toAddr)
                return (false, "Stash \(Self.hiddenPath) tidak ditemukan", 0)
            }

            if jbExists {
                RootExecutor.rcall(rc, "free", fromAddr)
                RootExecutor.rcall(rc, "free", toAddr)
                return (false, "\(Self.jbPath) sudah ada — tidak perlu restore", 0)
            }

            let result = RootExecutor.rcall(rc, "rename", fromAddr, toAddr)
            let err = remote_errno(rc)
            RootExecutor.rcall(rc, "free", fromAddr)
            RootExecutor.rcall(rc, "free", toAddr)

            let ok = result == 0
            if ok {
                DispatchQueue.main.async {
                    self.jbHidden = false
                    UserDefaults.standard.set(false, forKey: "dsploit.jb_hidden")
                    self.statusMessage = "✅ \(Self.jbPath) dikembalikan."
                    self.scanIndicators()
                }
            }

            return (ok, ok ? "Restored \(Self.jbPath)" : "rename failed: errno=\(err)", UInt64(result))
        }
        #endif
    }
}
