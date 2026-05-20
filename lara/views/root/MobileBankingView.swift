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
    @State private var jbPathVisible = false
    @State private var stashPathVisible = false
    // FIX: track apakah sedang menjalankan operasi hide/restore secara terpisah
    // agar tidak terblokir oleh banking_verify yang berjalan di background
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

    // FIX: tombol hide/restore hanya disabled jika operasi hide/restore sedang berjalan
    // BUKAN jika banking_verify sedang berjalan
    private var hideRestoreDisabled: Bool {
        !mgr.rcready || isHideRestoreRunning
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
                // Scan tidak perlu block tombol hide/restore
                .disabled(isHideRestoreRunning)

                if jbHidden {
                    Button {
                        showRestoreConfirm = true
                    } label: {
                        Label("Restore /var/jb", systemImage: "arrow.uturn.backward.circle.fill")
                            .foregroundStyle(hideRestoreDisabled ? Color.secondary : Color.blue)
                    }
                    .disabled(hideRestoreDisabled)
                    .alert("Restore /var/jb?", isPresented: $showRestoreConfirm) {
                        Button("Batal", role: .cancel) {}
                        Button("Restore") {
                            restoreJbPath()
                        }
                    } message: {
                        Text("Mengembalikan \(Self.jbPath) dari \(Self.hiddenPath). App perbankan mungkin akan blokir lagi.")
                    }
                } else {
                    Button {
                        showHideConfirm = true
                    } label: {
                        Label("Sembunyikan /var/jb", systemImage: "eye.slash")
                            .foregroundStyle(hideRestoreDisabled ? Color.secondary : Color.orange)
                    }
                    .disabled(hideRestoreDisabled)
                    .alert("Sembunyikan /var/jb?", isPresented: $showHideConfirm) {
                        Button("Batal", role: .cancel) {}
                        Button("Sembunyikan", role: .destructive) {
                            hideJbPath()
                        }
                    } message: {
                        Text("Folder \(Self.jbPath) akan dipindah ke \(Self.hiddenPath). Jailbreak tools di dalamnya tidak bisa dipakai sampai Anda restore.")
                    }
                }

                if isHideRestoreRunning {
                    HStack(spacing: 8) {
                        ProgressView().scaleEffect(0.8)
                        Text("Sedang memproses...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } else if !mgr.rcready {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .font(.caption)
                        Text("Butuh RemoteCall — jalankan Jailbreak di tab Main dulu, lalu kembali ke sini.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                Label("Aksi", systemImage: "bolt.fill")
            } footer: {
                Text(mgr.rcready
                     ? "Sembunyikan = rename cepat via launchd (<3 detik). Setelah hide: force-quit app bank, buka lagi."
                     : "RC belum ready. Jalankan Jailbreak di tab Main → tunggu 'exploit success' → kembali ke sini.")
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
                .disabled(!mgr.dsready)
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
            // FIX: hanya refresh local state saat appear, jangan trigger executeAsRoot
            // karena itu menyebabkan root.isExecuting = true dan block tombol hide
            refreshJbPathsLocal()
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

    private func localPathExists(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    private func refreshJbPathsLocal() {
        jbPathVisible = localPathExists(Self.jbPath)
        stashPathVisible = localPathExists(Self.hiddenPath)
        // jbHidden = stash ada DAN /var/jb tidak ada
        // Jika keduanya ada = kondisi tidak konsisten (hide gagal di tengah jalan)
        jbHidden = stashPathVisible && !jbPathVisible
        UserDefaults.standard.set(jbHidden, forKey: "dsploit.jb_hidden")

        // Update status message jika kondisi tidak konsisten
        if jbPathVisible && stashPathVisible {
            statusMessage = "⚠️ Kondisi tidak konsisten: /var/jb DAN stash keduanya ada. Tap Sembunyikan untuk coba lagi (stash akan dihapus dulu)."
        }
    }

    /// Scan jejak — FileManager lokal + update state jb hidden
    private func scanIndicators() {
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

        // FIX: hanya refresh local, tidak trigger executeAsRoot
        refreshJbPathsLocal()

        indicators = probes.map { label, path, critical in
            JailbreakIndicator(
                label: label,
                path: path,
                exists: localPathExists(path),
                critical: critical
            )
        }
        let visCount = indicators.filter(\.exists).count
        statusMessage = "Scan lokal — \(visCount) path terlihat. Path di luar akses app mungkin tidak terdeteksi (butuh root)."
    }

    private func hideJbPath() {
        guard mgr.rcready, !isHideRestoreRunning else { return }
        isHideRestoreRunning = true
        statusMessage = "Menyembunyikan /var/jb..."

        #if !DISABLE_REMOTECALL
        // FIX: gunakan mgr.rcinitDaemon langsung, tidak lewat executeAsRoot
        // agar tidak terblokir oleh root.isExecuting dari operasi lain
        mgr.rcinitDaemon(
            serviceName: "com.apple.launchd",
            framework: nil,
            process: "launchd",
            migbypass: false
        ) { [self] launchdRC in
            guard let rc = launchdRC else {
                DispatchQueue.main.async {
                    self.statusMessage = "❌ Gagal connect ke launchd"
                    self.isHideRestoreRunning = false
                }
                return
            }

            let fromAddr = remote_alloc_str(rc, Self.jbPath)
            let toAddr = remote_alloc_str(rc, Self.hiddenPath)

            let jbExists = RootExecutor.rcall(rc, "access", fromAddr, 0) == 0
            let stashExists = RootExecutor.rcall(rc, "access", toAddr, 0) == 0

            var msg = ""
            var ok = false

            if !jbExists {
                msg = "⚠️ \(Self.jbPath) tidak ditemukan (mungkin sudah disembunyikan?)"
                DispatchQueue.main.async {
                    self.jbHidden = stashExists
                    self.jbPathVisible = false
                    self.stashPathVisible = stashExists
                }
            } else if stashExists {
                // Kondisi tidak konsisten: keduanya ada — hapus stash lama dulu lalu rename
                let rmResult = RootExecutor.rcall(rc, "unlink", toAddr)
                if rmResult == 0 {
                    // Stash berhasil dihapus, coba rename sekarang
                    let result = RootExecutor.rcall(rc, "rename", fromAddr, toAddr)
                    let err = remote_errno(rc)
                    ok = result == 0
                    msg = ok
                        ? "✅ \(Self.jbPath) disembunyikan (stash lama dihapus dulu). Force-quit app bank lalu buka lagi."
                        : "❌ rename gagal setelah hapus stash: errno=\(err)"
                    if ok {
                        DispatchQueue.main.async {
                            self.jbHidden = true
                            self.jbPathVisible = false
                            self.stashPathVisible = true
                        }
                    }
                } else {
                    // unlink gagal — stash mungkin folder, coba rmdir
                    let rmdirResult = RootExecutor.rcall(rc, "rmdir", toAddr)
                    if rmdirResult == 0 {
                        let result = RootExecutor.rcall(rc, "rename", fromAddr, toAddr)
                        let err = remote_errno(rc)
                        ok = result == 0
                        msg = ok
                            ? "✅ \(Self.jbPath) disembunyikan (stash folder lama dihapus). Force-quit app bank lalu buka lagi."
                            : "❌ rename gagal setelah rmdir stash: errno=\(err)"
                        if ok {
                            DispatchQueue.main.async {
                                self.jbHidden = true
                                self.jbPathVisible = false
                                self.stashPathVisible = true
                            }
                        }
                    } else {
                        let rmErr = remote_errno(rc)
                        msg = "❌ \(Self.hiddenPath) sudah ada dan tidak bisa dihapus (errno=\(rmErr)). Hapus manual via File Manager."
                    }
                }
            } else {
                let result = RootExecutor.rcall(rc, "rename", fromAddr, toAddr)
                let err = remote_errno(rc)
                ok = result == 0
                msg = ok
                    ? "✅ \(Self.jbPath) disembunyikan. Force-quit app bank lalu buka lagi."
                    : "❌ rename gagal: errno=\(err)"
                if ok {
                    DispatchQueue.main.async {
                        self.jbHidden = true
                        self.jbPathVisible = false
                        self.stashPathVisible = true
                    }
                }
            }

            RootExecutor.rcall(rc, "free", fromAddr)
            RootExecutor.rcall(rc, "free", toAddr)
            rc.destroy()

            DispatchQueue.main.async {
                self.statusMessage = msg
                self.isHideRestoreRunning = false
                // FIX: jika sukses, jangan refresh dari FileManager — sandbox masih
                // melihat /var/jb karena kernel vnode cache belum flush.
                // State sudah di-set benar dari RC result di atas.
                // FIX: jangan panggil scanIndicators() jika ok — akan overwrite jbHidden via refreshJbPathsLocal
                if !ok { self.refreshJbPathsLocal() }
                if !ok, !self.indicators.isEmpty { self.scanIndicators() }
            }
        }
        #else
        isHideRestoreRunning = false
        statusMessage = "❌ RemoteCall disabled"
        #endif
    }

    private func restoreJbPath() {
        guard mgr.rcready, !isHideRestoreRunning else { return }
        isHideRestoreRunning = true
        statusMessage = "Mengembalikan /var/jb..."

        #if !DISABLE_REMOTECALL
        mgr.rcinitDaemon(
            serviceName: "com.apple.launchd",
            framework: nil,
            process: "launchd",
            migbypass: false
        ) { [self] launchdRC in
            guard let rc = launchdRC else {
                DispatchQueue.main.async {
                    self.statusMessage = "❌ Gagal connect ke launchd"
                    self.isHideRestoreRunning = false
                }
                return
            }

            let fromAddr = remote_alloc_str(rc, Self.hiddenPath)
            let toAddr = remote_alloc_str(rc, Self.jbPath)

            let stashExists = RootExecutor.rcall(rc, "access", fromAddr, 0) == 0
            let jbExists = RootExecutor.rcall(rc, "access", toAddr, 0) == 0

            var msg = ""
            var ok = false

            if !stashExists {
                msg = "⚠️ Stash \(Self.hiddenPath) tidak ditemukan"
            } else if jbExists {
                msg = "⚠️ \(Self.jbPath) sudah ada — tidak perlu restore"
                DispatchQueue.main.async {
                    self.jbHidden = false
                    self.jbPathVisible = true
                }
            } else {
                let result = RootExecutor.rcall(rc, "rename", fromAddr, toAddr)
                let err = remote_errno(rc)
                ok = result == 0
                msg = ok
                    ? "✅ \(Self.jbPath) dikembalikan."
                    : "❌ rename gagal: errno=\(err)"
                if ok {
                    DispatchQueue.main.async {
                        self.jbHidden = false
                        self.jbPathVisible = true
                        self.stashPathVisible = false
                    }
                }
            }

            RootExecutor.rcall(rc, "free", fromAddr)
            RootExecutor.rcall(rc, "free", toAddr)
            rc.destroy()

            DispatchQueue.main.async {
                self.statusMessage = msg
                self.isHideRestoreRunning = false
                // FIX: jika sukses, jangan refresh dari FileManager — sandbox masih
                // melihat /var/jb karena kernel vnode cache belum flush.
                // State sudah di-set benar dari RC result di atas.
                // FIX: jangan panggil scanIndicators() jika ok — akan overwrite jbHidden via refreshJbPathsLocal
                if !ok { self.refreshJbPathsLocal() }
                if !ok, !self.indicators.isEmpty { self.scanIndicators() }
            }
        }
        #else
        isHideRestoreRunning = false
        statusMessage = "❌ RemoteCall disabled"
        #endif
    }
}
