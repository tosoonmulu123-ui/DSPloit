//
//  DiskSelfCheckView.swift
//  lara
//
//  Created by Codex on 15.04.26.
//

import SwiftUI

private struct DiskCheckResult: Identifiable {
    let id = UUID()
    let title: String
    let ok: Bool
    let detail: String
}

struct DiskSelfCheckView: View {
    @ObservedObject private var mgr = laramgr.shared
    @State private var isRunning = false
    @State private var results: [DiskCheckResult] = []
    
    var body: some View {
        List {
            Section(L("Status", "Status")) {
                HStack {
                    Text("Kernel R/W")
                    Spacer()
                    Text(mgr.dsready ? "ready" : "not ready")
                        .foregroundColor(mgr.dsready ? .green : .red)
                }
                HStack {
                    Text("SBX")
                    Spacer()
                    Text(mgr.sbxready ? "ready" : "not ready")
                        .foregroundColor(mgr.sbxready ? .green : .red)
                }
                HStack {
                    Text("VFS")
                    Spacer()
                    Text(mgr.vfsready ? "ready" : "not ready")
                        .foregroundColor(mgr.vfsready ? .green : .red)
                }
            }
            
            Section(L("Run Checks", "Jalankan Pengecekan")) {
                Button(isRunning ? L("Running...", "Menjalankan...") : L("Run Disk R/W Self-Check", "Jalankan Cek Mandiri Disk R/W")) {
                    runChecks()
                }
                .disabled(isRunning || !mgr.dsready || (!mgr.sbxready && !mgr.vfsready))
                
                Text(L("Runs safe tests in /var/tmp using temp files: create, read-back, overwrite smaller, overwrite larger.", "Menjalankan tes aman di /var/tmp memakai file sementara: buat, baca ulang, overwrite lebih kecil, overwrite lebih besar."))
                    .foregroundColor(.secondary)
            }
            
            Section(L("Results", "Hasil")) {
                if results.isEmpty {
                    Text(L("No results yet.", "Belum ada hasil."))
                        .foregroundColor(.secondary)
                } else {
                    ForEach(results) { result in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(result.title)
                                Spacer()
                                Image(systemName: result.ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .foregroundColor(result.ok ? .green : .red)
                            }
                            Text(result.detail)
                                .font(.footnote)
                                .foregroundColor(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                }
            }
        }
        .navigationTitle(L("Disk R/W Self-Check", "Cek Mandiri Disk R/W"))
    }
    
    private func runChecks() {
        isRunning = true
        results = []
        
        DispatchQueue.global(qos: .userInitiated).async {
            let created = Date().timeIntervalSince1970
            let base = "/var/tmp/lara_selfcheck_\(Int(created))_\(Int.random(in: 1000...9999))"
            let fm = FileManager.default
            
            var localResults: [DiskCheckResult] = []
            
            if mgr.sbxready {
                localResults.append(runSBXChecks(base: base, fileManager: fm))
            } else {
                localResults.append(DiskCheckResult(title: L("SBX checks", "Cek SBX"), ok: false, detail: L("SBX not ready", "SBX belum siap")))
            }
            
            if mgr.vfsready {
                localResults.append(runVFSChecks(base: base))
            } else {
                localResults.append(DiskCheckResult(title: L("VFS checks", "Cek VFS"), ok: false, detail: L("VFS not ready", "VFS belum siap")))
            }
            
            DispatchQueue.main.async {
                results = localResults
                isRunning = false
            }
        }
    }
    
    private func runSBXChecks(base: String, fileManager fm: FileManager) -> DiskCheckResult {
        let path = base + "_sbx.txt"
        defer { try? fm.removeItem(atPath: path) }
        
        let small = Data("SBX_SMALL".utf8)
        let large = Data("SBX_LARGE_PAYLOAD_\(String(repeating: "X", count: 256))".utf8)
        
        do {
            try small.write(to: URL(fileURLWithPath: path), options: .atomic)
            let readSmall = try Data(contentsOf: URL(fileURLWithPath: path))
            guard readSmall == small else {
                return DiskCheckResult(title: L("SBX checks", "Cek SBX"), ok: false, detail: L("Small write/read-back mismatch", "Tulis kecil/baca ulang tidak cocok"))
            }
            
            let rewrite = mgr.lara_writeexpandsafe(target: path, data: large)
            guard rewrite.ok else {
                return DiskCheckResult(title: L("SBX checks", "Cek SBX"), ok: false, detail: L("Growth write failed:", "Tulis growth gagal:") + " \(rewrite.message)")
            }
            
            let readLarge = try Data(contentsOf: URL(fileURLWithPath: path))
            guard readLarge == large else {
                return DiskCheckResult(title: L("SBX checks", "Cek SBX"), ok: false, detail: L("Large write/read-back mismatch", "Tulis besar/baca ulang tidak cocok"))
            }
            
            return DiskCheckResult(title: L("SBX checks", "Cek SBX"), ok: true, detail: L("Create + growth overwrite + read-back succeeded", "Buat + overwrite growth + baca ulang berhasil"))
        } catch {
            return DiskCheckResult(title: L("SBX checks", "Cek SBX"), ok: false, detail: error.localizedDescription)
        }
    }
    
    private func runVFSChecks(base: String) -> DiskCheckResult {
        let path = base + "_vfs.txt"
        let start = Data("VFS_START".utf8)
        let bigger = Data("VFS_GROW_\(String(repeating: "Y", count: 512))".utf8)
        
        let seed = mgr.lara_writeexpandsafe(target: path, data: start)
        guard seed.ok else {
            return DiskCheckResult(title: L("VFS checks", "Cek VFS"), ok: false, detail: L("Seed write failed:", "Seed write gagal:") + " \(seed.message)")
        }
        
        let grown = mgr.lara_writeexpandsafe(target: path, data: bigger)
        guard grown.ok else {
            return DiskCheckResult(title: L("VFS checks", "Cek VFS"), ok: false, detail: L("Growth write failed:", "Tulis growth gagal:") + " \(grown.message)")
        }
        
        guard let readBack = mgr.vfsread(path: path, maxSize: bigger.count + 1) else {
            return DiskCheckResult(title: L("VFS checks", "Cek VFS"), ok: false, detail: L("VFS read-back failed", "Baca ulang VFS gagal"))
        }
        guard readBack == bigger else {
            return DiskCheckResult(title: L("VFS checks", "Cek VFS"), ok: false, detail: L("VFS read-back mismatch", "Baca ulang VFS tidak cocok"))
        }
        
        _ = try? FileManager.default.removeItem(atPath: path)
        return DiskCheckResult(title: L("VFS checks", "Cek VFS"), ok: true, detail: L("Seed + growth overwrite + VFS read-back succeeded", "Seed + overwrite growth + baca ulang VFS berhasil"))
    }
}
