//
//  CustomView.swift
//  lara
//
//  Created by ruter on 29.03.26.
//

import SwiftUI
import UniformTypeIdentifiers

struct CustomView: View {
    @ObservedObject var mgr: laramgr
    @State private var targetPath: String = "/"
    @State private var showImporter = false
    @State private var sourcePath: String = ""
    @State private var sourceName: String = "No file selected"
    @State private var isOverwriting = false

    var body: some View {
        List {
            Section {
                TextField("/path/to/target", text: $targetPath)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)

                HStack {
                    Text(L("Source", "Sumber"))
                    Spacer()
                    Text(sourceName)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }

                Button(L("Choose Source File", "Pilih File Sumber")) {
                    showImporter = true
                }

                Button(isOverwriting ? L("Overwriting...", "Menimpa...") : L("Overwrite Target", "Timpa Target")) {
                    guard !isOverwriting else { return }
                    overwrite()
                }
                .disabled(!canOverwrite)
            } header: {
                Text(L("Custom Path Overwrite", "Timpa Path Kustom"))
            } footer: {
                Text(L("This will overwrite the target file with the selected source file. If possible, it now uses a growth-safe path when the new file is larger.", "Ini akan menimpa file target dengan file sumber yang dipilih. Jika memungkinkan, sekarang memakai jalur aman untuk file yang ukurannya membesar."))
            }

            Section {
                    Text(globallogger.logs.last ?? L("No logs yet", "Belum ada log"))
                    .font(.system(size: 13, design: .monospaced))
            }
        }
        .navigationTitle(L("Custom Overwrite", "Overwrite Kustom"))
        .fileImporter(
            isPresented: $showImporter,
            allowedContentTypes: [.item],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let url = urls.first {
                importSource(url)
            }
        }
    }

    private var canOverwrite: Bool {
        mgr.vfsready && !targetPath.isEmpty && !sourcePath.isEmpty && !isOverwriting
    }

    private func importSource(_ url: URL) {
        let fm = FileManager.default
        let tmpDir = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        let dest = tmpDir.appendingPathComponent("vfs_custom_\(UUID().uuidString)")

        do {
            if fm.fileExists(atPath: dest.path) {
                try fm.removeItem(at: dest)
            }
            try fm.copyItem(at: url, to: dest)
            sourcePath = dest.path
            sourceName = url.lastPathComponent
            mgr.logmsg(L("selected source:", "sumber terpilih:") + " \(sourceName)")
        } catch {
            mgr.logmsg(L("failed to import source:", "gagal impor sumber:") + " \(error.localizedDescription)")
        }
    }

    private func overwrite() {
        guard canOverwrite else { return }
        isOverwriting = true
        DispatchQueue.global(qos: .userInitiated).async {
            let result = mgr.lara_writeexpandsafe(target: targetPath, source: sourcePath)
            DispatchQueue.main.async {
                isOverwriting = false
                result.ok
                    ? mgr.logmsg(L("overwrite ok:", "overwrite berhasil:") + " \(targetPath) (\(result.message))")
                    : mgr.logmsg(L("overwrite failed:", "overwrite gagal:") + " \(targetPath) (\(result.message))")
            }
        }
    }
}

