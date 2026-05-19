//
//  GuideView.swift
//  DSPloit — Quick start for new and advanced users
//

import SwiftUI

struct GuideView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var mgr = dspmgr.shared

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("DSPloit membuka akses root tanpa PC setelah terpasang. Ikuti urutan ini untuk hasil terbaik.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Section("Status perangkat") {
                    SystemStatusStrip(mgr: mgr)
                        .listRowBackground(Color.clear)
                }

                Section("Pemula — 3 langkah") {
                    guideStep(1, "Main", "Tap **Jailbreak** dan tunggu semua langkah hijau (Kernel → Bootstrap).")
                    guideStep(2, "Root", "Shell, Files, Banking, Bootstrap, dan tools root lainnya.")
                    guideStep(3, "Aman", "Jangan tutup app saat AMFI Lab berjalan. Respring dari Main jika perlu.")
                }

                Section("Lanjutan") {
                    Label("AMFI Lab — riset bypass code signing (Root → Advanced)", systemImage: "flask")
                    Label("VarClean — bersihkan jejak jailbreak (Root → Banking)", systemImage: "trash")
                    Label("Offsets — Settings jika device belum dikenali", systemImage: "slider.horizontal.3")
                }

                Section("Banking app diblokir?") {
                    Text("Root → **Banking** → Sembunyikan /var/jb → force-quit app bank → buka lagi → Restore setelah selesai.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Section("Peringatan") {
                    Label("Reboot = hilang jailbreak (jailbreak ulang)", systemImage: "arrow.clockwise")
                    Label("Tutup app dari switcher bisa panic — gunakan Respring", systemImage: "exclamationmark.triangle")
                    Label("Backup data penting sebelum eksperimen AMFI", systemImage: "externaldrive")
                }
            }
            .navigationTitle("Panduan")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Selesai") { dismiss() }
                }
            }
        }
    }

    private func guideStep(_ num: Int, _ tab: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(num)")
                .font(.caption.bold())
                .frame(width: 22, height: 22)
                .background(Circle().fill(Color.accentColor.opacity(0.2)))
            VStack(alignment: .leading, spacing: 4) {
                Text(tab)
                    .font(.subheadline.bold())
                Text(LocalizedStringKey(text))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}
