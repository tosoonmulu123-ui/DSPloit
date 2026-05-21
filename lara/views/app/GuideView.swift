//
//  GuideView.swift
//  DSPloit — Quick start (Indonesia)
//

import SwiftUI

struct GuideView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var mgr = dspmgr.shared

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text("Guide for **all supported devices** (A11–A18, iOS 16.0–18.2). After reboot, repeat from Step 1.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Section("Current Status") {
                    SystemStatusStrip(mgr: mgr)
                        .listRowBackground(Color.clear)
                    checklistRow("Kernel (KRW)", mgr.dsready)
                    checklistRow("Kernelcache (XPF)", mgr.hasOffsets)
                    checklistRow("VFS", mgr.vfsready)
                    checklistRow("Sandbox", mgr.sbxready)
                    checklistRow("RemoteCall", mgr.rcready)
                }

                Section {
                    stepHeader("Step 1", "Run exploit")
                    stepBody("""
                    **Main** tab → tap **Jailbreak** → wait until complete or fails at sandbox.

                    **Success in Logs:** green line `(ds) exploit success!` and `kernel r/w is ready!`

                    **No reboot needed** after this.
                    """)
                }

                Section {
                    stepHeader("Step 2", "Kernelcache (required for AMFI)")
                    stepBody("""
                    **Settings** (gear icon) → **Kernelcache** section:

                    • First time: tap **Fetch Kernelcache** (must be **after** Step 1).
                    • If already fetched: don't delete unless having issues.
                    • **Remove** only to start fresh → Fetch again.

                    **Success in Logs:** `(kcache) XPF resolve OK` or `(offs) kernproc: 0x...`

                    **Failed:** `(offs) kernelcache download failed` → try **Import** file from your IPSW (see info ⓘ in Settings).
                    """)
                }

                Section {
                    stepHeader("Step 3", "AMFI Lab (without full jailbreak)")
                    stepBody("""
                    Only need **Step 1 + 2**. **Root** tab → **AMFI Lab** → **Jailbreak Path**:

                    ① **Physmap Access (74)** — tunggu hijau (boleh skip jika sudah verified).
                    ② **Trust Cache Probe (77)** — baca hasil di kartu + Logs.
                    ③ **Inject** — **jangan** sampai ② hijau.

                    **Jangan tutup app** dari app switcher (bisa panic). Pakai **Respring** di Main jika perlu.
                    """)
                }

                Section {
                    stepHeader("Opsional", "Jailbreak penuh (bootstrap)")
                    stepBody("""
                    Jika Jailbreak di Main sampai **🎉 Jailbreak complete!** → bootstrap `/var/jb` siap.

                    Kalau gagal di **Sandbox escape** tapi exploit hijau → AMFI Lab tetap bisa (hanya butuh KRW). Build terbaru memperlonggar verifikasi sandbox.
                    """)
                }

                Section("Cara baca Logs") {
                    Label("Tap ikon terminal di Main → filter chip: Exploit, Offsets, Kcache", systemImage: "terminal")
                    Label("Hijau = sukses · Merah = gagal · Oranye = peringatan", systemImage: "paintpalette")
                    Label("Tap satu baris = salin ke clipboard", systemImage: "doc.on.doc")
                    Label("Settings → matikan **Log polos** untuk warna + filter chip", systemImage: "text.alignleft")
                }

                Section("Peringatan") {
                    Label("Reboot = hilang jailbreak — ulangi Langkah 1–2", systemImage: "arrow.clockwise")
                    Label("Exp 77 Inject bisa panic — hanya setelah Probe hijau", systemImage: "exclamationmark.triangle")
                    Label("Jangan baca __ppl_data (otomatis dilewati di Probe)", systemImage: "hand.raised")
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

    private func stepHeader(_ step: String, _ title: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(step)
                .font(.caption.bold())
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
        }
        .padding(.bottom, 4)
    }

    private func stepBody(_ text: String) -> some View {
        Text(LocalizedStringKey(text.trimmingCharacters(in: .whitespacesAndNewlines)))
            .font(.subheadline)
            .foregroundStyle(.secondary)
    }

    private func checklistRow(_ label: String, _ ok: Bool) -> some View {
        HStack {
            Image(systemName: ok ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(ok ? .green : .secondary)
            Text(label)
        }
        .font(.subheadline)
    }
}
