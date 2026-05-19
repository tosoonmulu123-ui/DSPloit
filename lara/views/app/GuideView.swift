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
                    Text("Panduan untuk **iPhone XR (iPhone11,8) · iOS 18.2 · build 22C152**. Setelah reboot, ulangi dari Langkah 1.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Section("Status sekarang") {
                    SystemStatusStrip(mgr: mgr)
                        .listRowBackground(Color.clear)
                    checklistRow("Kernel (KRW)", mgr.dsready)
                    checklistRow("Kernelcache (XPF)", mgr.hasOffsets)
                    checklistRow("VFS", mgr.vfsready)
                    checklistRow("Sandbox", mgr.sbxready)
                    checklistRow("RemoteCall", mgr.rcready)
                }

                Section {
                    stepHeader("Langkah 1", "Jalankan exploit")
                    stepBody("""
                    Tab **Main** → tap **Jailbreak** → tunggu sampai selesai atau gagal di sandbox.

                    **Sukses di Logs:** baris hijau `(ds) exploit success!` dan `kernel r/w is ready!`

                    **Tidak perlu reboot** setelah ini.
                    """)
                }

                Section {
                    stepHeader("Langkah 2", "Kernelcache (wajib untuk AMFI)")
                    stepBody("""
                    **Settings** (ikon gear) → bagian **Kernelcache**:

                    • Pertama kali: tap **Fetch Kernelcache** (harus **setelah** Langkah 1).
                    • Kalau sudah pernah: jangan hapus kecuali bermasalah.
                    • **Remove** hanya jika mau mulai bersih → Fetch lagi.

                    **Sukses di Logs:** `(kcache) XPF resolve OK` atau `(offs) kernproc: 0x...`

                    **Gagal:** `(offs) kernelcache download failed` → coba **Import** file dari IPSW 22C152 (lihat info ⓘ di Settings).
                    """)
                }

                Section {
                    stepHeader("Langkah 3", "AMFI Lab (tanpa jailbreak penuh)")
                    stepBody("""
                    Cukup **Langkah 1 + 2**. Tab **Root** → **AMFI Lab** → **Jailbreak Path**:

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
