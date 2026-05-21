//
//  GuideView.swift
//  DSPloit — Quick Start Guide
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

                    **Failed:** `(offs) kernelcache download failed` → try **Import** from your IPSW (see info ⓘ in Settings).
                    """)
                }

                Section {
                    stepHeader("Step 3", "Full Jailbreak")
                    stepBody("""
                    If Jailbreak on Main completes with **🎉 Jailbreak complete!** → bootstrap `/var/jb` is ready.

                    Open **Root** tab to access:
                    • **File Manager** — browse filesystem with root access
                    • **Packages** — install Sileo, Filza, tweaks (.deb)
                    • **Banking** — hide jailbreak from banking apps
                    """)
                }

                Section {
                    stepHeader("Optional", "AMFI Lab (advanced)")
                    stepBody("""
                    Only need **Step 1 + 2**. **Root** tab → **AMFI Lab** → **Jailbreak Path**:

                    ① **Physmap Access (74)** — wait for green (skip if already verified).
                    ② **Trust Cache Probe (77)** — read results in card + Logs.

                    **Do NOT close app** from app switcher (can cause panic). Use **Respring** on Main if needed.
                    """)
                }

                Section("Reading Logs") {
                    Label("Tap terminal icon on Main → filter chips: Exploit, Offsets, Kcache", systemImage: "terminal")
                    Label("Green = success · Red = failed · Orange = warning", systemImage: "paintpalette")
                    Label("Tap a line = copy to clipboard", systemImage: "doc.on.doc")
                    Label("Settings → disable **Plain Log** for colors + filter chips", systemImage: "text.alignleft")
                }

                Section("Warnings") {
                    Label("Reboot = jailbreak lost — repeat Steps 1–2", systemImage: "arrow.clockwise")
                    Label("AMFI Inject can panic — only after Probe is green", systemImage: "exclamationmark.triangle")
                    Label("Don't read __ppl_data (auto-skipped in Probe)", systemImage: "hand.raised")
                }
            }
            .navigationTitle("Guide")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
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
