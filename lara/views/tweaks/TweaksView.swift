//
//  TweaksView.swift
//  DSPloit
//

import SwiftUI

struct TweaksView: View {
    @AppStorage("logsdisplaymode") private var selectedlogsdisplaymode: logsdisplaymode = .toolbar
    @ObservedObject var mgr: dspmgr
    @State private var showGuide = false

    var body: some View {
        NavigationStack {
            List {
                if !mgr.dsready {
                    Section {
                        ReadinessBanner(mgr: mgr, requirement: .kernel)
                    }
                } else {
                    Section {
                        SystemStatusStrip(mgr: mgr)
                            .listRowBackground(Color.clear)
                    }
                }

                Section {
                    featureLink("person.badge.key.fill", "Root Operations", "Shell, files, banking — sama seperti tab Root", .red, RootDashboardView(), req: .remoteCall)
                } header: {
                    HeaderLabel(text: "Root", icon: "person.badge.key.fill")
                }

                Section {
                    featureLink("house", "RemoteCall Customizer", "Ubah SpringBoard via RC", .blue, RemoteView(mgr: mgr), req: .remoteCall)
                    featureLink("drop.fill", "Liquid Glass", "Efek kaca iOS 26", .cyan, LiquidGlassView(), req: .vfs)
                    experimentalRow("moon.fill", "DarkBoard", "Icon themer — masih eksperimental", .indigo)
                } header: {
                    HeaderLabel(text: "SpringBoard", icon: "house")
                }

                Section {
                    featureLink("lock", "Passcode Theme", "Tema layar kunci", .purple, PasscodeView(mgr: mgr), req: .sandbox)
                } header: {
                    HeaderLabel(text: "Lock Screen", icon: "lock")
                }

                Section {
                    featureLink("creditcard", "Card Overwrite", "Ganti kartu App Store", .orange, CardView(), req: .vfs)
                    featureLink("app.badge", "3 App Bypass", "Bypass limit 3 app", .green, AppsView(), req: .sandbox)
                    featureLink("checkmark.shield", "Unblacklist", "Whitelist bundle ID", .mint, WhitelistView(), req: .sandbox)
                    featureLink("bolt", "JIT Enabler", "JIT untuk emulator", .yellow, JitView(), req: .sandbox)
                } header: {
                    HeaderLabel(text: "Apps", icon: "app")
                }

                Section {
                    featureLink("paintbrush", "dirtyZero", "Tweak UI tanpa file permanen", .pink, dirtyZeroView(), req: .vfs)
                    featureLink("iphone", "MobileGestalt", "Ubah identitas device", .teal, GestaltView(), req: .sandbox)
                    featureLink("textformat", "Font Overwrite", "Ganti font sistem", .brown, FontPicker(mgr: mgr), req: .vfs)
                    featureLink("paintpalette", "SystemColor", "Patch warna sistem", .indigo, SystemColor(mgr: mgr), req: .vfs, extra: mgr.sbxready)
                } header: {
                    HeaderLabel(text: "User Interface", icon: "eye")
                } footer: {
                    Text("Kebanyakan tweak butuh respring. Jika gagal, jailbreak ulang dari Home.")
                        .font(.caption2)
                }

                Section {
                    featureLink("trash", "VarClean", "Hapus jejak jailbreak", .red, VarCleanView(), req: .sandbox)
                    featureLink("doc.badge.gearshape", "Custom Overwrite", "Tulis file custom", .gray, CustomView(mgr: mgr), req: .vfs)
                    NavigationLink {
                        ToolsView()
                    } label: {
                        FeatureLinkRow(
                            icon: "wrench.and.screwdriver",
                            title: "Extra Tools",
                            subtitle: "ASLR, sandbox token, respring",
                            color: .secondary,
                            badge: mgr.dsready ? .ready : .locked,
                            disabled: !mgr.dsready
                        )
                    }
                    .disabled(!mgr.dsready)
                } header: {
                    HeaderLabel(text: "System", icon: "gear")
                }
            }
            .disabled(!mgr.dsready)
            .navigationTitle("Tweaks")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showGuide = true
                    } label: {
                        Image(systemName: "questionmark.circle")
                    }
                }
                if selectedlogsdisplaymode == .toolbar {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button {
                            mgr.showLogs.toggle()
                        } label: {
                            Image(systemName: "terminal")
                        }
                    }
                }
            }
            .sheet(isPresented: $showGuide) {
                GuideView()
            }
        }
        .premiumStyling()
    }

    @ViewBuilder
    private func featureLink<D: View>(
        _ icon: String,
        _ title: String,
        _ subtitle: String,
        _ color: Color,
        _ dest: D,
        req: DSPRequirement,
        extra: Bool = true
    ) -> some View {
        let enabled = req.isMet(by: mgr) && extra
        NavigationLink(destination: dest) {
            FeatureLinkRow(
                icon: icon,
                title: title,
                subtitle: subtitle,
                color: color,
                badge: enabled ? .ready : .locked,
                disabled: !enabled
            )
        }
        .disabled(!enabled)
    }

    private func experimentalRow(_ icon: String, _ title: String, _ subtitle: String, _ color: Color) -> some View {
        HStack {
            FeatureLinkRow(
                icon: icon,
                title: title,
                subtitle: subtitle,
                color: color,
                badge: .beta,
                disabled: true
            )
        }
    }
}
