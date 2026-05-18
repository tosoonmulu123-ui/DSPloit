//
//  TweaksView.swift
//  DSPloit
//
//  Created by lunginspector on 5/3/26.
//

import SwiftUI

struct TweaksView: View {
    @AppStorage("logsdisplaymode") private var selectedlogsdisplaymode: logsdisplaymode = .toolbar
    @ObservedObject var mgr: dspmgr
    
    var body: some View {
        NavigationStack {
            List {
                // Root Operations
                Section(header: HeaderLabel(text: "Root", icon: "person.badge.key.fill")) {
                    NavigationLink(destination: RootDashboardView()) {
                        HStack(spacing: 14) {
                            Image(systemName: "person.badge.key.fill")
                                .font(.title3)
                                .foregroundStyle(.red)
                                .frame(width: 32)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Root Operations")
                                    .font(.subheadline.weight(.semibold))
                                Text("Shell, file manager, spawn, persistence")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 3)
                    }
                    .disabled(!mgr.rcready)
                }
                
                Section(header: HeaderLabel(text: "SpringBoard", icon: "house")) {
                    NavigationLink("RemoteCall Customizer", destination: RemoteView(mgr: mgr))
                        .disabled(!mgr.rcready)
                    NavigationLink("DarkBoard", destination: DarkBoardView())
                        .disabled(true)
                    NavigationLink("Liquid Glass", destination: LiquidGlassView())
                        .disabled(!mgr.vfsready)
                }
                
                Section(header: HeaderLabel(text: "Lock Screen", icon: "lock")) {
                    NavigationLink("Passcode Theme", destination: PasscodeView(mgr: mgr))
                        .disabled(!mgr.sbxready)
                }
                
                Section(header: HeaderLabel(text: "Apps", icon: "app")) {
                    NavigationLink("Card Overwrite", destination: CardView())
                        .disabled(!mgr.vfsready)
                    NavigationLink("3 App Bypass", destination: AppsView())
                        .disabled(!mgr.sbxready)
                    NavigationLink("Unblacklist", destination: WhitelistView())
                        .disabled(!mgr.sbxready)
                    NavigationLink("JIT Enabler", destination: JitView())
                        .disabled(!mgr.sbxready)
                }
                
                Section(header: HeaderLabel(text: "User Interface", icon: "eye")) {
                    NavigationLink("dirtyZero", destination: dirtyZeroView())
                        .disabled(!mgr.vfsready)
                    NavigationLink("MobileGestalt", destination: GestaltView())
                        .disabled(!mgr.sbxready)
                    NavigationLink("Font Overwrite", destination: FontPicker(mgr: mgr))
                        .disabled(!mgr.vfsready)
                    NavigationLink("SystemColor Patcher", destination: SystemColor(mgr: mgr))
                        .disabled(!mgr.sbxready || !mgr.vfsready)
                }
                
                Section(header: HeaderLabel(text: "System", icon: "gear")) {
                    NavigationLink("VarClean", destination: VarCleanView())
                        .disabled(!mgr.sbxready)
                    NavigationLink("Custom Overwrite", destination: CustomView(mgr: mgr))
                        .disabled(!mgr.vfsready)
                }
                
                NavigationLink("Extra Tools", destination: ToolsView())
            }
            .disabled(!mgr.dsready)
            .navigationTitle("Tweaks")
            .toolbar {
                if selectedlogsdisplaymode == .toolbar {
                    Button(action: {
                        mgr.showLogs.toggle()
                    }) {
                        Image(systemName: "terminal")
                    }
                }
            }
        }
        .premiumStyling()
    }
}
