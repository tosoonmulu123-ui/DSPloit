//
//  RootDashboardView.swift
//  DSPloit
//
//  Root tools — clean native list style
//

import SwiftUI

struct RootDashboardView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    @ObservedObject private var jb = JailbreakEngine.shared
    @State private var showGuide = false

    private var rootReady: Bool {
        mgr.rcready || root.rootConfirmed || jb.isJailbroken
    }

    var body: some View {
        NavigationStack {
            List {
                if rootReady {
                    Section("Tools") {
                        toolRow("folder.fill", "File Manager", "Browse and edit files", .blue, RootFileManagerView())
                        toolRow("shippingbox.fill", "Packages", "Install apps and tweaks", .purple, PackageManagerView())
                        toolRow("building.columns.fill", "Banking", "Hide jailbreak detection", .green, MobileBankingView())
                        toolRow("gearshape.2.fill", "Daemons", "Manage system services", .orange, DaemonDisableView())
                        toolRow("flask.fill", "Experiments", "Test trust cache inject", .red, ExperimentsView())
                    }
                } else {
                    Section {
                        VStack(spacing: 12) {
                            Image(systemName: "lock.fill")
                                .font(.largeTitle)
                                .foregroundStyle(.secondary)
                            Text("Root Not Active")
                                .font(.headline)
                            Text("Run Jailbreak from the Main tab first.")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 32)
                    }
                }
            }
            .navigationTitle("Root")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    HStack(spacing: 16) {
                        Button { mgr.showLogs.toggle() } label: {
                            Image(systemName: "terminal")
                        }
                        Button { showGuide = true } label: {
                            Image(systemName: "questionmark.circle")
                        }
                    }
                }
            }
            .sheet(isPresented: $showGuide) {
                GuideView()
            }
        }
    }

    private func toolRow<D: View>(_ icon: String, _ title: String, _ subtitle: String, _ color: Color, _ dest: D) -> some View {
        NavigationLink(destination: dest) {
            HStack(spacing: 14) {
                Image(systemName: icon)
                    .font(.body)
                    .foregroundStyle(color)
                    .frame(width: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.body)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 4)
        }
    }
}
