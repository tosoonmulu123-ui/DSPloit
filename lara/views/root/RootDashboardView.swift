//
//  RootDashboardView.swift
//  DSPloit — Root tools
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
            ScrollView {
                if rootReady {
                    VStack(spacing: 10) {
                        toolCard("folder.fill", "File Manager", "Browse and edit files", .blue, RootFileManagerView())
                        toolCard("shippingbox.fill", "Packages", "Install apps and tweaks", .purple, PackageManagerView())
                        toolCard("building.columns.fill", "Banking", "Hide jailbreak detection", .green, MobileBankingView())
                        toolCard("gearshape.2.fill", "Daemons", "Manage system services", .orange, DaemonDisableView())
                        toolCard("flask.fill", "Experiments", "TC load + AMFI research", .red, ExperimentsView())
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 8)
                } else {
                    lockedState
                }
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Root")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    HStack(spacing: 14) {
                        Button { mgr.showLogs.toggle() } label: {
                            Image(systemName: "terminal")
                                .foregroundStyle(.secondary)
                        }
                        Button { showGuide = true } label: {
                            Image(systemName: "questionmark.circle")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .sheet(isPresented: $showGuide) { GuideView() }
        }
    }

    private func toolCard<D: View>(_ icon: String, _ title: String, _ subtitle: String, _ color: Color, _ dest: D) -> some View {
        NavigationLink(destination: dest) {
            HStack(spacing: 14) {
                Image(systemName: icon)
                    .font(.system(size: 18))
                    .foregroundStyle(color)
                    .frame(width: 32)
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 15, weight: .medium))
                        .foregroundStyle(.primary)
                    Text(subtitle)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                
                Spacer()
                
                Image(systemName: "chevron.right")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(14)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color(.secondarySystemGroupedBackground)))
        }
    }
    
    private var lockedState: some View {
        VStack(spacing: 16) {
            Spacer().frame(height: 80)
            Image(systemName: "lock.fill")
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
            Text("Root Not Active")
                .font(.system(size: 17, weight: .semibold))
            Text("Run Jailbreak from the Main tab first.")
                .font(.system(size: 13))
                .foregroundStyle(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}
