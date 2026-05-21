//
//  RootDashboardView.swift
//  DSPloit
//
//  Root tools dashboard
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
                VStack(spacing: 16) {
                    SystemStatusStrip(mgr: mgr)
                        .padding(.horizontal, 4)

                    if rootReady {
                        essentialsSection
                        advancedSection
                    } else {
                        EmptyStateView(
                            icon: "lock.fill",
                            title: "Root belum aktif",
                            message: "Jalankan Jailbreak di tab Main sampai langkah RemoteCall dan Root hijau.",
                            buttonTitle: "Buka Panduan",
                            action: { showGuide = true }
                        )
                    }

                    VStack(spacing: 4) {
                        Text("DSPloit")
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                        Text("iOS 16–18.2 • A11–A18 • Full Jailbreak")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    .padding(.top, 8)
                }
                .padding(.horizontal, 16)
                .padding(.top, 12)
            }
            .navigationTitle("Root")
            .background(Color(.systemGroupedBackground))
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

    // MARK: - Sections

    private var essentialsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("Jailbreak Tools", icon: "star.fill")
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                navTool("folder.fill", "Filza", "File manager", .blue, RootFileManagerView())
                navTool("shippingbox.fill", "Sileo", "Package manager", .purple, BootstrapView())
                navTool("building.columns.fill", "Banking", "Hide jailbreak", .green, MobileBankingView())
            }
        }
    }

    private var advancedSection: some View {
        EmptyView()
    }

    private func sectionHeader(_ title: String, icon: String) -> some View {
        Label(title, systemImage: icon)
            .font(.subheadline.bold())
            .foregroundStyle(.secondary)
            .padding(.leading, 4)
    }

    private func navTool<D: View>(
        _ icon: String,
        _ title: String,
        _ subtitle: String,
        _ color: Color,
        _ dest: D,
        badge: FeatureBadge? = nil
    ) -> some View {
        NavigationLink(destination: dest) {
            ToolCard(icon: icon, title: title, subtitle: subtitle, color: color, badge: badge)
        }
        .buttonStyle(.plain)
    }
}
