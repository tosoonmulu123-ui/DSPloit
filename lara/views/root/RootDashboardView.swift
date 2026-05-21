//
//  RootDashboardView.swift
//  DSPloit
//
//  Root tools dashboard — modern card-based layout
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
                        toolsSection
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
            sectionHeader("Jailbreak Essentials", icon: "star.fill")
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                navTool("folder.fill", "File Manager", "Root file browser", .blue, RootFileManagerView())
                navTool("shippingbox.fill", "Packages", "Install tweaks & debs", .purple, PackageManagerView())
                navTool("building.columns.fill", "Banking", "Hide jailbreak", .green, MobileBankingView())
            }
        }
    }

    private var toolsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("System Tools", icon: "wrench.and.screwdriver.fill")
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                navTool("terminal.fill", "Shell", "Root terminal", .cyan, RootShellView())
                navTool("gearshape.2.fill", "Processes", "Running processes", .indigo, RootProcessView())
                navTool("slider.horizontal.3", "Prefs Editor", "Edit system plists", .pink, PrefsEditorView())
                navTool("network", "Network", "Network tools", .teal, NetworkToolsView())
            }
        }
    }

    private var advancedSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("Advanced", icon: "bolt.shield.fill")
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                navTool("shippingbox.circle.fill", "Bootstrap", "Setup /var/jb", .orange, BootstrapView())
                navTool("flask.fill", "AMFI Lab", "Experiments", .red, AMFIExperimentView(), badge: .advanced)
                navTool("arrow.clockwise.circle.fill", "Persistence", "Survive reboot", .mint, RootPersistenceView())
                navTool("ladybug.fill", "Daemons", "LaunchDaemons", .brown, DaemonManagerView())
            }
        }
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
