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
                            message: "Jalankan Jailbreak di tab Home sampai langkah RemoteCall dan Root hijau.",
                            buttonTitle: "Buka Panduan",
                            action: { showGuide = true }
                        )
                    }

                    VStack(spacing: 4) {
                        Text("DSPloit")
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                        Text("Rootless • iOS 16–26 • A10–A18")
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
                    Button {
                        showGuide = true
                    } label: {
                        Image(systemName: "questionmark.circle")
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
            sectionHeader("Essentials", icon: "star.fill")
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                navTool("terminal.fill", "Shell", "Perintah root", .red, RootShellView())
                navTool("folder.fill", "Files", "Baca/tulis file", .blue, RootFileManagerView())
                navTool("building.columns.fill", "Banking", "Sembunyikan /var/jb", .green, MobileBankingView())
                navTool("shippingbox.fill", "Bootstrap", "/var/jb setup", .cyan, BootstrapView())
                navTool("play.circle.fill", "Processes", "Daftar proses", .orange, RootProcessView())
                navTool("info.circle.fill", "System", "Info perangkat", .teal, SystemInfoView())
            }
        }
    }

    private var advancedSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            sectionHeader("Advanced", icon: "gearshape.2.fill")
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                navTool("paintbrush.fill", "Tweaks", "SpringBoard RC", .pink, TweaksManagerView())
                navTool("slider.horizontal.3", "Prefs", "Edit plist", .mint, PrefsEditorView())
                navTool("arrow.clockwise", "Persist", "LaunchDaemon", .purple, RootPersistenceView())
                navTool("network", "Network", "hosts, DNS", .indigo, NetworkToolsView())
                navTool("gear.badge", "Daemons", "Kelola daemon", .brown, DaemonManagerView())
                navTool("flask.fill", "AMFI Lab", "Riset AMFI", .yellow, AMFIExperimentView(), badge: .advanced)
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
