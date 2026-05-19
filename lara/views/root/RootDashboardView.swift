//
//  RootDashboardView.swift
//  DSPloit
//
//  Root tools dashboard — just tools, no status (main tab has that)
//

import SwiftUI

struct RootDashboardView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    @ObservedObject private var jb = JailbreakEngine.shared
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if mgr.rcready || root.rootConfirmed || jb.isJailbroken {
                        // Tools Grid
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                            NavigationLink(destination: RootShellView()) {
                                ToolCard(icon: "terminal.fill", title: "Shell", color: .red)
                            }
                            NavigationLink(destination: RootFileManagerView()) {
                                ToolCard(icon: "folder.fill", title: "Files", color: .blue)
                            }
                            NavigationLink(destination: RootProcessView()) {
                                ToolCard(icon: "play.circle.fill", title: "Processes", color: .orange)
                            }
                            NavigationLink(destination: TweaksManagerView()) {
                                ToolCard(icon: "paintbrush.fill", title: "Tweaks", color: .pink)
                            }
                            NavigationLink(destination: BootstrapView()) {
                                ToolCard(icon: "shippingbox.fill", title: "Bootstrap", color: .cyan)
                            }
                            NavigationLink(destination: PrefsEditorView()) {
                                ToolCard(icon: "slider.horizontal.3", title: "Prefs", color: .mint)
                            }
                            NavigationLink(destination: RootPersistenceView()) {
                                ToolCard(icon: "arrow.clockwise", title: "Persist", color: .purple)
                            }
                            NavigationLink(destination: NetworkToolsView()) {
                                ToolCard(icon: "network", title: "Network", color: .indigo)
                            }
                            NavigationLink(destination: AMFIExperimentView()) {
                                ToolCard(icon: "flask.fill", title: "AMFI Lab", color: .yellow)
                            }
                            NavigationLink(destination: SystemInfoView()) {
                                ToolCard(icon: "info.circle.fill", title: "System", color: .teal)
                            }
                        }
                    } else {
                        // Not jailbroken yet
                        VStack(spacing: 12) {
                            Spacer().frame(height: 40)
                            Image(systemName: "lock.fill")
                                .font(.system(size: 40))
                                .foregroundStyle(.secondary)
                            Text("Jailbreak from main tab first")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                            Spacer()
                        }
                    }
                    
                    // About
                    VStack(spacing: 4) {
                        Text("DSPloit")
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                        Text("Rootless Jailbreak • iOS 17-26 • A10-A18")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    .padding(.top, 20)
                }
                .padding(.horizontal, 16)
                .padding(.top, 12)
            }
            .navigationTitle("Root Tools")
            .background(Color(.systemGroupedBackground))
        }
    }
}

// MARK: - Tool Card

struct ToolCard: View {
    let icon: String
    let title: String
    let color: Color
    
    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 22))
                .foregroundStyle(color)
            Text(title)
                .font(.caption.bold())
                .foregroundStyle(.primary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 18)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(.secondarySystemGroupedBackground))
        )
    }
}

// MARK: - Keep ToolRow for other views
struct ToolRow: View {
    let icon: String
    let title: String
    let subtitle: String
    let color: Color
    
    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(color.opacity(0.12))
                    .frame(width: 40, height: 40)
                Image(systemName: icon)
                    .font(.system(size: 18))
                    .foregroundStyle(color)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.bold())
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}
