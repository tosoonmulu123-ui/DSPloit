//
//  RootDashboardView.swift
//  DSPloit
//
//  Main dashboard for root-level operations
//

import SwiftUI

struct RootDashboardView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    var body: some View {
        NavigationStack {
            List {
                // Status
                Section {
                    HStack(spacing: 14) {
                        ZStack {
                            Circle()
                                .fill(statusColor.opacity(0.15))
                                .frame(width: 50, height: 50)
                            Image(systemName: statusIcon)
                                .font(.title2)
                                .foregroundStyle(statusColor)
                        }
                        VStack(alignment: .leading, spacing: 4) {
                            Text(statusTitle)
                                .font(.headline)
                            Text(statusSubtitle)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                }
                
                // Root Tools
                Section {
                    NavigationLink(destination: RootShellView()) {
                        ToolRow(icon: "terminal.fill", title: "Root Shell", subtitle: "Execute commands as uid=0", color: .red)
                    }
                    
                    NavigationLink(destination: RootFileManagerView()) {
                        ToolRow(icon: "folder.fill", title: "File Manager", subtitle: "Read/write files with root access", color: .blue)
                    }
                    
                    NavigationLink(destination: RootProcessView()) {
                        ToolRow(icon: "play.circle.fill", title: "Process Manager", subtitle: "Spawn & manage root processes", color: .orange)
                    }
                    
                    NavigationLink(destination: RootPersistenceView()) {
                        ToolRow(icon: "arrow.clockwise.circle.fill", title: "Persistence", subtitle: "LaunchDaemons, KRW stash, boot hooks", color: .purple)
                    }
                } header: {
                    Text("Root Tools")
                }
                
                // Quick Actions
                Section {
                    Button(action: { root.verifyRoot() }) {
                        HStack {
                            Label("Verify Root", systemImage: "checkmark.shield")
                            Spacer()
                            if root.isExecuting {
                                ProgressView()
                            } else if root.rootConfirmed {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                    .disabled(!mgr.rcready || root.isExecuting)
                } header: {
                    Text("Quick Actions")
                }
                
                // Credits
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("DSPloit")
                            .font(.subheadline.bold())
                        Text("iOS 18.2 root exploit — iPhone XR (A12)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("Based on [lara](https://github.com/royan) by royan")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("About")
                }
            }
            .navigationTitle("DSPloit")
        }
    }
    
    private var statusColor: Color {
        if root.rootConfirmed { return .green }
        if mgr.rcready { return .blue }
        if mgr.dsready { return .orange }
        return .secondary
    }
    
    private var statusIcon: String {
        if root.rootConfirmed { return "person.badge.key.fill" }
        if mgr.rcready { return "link.circle.fill" }
        if mgr.dsready { return "bolt.shield.fill" }
        return "lock.fill"
    }
    
    private var statusTitle: String {
        if root.rootConfirmed { return "Root Active" }
        if mgr.rcready { return "RemoteCall Ready" }
        if mgr.dsready { return "Kernel Exploited" }
        return "Not Exploited"
    }
    
    private var statusSubtitle: String {
        if root.rootConfirmed { return "uid=0 via launchd — full access" }
        if mgr.rcready { return "SpringBoard connected — tap Verify Root" }
        if mgr.dsready { return "KRW active — initialize system next" }
        return "Run exploit from Setup tab"
    }
}

// MARK: - Reusable Row

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
                Text(title)
                    .font(.subheadline.bold())
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}
