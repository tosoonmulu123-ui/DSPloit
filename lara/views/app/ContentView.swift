//
//  ContentView.swift
//  DSPloit
//
//  Main tab — user-friendly, clean iOS native style
//

import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var mgr: dspmgr
    @ObservedObject private var jb = JailbreakEngine.shared
    @ObservedObject private var root = RootExecutor.shared
    
    @State private var showSettings = false
    @State private var showGuide = false

    init() { globallogger.capture() }
    
    var body: some View {
        NavigationStack {
            List {
                // Main status
                Section {
                    mainStatusRow
                }
                
                // Jailbreak button
                Section {
                    jailbreakButton
                } footer: {
                    if !isJailbroken && !jb.isRunning {
                        Text("Tap to unlock full device access. This may take 30–60 seconds.")
                    }
                }
                
                // Progress (only while running)
                if jb.isRunning {
                    Section("Progress") {
                        ProgressView(value: jb.progress)
                            .tint(.blue)
                        Text(jb.state.rawValue)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                
                // Actions (after jailbreak)
                if isJailbroken {
                    Section("Quick Actions") {
                        Button(action: safeRespring) {
                            Label("Respring", systemImage: "arrow.clockwise")
                        }
                        #if !DISABLE_REMOTECALL
                        Button {
                            mgr.rcfailed = false
                            mgr.rcLastError = nil
                            mgr.rcinit(process: "SpringBoard", migbypass: false) { _ in }
                        } label: {
                            Label("Reconnect", systemImage: "wifi.exclamationmark")
                        }
                        #endif
                    }
                }
                
                // Error
                if let error = jb.errorMessage {
                    Section {
                        HStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                            Text(error)
                                .font(.subheadline)
                        }
                        
                        Button("Try Again") {
                            jb.runFullChain()
                        }
                        .font(.subheadline.bold())
                    } header: {
                        Text("Error")
                    }
                }
                
                // Success banner
                if isJailbroken && !jb.isRunning {
                    Section {
                        HStack(spacing: 10) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Jailbreak Active")
                                    .font(.subheadline.bold())
                                Text("Full root access. Use Re-Jailbreak after respring/reboot.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                
                // Help (before jailbreak)
                if !isJailbroken && !jb.isRunning && jb.state != .failed {
                    Section {
                        Button { showGuide = true } label: {
                            Label("How does this work?", systemImage: "questionmark.circle")
                        }
                    }
                }
            }
            .navigationTitle("DSPloit")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { showGuide = true } label: {
                        Image(systemName: "questionmark.circle")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    HStack(spacing: 16) {
                        Button { mgr.showLogs.toggle() } label: {
                            Image(systemName: "terminal")
                        }
                        Button { showSettings = true } label: {
                            Image(systemName: "gear")
                        }
                    }
                }
            }
            .sheet(isPresented: $showSettings) { SettingsView() }
            .sheet(isPresented: $showGuide) { GuideView() }
        }
    }
    
    // MARK: - Main Status
    
    private var mainStatusRow: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle()
                    .fill(statusBgColor.opacity(0.12))
                    .frame(width: 48, height: 48)
                Image(systemName: statusIcon)
                    .font(.title3)
                    .foregroundStyle(statusBgColor)
            }
            
            VStack(alignment: .leading, spacing: 3) {
                Text(statusTitle)
                    .font(.headline)
                Text(statusSubtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            
            Spacer()
        }
        .padding(.vertical, 4)
    }
    
    // MARK: - Jailbreak Button
    
    @ViewBuilder
    private var jailbreakButton: some View {
        #if !DISABLE_REMOTECALL
        Button(action: {
            guard !jb.isRunning else { return }
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            if isJailbroken {
                // Re-jailbreak: reset state and run again
                jb.isJailbroken = false
                root.rootConfirmed = false
            }
            jb.runFullChain()
        }) {
            HStack {
                Spacer()
                Group {
                    if jb.isRunning {
                        ProgressView().tint(.white)
                    } else {
                        Image(systemName: isJailbroken ? "arrow.clockwise" : "bolt.fill")
                    }
                }
                Text(isJailbroken ? "Re-Jailbreak" : (jb.isRunning ? "Working..." : "Jailbreak"))
                    .fontWeight(.semibold)
                Spacer()
            }
            .foregroundStyle(.white)
            .padding(.vertical, 14)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(isJailbroken ? Color.orange : (jb.isRunning ? Color.blue : Color.accentColor))
            )
        }
        .disabled(jb.isRunning)
        .listRowInsets(EdgeInsets(top: 4, leading: 16, bottom: 4, trailing: 16))
        .listRowBackground(Color.clear)
        #else
        EmptyView()
        #endif
    }
    
    // MARK: - Safe Respring
    
    private func safeRespring() {
        #if !DISABLE_REMOTECALL
        if mgr.rcready, let sb = mgr.sbProc {
            let sel = remote_sel(sb, "terminateWithSuccess")
            let app = remote_getClass(sb, "UIApplication")
            let shared = remote_msg(sb, app, remote_sel(sb, "sharedApplication"), 0, 0, 0, 0)
            remote_msg(sb, shared, sel, 0, 0, 0, 0)
            return
        }
        #endif
        if mgr.dsready {
            let sbProc = mgr.findProc(name: "SpringBoard")
            if sbProc != 0 {
                let pid = Int32(ds_kread32(sbProc + 0x68))
                if pid > 0 { kill(pid, SIGKILL) }
                return
            }
        }
        mgr.respring()
    }
    
    // MARK: - Helpers
    
    private var isJailbroken: Bool {
        root.rootConfirmed || jb.isJailbroken
    }
    
    private var statusIcon: String {
        if isJailbroken { return "lock.open.fill" }
        if jb.isRunning { return "hourglass" }
        if jb.state == .failed { return "xmark.circle.fill" }
        return "lock.fill"
    }
    
    private var statusBgColor: Color {
        if isJailbroken { return .green }
        if jb.isRunning { return .blue }
        if jb.state == .failed { return .red }
        return .secondary
    }
    
    private var statusTitle: String {
        if isJailbroken { return "Jailbroken" }
        if jb.isRunning { return "In Progress" }
        if jb.state == .failed { return "Failed" }
        return "Locked"
    }
    
    private var statusSubtitle: String {
        if isJailbroken { return "Full root access active" }
        if jb.isRunning { return "\(Int(jb.progress * 100))% complete" }
        if jb.state == .failed { return "Something went wrong" }
        return "Tap Jailbreak to get started"
    }
}
