//
//  ContentView.swift
//  DSPloit
//
//  Main tab — One-Tap Jailbreak + status
//

import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var mgr: dspmgr
    @ObservedObject private var jb = JailbreakEngine.shared
    @ObservedObject private var root = RootExecutor.shared
    
    @State private var showSettings = false
    
    init() { globallogger.capture() }
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                ScrollView {
                    VStack(spacing: 20) {
                        Spacer().frame(height: 20)
                        
                        // Main status circle
                        StatusCircle()
                        
                        // Progress steps
                        StepsView()
                        
                        // Jailbreak button
                        JailbreakButton()
                        
                        // Actions
                        ActionsView()
                        
                        // Info
                        if mgr.dsready {
                            InfoView()
                        }
                        
                        Spacer().frame(height: 20)
                    }
                    .padding(.horizontal, 24)
                }
            }
            .background(Color(.systemBackground))
            .navigationTitle("DSPloit")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(action: { showSettings.toggle() }) {
                        Image(systemName: "gear")
                    }
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
            }
        }
    }
    
    // MARK: - Status Circle
    
    @ViewBuilder
    private func StatusCircle() -> some View {
        ZStack {
            // Background ring
            Circle()
                .stroke(Color.secondary.opacity(0.15), lineWidth: 6)
                .frame(width: 140, height: 140)
            
            // Progress ring
            if jb.isRunning {
                Circle()
                    .trim(from: 0, to: jb.progress)
                    .stroke(Color.blue, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                    .frame(width: 140, height: 140)
                    .rotationEffect(.degrees(-90))
                    .animation(.easeInOut(duration: 0.3), value: jb.progress)
            } else if isJailbroken {
                Circle()
                    .stroke(Color.green, lineWidth: 6)
                    .frame(width: 140, height: 140)
            }
            
            // Icon
            VStack(spacing: 6) {
                Image(systemName: statusIcon)
                    .font(.system(size: 40))
                    .foregroundStyle(statusColor)
                
                Text(statusText)
                    .font(.caption.bold())
                    .foregroundStyle(statusColor)
            }
        }
    }
    
    // MARK: - Steps
    
    @ViewBuilder
    private func StepsView() -> some View {
        VStack(spacing: 8) {
            JBStep(num: 1, label: "Kernel Exploit", done: mgr.dsready, active: jb.state == .exploiting)
            JBStep(num: 2, label: "System Init", done: mgr.vfsready && mgr.sbxready, active: jb.state == .initializing)
            JBStep(num: 3, label: "RemoteCall", done: mgr.rcready, active: jb.state == .connectingRC)
            JBStep(num: 4, label: "Root Access", done: root.rootConfirmed, active: jb.state == .verifyingRoot)
            JBStep(num: 5, label: "Bootstrap", done: jb.isJailbroken, active: jb.state == .bootstrapping)
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color(.secondarySystemGroupedBackground)))
    }
    
    // MARK: - Jailbreak Button
    
    @ViewBuilder
    private func JailbreakButton() -> some View {
        #if !DISABLE_REMOTECALL
        Button(action: {
            if !jb.isRunning && !isJailbroken {
                jb.runFullChain()
            }
        }) {
            HStack(spacing: 10) {
                if jb.isRunning {
                    ProgressView()
                        .tint(.white)
                } else {
                    Image(systemName: isJailbroken ? "checkmark.circle.fill" : "bolt.fill")
                }
                Text(isJailbroken ? "Jailbroken" : (jb.isRunning ? jb.state.rawValue : "Jailbreak"))
                    .font(.headline)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 16)
            .background(isJailbroken ? Color.green : (jb.isRunning ? Color.blue : Color.red))
            .foregroundStyle(.white)
            .clipShape(RoundedRectangle(cornerRadius: 14))
        }
        .disabled(jb.isRunning || isJailbroken)
        
        if let error = jb.errorMessage {
            Text(error)
                .font(.caption)
                .foregroundStyle(.red)
                .multilineTextAlignment(.center)
        }
        #endif
    }
    
    // MARK: - Actions
    
    @ViewBuilder
    private func ActionsView() -> some View {
        VStack(spacing: 0) {
            Button(action: safeRespring) {
                HStack {
                    Image(systemName: "arrow.clockwise")
                        .foregroundStyle(.blue)
                        .frame(width: 24)
                    Text("Safe Respring")
                        .font(.subheadline)
                        .foregroundStyle(.primary)
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .buttonStyle(.plain)
            
            Divider().padding(.leading, 52)
            
            #if !DISABLE_REMOTECALL
            Button(action: {
                mgr.rcfailed = false
                mgr.rcLastError = nil
                mgr.rcinit(process: "SpringBoard", migbypass: false) { _ in }
            }) {
                HStack {
                    Image(systemName: "arrow.counterclockwise")
                        .foregroundStyle(.orange)
                        .frame(width: 24)
                    Text("Re-init RemoteCall")
                        .font(.subheadline)
                        .foregroundStyle(.primary)
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .buttonStyle(.plain)
            #endif
        }
        .background(RoundedRectangle(cornerRadius: 14).fill(Color(.secondarySystemGroupedBackground)))
    }
    
    // MARK: - Info
    
    @ViewBuilder
    private func InfoView() -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Kernel")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(String(format: "0x%llx", mgr.kernbase))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.orange)
            }
            HStack {
                Text("Slide")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Text(String(format: "0x%llx", mgr.kernslide))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.purple)
            }
            if let error = mgr.rcLastError {
                HStack {
                    Text("Error")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text(error)
                        .font(.system(size: 10))
                        .foregroundStyle(.red)
                        .lineLimit(1)
                }
            }
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color(.secondarySystemGroupedBackground)))
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
        if jb.isRunning { return "bolt.circle.fill" }
        if jb.state == .failed { return "xmark.circle.fill" }
        return "lock.fill"
    }
    
    private var statusColor: Color {
        if isJailbroken { return .green }
        if jb.isRunning { return .blue }
        if jb.state == .failed { return .red }
        return .secondary
    }
    
    private var statusText: String {
        if isJailbroken { return "Jailbroken" }
        if jb.isRunning { return "Working..." }
        if jb.state == .failed { return "Failed" }
        return "Locked"
    }
}

// MARK: - Step Row

struct JBStep: View {
    let num: Int
    let label: String
    let done: Bool
    let active: Bool
    
    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(done ? Color.green : (active ? Color.blue : Color.secondary.opacity(0.2)))
                    .frame(width: 28, height: 28)
                
                if done {
                    Image(systemName: "checkmark")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundStyle(.white)
                } else if active {
                    ProgressView()
                        .scaleEffect(0.5)
                        .tint(.white)
                } else {
                    Text("\(num)")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundStyle(.secondary)
                }
            }
            
            Text(label)
                .font(.subheadline)
                .foregroundStyle(done ? Color.primary : (active ? Color.blue : Color.secondary))
            
            Spacer()
            
            if done {
                Image(systemName: "checkmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.green)
            }
        }
    }
}
