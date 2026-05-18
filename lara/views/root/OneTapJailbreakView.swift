//
//  OneTapJailbreakView.swift
//  DSPloit
//
//  One-tap jailbreak — chains all steps automatically
//

import SwiftUI

struct OneTapJailbreakView: View {
    @ObservedObject private var engine = JailbreakEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    @ObservedObject private var root = RootExecutor.shared
    
    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            
            // Status icon
            ZStack {
                Circle()
                    .fill(statusColor.opacity(0.1))
                    .frame(width: 120, height: 120)
                
                Circle()
                    .stroke(statusColor.opacity(0.3), lineWidth: 3)
                    .frame(width: 120, height: 120)
                
                if engine.isRunning {
                    Circle()
                        .trim(from: 0, to: engine.progress)
                        .stroke(statusColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                        .frame(width: 120, height: 120)
                        .rotationEffect(.degrees(-90))
                        .animation(.easeInOut, value: engine.progress)
                }
                
                Image(systemName: statusIcon)
                    .font(.system(size: 44))
                    .foregroundStyle(statusColor)
            }
            
            // Status text
            Text(engine.state.rawValue)
                .font(.title3.bold())
                .foregroundStyle(statusColor)
            
            if let error = engine.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }
            
            // Progress steps
            VStack(alignment: .leading, spacing: 8) {
                StepRow(label: "Kernel Exploit", done: mgr.dsready, active: engine.state == .exploiting)
                StepRow(label: "VFS + Sandbox", done: mgr.vfsready && mgr.sbxready, active: engine.state == .initializing)
                StepRow(label: "RemoteCall", done: mgr.rcready, active: engine.state == .connectingRC)
                StepRow(label: "Root (uid=0)", done: root.rootConfirmed, active: engine.state == .verifyingRoot)
                StepRow(label: "Bootstrap", done: engine.isJailbroken, active: engine.state == .bootstrapping)
            }
            .padding(.horizontal, 40)
            
            Spacer()
            
            // Main button
            #if !DISABLE_REMOTECALL
            Button(action: { engine.runFullChain() }) {
                HStack {
                    Image(systemName: engine.isJailbroken ? "checkmark.circle.fill" : "bolt.fill")
                    Text(engine.isJailbroken ? "Jailbroken" : "Jailbreak")
                        .font(.headline)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(engine.isJailbroken ? Color.green : Color.red)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .disabled(engine.isRunning || engine.isJailbroken)
            .padding(.horizontal, 24)
            #endif
            
            // Log (collapsible)
            if !engine.log.isEmpty {
                DisclosureGroup("Log") {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(engine.log, id: \.self) { line in
                                Text(line)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .frame(maxHeight: 150)
                }
                .padding(.horizontal, 24)
            }
            
            Spacer().frame(height: 20)
        }
        .navigationTitle("Jailbreak")
        .navigationBarTitleDisplayMode(.inline)
    }
    
    private var statusColor: Color {
        if engine.isJailbroken { return .green }
        if engine.state == .failed { return .red }
        if engine.isRunning { return .blue }
        return .secondary
    }
    
    private var statusIcon: String {
        if engine.isJailbroken { return "lock.open.fill" }
        if engine.state == .failed { return "xmark.circle.fill" }
        if engine.isRunning { return "bolt.circle.fill" }
        return "lock.fill"
    }
}

struct StepRow: View {
    let label: String
    let done: Bool
    let active: Bool
    
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: done ? "checkmark.circle.fill" : (active ? "circle.dotted" : "circle"))
                .foregroundStyle(done ? Color.green : (active ? Color.blue : Color.secondary))
                .font(.body)
            Text(label)
                .font(.subheadline)
                .foregroundStyle(done ? Color.primary : (active ? Color.blue : Color.secondary))
            Spacer()
            if active {
                ProgressView()
                    .scaleEffect(0.7)
            }
        }
    }
}
