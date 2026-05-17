//
//  BleedingEdgeThreadHijackerView.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Kernel Thread Hijacker & Control Flow UI
//  Thread enumeration, register inspection, PC hijacking, stack pivot
//  Created by Royan
//

import SwiftUI

struct BleedingEdgeThreadHijackerView: View {
    @ObservedObject private var hijacker = KernelThreadHijacker.shared
    @ObservedObject private var mgr = dspmgr.shared
    @State private var targetPid = ""
    @State private var targetPC = ""
    @State private var selectedThread: KernelThreadState?
    @State private var showRegisters = false
    
    var body: some View {
        List {
            // Status
            Section {
                HStack(spacing: 14) {
                    ZStack {
                        Circle()
                            .fill((mgr.dsready ? Color.pink : Color.red).opacity(0.15))
                            .frame(width: 50, height: 50)
                        Image(systemName: "arrow.triangle.2.circlepath")
                            .font(.title2)
                            .foregroundStyle(mgr.dsready ? .pink : .red)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text(mgr.dsready ? "Thread Hijacker Ready" : "Kernel Access Required")
                            .font(.headline)
                        Text("\(hijacker.threads.count) threads discovered")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                HeaderLabel(text: "Thread Control", icon: "arrow.triangle.2.circlepath")
            }
            
            // Enumerate
            Section {
                HStack {
                    TextField("PID (-1 for self)", text: $targetPid)
                        .font(.system(.caption, design: .monospaced))
                        .keyboardType(.numberPad)
                    
                    Button("Scan") {
                        let pid = Int32(targetPid) ?? -1
                        hijacker.enumerateKernelThreads(forPid: pid)
                    }
                    .disabled(!mgr.dsready || hijacker.isScanning)
                }
                
                if hijacker.isScanning {
                    HStack {
                        ProgressView()
                        Text("Scanning threads...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                HeaderLabel(text: "Enumerate", icon: "magnifyingglass")
            }
            
            // Thread List
            if !hijacker.threads.isEmpty {
                Section {
                    ForEach(hijacker.threads) { thread in
                        Button(action: {
                            selectedThread = thread
                            showRegisters = true
                        }) {
                            HStack(spacing: 12) {
                                Circle()
                                    .fill(threadStateColor(thread.state))
                                    .frame(width: 8, height: 8)
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(String(format: "0x%016llx", thread.threadAddr))
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundStyle(.cyan)
                                    
                                    HStack(spacing: 8) {
                                        Text("PID: \(thread.pid)")
                                            .font(.caption2)
                                        Text("Pri: \(thread.priority)")
                                            .font(.caption2)
                                        Text(thread.state.rawValue)
                                            .font(.caption2)
                                            .foregroundStyle(threadStateColor(thread.state))
                                    }
                                    .foregroundStyle(.secondary)
                                }
                                
                                Spacer()
                                
                                VStack(alignment: .trailing, spacing: 2) {
                                    Text(String(format: "PC: 0x%llx", thread.registers.pc))
                                        .font(.system(size: 8, design: .monospaced))
                                        .foregroundStyle(.orange)
                                    Text(String(format: "%.1f%%", thread.cpuUsage))
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                } header: {
                    HeaderLabel(text: "Threads (\(hijacker.threads.count))", icon: "list.bullet")
                }
            }
            
            // Hijack Controls
            Section {
                TextField("Target PC (hex)", text: $targetPC)
                    .font(.system(.caption, design: .monospaced))
                    .autocapitalization(.none)
                
                if let thread = selectedThread {
                    HStack {
                        Text("Selected:")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(String(format: "0x%llx", thread.threadAddr))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.cyan)
                    }
                    
                    Button("⚡ Hijack Thread PC") {
                        guard let pc = UInt64(targetPC.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                        let _ = hijacker.hijackThread(threadAddr: thread.threadAddr, targetPC: pc)
                    }
                    .disabled(!mgr.dsready || targetPC.isEmpty)
                    .foregroundStyle(.red)
                    
                    Button("Suspend Thread") {
                        let _ = hijacker.suspendThread(threadAddr: thread.threadAddr)
                    }
                    .disabled(!mgr.dsready)
                    
                    Button("Resume Thread") {
                        let _ = hijacker.resumeThread(threadAddr: thread.threadAddr)
                    }
                    .disabled(!mgr.dsready)
                } else {
                    Text("Select a thread from the list above")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } header: {
                HeaderLabel(text: "Hijack Controls", icon: "bolt.fill")
            }
            
            // Hijack Results
            if !hijacker.hijackResults.isEmpty {
                Section {
                    ForEach(hijacker.hijackResults.prefix(10)) { result in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: result.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    .foregroundStyle(result.success ? .green : .red)
                                Text(result.timestamp, style: .time)
                                    .font(.caption)
                                Spacer()
                            }
                            
                            HStack {
                                Text("PC:")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                Text(String(format: "0x%llx → 0x%llx", result.originalPC, result.newPC))
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundStyle(.cyan)
                            }
                            
                            if let error = result.error {
                                Text(error)
                                    .font(.caption2)
                                    .foregroundStyle(.red)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                } header: {
                    HeaderLabel(text: "Hijack Results", icon: "list.bullet.rectangle")
                }
            }
        }
        .navigationTitle("Thread Hijacker")
        .premiumStyling()
        .sheet(isPresented: $showRegisters) {
            if let thread = selectedThread {
                RegisterInspectorView(thread: thread, hijacker: hijacker)
            }
        }
    }
    
    private func threadStateColor(_ state: KernelThreadState.ThreadRunState) -> Color {
        switch state {
        case .running: return .green
        case .waiting: return .yellow
        case .suspended: return .orange
        case .halted: return .red
        case .uninterruptible: return .purple
        }
    }
}

// MARK: - Register Inspector

struct RegisterInspectorView: View {
    let thread: KernelThreadState
    @ObservedObject var hijacker: KernelThreadHijacker
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Thread: \(String(format: "0x%016llx", thread.threadAddr))")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.orange)
                        .padding(.bottom, 8)
                    
                    // General Purpose Registers
                    ForEach(0..<31, id: \.self) { i in
                        HStack {
                            Text(String(format: "X%-2d", i))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.green)
                                .frame(width: 30, alignment: .leading)
                            Text("=")
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.secondary)
                            Text(String(format: "0x%016llx", thread.registers.x[i]))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.cyan)
                                .textSelection(.enabled)
                        }
                    }
                    
                    Divider().padding(.vertical, 4)
                    
                    // Special Registers
                    HStack {
                        Text("SP ")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.yellow)
                            .frame(width: 30, alignment: .leading)
                        Text("=")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Text(String(format: "0x%016llx", thread.registers.sp))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.cyan)
                            .textSelection(.enabled)
                    }
                    
                    HStack {
                        Text("PC ")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.red)
                            .frame(width: 30, alignment: .leading)
                        Text("=")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Text(String(format: "0x%016llx", thread.registers.pc))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.cyan)
                            .textSelection(.enabled)
                    }
                    
                    HStack {
                        Text("CPSR")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.purple)
                            .frame(width: 40, alignment: .leading)
                        Text("=")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                        Text(String(format: "0x%08x", thread.registers.cpsr))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.cyan)
                            .textSelection(.enabled)
                    }
                }
                .padding()
            }
            .background(Color.black.opacity(0.9))
            .navigationTitle("Registers")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .topBarLeading) {
                    Button("Copy") {
                        UIPasteboard.general.string = thread.registers.description
                    }
                }
            }
        }
    }
}
