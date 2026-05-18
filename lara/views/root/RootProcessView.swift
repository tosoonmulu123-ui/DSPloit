//
//  RootProcessView.swift
//  DSPloit
//
//  Spawn and manage processes as root
//

import SwiftUI

struct RootProcessView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var binary = "/bin/ls"
    @State private var args = "-la /var/root"
    @State private var spawnResults: [(binary: String, pid: UInt64, success: Bool)] = []
    
    var body: some View {
        List {
            // Spawn
            Section {
                TextField("Binary path", text: $binary)
                    .font(.system(.body, design: .monospaced))
                TextField("Arguments", text: $args)
                    .font(.system(.caption, design: .monospaced))
                
                Button(action: {
                    let argList = args.components(separatedBy: " ").filter { !$0.isEmpty }
                    root.spawnAsRoot(binary: binary, args: argList)
                    
                    DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                        if let r = root.lastResult, r.operation == "posix_spawn" {
                            spawnResults.insert((binary: binary, pid: r.returnValue, success: r.success), at: 0)
                        }
                    }
                }) {
                    Label("Spawn as Root", systemImage: "play.circle.fill")
                        .foregroundStyle(.orange)
                }
                .disabled(!mgr.rcready || root.isExecuting)
            } header: {
                Label("posix_spawn (uid=0)", systemImage: "play.fill")
            }
            
            // Quick spawns
            Section {
                Button("ls -la /") {
                    root.spawnAsRoot(binary: "/bin/ls", args: ["-la", "/"])
                }
                Button("id") {
                    root.shellAsRoot(command: "id")
                }
                Button("cat /etc/passwd") {
                    root.shellAsRoot(command: "cat /etc/passwd")
                }
                Button("ps aux") {
                    root.shellAsRoot(command: "ps aux")
                }
            } header: {
                Label("Quick Commands", systemImage: "bolt")
            }
            .disabled(!mgr.rcready || root.isExecuting)
            
            // History
            if !spawnResults.isEmpty {
                Section {
                    ForEach(Array(spawnResults.enumerated()), id: \.offset) { _, entry in
                        HStack {
                            Image(systemName: entry.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(entry.success ? .green : .red)
                            Text(entry.binary)
                                .font(.system(.caption, design: .monospaced))
                            Spacer()
                            if entry.success {
                                Text("PID \(entry.pid)")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    Label("History", systemImage: "clock")
                }
            }
            
            // Result
            if let r = root.lastResult {
                Section {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Image(systemName: r.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(r.success ? .green : .red)
                            Text(r.operation)
                                .font(.caption.bold())
                        }
                        Text(r.message)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                } header: {
                    Label("Last Result", systemImage: "info.circle")
                }
            }
        }
        .navigationTitle("Processes")
        .navigationBarTitleDisplayMode(.inline)
    }
}
