//
//  RootProcessView.swift
//  DSPloit
//
//  Process manager — spawn, list, and kill processes as root
//

import SwiftUI

struct RootProcessView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var binary = "/bin/ps"
    @State private var args = "aux"
    @State private var processList: [ProcessEntry] = []
    @State private var isLoadingList = false
    @State private var spawnResults: [SpawnEntry] = []
    
    struct ProcessEntry: Identifiable {
        let id = UUID()
        let pid: String
        let name: String
        let user: String
    }
    
    struct SpawnEntry: Identifiable {
        let id = UUID()
        let binary: String
        let pid: UInt64
        let success: Bool
        let timestamp: Date
    }
    
    var body: some View {
        List {
            // Process List
            Section {
                Button(action: loadProcessList) {
                    HStack {
                        Label("Refresh Process List", systemImage: "arrow.clockwise")
                            .foregroundStyle(.blue)
                        Spacer()
                        if isLoadingList {
                            ProgressView().scaleEffect(0.7)
                        } else {
                            Text("\(processList.count)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .disabled(!mgr.rcready || isLoadingList)
                
                if !processList.isEmpty {
                    ForEach(processList.prefix(50)) { proc in
                        HStack(spacing: 8) {
                            Text(proc.pid)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.orange)
                                .frame(width: 40, alignment: .trailing)
                            Text(proc.name)
                                .font(.system(size: 12, design: .monospaced))
                                .lineLimit(1)
                            Spacer()
                            Text(proc.user)
                                .font(.system(size: 10))
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Label("Running (\(processList.count))", systemImage: "list.number")
            }
            
            // Spawn
            Section {
                HStack {
                    Image(systemName: "terminal")
                        .foregroundStyle(.orange)
                        .frame(width: 20)
                    TextField("/bin/ps", text: $binary)
                        .font(.system(size: 13, design: .monospaced))
                        .textInputAutocapitalization(.never)
                }
                HStack {
                    Image(systemName: "text.alignleft")
                        .foregroundStyle(.secondary)
                        .frame(width: 20)
                    TextField("args", text: $args)
                        .font(.system(size: 12, design: .monospaced))
                        .textInputAutocapitalization(.never)
                }
                
                Button(action: spawnBinary) {
                    HStack {
                        Label("Spawn", systemImage: "play.circle.fill")
                            .foregroundStyle(.green)
                        Spacer()
                        if root.isExecuting {
                            ProgressView().scaleEffect(0.7)
                        }
                    }
                }
                .disabled(!mgr.rcready || root.isExecuting)
            } header: {
                Label("Spawn as Root", systemImage: "play.fill")
            }
            
            // Quick Commands
            Section {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        QuickSpawn("ps aux") { binary = "/bin/ps"; args = "aux"; spawnBinary() }
                        QuickSpawn("ls /") { binary = "/bin/ls"; args = "-la /"; spawnBinary() }
                        QuickSpawn("df -h") { binary = "/bin/df"; args = "-h"; spawnBinary() }
                        QuickSpawn("mount") { binary = "/sbin/mount"; args = ""; spawnBinary() }
                        QuickSpawn("ifconfig") { binary = "/sbin/ifconfig"; args = ""; spawnBinary() }
                    }
                }
                .listRowInsets(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
            } header: {
                Label("Quick", systemImage: "bolt")
            }
            
            // Spawn History
            if !spawnResults.isEmpty {
                Section {
                    ForEach(spawnResults.prefix(10)) { entry in
                        HStack {
                            Image(systemName: entry.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(entry.success ? .green : .red)
                                .font(.caption)
                            Text(entry.binary)
                                .font(.system(size: 11, design: .monospaced))
                                .lineLimit(1)
                            Spacer()
                            if entry.success && entry.pid != 0 {
                                Text("PID \(entry.pid)")
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.orange)
                            }
                            Text(entry.timestamp, style: .time)
                                .font(.system(size: 9))
                                .foregroundStyle(.tertiary)
                        }
                    }
                    
                    Button("Clear") { spawnResults.removeAll() }
                        .font(.caption)
                        .foregroundStyle(.red)
                } header: {
                    Label("History", systemImage: "clock")
                }
            }
            
            // Last Output
            if let r = root.lastResult {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Image(systemName: r.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(r.success ? .green : .red)
                            Text(r.operation)
                                .font(.caption.bold())
                            Spacer()
                        }
                        Text(r.message)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .lineLimit(20)
                    }
                } header: {
                    Label("Output", systemImage: "doc.text")
                }
            }
        }
        .navigationTitle("Processes")
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { loadProcessList() }
        .onAppear { if processList.isEmpty { loadProcessList() } }
    }
    
    private func spawnBinary() {
        let argList = args.components(separatedBy: " ").filter { !$0.isEmpty }
        root.spawnAsRoot(binary: binary, args: argList)
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
            if let r = root.lastResult {
                spawnResults.insert(SpawnEntry(
                    binary: binary,
                    pid: r.returnValue,
                    success: r.success,
                    timestamp: Date()
                ), at: 0)
            }
        }
    }
    
    private func loadProcessList() {
        isLoadingList = true
        processList.removeAll()
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "ps") { rc in
            var entries: [ProcessEntry] = []
            let mem = rc.trojanMem
            
            // Use posix_spawn /bin/ps with output capture
            let outFile = "/tmp/.dsp_ps_out"
            let outAddr = remote_alloc_str(rc, outFile)
            RootExecutor.rcall(rc, "unlink", outAddr)
            
            let actionsAddr = mem + 0x100
            rc[actionsAddr].setValue64(0)
            RootExecutor.rcall(rc, "posix_spawn_file_actions_init", actionsAddr)
            RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen", actionsAddr, 1, outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
            
            let binAddr = remote_alloc_str(rc, "/bin/ps")
            let argAddr = remote_alloc_str(rc, "aux")
            let argvBase = mem + 0x400
            rc[argvBase].setValue64(binAddr)
            rc[argvBase + 8].setValue64(argAddr)
            rc[argvBase + 16].setValue64(0)
            
            let pidAddr = mem + 0x300
            rc[pidAddr].setValue64(0)
            RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, actionsAddr, 0, argvBase, 0)
            RootExecutor.rcall(rc, "usleep", 2000000) // 2s (increased for reliability)
            RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), mem + 0x380, UInt64(WNOHANG))
            
            // Read output
            let readFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_RDONLY), 0)
            if readFd != UInt64(bitPattern: -1) {
                let size = RootExecutor.rcall(rc, "lseek", readFd, 0, 2)
                RootExecutor.rcall(rc, "lseek", readFd, 0, 0)
                if size > 0 && size < 8000 {
                    let bufAddr = mem + 0x800
                    let n = RootExecutor.rcall(rc, "read", readFd, bufAddr, min(size, 7000))
                    if n > 0 {
                        var buf = [UInt8](repeating: 0, count: Int(n))
                        rc.remoteRead(bufAddr, to: &buf, size: n)
                        let output = String(bytes: buf, encoding: .utf8) ?? ""
                        
                        // Parse ps output
                        let lines = output.components(separatedBy: "\n").dropFirst() // skip header
                        for line in lines {
                            let parts = line.split(separator: " ", maxSplits: 10, omittingEmptySubsequences: true)
                            if parts.count >= 4 {
                                entries.append(ProcessEntry(
                                    pid: String(parts[1]),
                                    name: String(parts.last ?? "?"),
                                    user: String(parts[0])
                                ))
                            }
                        }
                    }
                }
                RootExecutor.rcall(rc, "close", readFd)
            }
            
            RootExecutor.rcall(rc, "unlink", outAddr)
            RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", actionsAddr)
            RootExecutor.rcall(rc, "free", outAddr)
            RootExecutor.rcall(rc, "free", binAddr)
            RootExecutor.rcall(rc, "free", argAddr)
            
            DispatchQueue.main.async {
                self.processList = entries
                self.isLoadingList = false
                if !entries.isEmpty {
                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
                }
            }
            return (true, "\(entries.count) processes", 0)
        }
        #endif
    }
}

struct QuickSpawn: View {
    let label: String
    let action: () -> Void
    
    init(_ label: String, action: @escaping () -> Void) {
        self.label = label
        self.action = action
    }
    
    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 11, design: .monospaced))
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(Capsule().fill(Color.orange.opacity(0.15)))
                .foregroundStyle(.orange)
        }
        .buttonStyle(.plain)
    }
}
