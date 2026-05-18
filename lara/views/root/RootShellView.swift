//
//  RootShellView.swift
//  DSPloit
//
//  Root shell — execute commands as uid=0 with output capture
//  Pattern: /bin/sh -c "command > /tmp/.dsploit_out 2>&1" → read output back
//

import SwiftUI

struct RootShellView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var command = ""
    @State private var history: [ShellEntry] = []
    @State private var isExecuting = false
    
    struct ShellEntry: Identifiable {
        let id = UUID()
        let command: String
        var output: String
        var success: Bool
        var isLoading: Bool
    }
    
    private let outputPath = "/tmp/.dsploit_shell_out"
    
    var body: some View {
        VStack(spacing: 0) {
            // Output area
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(history) { entry in
                            VStack(alignment: .leading, spacing: 4) {
                                // Command line
                                HStack(spacing: 4) {
                                    Text("root#")
                                        .foregroundStyle(.red)
                                        .font(.system(size: 13, weight: .bold, design: .monospaced))
                                    Text(entry.command)
                                        .foregroundStyle(.primary)
                                        .font(.system(size: 13, design: .monospaced))
                                }
                                
                                // Output
                                if entry.isLoading {
                                    HStack(spacing: 6) {
                                        ProgressView()
                                            .scaleEffect(0.6)
                                        Text("executing...")
                                            .font(.system(size: 11, design: .monospaced))
                                            .foregroundStyle(.secondary)
                                    }
                                } else if !entry.output.isEmpty {
                                    Text(entry.output)
                                        .font(.system(size: 12, design: .monospaced))
                                        .foregroundStyle(entry.success ? .green : .orange)
                                        .textSelection(.enabled)
                                }
                            }
                            .id(entry.id)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                }
                .onChange(of: history.count) { _ in
                    if let last = history.last {
                        withAnimation {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
            .background(Color.black.opacity(0.3))
            
            // Input bar
            HStack(spacing: 8) {
                Text("root#")
                    .font(.system(size: 14, weight: .bold, design: .monospaced))
                    .foregroundStyle(.red)
                
                TextField("command", text: $command)
                    .font(.system(size: 14, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .onSubmit { executeCommand() }
                
                Button(action: executeCommand) {
                    Image(systemName: "arrow.right.circle.fill")
                        .font(.title3)
                        .foregroundStyle(.blue)
                }
                .disabled(command.isEmpty || isExecuting || !mgr.rcready)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(.ultraThinMaterial)
            
            // Quick commands
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    QuickCmd("id") { run("id") }
                    QuickCmd("whoami") { run("whoami") }
                    QuickCmd("ls /var/root") { run("ls -la /var/root/") }
                    QuickCmd("uname -a") { run("uname -a") }
                    QuickCmd("ps aux") { run("ps aux") }
                    QuickCmd("df -h") { run("df -h") }
                    QuickCmd("ls /var/jb") { run("ls -la /var/jb/") }
                    QuickCmd("cat /etc/passwd") { run("cat /etc/passwd") }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
            }
            .background(.ultraThinMaterial)
        }
        .navigationTitle("Root Shell")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Clear") {
                    history.removeAll()
                }
            }
        }
    }
    
    private func run(_ cmd: String) {
        command = cmd
        executeCommand()
    }
    
    private func executeCommand() {
        guard !command.isEmpty, !isExecuting, mgr.rcready else { return }
        
        let cmd = command
        command = ""
        isExecuting = true
        
        let entry = ShellEntry(command: cmd, output: "", success: true, isLoading: true)
        history.append(entry)
        let idx = history.count - 1
        
        #if !DISABLE_REMOTECALL
        // Execute command with output capture:
        // /bin/sh -c "command > /tmp/.dsploit_shell_out 2>&1"
        // Then read the output file back
        root.executeAsRoot(operation: "shell") { [self] rc in
            // Step 1: Execute command, redirect stdout+stderr to file
            let fullCmd = "\(cmd) > \(self.outputPath) 2>&1"
            let cmdAddr = remote_alloc_str(rc, fullCmd)
            let shAddr = remote_alloc_str(rc, "/bin/sh")
            let dashC = remote_alloc_str(rc, "-c")
            
            // Build argv: ["/bin/sh", "-c", "command > file 2>&1", NULL]
            let argvBase = rc.trojanMem + 0x400
            rc[argvBase].setValue64(shAddr)
            rc[argvBase + 8].setValue64(dashC)
            rc[argvBase + 16].setValue64(cmdAddr)
            rc[argvBase + 24].setValue64(0) // NULL
            
            // posix_spawn
            let pidAddr = rc.trojanMem + 0x300
            rc[pidAddr].setValue32(0)
            let spawnResult = RootExecutor.rcall(rc, "posix_spawn", pidAddr, shAddr, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()
            
            // Wait briefly for command to finish
            // waitpid(pid, NULL, 0) — wait for child
            if pid != 0 && spawnResult == 0 {
                let statusAddr = rc.trojanMem + 0x380
                rc[statusAddr].setValue32(0)
                RootExecutor.rcall(rc, "waitpid", UInt64(pid), statusAddr, 0)
            }
            
            // Step 2: Read output file
            let outPathAddr = remote_alloc_str(rc, self.outputPath)
            let fd = RootExecutor.rcall(rc, "open", outPathAddr, UInt64(O_RDONLY), 0)
            
            var output = ""
            if fd != UInt64(bitPattern: -1) {
                let bufAddr = rc.trojanMem + 0x800
                let n = RootExecutor.rcall(rc, "read", fd, bufAddr, 4000) // max 4KB output
                if n > 0 && n < 4001 {
                    var buf = [UInt8](repeating: 0, count: Int(n))
                    rc.remoteRead(bufAddr, to: &buf, size: n)
                    output = String(bytes: buf, encoding: .utf8) ?? "(binary output)"
                }
                RootExecutor.rcall(rc, "close", fd)
            }
            
            // Cleanup
            RootExecutor.rcall(rc, "unlink", outPathAddr)
            RootExecutor.rcall(rc, "free", cmdAddr)
            RootExecutor.rcall(rc, "free", shAddr)
            RootExecutor.rcall(rc, "free", dashC)
            RootExecutor.rcall(rc, "free", outPathAddr)
            
            let success = spawnResult == 0
            
            DispatchQueue.main.async {
                if idx < self.history.count {
                    self.history[idx] = ShellEntry(
                        command: cmd,
                        output: output.isEmpty ? (success ? "(no output)" : "(spawn failed)") : output.trimmingCharacters(in: .whitespacesAndNewlines),
                        success: success,
                        isLoading: false
                    )
                }
                self.isExecuting = false
            }
            
            return (success, output.prefix(100).description, UInt64(pid))
        }
        #endif
    }
}

// MARK: - Quick Command Button

struct QuickCmd: View {
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
                .padding(.vertical, 5)
                .background(Color.blue.opacity(0.15))
                .clipShape(Capsule())
        }
    }
}
