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
        guard !command.isEmpty, !isExecuting else { return }
        // Don't check mgr.rcready here — executeAsRoot handles auto-reconnect
        
        let cmd = command
        command = ""
        isExecuting = true
        
        let entry = ShellEntry(command: cmd, output: "", success: true, isLoading: true)
        history.append(entry)
        let idx = history.count - 1
        
        #if !DISABLE_REMOTECALL
        // Execute command with output capture
        // Use system() which is simpler than posix_spawn and works in launchd context
        // system("command > /tmp/out 2>&1") is equivalent to fork+exec+wait
        root.executeAsRoot(operation: "shell") { [self] rc in
            // Method: use system() — it's a single call that handles everything
            // system() calls /bin/sh -c internally
            let fullCmd = "\(cmd) > \(self.outputPath) 2>&1"
            let cmdAddr = remote_alloc_str(rc, fullCmd)
            
            // Try system() first — simplest approach
            let systemResult = RootExecutor.rcall(rc, "system", cmdAddr)
            
            // Read output file
            let outPathAddr = remote_alloc_str(rc, self.outputPath)
            let fd = RootExecutor.rcall(rc, "open", outPathAddr, UInt64(O_RDONLY), 0)
            
            var output = ""
            if fd != UInt64(bitPattern: -1) {
                let bufAddr = rc.trojanMem + 0x800
                let n = RootExecutor.rcall(rc, "read", fd, bufAddr, 4000)
                if n > 0 && n < 4001 {
                    var buf = [UInt8](repeating: 0, count: Int(n))
                    rc.remoteRead(bufAddr, to: &buf, size: n)
                    output = String(bytes: buf, encoding: .utf8) ?? "(binary output)"
                }
                RootExecutor.rcall(rc, "close", fd)
            } else {
                // open failed — maybe system() didn't work either
                // Try alternative: just call the command function directly
                // For simple commands like "id", "getuid", we can call C functions
                output = self.tryDirectCall(rc: rc, cmd: cmd)
            }
            
            // Cleanup
            RootExecutor.rcall(rc, "unlink", outPathAddr)
            RootExecutor.rcall(rc, "free", cmdAddr)
            RootExecutor.rcall(rc, "free", outPathAddr)
            
            let success = !output.isEmpty || systemResult == 0
            
            DispatchQueue.main.async {
                if idx < self.history.count {
                    self.history[idx] = ShellEntry(
                        command: cmd,
                        output: output.isEmpty ? (success ? "(executed, no output)" : "(failed: ret=\(systemResult))") : output.trimmingCharacters(in: .whitespacesAndNewlines),
                        success: success,
                        isLoading: false
                    )
                }
                self.isExecuting = false
            }
            
            return (success, output.prefix(100).description, systemResult)
        }
        #endif
    }
    
    /// For simple commands, call C functions directly instead of spawning shell
    private func tryDirectCall(rc: RemoteCall, cmd: String) -> String {
        switch cmd.trimmingCharacters(in: .whitespaces) {
        case "id":
            let uid = RootExecutor.rcall(rc, "getuid")
            let gid = RootExecutor.rcall(rc, "getgid")
            let euid = RootExecutor.rcall(rc, "geteuid")
            return "uid=\(uid) gid=\(gid) euid=\(euid)"
        case "whoami":
            let uid = RootExecutor.rcall(rc, "getuid")
            return uid == 0 ? "root" : "mobile (uid=\(uid))"
        case "uname -a", "uname":
            // Read uname via uname() syscall
            let unameAddr = rc.trojanMem + 0xC00
            let result = RootExecutor.rcall(rc, "uname", unameAddr)
            if result == 0 {
                // struct utsname: sysname[256], nodename[256], release[256], version[256], machine[256]
                var buf = [UInt8](repeating: 0, count: 256 * 5)
                rc.remoteRead(unameAddr, to: &buf, size: UInt64(buf.count))
                let sysname = String(cString: buf.withUnsafeBufferPointer { Array($0[0..<256]) } + [0])
                let nodename = String(cString: buf.withUnsafeBufferPointer { Array($0[256..<512]) } + [0])
                let release = String(cString: buf.withUnsafeBufferPointer { Array($0[512..<768]) } + [0])
                let machine = String(cString: buf.withUnsafeBufferPointer { Array($0[1024..<1280]) } + [0])
                return "\(sysname) \(nodename) \(release) \(machine)"
            }
            return "(uname failed)"
        default:
            return ""
        }
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
