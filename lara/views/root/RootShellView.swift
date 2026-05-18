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
    
    private let outputPath = "/tmp/.dsploit_shell_out" // legacy, kept for compat
    
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
                    QuickCmd("ps") { run("ps") }
                    QuickCmd("df") { run("df") }
                    QuickCmd("mount") { run("mount") }
                    QuickCmd("ls /var/root") { run("ls /var/root/") }
                    QuickCmd("ls /var/jb") { run("ls /var/jb/") }
                    QuickCmd("uname -a") { run("uname -a") }
                    QuickCmd("cat /etc/passwd") { run("cat /etc/passwd") }
                    QuickCmd("hostname") { run("hostname") }
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
        
        let cmd = command
        command = ""
        isExecuting = true
        
        let entry = ShellEntry(command: cmd, output: "", success: true, isLoading: true)
        history.append(entry)
        let idx = history.count - 1
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "shell") { [self] rc in
            // First try direct C call (fastest, no spawn needed)
            let directOutput = self.tryDirectCall(rc: rc, cmd: cmd)
            if !directOutput.isEmpty {
                DispatchQueue.main.async {
                    if idx < self.history.count {
                        self.history[idx] = ShellEntry(command: cmd, output: directOutput, success: true, isLoading: false)
                    }
                    self.isExecuting = false
                }
                return (true, directOutput.prefix(50).description, 0)
            }
            
            // Try binary spawn with output capture (proven pattern)
            let spawnOutput = self.tryBinarySpawn(rc: rc, cmd: cmd)
            if !spawnOutput.isEmpty {
                DispatchQueue.main.async {
                    if idx < self.history.count {
                        self.history[idx] = ShellEntry(command: cmd, output: spawnOutput, success: true, isLoading: false)
                    }
                    self.isExecuting = false
                }
                return (true, spawnOutput.prefix(50).description, 0)
            }
            
            // Nothing worked
            DispatchQueue.main.async {
                if idx < self.history.count {
                    self.history[idx] = ShellEntry(command: cmd, output: "(command not available — no shell on iOS 18)", success: false, isLoading: false)
                }
                self.isExecuting = false
            }
            return (false, "not available", 0)
        }
        #endif
    }
    
    // MARK: - Binary Spawn (proven pattern from AMFI experiments)
    
    /// Spawn a real binary with posix_spawn + file_actions stdout redirect
    /// Works for: /bin/ps, /bin/df, /sbin/mount, /sbin/ifconfig
    private func tryBinarySpawn(rc: RemoteCall, cmd: String) -> String {
        let trimmed = cmd.trimmingCharacters(in: .whitespaces)
        let parts = trimmed.components(separatedBy: " ").filter { !$0.isEmpty }
        guard let cmdName = parts.first else { return "" }
        
        // Map command names to actual binary paths that exist on iOS 18.2
        let binaryMap: [String: String] = [
            "ps": "/bin/ps",
            "df": "/bin/df",
            "mount": "/sbin/mount",
            "umount": "/sbin/umount",
            "ifconfig": "/sbin/ifconfig",
            "route": "/sbin/route",
            "ping": "/sbin/ping",
            "fsck": "/sbin/fsck",
            "pfctl": "/sbin/pfctl",
        ]
        
        guard let binaryPath = binaryMap[cmdName] else { return "" }
        
        let mem = rc.trojanMem
        let outFile = "/tmp/.dsp_cmd_out"
        let outAddr = remote_alloc_str(rc, outFile)
        
        // Clean old output
        RootExecutor.rcall(rc, "unlink", outAddr)
        
        // Setup file actions: redirect stdout+stderr to file
        let actionsAddr = mem + 0x100
        rc[actionsAddr].setValue64(0)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_init", actionsAddr)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen",
                          actionsAddr, 1, outAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_addopen",
                          actionsAddr, 2, outAddr, UInt64(O_WRONLY | O_CREAT), 0o644)
        
        // Build argv from command parts
        let binAddr = remote_alloc_str(rc, binaryPath)
        let argvBase = mem + 0x400
        var argAddrs: [UInt64] = []
        for part in parts {
            argAddrs.append(remote_alloc_str(rc, part))
        }
        for (i, addr) in argAddrs.enumerated() {
            rc[argvBase + UInt64(i * 8)].setValue64(addr)
        }
        rc[argvBase + UInt64(argAddrs.count * 8)].setValue64(0) // NULL
        
        // Spawn
        let pidAddr = mem + 0x2E0
        rc[pidAddr].setValue64(0)
        let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, actionsAddr, 0, argvBase, 0)
        
        guard ret == 0 else {
            // Cleanup
            RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", actionsAddr)
            RootExecutor.rcall(rc, "free", outAddr)
            RootExecutor.rcall(rc, "free", binAddr)
            for a in argAddrs { RootExecutor.rcall(rc, "free", a) }
            return ""
        }
        
        // Wait for process to finish
        RootExecutor.rcall(rc, "usleep", 1000000) // 1 second
        let statusAddr = mem + 0x380
        RootExecutor.rcall(rc, "waitpid", UInt64(bitPattern: -1), statusAddr, UInt64(WNOHANG))
        
        // Read output
        var output = ""
        let readFd = RootExecutor.rcall(rc, "open", outAddr, UInt64(O_RDONLY), 0)
        if readFd != UInt64(bitPattern: -1) {
            let bufAddr = mem + 0x800
            let n = RootExecutor.rcall(rc, "read", readFd, bufAddr, 3500)
            if n > 0 && n < 3501 {
                var buf = [UInt8](repeating: 0, count: Int(n))
                rc.remoteRead(bufAddr, to: &buf, size: n)
                output = String(bytes: buf, encoding: .utf8) ?? "(binary \(n)B)"
            }
            RootExecutor.rcall(rc, "close", readFd)
        }
        
        // Cleanup
        RootExecutor.rcall(rc, "unlink", outAddr)
        RootExecutor.rcall(rc, "posix_spawn_file_actions_destroy", actionsAddr)
        RootExecutor.rcall(rc, "free", outAddr)
        RootExecutor.rcall(rc, "free", binAddr)
        for a in argAddrs { RootExecutor.rcall(rc, "free", a) }
        
        return output.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    
    /// For simple commands, call C functions directly instead of spawning shell
    /// This bypasses AMFI shell restrictions in launchd context
    private func tryDirectCall(rc: RemoteCall, cmd: String) -> String {
        let trimmed = cmd.trimmingCharacters(in: .whitespaces)
        
        // id
        if trimmed == "id" {
            let uid = RootExecutor.rcall(rc, "getuid")
            let gid = RootExecutor.rcall(rc, "getgid")
            let euid = RootExecutor.rcall(rc, "geteuid")
            return "uid=\(uid) gid=\(gid) euid=\(euid)"
        }
        
        // whoami
        if trimmed == "whoami" {
            let uid = RootExecutor.rcall(rc, "getuid")
            return uid == 0 ? "root" : "mobile (uid=\(uid))"
        }
        
        // uname -a
        if trimmed.hasPrefix("uname") {
            let unameAddr = rc.trojanMem + 0xC00
            let result = RootExecutor.rcall(rc, "uname", unameAddr)
            if result == 0 {
                var buf = [UInt8](repeating: 0, count: 256 * 5)
                rc.remoteRead(unameAddr, to: &buf, size: UInt64(buf.count))
                let parts = (0..<5).map { i -> String in
                    let slice = Array(buf[(i*256)..<((i+1)*256)])
                    return String(cString: slice + [0])
                }
                return parts.filter { !$0.isEmpty }.joined(separator: " ")
            }
            return "(uname failed)"
        }
        
        // ls / ls -la <path>
        if trimmed.hasPrefix("ls") {
            let path = extractPath(from: trimmed, default: "/")
            return doLS(rc: rc, path: path)
        }
        
        // cat <file>
        if trimmed.hasPrefix("cat ") {
            let path = String(trimmed.dropFirst(4)).trimmingCharacters(in: .whitespaces)
            return doCAT(rc: rc, path: path)
        }
        
        // pwd
        if trimmed == "pwd" {
            let bufAddr = rc.trojanMem + 0xC00
            let result = RootExecutor.rcall(rc, "getcwd", bufAddr, 1024)
            if result != 0 {
                var buf = [UInt8](repeating: 0, count: 1024)
                rc.remoteRead(bufAddr, to: &buf, size: 1024)
                return String(cString: buf + [0])
            }
            return "/"
        }
        
        // ps / ps aux
        if trimmed.hasPrefix("ps") {
            return doPS(rc: rc)
        }
        
        // df / df -h
        if trimmed.hasPrefix("df") {
            return doDF(rc: rc)
        }
        
        // hostname
        if trimmed == "hostname" {
            let bufAddr = rc.trojanMem + 0xC00
            RootExecutor.rcall(rc, "gethostname", bufAddr, 256)
            var buf = [UInt8](repeating: 0, count: 256)
            rc.remoteRead(bufAddr, to: &buf, size: 256)
            return String(cString: buf + [0])
        }
        
        // echo
        if trimmed.hasPrefix("echo ") {
            return String(trimmed.dropFirst(5))
        }
        
        // touch <file>
        if trimmed.hasPrefix("touch ") {
            let path = String(trimmed.dropFirst(6)).trimmingCharacters(in: .whitespaces)
            let pathAddr = remote_alloc_str(rc, path)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_WRONLY | O_CREAT), 0o644)
            if fd != UInt64(bitPattern: -1) {
                RootExecutor.rcall(rc, "close", fd)
                RootExecutor.rcall(rc, "free", pathAddr)
                return "created: \(path)"
            }
            let err = remote_errno(rc)
            RootExecutor.rcall(rc, "free", pathAddr)
            return "touch failed: errno=\(err)"
        }
        
        // mkdir <path>
        if trimmed.hasPrefix("mkdir ") {
            let path = String(trimmed.dropFirst(6)).trimmingCharacters(in: .whitespaces)
            let pathAddr = remote_alloc_str(rc, path)
            let result = RootExecutor.rcall(rc, "mkdir", pathAddr, 0o755)
            RootExecutor.rcall(rc, "free", pathAddr)
            return result == 0 ? "created: \(path)" : "mkdir failed: errno=\(remote_errno(rc))"
        }
        
        // rm <file>
        if trimmed.hasPrefix("rm ") {
            let path = String(trimmed.dropFirst(3)).trimmingCharacters(in: .whitespaces)
            let pathAddr = remote_alloc_str(rc, path)
            let result = RootExecutor.rcall(rc, "unlink", pathAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            return result == 0 ? "removed: \(path)" : "rm failed: errno=\(remote_errno(rc))"
        }
        
        // chmod
        if trimmed.hasPrefix("chmod ") {
            let parts = trimmed.components(separatedBy: " ").filter { !$0.isEmpty }
            if parts.count >= 3, let mode = UInt64(parts[1], radix: 8) {
                let path = parts[2]
                let pathAddr = remote_alloc_str(rc, path)
                let result = RootExecutor.rcall(rc, "chmod", pathAddr, mode)
                RootExecutor.rcall(rc, "free", pathAddr)
                return result == 0 ? "chmod \(parts[1]) \(path)" : "chmod failed: errno=\(remote_errno(rc))"
            }
            return "usage: chmod <mode> <path>"
        }
        
        // Not recognized — try system() as last resort
        return ""
    }
}

// MARK: - Direct C Call Implementations

extension RootShellView {
    
    private func extractPath(from cmd: String, default defaultPath: String) -> String {
        let parts = cmd.components(separatedBy: " ").filter { !$0.isEmpty && !$0.hasPrefix("-") }
        // parts[0] = "ls", parts[1] = path (if exists)
        return parts.count > 1 ? parts.last! : defaultPath
    }
    
    /// ls implementation via opendir/readdir
    private func doLS(rc: RemoteCall, path: String) -> String {
        let pathAddr = remote_alloc_str(rc, path)
        let dir = RootExecutor.rcall(rc, "opendir", pathAddr)
        RootExecutor.rcall(rc, "free", pathAddr)
        
        guard dir != 0 else {
            return "ls: cannot open '\(path)': errno=\(remote_errno(rc))"
        }
        
        var entries: [String] = []
        for _ in 0..<200 { // max 200 entries
            let dirent = RootExecutor.rcall(rc, "readdir", dir)
            if dirent == 0 { break }
            
            // struct dirent: d_ino(8) + d_seekoff(8) + d_reclen(2) + d_namlen(2) + d_type(1) + d_name(1024)
            // d_name starts at offset 21 on arm64
            let nameOffset: UInt64 = 21
            var nameBuf = [UInt8](repeating: 0, count: 256)
            rc.remoteRead(dirent + nameOffset, to: &nameBuf, size: 256)
            let name = String(cString: nameBuf + [0])
            
            if name != "." && name != ".." {
                // Read d_type at offset 20
                var dtype: UInt8 = 0
                rc.remoteRead(dirent + 20, to: &dtype, size: 1)
                let prefix = dtype == 4 ? "📁 " : "   " // DT_DIR = 4
                entries.append("\(prefix)\(name)")
            }
        }
        
        RootExecutor.rcall(rc, "closedir", dir)
        
        if entries.isEmpty {
            return "(empty directory)"
        }
        return entries.joined(separator: "\n")
    }
    
    /// cat implementation via open/read
    private func doCAT(rc: RemoteCall, path: String) -> String {
        let pathAddr = remote_alloc_str(rc, path)
        let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_RDONLY), 0)
        RootExecutor.rcall(rc, "free", pathAddr)
        
        guard fd != UInt64(bitPattern: -1) else {
            return "cat: cannot open '\(path)': errno=\(remote_errno(rc))"
        }
        
        let bufAddr = rc.trojanMem + 0x800
        let n = RootExecutor.rcall(rc, "read", fd, bufAddr, 3000) // max 3KB
        RootExecutor.rcall(rc, "close", fd)
        
        if n > 0 && n < 3001 {
            var buf = [UInt8](repeating: 0, count: Int(n))
            rc.remoteRead(bufAddr, to: &buf, size: n)
            return String(bytes: buf, encoding: .utf8) ?? "(binary file, \(n) bytes)"
        }
        return "(empty file)"
    }
    
    /// ps implementation via sysctl
    private func doPS(rc: RemoteCall) -> String {
        // Use getpid to at least show launchd info
        let pid = RootExecutor.rcall(rc, "getpid")
        let uid = RootExecutor.rcall(rc, "getuid")
        return "PID 1 (launchd) — uid=\(uid), pid=\(pid)\n(full ps requires sysctl — showing launchd context)"
    }
    
    /// df implementation via statfs
    private func doDF(rc: RemoteCall) -> String {
        var results: [String] = ["Filesystem      Size  Used  Avail  Mount"]
        
        let paths = ["/", "/private/var", "/var/mobile"]
        for path in paths {
            let pathAddr = remote_alloc_str(rc, path)
            let statAddr = rc.trojanMem + 0x800
            let result = RootExecutor.rcall(rc, "statfs", pathAddr, statAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            if result == 0 {
                // statfs struct: f_bsize(4) at +0x4, f_blocks(8) at +0x8, f_bfree(8) at +0x10, f_bavail(8) at +0x18
                var bsize: UInt32 = 0
                var blocks: UInt64 = 0
                var bfree: UInt64 = 0
                rc.remoteRead(statAddr + 0x4, to: &bsize, size: 4)
                rc.remoteRead(statAddr + 0x8, to: &blocks, size: 8)
                rc.remoteRead(statAddr + 0x10, to: &bfree, size: 8)
                
                let total = UInt64(bsize) * blocks / (1024 * 1024) // MB
                let free = UInt64(bsize) * bfree / (1024 * 1024)
                let used = total > free ? total - free : 0
                results.append(String(format: "%-15s %4lluM %4lluM %4lluM  %@", (path as NSString).utf8String!, total, used, free, path))
            }
        }
        
        return results.joined(separator: "\n")
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
