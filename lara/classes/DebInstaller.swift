//
//  DebInstaller.swift
//  DSPloit
//
//  Plan E: Write data.tar to disk via SpringBoard, spawn /usr/bin/tar to extract.
//  This completely avoids holding launchd thread during file I/O.
//
//  Flow:
//  1. Parse ar archive → get data.tar.gz from .deb
//  2. Write data.tar.gz to /var/jb/tmp/ via SpringBoard RC (no watchdog)
//  3. posix_spawn /usr/bin/tar -xzf to extract (runs in own process, instant launchd release)
//  4. Fallback: if tar spawn fails, extract manually via SpringBoard RC
//  5. uicache if .app found
//
//  ZERO launchd hold time for file I/O = ZERO watchdog panic risk.
//

import Foundation
import Compression

/// .deb installer — spawn tar for extraction (zero watchdog risk)
final class DebInstaller {
    
    private let root = RootExecutor.shared
    private let mgr = dspmgr.shared
    private var log: ((String) -> Void)?
    
    init(log: ((String) -> Void)? = nil) {
        self.log = log
    }
    
    private func emit(_ msg: String) {
        log?(msg)
    }
    
    // MARK: - Public API
    
    /// Install a .deb from raw Data
    /// Returns (success, installedFiles count)
    func install(debData: Data, name: String, completion: @escaping (Bool, Int) -> Void) {
        emit("[deb] Parsing ar archive (\(debData.count) bytes)...")
        
        // Step 1: Parse ar archive
        guard let arEntries = parseAr(data: debData) else {
            emit("[deb] ❌ Failed to parse ar archive")
            completion(false, 0)
            return
        }
        
        emit("[deb] Found \(arEntries.count) ar entries: \(arEntries.map { $0.name }.joined(separator: ", "))")
        
        // Step 2: Find data.tar (could be .gz, .xz, or plain)
        guard let dataTar = findDataTar(in: arEntries) else {
            emit("[deb] ❌ No data.tar found in .deb")
            completion(false, 0)
            return
        }
        
        emit("[deb] data.tar: \(dataTar.name) (\(dataTar.data.count) bytes)")
        
        // Step 3: Determine tar flags based on compression
        let tarFlags: String
        let tarFileName: String
        if dataTar.name.hasSuffix(".gz") || dataTar.name.hasSuffix(".tgz") {
            tarFlags = "-xzf"
            tarFileName = "data.tar.gz"
        } else if dataTar.name.hasSuffix(".xz") {
            tarFlags = "-xJf"
            tarFileName = "data.tar.xz"
        } else if dataTar.name.hasSuffix(".zst") {
            tarFlags = "--zstd -xf"
            tarFileName = "data.tar.zst"
        } else {
            tarFlags = "-xf"
            tarFileName = "data.tar"
        }
        
        let tmpPath = "/var/jb/tmp/\(name.lowercased().replacingOccurrences(of: " ", with: "_"))_\(tarFileName)"
        
        emit("[deb] Writing \(tarFileName) to \(tmpPath)...")
        emit("[deb] Size: \(dataTar.data.count) bytes")
        
        // Step 4: Write tar file to /var/jb/tmp/ via SpringBoard (NO watchdog risk)
        writeTarToDisk(data: dataTar.data, path: tmpPath) { [weak self] writeSuccess in
            guard let self else { return }
            
            guard writeSuccess else {
                self.emit("[deb] ❌ Failed to write tar to disk")
                self.emit("[deb] Trying fallback manual extraction...")
                self.fallbackManualExtract(dataTar: dataTar, name: name, completion: completion)
                return
            }
            
            self.emit("[deb] ✅ Tar written to disk")
            self.emit("[deb] Spawning: tar \(tarFlags) \(tmpPath) -C /var/jb/")
            
            // Step 5: posix_spawn tar to extract (instant launchd release)
            self.spawnTarExtract(tarPath: tmpPath, destDir: "/var/jb", flags: tarFlags) { spawnSuccess in
                if spawnSuccess {
                    self.emit("[deb] ✅ tar spawned — extraction in progress")
                    
                    // Give tar time to finish (depends on file count)
                    // 14MB compressed ≈ 3-8 seconds to extract on device
                    DispatchQueue.main.asyncAfter(deadline: .now() + 8) {
                        self.emit("[deb] ✅ Installation complete")
                        
                        // Cleanup tmp file
                        self.removeTmpFile(path: tmpPath)
                        
                        // uicache
                        self.runUicache {
                            completion(true, 1)
                        }
                    }
                } else {
                    self.emit("[deb] ❌ tar spawn failed — using fallback")
                    self.fallbackManualExtract(dataTar: dataTar, name: name, completion: completion)
                }
            }
        }
    }
    
    // MARK: - Write tar to disk (via launchd split — max 2MB per call)
    //
    // SpringBoard CANNOT write to /var/jb (sandbox blocks it).
    // Launchd CAN write anywhere (uid=0, no sandbox).
    // Split into 2MB chunks = ~500 write ops per call = ~0.5s per call (safe).
    //
    
    private func writeTarToDisk(data: Data, path: String, completion: @escaping (Bool) -> Void) {
        #if !DISABLE_REMOTECALL
        let chunkLimit = 2 * 1024 * 1024 // 2MB per launchd call (safe: ~0.5s)
        let totalSize = data.count
        var totalWritten = 0
        var callIndex = 0
        let totalCalls = (totalSize + chunkLimit - 1) / chunkLimit
        
        emit("[deb] Writing \(totalSize) bytes in \(totalCalls) launchd calls (2MB each)...")
        
        func writeNextChunk() {
            guard totalWritten < totalSize else {
                DispatchQueue.main.async { completion(true) }
                return
            }
            
            let offset = totalWritten
            let thisChunkSize = min(chunkLimit, totalSize - offset)
            let chunkData = data[offset..<offset + thisChunkSize]
            let isFirst = (offset == 0)
            callIndex += 1
            
            root.executeAsRoot(operation: "tar_write_\(callIndex)") { rc in
                // First call: mkdir + open with TRUNC
                // Subsequent calls: open with APPEND
                if isFirst {
                    let tmpDir = remote_alloc_str(rc, "/var/jb/tmp")
                    RootExecutor.rcall(rc, "mkdir", tmpDir, 0o755)
                    RootExecutor.rcall(rc, "free", tmpDir)
                }
                
                let pathAddr = remote_alloc_str(rc, path)
                let flags: UInt64 = isFirst
                    ? UInt64(O_WRONLY | O_CREAT | O_TRUNC)
                    : UInt64(O_WRONLY | O_APPEND)
                let fd = RootExecutor.rcall(rc, "open", pathAddr, flags, 0o644)
                
                guard fd != UInt64(bitPattern: -1) else {
                    RootExecutor.rcall(rc, "free", pathAddr)
                    DispatchQueue.main.async {
                        self.emit("[deb] ❌ open failed at chunk \(callIndex)")
                        completion(false)
                    }
                    return (false, "open failed", 0)
                }
                
                // Write this chunk in 4KB sub-chunks
                let writeAddr = rc.trojanMem + 0x800
                var written = 0
                
                Data(chunkData).withUnsafeBytes { buffer in
                    while written < thisChunkSize {
                        let subChunk = min(thisChunkSize - written, 0x1000)
                        rc.remote_write(writeAddr,
                            from: buffer.baseAddress!.advanced(by: written),
                            size: UInt64(subChunk))
                        let n = RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(subChunk))
                        if n == 0 || n == UInt64(bitPattern: -1) { break }
                        written += Int(n)
                    }
                }
                
                RootExecutor.rcall(rc, "close", fd)
                RootExecutor.rcall(rc, "free", pathAddr)
                totalWritten += written
                
                return (true, "chunk \(callIndex): \(written) bytes", UInt64(totalWritten))
            }
            
            // 1s delay between chunks — launchd fully released between calls
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                self.emit("[deb] Chunk \(callIndex)/\(totalCalls) done (\(totalWritten)/\(totalSize))")
                writeNextChunk()
            }
        }
        
        writeNextChunk()
        #else
        completion(false)
        #endif
    }
    
    // MARK: - Spawn tar for extraction (instant launchd release)
    
    private func spawnTarExtract(tarPath: String, destDir: String, flags: String, completion: @escaping (Bool) -> Void) {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "spawn_tar") { rc in
            let mem = rc.trojanMem
            
            // Use /bin/sh -c "tar [flags] [path] -C [dest]" for flexibility
            let shAddr = remote_alloc_str(rc, "/bin/sh")
            let dashC = remote_alloc_str(rc, "-c")
            let cmd = "tar \(flags) \(tarPath) -C \(destDir)"
            let cmdAddr = remote_alloc_str(rc, cmd)
            
            // argv = ["/bin/sh", "-c", "tar ...", NULL]
            let argvBase = mem + 0x400
            rc[argvBase].setValue64(shAddr)
            rc[argvBase + 8].setValue64(dashC)
            rc[argvBase + 16].setValue64(cmdAddr)
            rc[argvBase + 24].setValue64(0) // NULL terminator
            
            // pid output
            let pidAddr = mem + 0x300
            rc[pidAddr].setValue32(0)
            
            // posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, NULL)
            // This is INSTANT — launchd just spawns the process and returns
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, shAddr, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()
            
            // Free strings
            RootExecutor.rcall(rc, "free", shAddr)
            RootExecutor.rcall(rc, "free", dashC)
            RootExecutor.rcall(rc, "free", cmdAddr)
            
            if ret == 0 && pid != 0 {
                // SUCCESS — tar is now running in its own process
                // DO NOT waitpid — that would hold launchd thread!
                DispatchQueue.main.async {
                    self.emit("[deb] ✅ tar spawned as PID \(pid)")
                    completion(true)
                }
                return (true, "spawned PID=\(pid)", UInt64(pid))
            } else {
                DispatchQueue.main.async {
                    self.emit("[deb] ❌ posix_spawn failed: ret=\(ret), pid=\(pid)")
                    completion(false)
                }
                return (false, "spawn failed ret=\(ret)", 0)
            }
        }
        #else
        completion(false)
        #endif
    }
    
    // MARK: - Cleanup
    
    private func removeTmpFile(path: String) {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "cleanup") { rc in
            let pathAddr = remote_alloc_str(rc, path)
            RootExecutor.rcall(rc, "unlink", pathAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            return (true, "cleaned \(path)", 0)
        }
        #endif
    }
    
    // MARK: - Fallback: Manual extraction via launchd (split per file)
    
    private func fallbackManualExtract(dataTar: ArEntry, name: String, completion: @escaping (Bool, Int) -> Void) {
        emit("[deb] Fallback: decompressing and extracting manually...")
        
        // Decompress on background thread
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let tarData: Data
            if dataTar.name.hasSuffix(".gz") || dataTar.name.hasSuffix(".tgz") {
                guard let decompressed = decompressGzip(dataTar.data) else {
                    DispatchQueue.main.async {
                        self.emit("[deb] ❌ Gzip decompression failed")
                        completion(false, 0)
                    }
                    return
                }
                tarData = decompressed
            } else {
                tarData = dataTar.data
            }
            
            // Parse tar
            let files = parseTar(data: tarData)
            guard !files.isEmpty else {
                DispatchQueue.main.async {
                    self.emit("[deb] ❌ No files in tar")
                    completion(false, 0)
                }
                return
            }
            
            DispatchQueue.main.async {
                self.emit("[deb] Fallback: \(files.count) files, writing via launchd (1 file per call)...")
                self.fallbackWriteFiles(files: files, index: 0, installed: 0, completion: completion)
            }
        }
    }
    
    private func fallbackWriteFiles(files: [TarFile], index: Int, installed: Int, completion: @escaping (Bool, Int) -> Void) {
        #if !DISABLE_REMOTECALL
        guard index < files.count else {
            emit("[deb] ✅ Fallback installed \(installed) items")
            runUicache { completion(true, installed) }
            return
        }
        
        let file = files[index]
        let fullPath = "/var/jb/\(file.path)"
        
        root.executeAsRoot(operation: "fb_\(index)") { rc in
            if file.isDirectory {
                let pathAddr = remote_alloc_str(rc, fullPath)
                RootExecutor.rcall(rc, "mkdir", pathAddr, 0o755)
                RootExecutor.rcall(rc, "free", pathAddr)
            } else if !file.data.isEmpty {
                // Ensure parent
                let parent = (fullPath as NSString).deletingLastPathComponent
                let parentAddr = remote_alloc_str(rc, parent)
                RootExecutor.rcall(rc, "mkdir", parentAddr, 0o755)
                RootExecutor.rcall(rc, "free", parentAddr)
                
                let pathAddr = remote_alloc_str(rc, fullPath)
                let fd = RootExecutor.rcall(rc, "open", pathAddr,
                    UInt64(O_WRONLY | O_CREAT | O_TRUNC), UInt64(file.mode))
                if fd != UInt64(bitPattern: -1) {
                    let writeAddr = rc.trojanMem + 0x800
                    var written = 0
                    file.data.withUnsafeBytes { buffer in
                        while written < file.data.count {
                            let chunk = min(file.data.count - written, 0x1000)
                            rc.remote_write(writeAddr,
                                from: buffer.baseAddress!.advanced(by: written),
                                size: UInt64(chunk))
                            let n = RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(chunk))
                            if n == 0 || n == UInt64(bitPattern: -1) { break }
                            written += Int(n)
                        }
                    }
                    RootExecutor.rcall(rc, "close", fd)
                    RootExecutor.rcall(rc, "chmod", pathAddr, UInt64(file.mode))
                }
                RootExecutor.rcall(rc, "free", pathAddr)
            }
            return (true, "file \(index)", 0)
        }
        
        let newInstalled = installed + 1
        if (index + 1) % 50 == 0 {
            emit("[deb] Fallback: \(index + 1)/\(files.count)")
        }
        
        // 0.3s delay — each file is small, launchd call is fast
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            self.fallbackWriteFiles(files: files, index: index + 1, installed: newInstalled, completion: completion)
        }
        #else
        completion(false, 0)
        #endif
    }
    
    // MARK: - AR Archive Parser
    
    struct ArEntry {
        let name: String
        let data: Data
    }
    
    private func parseAr(data: Data) -> [ArEntry]? {
        guard data.count > 8 else { return nil }
        let magic = String(data: data[0..<8], encoding: .ascii)
        guard magic == "!<arch>\n" else { return nil }
        
        var entries: [ArEntry] = []
        var offset = 8
        
        while offset + 60 < data.count {
            let headerData = data[offset..<offset+60]
            guard let header = String(data: headerData, encoding: .ascii) else { break }
            
            let nameRaw = String(header.prefix(16)).trimmingCharacters(in: .whitespaces)
            let name = nameRaw.replacingOccurrences(of: "/", with: "")
            
            let sizeStr = String(header.dropFirst(48).prefix(10)).trimmingCharacters(in: .whitespaces)
            guard let size = Int(sizeStr) else { break }
            
            offset += 60
            if offset + size > data.count { break }
            let entryData = data[offset..<offset+size]
            entries.append(ArEntry(name: name, data: Data(entryData)))
            
            offset += size
            if offset % 2 != 0 { offset += 1 }
        }
        
        return entries.isEmpty ? nil : entries
    }
    
    private func findDataTar(in entries: [ArEntry]) -> ArEntry? {
        for entry in entries {
            if entry.name.hasPrefix("data.tar") {
                return entry
            }
        }
        return nil
    }
    
    // MARK: - Gzip Decompression
    
    private func decompressGzip(_ data: Data) -> Data? {
        guard data.count > 2, data[0] == 0x1f, data[1] == 0x8b else {
            return data
        }
        
        var headerEnd = 10
        let flags = data[3]
        if flags & 0x04 != 0 {
            if headerEnd + 2 < data.count {
                let xlen = Int(data[headerEnd]) | (Int(data[headerEnd+1]) << 8)
                headerEnd += 2 + xlen
            }
        }
        if flags & 0x08 != 0 {
            while headerEnd < data.count && data[headerEnd] != 0 { headerEnd += 1 }
            headerEnd += 1
        }
        if flags & 0x10 != 0 {
            while headerEnd < data.count && data[headerEnd] != 0 { headerEnd += 1 }
            headerEnd += 1
        }
        if flags & 0x02 != 0 { headerEnd += 2 }
        
        guard headerEnd < data.count else { return nil }
        
        let compressed = Data(data[headerEnd..<(data.count - 8)])
        var src = [UInt8](compressed)
        let srcSize = src.count
        
        var dstCapacity = srcSize * 4
        if dstCapacity < 1024 * 1024 { dstCapacity = 4 * 1024 * 1024 }
        
        for attempt in 0..<4 {
            var dst = [UInt8](repeating: 0, count: dstCapacity)
            let result = compression_decode_buffer(
                &dst, dstCapacity,
                &src, srcSize,
                nil,
                COMPRESSION_ZLIB
            )
            
            if result > 0 && result < dstCapacity {
                return Data(dst.prefix(result))
            } else if result == dstCapacity {
                dstCapacity *= 2
                emit("[deb] Gzip buffer full, retrying \(dstCapacity / 1024 / 1024)MB (attempt \(attempt + 2))")
            } else {
                break
            }
        }
        
        emit("[deb] ⚠️ Gzip decompression failed")
        return nil
    }
    
    // MARK: - TAR Parser (fallback only)
    
    struct TarFile {
        let path: String
        let data: Data
        let isDirectory: Bool
        let mode: UInt16
    }
    
    private func parseTar(data: Data) -> [TarFile] {
        var files: [TarFile] = []
        var offset = 0
        
        while offset + 512 <= data.count {
            let header = data[offset..<offset+512]
            if header.allSatisfy({ $0 == 0 }) { break }
            
            let nameBytes = header[offset..<offset+100]
            let name = String(data: Data(nameBytes), encoding: .ascii)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0")) ?? ""
            
            let modeBytes = data[offset+100..<offset+108]
            let modeStr = String(data: Data(modeBytes), encoding: .ascii)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0 ")) ?? "644"
            let mode = UInt16(modeStr, radix: 8) ?? 0o644
            
            let sizeBytes = data[offset+124..<offset+136]
            let sizeStr = String(data: Data(sizeBytes), encoding: .ascii)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0 ")) ?? "0"
            let size = Int(sizeStr, radix: 8) ?? 0
            
            let typeFlag = data[offset+156]
            let isDir = typeFlag == 0x35 || name.hasSuffix("/")
            
            let prefixBytes = data[offset+345..<min(offset+500, data.count)]
            let prefix = String(data: Data(prefixBytes), encoding: .ascii)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0")) ?? ""
            
            let fullPath = prefix.isEmpty ? name : "\(prefix)/\(name)"
            
            offset += 512
            
            let fileData: Data
            if size > 0 && !isDir && offset + size <= data.count {
                fileData = data[offset..<offset+size]
            } else {
                fileData = Data()
            }
            
            var cleanPath = fullPath
            if cleanPath.hasPrefix("./") { cleanPath = String(cleanPath.dropFirst(2)) }
            if cleanPath.hasPrefix("/") { cleanPath = String(cleanPath.dropFirst(1)) }
            
            if !cleanPath.isEmpty && typeFlag != 0x78 && typeFlag != 0x67 {
                files.append(TarFile(path: cleanPath, data: Data(fileData), isDirectory: isDir, mode: mode))
            }
            
            let blocks = (size + 511) / 512
            offset += blocks * 512
        }
        
        return files
    }
    
    // MARK: - UICache
    
    private func runUicache(completion: @escaping () -> Void) {
        #if !DISABLE_REMOTECALL
        ensureAMFIDisabled()
        
        guard let sb = mgr.sbProc else {
            emit("[deb] ⚠️ SpringBoard RC not available — skip uicache")
            completion()
            return
        }
        
        let workspace = remote_getClass(sb, "LSApplicationWorkspace")
        let defaultWS = remote_msg(sb, workspace, remote_sel(sb, "defaultWorkspace"), 0, 0, 0, 0)
        
        if defaultWS != 0 {
            remote_msg(sb, defaultWS,
                remote_sel(sb, "_LSPrivateRebuildApplicationDatabasesForSystemApps:internal:user:"),
                1, 1, 1, 0)
            emit("[deb] ✅ uicache triggered")
        } else {
            emit("[deb] ⚠️ LSApplicationWorkspace not available")
        }
        
        completion()
        #else
        completion()
        #endif
    }
    
    // MARK: - AMFI Enforcement Disable
    
    private func ensureAMFIDisabled() {
        let kernBase = ds_get_kernel_base()
        guard kernBase != 0 else { return }
        
        let slide = kernBase - 0xfffffff007004000
        let amfiDataSlid = UInt64(0xfffffff00a330098) &+ slide
        let flagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]
        
        // Check if already disabled
        if ds_kread64_safe(amfiDataSlid &+ flagOffsets[0]) == 0 { return }
        
        // Disable all
        emit("[deb] Disabling AMFI flags...")
        var count = 0
        for off in flagOffsets {
            ds_kwrite64(amfiDataSlid &+ off, 0)
            if ds_kread64_safe(amfiDataSlid &+ off) == 0 { count += 1 }
        }
        emit("[deb] ✅ AMFI disabled (\(count)/10)")
    }
}
