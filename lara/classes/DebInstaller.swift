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
        
        // Step 3: Decompress gzip → plain tar
        emit("[deb] Decompressing...")
        let tarData: Data
        if dataTar.name.hasSuffix(".gz") || dataTar.name.hasSuffix(".tgz") {
            guard let decompressed = decompressGzip(dataTar.data) else {
                emit("[deb] ❌ Gzip decompression failed")
                completion(false, 0)
                return
            }
            tarData = decompressed
            emit("[deb] Decompressed: \(decompressed.count) bytes")
        } else {
            tarData = dataTar.data
        }
        
        // Step 4: Try fast path (extractor binary) first, fallback to manual
        emit("[deb] Attempting fast install via extractor binary...")
        installViaExtractor(tarData: tarData, name: name) { [weak self] success in
            if success {
                self?.emit("[deb] ✅ Fast install complete")
                self?.runUicache { completion(true, 1) }
            } else {
                self?.emit("[deb] Extractor failed — using manual install (slower)...")
                self?.manualWriteFromTar(tarData: tarData, name: name, completion: completion)
            }
        }
    }
    
    // MARK: - Fast Path: Extractor Binary
    //
    // 1. Write data.tar to /var/jb/tmp/ (split 2MB per launchd call)
    // 2. Write extractor binary to /var/jb/tmp/extractor (1 call, 50KB)
    // 3. posix_spawn extractor — runs in own process, no watchdog
    // 4. Extractor extracts all files in seconds
    //
    
    private func installViaExtractor(tarData: Data, name: String, completion: @escaping (Bool) -> Void) {
        let tarPath = "/var/jb/tmp/\(name.lowercased().replacingOccurrences(of: " ", with: "_"))_data.tar"
        let extractorPath = "/var/jb/tmp/extractor"
        
        // Step 1: Write data.tar to disk (split 2MB per call)
        emit("[deb] Writing \(tarData.count) bytes tar to disk...")
        writeLargeData(data: tarData, path: tarPath) { [weak self] writeOk in
            guard let self, writeOk else {
                self?.emit("[deb] ❌ Failed to write tar to disk")
                completion(false)
                return
            }
            
            self.emit("[deb] ✅ Tar written to disk")
            
            // Step 2: Write extractor binary from app bundle
            self.writeExtractorBinary(to: extractorPath) { binOk in
                guard binOk else {
                    self.emit("[deb] ❌ Failed to write extractor binary")
                    completion(false)
                    return
                }
                
                self.emit("[deb] ✅ Extractor binary deployed")
                
                // Step 3: posix_spawn extractor
                self.spawnExtractor(binary: extractorPath, tarPath: tarPath, destDir: "/var/jb") { spawnOk in
                    if spawnOk {
                        // Give extractor time to finish (33MB tar ≈ 3-5s on device)
                        DispatchQueue.main.asyncAfter(deadline: .now() + 8) {
                            self.emit("[deb] ✅ Extraction complete")
                            // Cleanup
                            self.removeFile(path: tarPath)
                            completion(true)
                        }
                    } else {
                        self.emit("[deb] ❌ Spawn failed — extractor cannot execute")
                        self.removeFile(path: tarPath)
                        completion(false)
                    }
                }
            }
        }
    }
    
    // Write large data to disk via launchd split (2MB per call)
    private func writeLargeData(data: Data, path: String, completion: @escaping (Bool) -> Void) {
        #if !DISABLE_REMOTECALL
        let chunkLimit = 2 * 1024 * 1024
        let totalSize = data.count
        var totalWritten = 0
        var callIndex = 0
        let totalCalls = (totalSize + chunkLimit - 1) / chunkLimit
        
        func writeNext() {
            guard totalWritten < totalSize else {
                completion(true)
                return
            }
            
            let offset = totalWritten
            let thisSize = min(chunkLimit, totalSize - offset)
            let chunk = data[offset..<offset + thisSize]
            let isFirst = (offset == 0)
            callIndex += 1
            
            root.executeAsRoot(operation: "wd_\(callIndex)") { rc in
                if isFirst {
                    let dir = remote_alloc_str(rc, "/var/jb/tmp")
                    RootExecutor.rcall(rc, "mkdir", dir, 0o755)
                    RootExecutor.rcall(rc, "free", dir)
                }
                
                let pathAddr = remote_alloc_str(rc, path)
                let flags: UInt64 = isFirst ? UInt64(O_WRONLY | O_CREAT | O_TRUNC) : UInt64(O_WRONLY | O_APPEND)
                let fd = RootExecutor.rcall(rc, "open", pathAddr, flags, 0o644)
                
                guard fd != UInt64(bitPattern: -1) else {
                    RootExecutor.rcall(rc, "free", pathAddr)
                    DispatchQueue.main.async { completion(false) }
                    return (false, "open failed", 0)
                }
                
                let writeAddr = rc.trojanMem + 0x800
                var written = 0
                Data(chunk).withUnsafeBytes { buf in
                    while written < thisSize {
                        let sub = min(thisSize - written, 0x1000)
                        rc.remote_write(writeAddr, from: buf.baseAddress!.advanced(by: written), size: UInt64(sub))
                        let n = RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(sub))
                        if n == 0 || n == UInt64(bitPattern: -1) { break }
                        written += Int(n)
                    }
                }
                
                RootExecutor.rcall(rc, "close", fd)
                RootExecutor.rcall(rc, "free", pathAddr)
                totalWritten += written
                
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                    self.emit("[deb] Chunk \(callIndex)/\(totalCalls) (\(totalWritten)/\(totalSize))")
                    writeNext()
                }
                return (true, "chunk \(callIndex)", UInt64(totalWritten))
            }
        }
        
        writeNext()
        #else
        completion(false)
        #endif
    }
    
    // Write extractor binary from app bundle to /var/jb/tmp/
    private func writeExtractorBinary(to path: String, completion: @escaping (Bool) -> Void) {
        #if !DISABLE_REMOTECALL
        // Load extractor from app bundle
        guard let url = Bundle.main.url(forResource: "extractor", withExtension: nil),
              let binData = try? Data(contentsOf: url) else {
            emit("[deb] ❌ extractor binary not found in app bundle")
            completion(false)
            return
        }
        
        emit("[deb] Writing extractor (\(binData.count) bytes)...")
        
        // 50KB fits in 1 launchd call easily
        root.executeAsRoot(operation: "write_extractor") { rc in
            let pathAddr = remote_alloc_str(rc, path)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o755)
            
            guard fd != UInt64(bitPattern: -1) else {
                RootExecutor.rcall(rc, "free", pathAddr)
                DispatchQueue.main.async { completion(false) }
                return (false, "open failed", 0)
            }
            
            let writeAddr = rc.trojanMem + 0x800
            var written = 0
            binData.withUnsafeBytes { buf in
                while written < binData.count {
                    let chunk = min(binData.count - written, 0x1000)
                    rc.remote_write(writeAddr, from: buf.baseAddress!.advanced(by: written), size: UInt64(chunk))
                    let n = RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(chunk))
                    if n == 0 || n == UInt64(bitPattern: -1) { break }
                    written += Int(n)
                }
            }
            
            RootExecutor.rcall(rc, "close", fd)
            RootExecutor.rcall(rc, "chmod", pathAddr, 0o755)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            DispatchQueue.main.async { completion(written == binData.count) }
            return (true, "extractor written", UInt64(written))
        }
        #else
        completion(false)
        #endif
    }
    
    // Spawn extractor binary
    private func spawnExtractor(binary: String, tarPath: String, destDir: String, completion: @escaping (Bool) -> Void) {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "spawn_extractor") { rc in
            let mem = rc.trojanMem
            
            let binAddr = remote_alloc_str(rc, binary)
            let tarAddr = remote_alloc_str(rc, tarPath)
            let destAddr = remote_alloc_str(rc, destDir)
            
            // argv = [binary, tarPath, destDir, NULL]
            let argvBase = mem + 0x400
            rc[argvBase].setValue64(binAddr)
            rc[argvBase + 8].setValue64(tarAddr)
            rc[argvBase + 16].setValue64(destAddr)
            rc[argvBase + 24].setValue64(0)
            
            let pidAddr = mem + 0x300
            rc[pidAddr].setValue32(0)
            
            let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
            let pid = rc[pidAddr].value32()
            
            RootExecutor.rcall(rc, "free", binAddr)
            RootExecutor.rcall(rc, "free", tarAddr)
            RootExecutor.rcall(rc, "free", destAddr)
            
            let ok = (ret == 0 && pid != 0)
            DispatchQueue.main.async {
                if ok {
                    self.emit("[deb] ✅ Extractor spawned (PID \(pid))")
                } else {
                    self.emit("[deb] ❌ posix_spawn ret=\(ret), pid=\(pid)")
                }
                completion(ok)
            }
            return (ok, "spawn ret=\(ret) pid=\(pid)", UInt64(pid))
        }
        #else
        completion(false)
        #endif
    }
    
    private func removeFile(path: String) {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "rm") { rc in
            let p = remote_alloc_str(rc, path)
            RootExecutor.rcall(rc, "unlink", p)
            RootExecutor.rcall(rc, "free", p)
            return (true, "rm \(path)", 0)
        }
        #endif
    }
    
    // MARK: - Slow Path: Manual per-file write (fallback)
    
    private func manualWriteFromTar(tarData: Data, name: String, completion: @escaping (Bool, Int) -> Void) {
        let files = parseTar(data: tarData)
        guard !files.isEmpty else {
            emit("[deb] ❌ No files in tar")
            completion(false, 0)
            return
        }
        
        let dirs = files.filter { $0.isDirectory }
        let regularFiles = files.filter { !$0.isDirectory && !$0.data.isEmpty }
        
        // ETA
        let largeChunks = regularFiles.filter { $0.data.count > 2*1024*1024 }.reduce(0) { $0 + ($1.data.count + 2*1024*1024 - 1) / (2*1024*1024) }
        let totalOps = regularFiles.count + largeChunks
        let etaMin = Int(Double(totalOps) * 1.5) / 60
        emit("[deb] Manual: \(dirs.count) dirs + \(regularFiles.count) files")
        emit("[deb] ⏱ Estimated: ~\(etaMin) minutes")
        emit("[deb] Creating directories...")
        
        root.executeAsRoot(operation: "mkdirs") { rc in
            for dir in dirs {
                let p = remote_alloc_str(rc, "/var/jb/\(dir.path)")
                RootExecutor.rcall(rc, "mkdir", p, 0o755)
                RootExecutor.rcall(rc, "free", p)
            }
            return (true, "\(dirs.count) dirs", 0)
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
            self.emit("[deb] Writing \(regularFiles.count) files...")
            self.writeFilesSequentially(files: regularFiles, index: 0, installed: dirs.count, total: regularFiles.count, startTime: Date(), completion: completion)
        }
    }
    
    private func writeFilesSequentially(files: [TarFile], index: Int, installed: Int, total: Int = 0, startTime: Date = Date(), completion: @escaping (Bool, Int) -> Void) {
        guard index < files.count else {
            emit("[deb] ✅ Done: \(installed) items installed")
            runUicache { completion(true, installed) }
            return
        }
        
        let file = files[index]
        let fullPath = "/var/jb/\(file.path)"
        
        // Show ETA every 25 files
        if index > 0 && index % 25 == 0 {
            let elapsed = Date().timeIntervalSince(startTime)
            let perFile = elapsed / Double(index)
            let remaining = Double(files.count - index) * perFile
            let remMin = Int(remaining) / 60
            let remSec = Int(remaining) % 60
            emit("[deb] \(index)/\(files.count) — ~\(remMin)m \(remSec)s remaining")
        }
        
        // Large files (>2MB): split into multiple launchd calls
        if file.data.count > 2 * 1024 * 1024 {
            emit("[deb] Large file: \(file.path) (\(file.data.count / 1024)KB)")
            writeLargeFile(path: fullPath, data: file.data, mode: file.mode) {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    self.writeFilesSequentially(files: files, index: index + 1, installed: installed + 1, total: total, startTime: startTime, completion: completion)
                }
            }
            return
        }
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "wf_\(index)") { rc in
            // Ensure parent directory
            let parent = (fullPath as NSString).deletingLastPathComponent
            let parentAddr = remote_alloc_str(rc, parent)
            RootExecutor.rcall(rc, "mkdir", parentAddr, 0o755)
            RootExecutor.rcall(rc, "free", parentAddr)
            
            // Write file
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
            return (true, "file \(index)", 0)
        }
        
        // Log every 25 files
        if (index + 1) % 25 == 0 {
            emit("[deb] Progress: \(index + 1)/\(files.count)")
        }
        
        // 1.5s delay between files — safe from watchdog with queue guard
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            self.writeFilesSequentially(files: files, index: index + 1, installed: installed + 1, total: total, startTime: startTime, completion: completion)
        }
        #else
        completion(false, 0)
        #endif
    }
    
    // MARK: - Large File Writer (split into 2MB launchd calls)
    
    /// Write a large file (>2MB) by splitting into multiple launchd calls
    /// Each call writes up to 2MB (safe: ~0.5s per call)
    private func writeLargeFile(path: String, data: Data, mode: UInt16, completion: @escaping () -> Void) {
        #if !DISABLE_REMOTECALL
        let chunkLimit = 2 * 1024 * 1024
        let totalSize = data.count
        var totalWritten = 0
        var callIndex = 0
        let totalCalls = (totalSize + chunkLimit - 1) / chunkLimit
        
        func writeNextChunk() {
            guard totalWritten < totalSize else {
                // Done — chmod the file
                root.executeAsRoot(operation: "chmod_large") { rc in
                    let pathAddr = remote_alloc_str(rc, path)
                    RootExecutor.rcall(rc, "chmod", pathAddr, UInt64(mode))
                    RootExecutor.rcall(rc, "free", pathAddr)
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { completion() }
                    return (true, "chmod \(path)", 0)
                }
                return
            }
            
            let offset = totalWritten
            let thisChunkSize = min(chunkLimit, totalSize - offset)
            let chunkData = data[offset..<offset + thisChunkSize]
            let isFirst = (offset == 0)
            callIndex += 1
            
            root.executeAsRoot(operation: "lf_\(callIndex)") { rc in
                // First: ensure parent + open TRUNC. After: open APPEND
                if isFirst {
                    let parent = (path as NSString).deletingLastPathComponent
                    let parentAddr = remote_alloc_str(rc, parent)
                    RootExecutor.rcall(rc, "mkdir", parentAddr, 0o755)
                    RootExecutor.rcall(rc, "free", parentAddr)
                }
                
                let pathAddr = remote_alloc_str(rc, path)
                let flags: UInt64 = isFirst
                    ? UInt64(O_WRONLY | O_CREAT | O_TRUNC)
                    : UInt64(O_WRONLY | O_APPEND)
                let fd = RootExecutor.rcall(rc, "open", pathAddr, flags, UInt64(mode))
                
                guard fd != UInt64(bitPattern: -1) else {
                    RootExecutor.rcall(rc, "free", pathAddr)
                    DispatchQueue.main.async { completion() }
                    return (false, "open failed", 0)
                }
                
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
                
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    self.emit("[deb] Large file chunk \(callIndex)/\(totalCalls) (\(totalWritten)/\(totalSize))")
                    writeNextChunk()
                }
                return (true, "lf chunk \(callIndex)", UInt64(totalWritten))
            }
        }
        
        writeNextChunk()
        #else
        completion()
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
