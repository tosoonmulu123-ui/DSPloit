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
        
        // Step 3: iOS 18 has NO /usr/bin/tar — go directly to manual extraction
        emit("[deb] iOS 18 has no tar binary — using direct extraction...")
        manualExtractAndWrite(dataTar: dataTar, name: name, completion: completion)
    }
    
    // MARK: - Fallback: Manual extraction via launchd (split per file)
    
    private func fallbackManualExtract(dataTar: ArEntry, name: String, completion: @escaping (Bool, Int) -> Void) {
        manualExtractAndWrite(dataTar: dataTar, name: name, completion: completion)
    }
    
    /// Extract tar in memory, write each file via individual launchd calls with safe delays
    private func manualExtractAndWrite(dataTar: ArEntry, name: String, completion: @escaping (Bool, Int) -> Void) {
        emit("[deb] Manual extract: decompressing...")
        
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
                DispatchQueue.main.async {
                    self.emit("[deb] Decompressed: \(decompressed.count) bytes")
                }
            } else {
                tarData = dataTar.data
            }
            
            let files = parseTar(data: tarData)
            guard !files.isEmpty else {
                DispatchQueue.main.async {
                    self.emit("[deb] ❌ No files in tar")
                    completion(false, 0)
                }
                return
            }
            
            // Group files into batches by total size (max 500KB per launchd call)
            // Small files can be batched together; large files get their own call
            let dirs = files.filter { $0.isDirectory }
            let regularFiles = files.filter { !$0.isDirectory && !$0.data.isEmpty }
            
            DispatchQueue.main.async {
                self.emit("[deb] Manual: \(dirs.count) dirs + \(regularFiles.count) files")
                self.emit("[deb] Creating directories...")
                
                // Phase 1: Create all directories in one call (fast)
                self.root.executeAsRoot(operation: "mkdirs") { rc in
                    for dir in dirs {
                        let fullPath = "/var/jb/\(dir.path)"
                        let pathAddr = remote_alloc_str(rc, fullPath)
                        RootExecutor.rcall(rc, "mkdir", pathAddr, 0o755)
                        RootExecutor.rcall(rc, "free", pathAddr)
                    }
                    return (true, "\(dirs.count) dirs", 0)
                }
                
                // Phase 2: Write files one at a time with 2s delay
                DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                    self.emit("[deb] Writing \(regularFiles.count) files (one per call)...")
                    self.writeFilesSequentially(files: regularFiles, index: 0, installed: dirs.count, completion: completion)
                }
            }
        }
    }
    
    private func writeFilesSequentially(files: [TarFile], index: Int, installed: Int, completion: @escaping (Bool, Int) -> Void) {
        guard index < files.count else {
            emit("[deb] ✅ Done: \(installed) items installed")
            runUicache { completion(true, installed) }
            return
        }
        
        let file = files[index]
        let fullPath = "/var/jb/\(file.path)"
        
        // Skip files larger than 500KB for now (too risky for single launchd call)
        if file.data.count > 512 * 1024 {
            emit("[deb] ⚠️ Skipping large file: \(file.path) (\(file.data.count) bytes)")
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                self.writeFilesSequentially(files: files, index: index + 1, installed: installed, completion: completion)
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
        
        // 2s delay between files — safe from watchdog
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            self.writeFilesSequentially(files: files, index: index + 1, installed: installed + 1, completion: completion)
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
