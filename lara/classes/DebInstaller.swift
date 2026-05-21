//
//  DebInstaller.swift
//  DSPloit
//
//  Proper .deb package installer:
//  1. Parse ar archive → extract data.tar.gz
//  2. Decompress gzip → tar
//  3. Parse tar → extract files
//  4. Write files to /var/jb/ via root
//  5. Run uicache to register .app bundles
//

import Foundation
import Compression

/// .deb installer — extracts and installs packages to /var/jb
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
        
        // Step 2: Find data.tar (could be .gz, .xz, .zst, .lzma, or plain)
        guard let dataTar = findDataTar(in: arEntries) else {
            emit("[deb] ❌ No data.tar found in .deb")
            completion(false, 0)
            return
        }
        
        emit("[deb] data.tar: \(dataTar.name) (\(dataTar.data.count) bytes)")
        
        // Step 3: Decompress if needed
        let tarData: Data
        if dataTar.name.hasSuffix(".gz") || dataTar.name.hasSuffix(".tgz") {
            emit("[deb] Decompressing gzip...")
            guard let decompressed = decompressGzip(dataTar.data) else {
                emit("[deb] ❌ Gzip decompression failed")
                completion(false, 0)
                return
            }
            tarData = decompressed
            emit("[deb] Decompressed: \(decompressed.count) bytes")
        } else if dataTar.name.hasSuffix(".xz") || dataTar.name.hasSuffix(".lzma") {
            // xz/lzma — try raw (some .debs use uncompressed tar labeled as .xz)
            emit("[deb] ⚠️ xz/lzma compression — attempting raw tar parse")
            tarData = dataTar.data
        } else {
            tarData = dataTar.data
        }
        
        // Step 4: Parse tar
        emit("[deb] Parsing tar archive...")
        let files = parseTar(data: tarData)
        emit("[deb] Found \(files.count) files in tar")
        
        if files.isEmpty {
            emit("[deb] ❌ No files extracted from tar")
            completion(false, 0)
            return
        }
        
        // Step 5: Write files to /var/jb/ via root
        emit("[deb] Installing \(files.count) files to /var/jb/...")
        installFiles(files: files, prefix: "/var/jb") { [weak self] installedCount in
            self?.emit("[deb] ✅ Installed \(installedCount)/\(files.count) files")
            
            // Step 6: Check if any .app bundle was installed → run uicache
            let appBundles = files.filter { $0.path.contains(".app/Info.plist") }
            if !appBundles.isEmpty {
                self?.emit("[deb] Found \(appBundles.count) app bundle(s) — running uicache...")
                self?.runUicache {
                    completion(true, installedCount)
                }
            } else {
                completion(true, installedCount)
            }
        }
    }
    
    // MARK: - AR Archive Parser
    
    struct ArEntry {
        let name: String
        let data: Data
    }
    
    private func parseAr(data: Data) -> [ArEntry]? {
        // AR magic: "!<arch>\n" (8 bytes)
        guard data.count > 8 else { return nil }
        let magic = String(data: data[0..<8], encoding: .ascii)
        guard magic == "!<arch>\n" else { return nil }
        
        var entries: [ArEntry] = []
        var offset = 8
        
        while offset + 60 < data.count {
            // AR header: 60 bytes
            // name[16] + mtime[12] + uid[6] + gid[6] + mode[8] + size[10] + magic[2]
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
            // AR entries are 2-byte aligned
            if offset % 2 != 0 { offset += 1 }
        }
        
        return entries.isEmpty ? nil : entries
    }
    
    private func findDataTar(in entries: [ArEntry]) -> ArEntry? {
        // Look for data.tar.gz, data.tar.xz, data.tar.zst, data.tar.lzma, data.tar
        for entry in entries {
            if entry.name.hasPrefix("data.tar") {
                return entry
            }
        }
        return nil
    }
    
    // MARK: - Gzip Decompression
    
    private func decompressGzip(_ data: Data) -> Data? {
        // Gzip header: 1f 8b
        guard data.count > 2, data[0] == 0x1f, data[1] == 0x8b else {
            // Not gzip — return as-is (might be uncompressed tar)
            return data
        }
        
        // Find deflate data start (skip gzip header)
        var headerEnd = 10
        let flags = data[3]
        if flags & 0x04 != 0 { // FEXTRA
            if headerEnd + 2 < data.count {
                let xlen = Int(data[headerEnd]) | (Int(data[headerEnd+1]) << 8)
                headerEnd += 2 + xlen
            }
        }
        if flags & 0x08 != 0 { // FNAME
            while headerEnd < data.count && data[headerEnd] != 0 { headerEnd += 1 }
            headerEnd += 1
        }
        if flags & 0x10 != 0 { // FCOMMENT
            while headerEnd < data.count && data[headerEnd] != 0 { headerEnd += 1 }
            headerEnd += 1
        }
        if flags & 0x02 != 0 { headerEnd += 2 } // FHCRC
        
        guard headerEnd < data.count else { return nil }
        
        let compressed = Data(data[headerEnd..<(data.count - 8)]) // strip gzip footer (8 bytes: CRC32 + ISIZE)
        
        // Streaming decompression for large files (Filza .deb can be 50MB+)
        var src = [UInt8](compressed)
        let srcSize = src.count
        
        // Start with 4x estimate, grow if needed
        var dstCapacity = srcSize * 4
        if dstCapacity < 1024 * 1024 { dstCapacity = 4 * 1024 * 1024 } // min 4MB
        
        // Try decompression, double buffer if it fills up
        for attempt in 0..<4 {
            var dst = [UInt8](repeating: 0, count: dstCapacity)
            let result = compression_decode_buffer(
                &dst, dstCapacity,
                &src, srcSize,
                nil,
                COMPRESSION_ZLIB
            )
            
            if result > 0 && result < dstCapacity {
                // Success — didn't fill the buffer
                return Data(dst.prefix(result))
            } else if result == dstCapacity {
                // Buffer was exactly filled — likely truncated, try bigger
                dstCapacity *= 2
                emit("[deb] Gzip buffer full, retrying with \(dstCapacity / 1024 / 1024)MB (attempt \(attempt + 2))")
            } else {
                // Decompression failed
                break
            }
        }
        
        emit("[deb] ⚠️ Gzip decompression failed after retries")
        return nil
    }
    
    // MARK: - TAR Parser
    
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
            // TAR header is 512 bytes
            let header = data[offset..<offset+512]
            
            // Check for empty block (end of archive)
            if header.allSatisfy({ $0 == 0 }) { break }
            
            // Name: bytes 0-99
            let nameBytes = header[offset..<offset+100]
            let name = String(data: Data(nameBytes), encoding: .ascii)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0")) ?? ""
            
            // Mode: bytes 100-107 (octal string)
            let modeBytes = data[offset+100..<offset+108]
            let modeStr = String(data: Data(modeBytes), encoding: .ascii)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0 ")) ?? "644"
            let mode = UInt16(modeStr, radix: 8) ?? 0o644
            
            // Size: bytes 124-135 (octal string)
            let sizeBytes = data[offset+124..<offset+136]
            let sizeStr = String(data: Data(sizeBytes), encoding: .ascii)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0 ")) ?? "0"
            let size = Int(sizeStr, radix: 8) ?? 0
            
            // Type: byte 156
            let typeFlag = data[offset+156]
            let isDir = typeFlag == 0x35 || name.hasSuffix("/") // '5' = directory
            
            // Prefix: bytes 345-499 (POSIX/ustar)
            let prefixBytes = data[offset+345..<min(offset+500, data.count)]
            let prefix = String(data: Data(prefixBytes), encoding: .ascii)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0")) ?? ""
            
            let fullPath: String
            if !prefix.isEmpty {
                fullPath = "\(prefix)/\(name)"
            } else {
                fullPath = name
            }
            
            offset += 512 // skip header
            
            // Read file data
            let fileData: Data
            if size > 0 && !isDir && offset + size <= data.count {
                fileData = data[offset..<offset+size]
            } else {
                fileData = Data()
            }
            
            // Clean path (remove leading ./ or /)
            var cleanPath = fullPath
            if cleanPath.hasPrefix("./") { cleanPath = String(cleanPath.dropFirst(2)) }
            if cleanPath.hasPrefix("/") { cleanPath = String(cleanPath.dropFirst(1)) }
            
            if !cleanPath.isEmpty && typeFlag != 0x78 && typeFlag != 0x67 { // skip pax headers
                files.append(TarFile(path: cleanPath, data: Data(fileData), isDirectory: isDir, mode: mode))
            }
            
            // Advance past file data (512-byte aligned)
            let blocks = (size + 511) / 512
            offset += blocks * 512
        }
        
        return files
    }
    
    // MARK: - File Installation (via root)
    //
    // CRITICAL: launchd (PID 1) has a strict 5s watchdog — ANY file write via launchd
    // risks panic if the operation takes too long. Even 1 file per connection can panic
    // if the file is large or there's latency.
    //
    // SOLUTION: Use SpringBoard RC (mgr.sbProc) for all file writes.
    // SpringBoard is a persistent connection with NO watchdog kill.
    // After sandbox escape, SpringBoard can write to /var/jb/.
    // If SpringBoard is unavailable, fall back to launchd with single small files only.
    //
    
    private func installFiles(files: [TarFile], prefix: String, completion: @escaping (Int) -> Void) {
        #if !DISABLE_REMOTECALL
        guard let sb = mgr.sbProc else {
            emit("[deb] ❌ SpringBoard RC not available — cannot install safely")
            completion(0)
            return
        }
        
        // All operations go through SpringBoard — no watchdog risk
        let directories = files.filter { $0.isDirectory }.sorted { $0.path < $1.path }
        let regularFiles = files.filter { !$0.isDirectory && !$0.data.isEmpty }
        
        emit("[deb] Using SpringBoard RC (no watchdog risk)")
        emit("[deb] Creating \(directories.count) directories...")
        
        // Phase 1: Create all directories via SpringBoard (instant, no risk)
        var installed = 0
        for dir in directories {
            let fullPath = "\(prefix)/\(dir.path)"
            let pathAddr = remote_alloc_str(sb, fullPath)
            RootExecutor.rcall(sb, "mkdir", pathAddr, 0o755)
            RootExecutor.rcall(sb, "free", pathAddr)
            installed += 1
        }
        
        emit("[deb] ✅ Created \(installed) directories")
        emit("[deb] Writing \(regularFiles.count) files via SpringBoard...")
        
        // Phase 2: Write all files via SpringBoard — chunked, no time limit
        var fileIndex = 0
        
        func writeNextFile() {
            guard fileIndex < regularFiles.count else {
                // All done
                DispatchQueue.main.async {
                    self.emit("[deb] ✅ All \(installed) items installed")
                }
                completion(installed)
                return
            }
            
            let file = regularFiles[fileIndex]
            fileIndex += 1
            let fullPath = "\(prefix)/\(file.path)"
            
            // Ensure parent directory exists
            let parentPath = (fullPath as NSString).deletingLastPathComponent
            let parentAddr = remote_alloc_str(sb, parentPath)
            RootExecutor.rcall(sb, "mkdir", parentAddr, 0o755)
            RootExecutor.rcall(sb, "free", parentAddr)
            
            // Open file
            let pathAddr = remote_alloc_str(sb, fullPath)
            let fd = RootExecutor.rcall(sb, "open", pathAddr,
                UInt64(O_WRONLY | O_CREAT | O_TRUNC), UInt64(file.mode))
            
            if fd != UInt64(bitPattern: -1) {
                // Write in 4KB chunks
                let writeAddr = sb.trojanMem + 0x800
                var written = 0
                file.data.withUnsafeBytes { buffer in
                    while written < file.data.count {
                        let chunk = min(file.data.count - written, 0x1000)
                        sb.remote_write(writeAddr,
                            from: buffer.baseAddress!.advanced(by: written),
                            size: UInt64(chunk))
                        let n = RootExecutor.rcall(sb, "write", fd, writeAddr, UInt64(chunk))
                        if n == 0 || n == UInt64(bitPattern: -1) { break }
                        written += Int(n)
                    }
                }
                RootExecutor.rcall(sb, "close", fd)
                RootExecutor.rcall(sb, "chmod", pathAddr, UInt64(file.mode))
                installed += 1
            }
            
            RootExecutor.rcall(sb, "free", pathAddr)
            
            // Log progress every 50 files
            if fileIndex % 50 == 0 || fileIndex == regularFiles.count {
                DispatchQueue.main.async {
                    self.emit("[deb] Progress: \(fileIndex)/\(regularFiles.count) files written")
                }
            }
            
            // Yield to main thread every 20 files to keep UI responsive
            if fileIndex % 20 == 0 {
                DispatchQueue.main.async {
                    writeNextFile()
                }
            } else {
                writeNextFile()
            }
        }
        
        // Start writing on background thread to not block UI
        DispatchQueue.global(qos: .userInitiated).async {
            writeNextFile()
        }
        #else
        completion(0)
        #endif
    }
    
    // MARK: - UICache (register app icons)
    
    private func runUicache(completion: @escaping () -> Void) {
        #if !DISABLE_REMOTECALL
        // Ensure AMFI is disabled before launching any new binary
        ensureAMFIDisabled()
        
        // uicache via SpringBoard's LSApplicationWorkspace
        guard let sb = mgr.sbProc else {
            emit("[deb] ⚠️ SpringBoard RC not available — skip uicache")
            completion()
            return
        }
        
        // Call [LSApplicationWorkspace defaultWorkspace] _LSPrivateRebuildApplicationDatabasesForSystemApps:internal:user:
        let workspace = remote_getClass(sb, "LSApplicationWorkspace")
        let defaultWS = remote_msg(sb, workspace, remote_sel(sb, "defaultWorkspace"), 0, 0, 0, 0)
        
        if defaultWS != 0 {
            // Trigger icon cache rebuild
            remote_msg(sb, defaultWS,
                remote_sel(sb, "_LSPrivateRebuildApplicationDatabasesForSystemApps:internal:user:"),
                1, 1, 1, 0)
            emit("[deb] ✅ uicache triggered — app should appear after respring")
        } else {
            emit("[deb] ⚠️ LSApplicationWorkspace not available")
        }
        
        completion()
        #else
        completion()
        #endif
    }
    
    // MARK: - AMFI Enforcement Disable
    
    /// Ensure AMFI flags are disabled so installed binaries can execute.
    /// This is idempotent — safe to call multiple times.
    private func ensureAMFIDisabled() {
        let kernBase = ds_get_kernel_base()
        guard kernBase != 0 else {
            emit("[deb] ⚠️ Kernel base unavailable — AMFI state unknown")
            return
        }
        
        let slide = kernBase - 0xfffffff007004000
        let amfiDataSlid = UInt64(0xfffffff00a330098) &+ slide
        let flagOffsets: [UInt64] = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]
        
        // Check if already disabled
        let firstFlag = ds_kread64_safe(amfiDataSlid &+ flagOffsets[0])
        if firstFlag == 0 {
            // Already disabled — no action needed
            return
        }
        
        // Disable all flags
        emit("[deb] AMFI flags still enabled — disabling for binary execution...")
        var count = 0
        for off in flagOffsets {
            ds_kwrite64(amfiDataSlid &+ off, 0)
            if ds_kread64_safe(amfiDataSlid &+ off) == 0 { count += 1 }
        }
        emit("[deb] ✅ AMFI disabled (\(count)/\(flagOffsets.count))")
    }
}
