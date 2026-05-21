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
        
        // Use Apple's Compression framework
        // Skip gzip header (10 bytes minimum) and decompress deflate stream
        var decompressed = Data()
        let bufferSize = 65536
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        
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
        
        let compressed = data[headerEnd..<(data.count - 8)] // strip gzip footer (CRC32 + size)
        
        // Use NSData's built-in decompression
        let nsData = compressed as NSData
        // Try zlib raw inflate
        return compressed.withUnsafeBytes { srcPtr -> Data? in
            guard let src = srcPtr.baseAddress else { return nil }
            let srcSize = compressed.count
            
            // Allocate output buffer (estimate 10x compression ratio)
            var dstSize = srcSize * 10
            var dst = [UInt8](repeating: 0, count: dstSize)
            
            let result = compression_decode_buffer(
                &dst, dstSize,
                src.assumingMemoryBound(to: UInt8.self), srcSize,
                nil,
                COMPRESSION_ZLIB
            )
            
            if result > 0 {
                return Data(dst.prefix(result))
            }
            return nil
        }
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
    
    private func installFiles(files: [TarFile], prefix: String, completion: @escaping (Int) -> Void) {
        #if !DISABLE_REMOTECALL
        // Sort: directories first, then files
        let sorted = files.sorted { a, b in
            if a.isDirectory != b.isDirectory { return a.isDirectory }
            return a.path < b.path
        }
        
        // Install in batches to avoid watchdog kill on launchd
        let batchSize = 15
        var installed = 0
        var batchIndex = 0
        let batches = stride(from: 0, to: sorted.count, by: batchSize).map {
            Array(sorted[$0..<min($0 + batchSize, sorted.count)])
        }
        
        func installBatch() {
            guard batchIndex < batches.count else {
                completion(installed)
                return
            }
            
            let batch = batches[batchIndex]
            batchIndex += 1
            
            root.executeAsRoot(operation: "install_batch_\(batchIndex)") { [self] rc in
                for file in batch {
                    let fullPath = "\(prefix)/\(file.path)"
                    let pathAddr = remote_alloc_str(rc, fullPath)
                    
                    if file.isDirectory {
                        RootExecutor.rcall(rc, "mkdir", pathAddr, UInt64(file.mode) | 0o755)
                        installed += 1
                    } else if !file.data.isEmpty {
                        // Write file
                        let fd = RootExecutor.rcall(rc, "open", pathAddr,
                            UInt64(O_WRONLY | O_CREAT | O_TRUNC), UInt64(file.mode))
                        if fd != UInt64(bitPattern: -1) {
                            // Write in chunks
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
                            
                            // chmod
                            RootExecutor.rcall(rc, "chmod", pathAddr, UInt64(file.mode))
                            installed += 1
                        }
                    }
                    RootExecutor.rcall(rc, "free", pathAddr)
                }
                
                DispatchQueue.main.async {
                    self.emit("[deb] Batch \(batchIndex)/\(batches.count) done (\(installed) files)")
                }
                return (true, "batch \(batchIndex)", UInt64(installed))
            }
            
            // Wait for batch to complete, then do next
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) {
                installBatch()
            }
        }
        
        installBatch()
        #else
        completion(0)
        #endif
    }
    
    // MARK: - UICache (register app icons)
    
    private func runUicache(completion: @escaping () -> Void) {
        #if !DISABLE_REMOTECALL
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
}
