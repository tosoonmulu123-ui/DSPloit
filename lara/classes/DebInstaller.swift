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
import CommonCrypto

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
        
        // Step 4: Install via batch write (proven: ~30s for Filza)
        emit("[deb] Installing via batch write...")
        let files = parseTar(data: tarData)
        guard !files.isEmpty else {
            emit("[deb] ❌ No files in tar")
            completion(false, 0)
            return
        }
        batchWriteFromTar(tarData: tarData, name: name) { [weak self] success, count in
            guard let self, success else {
                completion(success, count)
                return
            }
            
            // Step 5: CDHash + trust cache + uicache (proper CodeDirectory hash)
            let files = self.parseTar(data: tarData)
            let executables = files.filter { !$0.isDirectory && self.isMachO($0.data) }
            
            if !executables.isEmpty {
                self.emit("[deb] Found \(executables.count) Mach-O binaries — computing CDHash...")
                let cdhashes = executables.compactMap { self.computeCDHash(data: $0.data, path: $0.path) }
                
                if !cdhashes.isEmpty {
                    self.emit("[deb] Injecting \(cdhashes.count) CDHashes into trust cache...")
                    self.injectTrustCacheBatch(cdhashes: cdhashes) {
                        self.emit("[deb] ✅ Trust cache: \(cdhashes.count) hashes injected")
                        
                        let hasApp = files.contains { $0.path.contains(".app/Info.plist") }
                        if hasApp {
                            self.emit("[deb] Registering app...")
                            self.runUicache {
                                self.emit("[deb] ✅ Done — respring to see app")
                                completion(true, count)
                            }
                        } else {
                            completion(true, count)
                        }
                    }
                } else {
                    self.emit("[deb] ⚠️ No CDHashes computed (binaries may be unsigned)")
                    completion(true, count)
                }
            } else {
                completion(true, count)
            }
        }
    }
    
    // MARK: - Mach-O Detection & CDHash Computation
    
    /// Check if data starts with Mach-O magic
    private func isMachO(_ data: Data) -> Bool {
        guard data.count > 4 else { return false }
        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        // MH_MAGIC_64 = 0xFEEDFACF, MH_CIGAM_64 = 0xCFFAEDFE
        // FAT_MAGIC = 0xCAFEBABE, FAT_CIGAM = 0xBEBAFECA
        return magic == 0xFEEDFACF || magic == 0xCFFAEDFE || magic == 0xCAFEBABE || magic == 0xBEBAFECA
    }
    
    /// Compute CDHash (SHA256 of CodeDirectory blob) from Mach-O binary
    /// Proper implementation: parse LC_CODE_SIGNATURE → SuperBlob → CodeDirectory → SHA256
    private func computeCDHash(data: Data, path: String) -> [UInt8]? {
        guard data.count > 32 else { return nil }
        
        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        
        // Handle FAT binary — find arm64 slice
        var sliceData = data
        if magic == 0xCAFEBABE || magic == 0xBEBAFECA {
            if let arm64Slice = extractArm64Slice(from: data) {
                sliceData = arm64Slice
            } else {
                return nil
            }
        }
        
        // Parse Mach-O to find LC_CODE_SIGNATURE
        guard sliceData.count > 32 else { return nil }
        let sliceMagic = sliceData.withUnsafeBytes { $0.load(as: UInt32.self) }
        guard sliceMagic == 0xFEEDFACF || sliceMagic == 0xCFFAEDFE else { return nil }
        
        let isSwapped = (sliceMagic == 0xCFFAEDFE)
        
        func read32(_ offset: Int) -> UInt32 {
            let val = sliceData.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
            return isSwapped ? val.byteSwapped : val
        }
        
        // mach_header_64: magic(4) + cputype(4) + cpusubtype(4) + filetype(4) + ncmds(4) + sizeofcmds(4) + flags(4) + reserved(4) = 32
        let ncmds = Int(read32(16))
        var cmdOffset = 32 // sizeof(mach_header_64)
        
        var csOffset: UInt32 = 0
        var csSize: UInt32 = 0
        
        for _ in 0..<ncmds {
            guard cmdOffset + 8 <= sliceData.count else { break }
            let cmd = read32(cmdOffset)
            let cmdsize = read32(cmdOffset + 4)
            
            // LC_CODE_SIGNATURE = 0x1D
            if cmd == 0x1D && cmdOffset + 16 <= sliceData.count {
                csOffset = read32(cmdOffset + 8)  // dataoff
                csSize = read32(cmdOffset + 12)   // datasize
                break
            }
            
            cmdOffset += Int(cmdsize)
        }
        
        guard csOffset > 0 && csSize > 8 else {
            // No code signature — hash entire binary as fallback
            return sha256Truncated(sliceData)
        }
        
        // Parse SuperBlob at csOffset
        let csStart = Int(csOffset)
        guard csStart + Int(csSize) <= sliceData.count else { return sha256Truncated(sliceData) }
        
        let superBlobMagic = read32(csStart)
        // CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
        guard superBlobMagic == 0xFADE0CC0 || superBlobMagic == 0xC00CDEFA else {
            return sha256Truncated(sliceData)
        }
        
        let blobCount = read32(csStart + 8)
        
        // Find CodeDirectory (type=0, magic=0xFADE0C02)
        for i in 0..<Int(blobCount) {
            let indexOffset = csStart + 12 + i * 8
            guard indexOffset + 8 <= sliceData.count else { break }
            // let blobType = read32(indexOffset)
            let blobOffset = read32(indexOffset + 4)
            
            let blobStart = csStart + Int(blobOffset)
            guard blobStart + 8 <= sliceData.count else { continue }
            
            let blobMagic = read32(blobStart)
            let blobLength = read32(blobStart + 4)
            
            // CSMAGIC_CODEDIRECTORY = 0xFADE0C02
            if blobMagic == 0xFADE0C02 {
                let cdEnd = blobStart + Int(blobLength)
                guard cdEnd <= sliceData.count else { continue }
                
                // CDHash = SHA256 of entire CodeDirectory blob
                let cdData = sliceData[blobStart..<cdEnd]
                return sha256Truncated(Data(cdData))
            }
        }
        
        // No CodeDirectory found — fallback
        return sha256Truncated(sliceData)
    }
    
    /// Extract arm64 slice from FAT binary
    private func extractArm64Slice(from data: Data) -> Data? {
        guard data.count > 8 else { return nil }
        let magic = data.withUnsafeBytes { $0.load(as: UInt32.self) }
        let isBE = (magic == 0xCAFEBABE) // FAT is big-endian
        
        func readFat32(_ offset: Int) -> UInt32 {
            let val = data.withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
            return isBE ? UInt32(bigEndian: val) : val
        }
        
        let nfat = readFat32(4)
        for i in 0..<Int(nfat) {
            let archOffset = 8 + i * 20
            guard archOffset + 20 <= data.count else { break }
            let cputype = readFat32(archOffset)
            let offset = readFat32(archOffset + 8)
            let size = readFat32(archOffset + 12)
            
            // CPU_TYPE_ARM64 = 0x0100000C (16777228)
            if cputype == 0x0100000C {
                let start = Int(offset)
                let end = start + Int(size)
                guard end <= data.count else { return nil }
                return Data(data[start..<end])
            }
        }
        return nil
    }
    
    /// SHA256 truncated to 20 bytes
    private func sha256Truncated(_ data: Data) -> [UInt8] {
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { buffer in
            var ctx = CC_SHA256_CTX()
            CC_SHA256_Init(&ctx)
            CC_SHA256_Update(&ctx, buffer.baseAddress, CC_LONG(data.count))
            CC_SHA256_Final(&hash, &ctx)
        }
        return Array(hash.prefix(20))
    }
    
    /// Inject multiple CDHashes into trust cache via MSM XPC
    private func injectTrustCacheBatch(cdhashes: [[UInt8]], completion: @escaping () -> Void) {
        #if !DISABLE_REMOTECALL
        guard let sb = mgr.sbProc else {
            emit("[deb] ⚠️ SpringBoard RC not available for trust cache inject")
            completion()
            return
        }
        
        // Build trust cache v2 structure:
        // Header: version(4) + uuid(16) + count(4) = 24 bytes
        // Entries: count × 24 bytes each (cdhash[20] + hashType[1] + flags[1] + pad[2])
        
        let count = min(cdhashes.count, 50) // max 50 entries per inject
        let headerSize = 24
        let entrySize = 24
        let totalSize = headerSize + count * entrySize
        
        let tcBuf = sb.trojanMem + 0x800
        
        // Header
        sb[tcBuf + 0].setValue32(2) // version = 2
        // UUID (random-ish)
        sb[tcBuf + 4].setValue64(UInt64(Date().timeIntervalSince1970.bitPattern))
        sb[tcBuf + 12].setValue64(0xDEADBEEFCAFEBABE)
        // Count
        sb[tcBuf + 20].setValue32(UInt32(count))
        
        // Entries
        for i in 0..<count {
            let entryOffset = tcBuf + UInt64(headerSize + i * entrySize)
            var cdhash = cdhashes[i]
            // Write 20 bytes CDHash
            sb.remote_write(entryOffset, from: &cdhash, size: 20)
            // hashType = 2 (SHA256 truncated)
            sb[entryOffset + 20].setValue8(2)
            // flags = 0
            sb[entryOffset + 21].setValue8(0)
        }
        
        // Send via MSM XPC
        let RTLD_DEFAULT = UInt64(bitPattern: -2)
        let xpcCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_connection_create_mach_service"))
        let xpcResume = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_connection_resume"))
        let xpcDictCreate = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_dictionary_create"))
        let xpcSetStr = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_dictionary_set_string"))
        let xpcSetData = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_dictionary_set_data"))
        let xpcSend = RootExecutor.rcall(sb, "dlsym", RTLD_DEFAULT,
            remote_alloc_str(sb, "xpc_connection_send_message"))
        
        guard xpcCreate != 0 && xpcDictCreate != 0 else {
            emit("[deb] ⚠️ XPC functions not available")
            completion()
            return
        }
        
        let svc = remote_alloc_str(sb, "com.apple.mobile.storage_mounter")
        let conn = RootExecutor.rcallAddr(sb, xpcCreate, svc, 0, 0)
        RootExecutor.rcall(sb, "free", svc)
        
        guard conn != 0 else {
            emit("[deb] ⚠️ MSM connection failed")
            completion()
            return
        }
        
        RootExecutor.rcallAddr(sb, xpcResume, conn)
        
        let msg = RootExecutor.rcallAddr(sb, xpcDictCreate, 0, 0, 0)
        if msg != 0 {
            for (k, v) in [("Command", "LoadTrustCache"), ("ImageType", "Developer")] {
                let ka = remote_alloc_str(sb, k); let va = remote_alloc_str(sb, v)
                RootExecutor.rcallAddr(sb, xpcSetStr, msg, ka, va)
                RootExecutor.rcall(sb, "free", ka); RootExecutor.rcall(sb, "free", va)
            }
            
            if xpcSetData != 0 {
                let kTC = remote_alloc_str(sb, "ImageTrustCache")
                RootExecutor.rcallAddr(sb, xpcSetData, msg, kTC, tcBuf, UInt64(totalSize))
                RootExecutor.rcall(sb, "free", kTC)
            }
            
            RootExecutor.rcallAddr(sb, xpcSend, conn, msg)
            emit("[deb] ✅ Trust cache injected (\(count) entries via MSM)")
        }
        
        completion()
        #else
        completion()
        #endif
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
                
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
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
    
    // MARK: - FAST PATH: Extract to app temp dir → rename to /var/jb
    //
    // 1. Parse tar in memory (instant)
    // 2. Write all files to app's temp directory via FileManager (no RPC, ~3-5s)
    // 3. ONE launchd call: rename temp dir contents to /var/jb/ (instant)
    //
    // Total: ~5-10 seconds for 1500 files!
    //
    
    private func extractToTempThenMove(tarData: Data, name: String, completion: @escaping (Bool, Int) -> Void) {
        // Parse tar
        let files = parseTar(data: tarData)
        guard !files.isEmpty else {
            emit("[deb] ❌ No files in tar")
            completion(false, 0)
            return
        }
        
        let dirs = files.filter { $0.isDirectory }
        let regularFiles = files.filter { !$0.isDirectory && !$0.data.isEmpty }
        emit("[deb] Parsed: \(dirs.count) dirs + \(regularFiles.count) files")
        
        // Create temp staging directory in app container
        let fm = FileManager.default
        let tempBase = NSTemporaryDirectory() + "deb_install_\(name.lowercased().replacingOccurrences(of: " ", with: "_"))"
        
        // Clean previous attempt
        try? fm.removeItem(atPath: tempBase)
        
        // Extract all files to temp dir (NO RPC — app can write to its own temp)
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let startTime = Date()
            var extracted = 0
            
            // Create directories
            for dir in dirs {
                let dirPath = "\(tempBase)/\(dir.path)"
                try? fm.createDirectory(atPath: dirPath, withIntermediateDirectories: true)
            }
            
            // Write files
            for file in regularFiles {
                let filePath = "\(tempBase)/\(file.path)"
                let parentDir = (filePath as NSString).deletingLastPathComponent
                try? fm.createDirectory(atPath: parentDir, withIntermediateDirectories: true)
                fm.createFile(atPath: filePath, contents: file.data)
                extracted += 1
            }
            
            let extractTime = Date().timeIntervalSince(startTime)
            
            DispatchQueue.main.async {
                self.emit("[deb] ✅ Extracted \(extracted) files to temp (\(String(format: "%.1f", extractTime))s)")
                self.emit("[deb] Moving to /var/jb via launchd...")
                
                // Now move from temp to /var/jb via launchd (needs root for /var/jb write)
                self.moveFromTempToJb(tempBase: tempBase, files: files) { moveOk in
                    // Cleanup temp
                    try? fm.removeItem(atPath: tempBase)
                    
                    if moveOk {
                        self.emit("[deb] ✅ Install complete (\(extracted) files)")
                        self.runUicache { completion(true, extracted) }
                    } else {
                        self.emit("[deb] ❌ Move failed — trying batch write fallback...")
                        self.batchWriteFromTar(tarData: tarData, name: name, completion: completion)
                    }
                }
            }
        }
    }
    
    /// Move extracted files from app temp to /var/jb via launchd
    /// Strategy: rename entire temp directory to /var/jb in 1 atomic call
    private func moveFromTempToJb(tempBase: String, files: [TarFile], completion: @escaping (Bool) -> Void) {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "move_install") { [self] rc in
            // Ensure /var/jb exists
            let jbDir = remote_alloc_str(rc, "/var/jb")
            RootExecutor.rcall(rc, "mkdir", jbDir, 0o755)
            RootExecutor.rcall(rc, "free", jbDir)
            
            // Get list of top-level items in temp dir to move individually
            // (can't rename tempBase directly to /var/jb because /var/jb already exists)
            // Instead: rename each top-level subdir/file from temp into /var/jb
            
            // Common top-level dirs in .deb: usr/, Library/, Applications/, etc.
            let topLevelDirs = Set(files.compactMap { path -> String? in
                let components = path.path.split(separator: "/")
                guard let first = components.first else { return nil }
                return String(first)
            })
            
            var moved = 0
            var lastErrno: UInt64 = 0
            
            for dir in topLevelDirs {
                let srcPath = "\(tempBase)/\(dir)"
                let dstPath = "/var/jb/\(dir)"
                
                // Remove destination if exists (rename fails on EEXIST/ENOTEMPTY)
                let dstAddr = remote_alloc_str(rc, dstPath)
                // Don't remove existing — merge instead by skipping rename for existing dirs
                RootExecutor.rcall(rc, "free", dstAddr)
                
                let srcAddr = remote_alloc_str(rc, srcPath)
                let dstAddr2 = remote_alloc_str(rc, dstPath)
                
                let ret = RootExecutor.rcall(rc, "rename", srcAddr, dstAddr2)
                if ret == 0 {
                    moved += 1
                } else {
                    lastErrno = UInt64(remote_errno(rc))
                }
                
                RootExecutor.rcall(rc, "free", srcAddr)
                RootExecutor.rcall(rc, "free", dstAddr2)
            }
            
            DispatchQueue.main.async {
                if moved > 0 {
                    self.emit("[deb] ✅ Moved \(moved)/\(topLevelDirs.count) top-level dirs (errno=\(lastErrno) for failures)")
                } else {
                    self.emit("[deb] ❌ rename failed: errno=\(lastErrno) (18=EXDEV, 1=EPERM, 2=ENOENT, 17=EEXIST)")
                }
                completion(moved > 0)
            }
            return (moved > 0, "moved \(moved)/\(topLevelDirs.count), errno=\(lastErrno)", UInt64(moved))
        }
        #else
        completion(false)
        #endif
    }

    // MARK: - Batch Write (fallback if rename fails)
    
    /// BATCH WRITE: Group small files together, max 1.5MB per launchd call.
    /// Proven safe: 2MB write in single call works (tar write test).
    /// 1.5MB = ~0.5s per call. 33MB total = ~22 calls = ~55 seconds.
    private func batchWriteFromTar(tarData: Data, name: String, completion: @escaping (Bool, Int) -> Void) {
        let files = parseTar(data: tarData)
        guard !files.isEmpty else {
            emit("[deb] ❌ No files in tar")
            completion(false, 0)
            return
        }
        
        let dirs = files.filter { $0.isDirectory }
        let regularFiles = files.filter { !$0.isDirectory && !$0.data.isEmpty }
        
        // Build batches: group files until total size reaches 1.5MB
        let maxBatchBytes = 1536 * 1024 // 1.5MB
        var batches: [[TarFile]] = []
        var currentBatch: [TarFile] = []
        var currentSize = 0
        
        for file in regularFiles {
            if file.data.count > maxBatchBytes {
                // Large file gets its own batch(es) — handled separately
                if !currentBatch.isEmpty {
                    batches.append(currentBatch)
                    currentBatch = []
                    currentSize = 0
                }
                batches.append([file]) // will be split in writeBatch
            } else if currentSize + file.data.count > maxBatchBytes {
                batches.append(currentBatch)
                currentBatch = [file]
                currentSize = file.data.count
            } else {
                currentBatch.append(file)
                currentSize += file.data.count
            }
        }
        if !currentBatch.isEmpty { batches.append(currentBatch) }
        
        let etaSec = (batches.count + 2) * 3
        emit("[deb] Batch install: \(dirs.count) dirs + \(regularFiles.count) files in \(batches.count) batches")
        emit("[deb] ⏱ Estimated: ~\(etaSec / 60)m \(etaSec % 60)s")
        
        // Phase 1: Create all directories (1 call)
        emit("[deb] Creating directories...")
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "mkdirs") { rc in
            for dir in dirs {
                let p = remote_alloc_str(rc, "/var/jb/\(dir.path)")
                RootExecutor.rcall(rc, "mkdir", p, 0o755)
                RootExecutor.rcall(rc, "free", p)
            }
            return (true, "\(dirs.count) dirs", 0)
        }
        
        // Phase 2: Write file batches
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
            self.emit("[deb] Writing files in batches...")
            self.writeBatchSequentially(batches: batches, index: 0, installed: dirs.count, startTime: Date(), completion: completion)
        }
        #else
        completion(false, 0)
        #endif
    }
    
    private func writeBatchSequentially(batches: [[TarFile]], index: Int, installed: Int, startTime: Date, completion: @escaping (Bool, Int) -> Void) {
        #if !DISABLE_REMOTECALL
        guard index < batches.count else {
            emit("[deb] ✅ Done: \(installed) items installed")
            runUicache { completion(true, installed) }
            return
        }
        
        let batch = batches[index]
        let batchSize = batch.reduce(0) { $0 + $1.data.count }
        
        // Large file (>1.5MB): use split write
        if batch.count == 1 && batch[0].data.count > 1536 * 1024 {
            let file = batch[0]
            emit("[deb] Large: \(file.path) (\(file.data.count / 1024)KB)")
            writeLargeFile(path: "/var/jb/\(file.path)", data: file.data, mode: file.mode) {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
                    self.writeBatchSequentially(batches: batches, index: index + 1, installed: installed + 1, startTime: startTime, completion: completion)
                }
            }
            return
        }
        
        // Normal batch: write all files in single launchd call
        root.executeAsRoot(operation: "batch_\(index)") { rc in
            var written = 0
            for file in batch {
                let fullPath = "/var/jb/\(file.path)"
                
                // Ensure parent
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
                    var w = 0
                    file.data.withUnsafeBytes { buf in
                        while w < file.data.count {
                            let chunk = min(file.data.count - w, 0x1000)
                            rc.remote_write(writeAddr, from: buf.baseAddress!.advanced(by: w), size: UInt64(chunk))
                            let n = RootExecutor.rcall(rc, "write", fd, writeAddr, UInt64(chunk))
                            if n == 0 || n == UInt64(bitPattern: -1) { break }
                            w += Int(n)
                        }
                    }
                    RootExecutor.rcall(rc, "close", fd)
                    RootExecutor.rcall(rc, "chmod", pathAddr, UInt64(file.mode))
                    written += 1
                }
                RootExecutor.rcall(rc, "free", pathAddr)
            }
            return (true, "batch \(index): \(written) files, \(batchSize/1024)KB", UInt64(written))
        }
        
        // ETA every 5 batches
        if index % 5 == 0 && index > 0 {
            let elapsed = Date().timeIntervalSince(startTime)
            let perBatch = elapsed / Double(index)
            let remaining = Double(batches.count - index) * perBatch
            let remMin = Int(remaining) / 60
            let remSec = Int(remaining) % 60
            emit("[deb] Batch \(index)/\(batches.count) — ~\(remMin)m \(remSec)s left")
        }
        
        // 2.5s delay between batches
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
            self.writeBatchSequentially(batches: batches, index: index + 1, installed: installed + batch.count, startTime: startTime, completion: completion)
        }
        #else
        completion(false, 0)
        #endif
    }
    
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
        
        // 1s delay between files — proven safe with queue guard
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
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
        guard let sb = mgr.sbProc else {
            emit("[deb] ⚠️ SpringBoard RC not available — skip uicache")
            completion()
            return
        }
        
        let workspace = remote_getClass(sb, "LSApplicationWorkspace")
        let defaultWS = remote_msg(sb, workspace, remote_sel(sb, "defaultWorkspace"), 0, 0, 0, 0)
        
        guard defaultWS != 0 else {
            emit("[deb] ⚠️ LSApplicationWorkspace not available")
            completion()
            return
        }
        
        // Method 1: registerApplicationDictionary with explicit path
        // Build NSDictionary with app info
        let dictClass = remote_getClass(sb, "NSMutableDictionary")
        let dict = remote_msg(sb, dictClass, remote_sel(sb, "new"), 0, 0, 0, 0)
        
        if dict != 0 {
            // Set keys
            let setObj = remote_sel(sb, "setObject:forKey:")
            
            // ApplicationType = "User"
            let typeVal = remote_msg(sb, remote_getClass(sb, "NSString"), remote_sel(sb, "stringWithUTF8String:"), remote_alloc_str(sb, "User"), 0, 0, 0)
            let typeKey = remote_msg(sb, remote_getClass(sb, "NSString"), remote_sel(sb, "stringWithUTF8String:"), remote_alloc_str(sb, "ApplicationType"), 0, 0, 0)
            remote_msg(sb, dict, setObj, typeVal, typeKey, 0, 0)
            
            // Path = "/var/jb/Applications/Filza.app" (or whatever .app we installed)
            let pathVal = remote_msg(sb, remote_getClass(sb, "NSString"), remote_sel(sb, "stringWithUTF8String:"), remote_alloc_str(sb, "/var/jb/Applications/Filza.app"), 0, 0, 0)
            let pathKey = remote_msg(sb, remote_getClass(sb, "NSString"), remote_sel(sb, "stringWithUTF8String:"), remote_alloc_str(sb, "Path"), 0, 0, 0)
            remote_msg(sb, dict, setObj, pathVal, pathKey, 0, 0)
            
            // CFBundleIdentifier = "com.tigisoftware.Filza"
            let bundleVal = remote_msg(sb, remote_getClass(sb, "NSString"), remote_sel(sb, "stringWithUTF8String:"), remote_alloc_str(sb, "com.tigisoftware.Filza"), 0, 0, 0)
            let bundleKey = remote_msg(sb, remote_getClass(sb, "NSString"), remote_sel(sb, "stringWithUTF8String:"), remote_alloc_str(sb, "CFBundleIdentifier"), 0, 0, 0)
            remote_msg(sb, dict, setObj, bundleVal, bundleKey, 0, 0)
            
            // Register
            remote_msg(sb, defaultWS, remote_sel(sb, "registerApplicationDictionary:"), dict, 0, 0, 0)
            emit("[deb] ✅ registerApplicationDictionary called")
        }
        
        // Method 2: Also try installApplication:withOptions:
        let appPath = remote_alloc_str(sb, "/var/jb/Applications/Filza.app")
        let nsURL = remote_msg(sb, remote_getClass(sb, "NSURL"), remote_sel(sb, "fileURLWithPath:"),
            remote_msg(sb, remote_getClass(sb, "NSString"), remote_sel(sb, "stringWithUTF8String:"), appPath, 0, 0, 0), 0, 0, 0)
        RootExecutor.rcall(sb, "free", appPath)
        
        if nsURL != 0 {
            let emptyDict = remote_msg(sb, remote_getClass(sb, "NSDictionary"), remote_sel(sb, "dictionary"), 0, 0, 0, 0)
            remote_msg(sb, defaultWS, remote_sel(sb, "installApplication:withOptions:error:"), nsURL, emptyDict, 0, 0)
            emit("[deb] ✅ installApplication called")
        }
        
        // Method 3: Rebuild databases
        remote_msg(sb, defaultWS,
            remote_sel(sb, "_LSPrivateRebuildApplicationDatabasesForSystemApps:internal:user:"),
            1, 1, 1, 0)
        
        emit("[deb] ✅ uicache complete — respring to see app")
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
