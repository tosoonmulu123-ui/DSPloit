//
//  fetchkcache.swift
//  DSPloit
//
//  Kernelcache fetching with fallback + cache validation
//  Created by ruter on 12.05.26.
//  Updated by Royan | 2026-05-24 — added validation, retry, fallback guidance
//

import Foundation

func syskcpath() -> String? {
    guard let hash = getbmhash() else { return nil }
    return "/private/preboot/\(hash)/System/Library/Caches/com.apple.kernelcaches/kernelcache"
}

func dspkcpath() -> String? {
    guard let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return nil }
    return docs.appendingPathComponent("kernelcache").path
}

// MARK: - Cache Validation

/// Validate that a kernelcache file is not corrupt
/// Checks: file exists, minimum size, valid header (0x30 0x84 for IMG4 or MH_MAGIC_64)
func validateKernelcache(at path: String) -> (valid: Bool, reason: String) {
    guard FileManager.default.fileExists(atPath: path) else {
        return (false, "file does not exist")
    }
    
    guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
          let size = attrs[.size] as? Int64 else {
        return (false, "cannot read file attributes")
    }
    
    // Kernelcache should be at least 10MB (typical is 20-40MB)
    if size < 10 * 1024 * 1024 {
        return (false, "file too small (\(size) bytes) — likely corrupt or incomplete")
    }
    
    // Check header magic
    guard let handle = FileHandle(forReadingAtPath: path) else {
        return (false, "cannot open file")
    }
    defer { handle.closeFile() }
    
    let headerData = handle.readData(ofLength: 4)
    guard headerData.count >= 4 else {
        return (false, "cannot read header")
    }
    
    let bytes = [UInt8](headerData)
    
    // IMG4 container: starts with 0x30 0x84
    let isIMG4 = bytes[0] == 0x30 && bytes[1] == 0x84
    // Raw Mach-O: starts with 0xCF 0xFA 0xED 0xFE (MH_MAGIC_64 LE)
    let isMachO = bytes[0] == 0xCF && bytes[1] == 0xFA && bytes[2] == 0xED && bytes[3] == 0xFE
    // Compressed: starts with "comp" (0x63 0x6F 0x6D 0x70)
    let isCompressed = bytes[0] == 0x63 && bytes[1] == 0x6F && bytes[2] == 0x6D && bytes[3] == 0x70
    
    if !isIMG4 && !isMachO && !isCompressed {
        return (false, "invalid header (0x\(String(format: "%02x%02x%02x%02x", bytes[0], bytes[1], bytes[2], bytes[3])))")
    }
    
    return (true, "valid (\(size / 1024 / 1024)MB, \(isIMG4 ? "IMG4" : isMachO ? "Mach-O" : "compressed"))")
}

// MARK: - Fetch from Device (Primary)

func fetchkcache() -> Bool {
    guard let kcpath = syskcpath() else {
        globallogger.log("(fetchkcache) failed to get kernelcache path")
        return false
    }

    guard let outpath = dspkcpath() else {
        globallogger.log("(fetchkcache) failed to get output path")
        return false
    }

    let fakeread = "/private/preboot/Cryptexes/OS/System/Library/CoreServices/RestoreVersion.plist"

    unlink(outpath)

    var ogvn: UInt64 = 0
    var ogvd: UInt64 = 0

    let redirect = kcpath.withCString { kcCString in
        vn_fileredirect(fakeread, kcCString, &ogvn, &ogvd)
    }
    if !redirect {
        globallogger.log("(fetchkcache) failed to redirect vnode")
        return false
    }

    let src = open(fakeread, O_RDONLY)
    if src < 0 {
        globallogger.log("(fetchkcache) open failed errno=\(errno)")
        vn_fileunredirect(ogvn, ogvd)
        return false
    }

    let dst = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
    if dst < 0 {
        close(src)
        vn_fileunredirect(ogvn, ogvd)
        return false
    }

    defer {
        close(src)
        close(dst)
        vn_fileunredirect(ogvn, ogvd)
    }

    var buffer = [UInt8](repeating: 0, count: 0x4000)
    var totalBytes: Int64 = 0

    while true {
        let n = read(src, &buffer, buffer.count)
        if n <= 0 { break }
        let written = write(dst, buffer, n)
        if written <= 0 { break }
        totalBytes += Int64(written)
    }

    // Validate the fetched file
    let validation = validateKernelcache(at: outpath)
    if !validation.valid {
        globallogger.log("(fetchkcache) validation failed: \(validation.reason)")
        try? FileManager.default.removeItem(atPath: outpath)
        return false
    }
    
    globallogger.log("(fetchkcache) success! \(totalBytes) bytes — \(validation.reason)")
    return true
}

// MARK: - Download via libgrabkernel2 (Fallback 1)

/// Download kernelcache from Apple CDN with retry logic
func downloadKernelcacheWithRetry(maxRetries: Int = 3) -> Bool {
    guard let outpath = dspkcpath() else { return false }
    
    for attempt in 1...maxRetries {
        globallogger.log("(kcache) download attempt \(attempt)/\(maxRetries)...")
        
        // Remove any partial download
        try? FileManager.default.removeItem(atPath: outpath)
        
        let ok = dlkcache()
        if ok {
            // Validate after download
            let validation = validateKernelcache(at: outpath)
            if validation.valid {
                globallogger.log("(kcache) download + validate OK on attempt \(attempt)")
                return true
            } else {
                globallogger.log("(kcache) download succeeded but validation failed: \(validation.reason)")
                try? FileManager.default.removeItem(atPath: outpath)
            }
        } else {
            globallogger.log("(kcache) download failed on attempt \(attempt)")
        }
        
        // Wait before retry (exponential backoff)
        if attempt < maxRetries {
            let delay = Double(attempt) * 2.0
            globallogger.log("(kcache) retrying in \(delay)s...")
            Thread.sleep(forTimeInterval: delay)
        }
    }
    
    return false
}

// MARK: - Manual Import Guidance (Fallback 2)

/// Returns instructions for manual kernelcache extraction from IPSW
func manualKernelcacheInstructions() -> String {
    let version = UIDevice.current.systemVersion
    let model = utsname_machine()
    
    return """
    Automatic kernelcache download failed.
    
    Manual extraction steps:
    1. Download your IPSW from ipsw.me:
       iOS \(version) for \(model)
    2. Extract the IPSW (it's a ZIP file)
    3. Find: kernelcache.release.*
    4. Use img4tool to decrypt:
       img4tool -e kernelcache.release.* -o kernelcache
    5. Transfer 'kernelcache' to this app via:
       - Files app → DSPloit folder
       - iTunes File Sharing
       - AirDrop to app
    
    The file will be picked up automatically on next jailbreak.
    """
}

private func utsname_machine() -> String {
    var sys = utsname()
    uname(&sys)
    return withUnsafePointer(to: &sys.machine) {
        $0.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) {
            String(cString: $0)
        }
    }
}

// MARK: - Main Entry Point

/// Copy from preboot (if possible) then run XPF/ChOma resolve. Only true when symbols resolve.
/// Enhanced with: validation, retry, fallback guidance.
func ensureKernelcacheResolved() -> Bool {
    guard let outpath = dspkcpath() else { return false }
    
    // Check if we already have a valid cached kernelcache
    if FileManager.default.fileExists(atPath: outpath) {
        let validation = validateKernelcache(at: outpath)
        if validation.valid {
            globallogger.log("(kcache) using cached kernelcache: \(validation.reason)")
            // Try XPF resolve on existing file
            if emergencyfixfunctiontobereplacedlateronquestionmark() {
                globallogger.log("(kcache) XPF resolve OK (cached)")
                return true
            }
            // XPF failed on valid file — might be wrong iOS version
            globallogger.log("(kcache) XPF failed on cached file — removing and re-fetching")
            try? FileManager.default.removeItem(atPath: outpath)
        } else {
            globallogger.log("(kcache) cached file invalid: \(validation.reason) — removing")
            try? FileManager.default.removeItem(atPath: outpath)
        }
    }
    
    // Strategy 1: Copy from device preboot (fastest, no network)
    globallogger.log("(kcache) trying device preboot copy...")
    if fetchkcache() {
        globallogger.log("(kcache) copied from device preboot")
        if emergencyfixfunctiontobereplacedlateronquestionmark() {
            globallogger.log("(kcache) XPF resolve OK")
            return true
        }
        globallogger.log("(kcache) XPF failed on preboot copy")
    } else {
        globallogger.log("(kcache) preboot copy failed")
    }
    
    // Strategy 2: Download from Apple CDN with retry
    globallogger.log("(kcache) trying Apple CDN download (with retry)...")
    if downloadKernelcacheWithRetry(maxRetries: 3) {
        globallogger.log("(kcache) download successful")
        // dlkcache already calls resolvekernoffsets internally
        return true
    }
    
    // Strategy 3: Check if user manually imported a file
    if FileManager.default.fileExists(atPath: outpath) {
        let validation = validateKernelcache(at: outpath)
        if validation.valid {
            globallogger.log("(kcache) found manually imported kernelcache")
            if emergencyfixfunctiontobereplacedlateronquestionmark() {
                return true
            }
        }
    }
    
    // All strategies failed — log instructions for manual import
    globallogger.log("(kcache) ❌ All automatic methods failed")
    globallogger.log("(kcache) Manual import required — see Settings → Import Kernelcache")
    globallogger.log(manualKernelcacheInstructions())
    
    return false
}
