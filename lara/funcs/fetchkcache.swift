//
//  fetchkcache.swift
//  DSPloit
//
//  Created by ruter on 12.05.26.
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

    while true {
        let n = read(src, &buffer, buffer.count)

        if n <= 0 {
            break
        }

        _ = write(dst, buffer, n)
    }

    if !FileManager.default.fileExists(atPath: outpath) {
        globallogger.log("(fetchkcache) kernelcache output missing")
        return false
    } else if let attrs = try? FileManager.default.attributesOfItem(atPath: outpath),
              let size = attrs[.size] as? NSNumber {
        globallogger.log("(fetchkcache) kernelcache fetch success! size=\(size.intValue) bytes")
    } else {
        globallogger.log("(fetchkcache) kernelcache fetch success!")
    }

    return true
}

/// Copy from preboot (if possible) then run XPF/ChOma resolve. Only true when symbols resolve.
func ensureKernelcacheResolved() -> Bool {
    if !FileManager.default.fileExists(atPath: dspkcpath() ?? "") {
        if fetchkcache() {
            globallogger.log("(kcache) copied kernelcache from device preboot")
        } else {
            globallogger.log("(kcache) device copy failed — will try download")
        }
    }

    if emergencyfixfunctiontobereplacedlateronquestionmark() {
        globallogger.log("(kcache) XPF resolve OK")
        return true
    }

    globallogger.log("(kcache) XPF resolve failed — trying grab_kernelcache download")
    return dlkcache()
}
