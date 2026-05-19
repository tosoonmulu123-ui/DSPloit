//
//  SystemInfoView.swift
//  DSPloit
//
//  System information gathered from root context
//  Reads kernel data, device info, and system state
//

import SwiftUI

struct SystemInfoView: View {
    @ObservedObject private var mgr = dspmgr.shared
    @ObservedObject private var root = RootExecutor.shared
    
    @State private var info: [InfoSection] = []
    @State private var isLoading = false
    
    struct InfoSection: Identifiable {
        let id = UUID()
        let title: String
        let icon: String
        let items: [(String, String)]
    }
    
    var body: some View {
        List {
            if isLoading {
                Section {
                    HStack {
                        ProgressView()
                        Text("Gathering system info...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            
            ForEach(info) { section in
                Section {
                    ForEach(section.items, id: \.0) { key, value in
                        HStack {
                            Text(key)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .frame(width: 110, alignment: .leading)
                            Spacer()
                            Text(value)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(.primary)
                                .textSelection(.enabled)
                                .multilineTextAlignment(.trailing)
                        }
                    }
                } header: {
                    Label(section.title, systemImage: section.icon)
                }
            }
        }
        .navigationTitle("System Info")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(action: gatherInfo) {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(isLoading)
            }
        }
        .onAppear { if info.isEmpty { gatherInfo() } }
    }
    
    private func gatherInfo() {
        isLoading = true
        info.removeAll()
        
        // Device info (available without RC)
        var deviceItems: [(String, String)] = []
        deviceItems.append(("Model", UIDevice.current.model))
        deviceItems.append(("Name", UIDevice.current.name))
        deviceItems.append(("iOS", UIDevice.current.systemVersion))
        
        var sysinfo = utsname()
        uname(&sysinfo)
        let machine = withUnsafePointer(to: &sysinfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 256) { String(cString: $0) }
        }
        let release = withUnsafePointer(to: &sysinfo.release) {
            $0.withMemoryRebound(to: CChar.self, capacity: 256) { String(cString: $0) }
        }
        deviceItems.append(("Machine", machine))
        deviceItems.append(("Kernel", release))
        
        info.append(InfoSection(title: "Device", icon: "iphone", items: deviceItems))
        
        // Kernel info
        var kernelItems: [(String, String)] = []
        if mgr.dsready {
            kernelItems.append(("Base", String(format: "0x%llx", mgr.kernbase)))
            kernelItems.append(("Slide", String(format: "0x%llx", mgr.kernslide)))
            kernelItems.append(("Our Proc", String(format: "0x%llx", ds_get_our_proc())))
            kernelItems.append(("Our Task", String(format: "0x%llx", ds_get_our_task())))
        } else {
            kernelItems.append(("Status", "Not exploited"))
        }
        info.append(InfoSection(title: "Kernel", icon: "cpu", items: kernelItems))
        
        // Jailbreak status
        var jbItems: [(String, String)] = []
        jbItems.append(("Exploit", mgr.dsready ? "✅ Active" : "❌ Not run"))
        jbItems.append(("VFS", mgr.vfsready ? "✅ Ready" : "❌"))
        jbItems.append(("Sandbox", mgr.sbxready ? "✅ Escaped" : "❌"))
        jbItems.append(("RemoteCall", mgr.rcready ? "✅ Connected" : "❌"))
        jbItems.append(("Root", root.rootConfirmed ? "✅ uid=0" : "❌"))
        info.append(InfoSection(title: "Jailbreak", icon: "lock.open.fill", items: jbItems))
        
        // Gather root-level info if available
        #if !DISABLE_REMOTECALL
        if mgr.rcready {
            root.executeAsRoot(operation: "sysinfo") { rc in
                var rootItems: [(String, String)] = []
                var netItems: [(String, String)] = []
                var storageItems: [(String, String)] = []
                
                // Hostname
                let hostBuf = rc.trojanMem + 0x800
                RootExecutor.rcall(rc, "gethostname", hostBuf, 256)
                var hBuf = [UInt8](repeating: 0, count: 64)
                rc.remoteRead(hostBuf, to: &hBuf, size: 64)
                let hostname = String(cString: hBuf + [0])
                rootItems.append(("Hostname", hostname))
                
                // PID 1 (launchd)
                let pid = RootExecutor.rcall(rc, "getpid")
                let uid = RootExecutor.rcall(rc, "getuid")
                rootItems.append(("Context PID", "\(pid)"))
                rootItems.append(("Context UID", "\(uid)"))
                
                // Uptime via sysctl
                let uptimeAddr = rc.trojanMem + 0xA00
                let uptimeSizeAddr = rc.trojanMem + 0xA10
                rc[uptimeSizeAddr].setValue64(16)
                let uptimeName = remote_alloc_str(rc, "kern.boottime")
                let uptimeRet = RootExecutor.rcall(rc, "sysctlbyname", uptimeName, uptimeAddr, uptimeSizeAddr, 0, 0)
                if uptimeRet == 0 {
                    let bootSec = rc[uptimeAddr].value64()
                    let now = UInt64(Date().timeIntervalSince1970)
                    let uptime = now - bootSec
                    let hours = uptime / 3600
                    let mins = (uptime % 3600) / 60
                    rootItems.append(("Uptime", "\(hours)h \(mins)m"))
                }
                RootExecutor.rcall(rc, "free", uptimeName)
                
                // Process count
                let procCount = self.countProcesses(rc: rc)
                rootItems.append(("Processes", "\(procCount)"))
                
                // Network: get IP via gethostbyname or ifconfig output
                let ifconfigBin = remote_alloc_str(rc, "/sbin/ifconfig")
                let statAddr = rc.trojanMem + 0xC00
                let ifExists = RootExecutor.rcall(rc, "stat", ifconfigBin, statAddr)
                netItems.append(("ifconfig", ifExists == 0 ? "Available" : "Not found"))
                RootExecutor.rcall(rc, "free", ifconfigBin)
                
                // DNS
                let resolvPath = remote_alloc_str(rc, "/etc/resolv.conf")
                let resolvFd = RootExecutor.rcall(rc, "open", resolvPath, UInt64(O_RDONLY), 0)
                if resolvFd != UInt64(bitPattern: -1) {
                    let buf = rc.trojanMem + 0xD00
                    let n = RootExecutor.rcall(rc, "read", resolvFd, buf, 256)
                    if n > 0 && n < 257 {
                        var rBuf = [UInt8](repeating: 0, count: Int(n))
                        rc.remoteRead(buf, to: &rBuf, size: n)
                        let content = String(bytes: rBuf, encoding: .utf8) ?? ""
                        let dns = content.components(separatedBy: "\n")
                            .filter { $0.hasPrefix("nameserver") }
                            .first?.replacingOccurrences(of: "nameserver ", with: "") ?? "?"
                        netItems.append(("DNS", dns))
                    }
                    RootExecutor.rcall(rc, "close", resolvFd)
                }
                RootExecutor.rcall(rc, "free", resolvPath)
                
                // Storage: statfs on /
                let rootPath = remote_alloc_str(rc, "/")
                let statfsBuf = rc.trojanMem + 0x1000
                let statfsRet = RootExecutor.rcall(rc, "statfs", rootPath, statfsBuf)
                if statfsRet == 0 {
                    // struct statfs: f_bsize at +4, f_blocks at +16, f_bfree at +24
                    let bsize = rc[statfsBuf + 4].value32()
                    let blocks = rc[statfsBuf + 16].value64()
                    let bfree = rc[statfsBuf + 24].value64()
                    let totalGB = Double(UInt64(bsize) * blocks) / 1_073_741_824.0
                    let freeGB = Double(UInt64(bsize) * bfree) / 1_073_741_824.0
                    storageItems.append(("Total", String(format: "%.1f GB", totalGB)))
                    storageItems.append(("Free", String(format: "%.1f GB", freeGB)))
                    storageItems.append(("Used", String(format: "%.1f GB", totalGB - freeGB)))
                }
                RootExecutor.rcall(rc, "free", rootPath)
                
                DispatchQueue.main.async {
                    self.info.append(InfoSection(title: "Root Context", icon: "person.fill", items: rootItems))
                    if !netItems.isEmpty {
                        self.info.append(InfoSection(title: "Network", icon: "wifi", items: netItems))
                    }
                    if !storageItems.isEmpty {
                        self.info.append(InfoSection(title: "Storage", icon: "internaldrive", items: storageItems))
                    }
                    self.isLoading = false
                }
                
                return (true, "sysinfo gathered", 0)
            }
        } else {
            isLoading = false
        }
        #else
        isLoading = false
        #endif
    }
    
    #if !DISABLE_REMOTECALL
    private func countProcesses(rc: RemoteCall) -> Int {
        // Use sysctl to count processes
        let mem = rc.trojanMem
        let nameAddr = remote_alloc_str(rc, "kern.proc.all")
        let sizeAddr = mem + 0xB00
        rc[sizeAddr].setValue64(0)
        // First call with NULL buf to get size
        let ret = RootExecutor.rcall(rc, "sysctlbyname", nameAddr, 0, sizeAddr, 0, 0)
        let size = rc[sizeAddr].value64()
        RootExecutor.rcall(rc, "free", nameAddr)
        if ret == 0 && size > 0 {
            // Each kinfo_proc is ~648 bytes on arm64
            return Int(size / 648)
        }
        return 0
    }
    #endif
}
