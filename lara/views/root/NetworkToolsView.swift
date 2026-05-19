//
//  NetworkToolsView.swift
//  DSPloit
//
//  Network tools — DNS info, hosts file, connections
//  All operations via root RemoteCall
//

import SwiftUI

struct NetworkToolsView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var hostsContent = ""
    @State private var dnsServers: [String] = []
    @State private var networkInfo: [(String, String)] = []
    @State private var isLoading = false
    @State private var customHost = ""
    @State private var customIP = "0.0.0.0"
    @State private var addedHosts: [String] = []
    
    var body: some View {
        List {
            // Network Info
            Section {
                if isLoading {
                    HStack {
                        ProgressView()
                        Text("Loading...")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } else if networkInfo.isEmpty {
                    Button("Load Network Info") { loadNetworkInfo() }
                } else {
                    ForEach(networkInfo, id: \.0) { key, value in
                        HStack {
                            Text(key)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Text(value)
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                }
            } header: {
                Label("Network", systemImage: "network")
            }
            
            // DNS
            Section {
                if !dnsServers.isEmpty {
                    ForEach(dnsServers, id: \.self) { dns in
                        HStack {
                            Image(systemName: "server.rack")
                                .foregroundStyle(.blue)
                                .font(.caption)
                            Text(dns)
                                .font(.system(size: 12, design: .monospaced))
                        }
                    }
                }
            } header: {
                Label("DNS Servers", systemImage: "globe")
            }
            
            // Hosts File (Ad Blocking)
            Section {
                HStack {
                    TextField("domain.com", text: $customHost)
                        .font(.system(size: 12, design: .monospaced))
                        .textInputAutocapitalization(.never)
                    Text("→")
                        .foregroundStyle(.secondary)
                    TextField("0.0.0.0", text: $customIP)
                        .font(.system(size: 12, design: .monospaced))
                        .frame(width: 90)
                }
                
                Button(action: addHostEntry) {
                    Label("Block Domain", systemImage: "xmark.shield")
                        .foregroundStyle(.red)
                }
                .disabled(customHost.isEmpty || !mgr.rcready)
                
                // Quick blocks
                Button("Block Ads (common)") { blockCommonAds() }
                    .font(.caption)
                    .disabled(!mgr.rcready)
            } header: {
                Label("Hosts File", systemImage: "doc.text")
            } footer: {
                Text("Adds entries to /etc/hosts to block domains system-wide")
                    .font(.system(size: 9))
            }
            
            // Added hosts
            if !addedHosts.isEmpty {
                Section {
                    ForEach(addedHosts, id: \.self) { entry in
                        Text(entry)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(.green)
                    }
                } header: {
                    Label("Added Entries", systemImage: "checkmark.circle")
                }
            }
            
            // Current /etc/hosts
            if !hostsContent.isEmpty {
                Section {
                    Text(hostsContent)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                } header: {
                    Label("/etc/hosts", systemImage: "doc")
                }
            }
        }
        .navigationTitle("Network")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(action: loadNetworkInfo) {
                    Image(systemName: "arrow.clockwise")
                }
            }
        }
        .onAppear { if networkInfo.isEmpty { loadNetworkInfo() } }
    }
    
    private func loadNetworkInfo() {
        isLoading = true
        networkInfo.removeAll()
        dnsServers.removeAll()
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "netinfo") { rc in
            var items: [(String, String)] = []
            var dns: [String] = []
            let mem = rc.trojanMem
            
            // Hostname
            let hostBuf = mem + 0x800
            RootExecutor.rcall(rc, "gethostname", hostBuf, 256)
            var hBuf = [UInt8](repeating: 0, count: 64)
            rc.remoteRead(hostBuf, to: &hBuf, size: 64)
            items.append(("Hostname", String(cString: hBuf + [0])))
            
            // Read /etc/resolv.conf for DNS
            let resolvPath = remote_alloc_str(rc, "/etc/resolv.conf")
            let fd = RootExecutor.rcall(rc, "open", resolvPath, UInt64(O_RDONLY), 0)
            if fd != UInt64(bitPattern: -1) {
                let buf = mem + 0xA00
                let n = RootExecutor.rcall(rc, "read", fd, buf, 1024)
                if n > 0 && n < 1025 {
                    var rBuf = [UInt8](repeating: 0, count: Int(n))
                    rc.remoteRead(buf, to: &rBuf, size: n)
                    let content = String(bytes: rBuf, encoding: .utf8) ?? ""
                    dns = content.components(separatedBy: "\n")
                        .filter { $0.hasPrefix("nameserver") }
                        .map { $0.replacingOccurrences(of: "nameserver ", with: "") }
                }
                RootExecutor.rcall(rc, "close", fd)
            }
            RootExecutor.rcall(rc, "free", resolvPath)
            
            // Read /etc/hosts
            var hostsStr = ""
            let hostsPath = remote_alloc_str(rc, "/etc/hosts")
            let hfd = RootExecutor.rcall(rc, "open", hostsPath, UInt64(O_RDONLY), 0)
            if hfd != UInt64(bitPattern: -1) {
                let buf = mem + 0x1000
                let n = RootExecutor.rcall(rc, "read", hfd, buf, 2048)
                if n > 0 && n < 2049 {
                    var rBuf = [UInt8](repeating: 0, count: Int(n))
                    rc.remoteRead(buf, to: &rBuf, size: n)
                    hostsStr = String(bytes: rBuf, encoding: .utf8) ?? ""
                }
                RootExecutor.rcall(rc, "close", hfd)
            }
            RootExecutor.rcall(rc, "free", hostsPath)
            
            DispatchQueue.main.async {
                self.networkInfo = items
                self.dnsServers = dns
                self.hostsContent = hostsStr
                self.isLoading = false
            }
            return (true, "netinfo", 0)
        }
        #endif
    }
    
    private func addHostEntry() {
        guard !customHost.isEmpty else { return }
        let entry = "\(customIP) \(customHost)"
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "add_host") { rc in
            let mem = rc.trojanMem
            let hostsPath = remote_alloc_str(rc, "/etc/hosts")
            let fd = RootExecutor.rcall(rc, "open", hostsPath, UInt64(O_WRONLY | O_APPEND), 0)
            
            if fd != UInt64(bitPattern: -1) {
                let line = "\n\(entry)\n"
                let lineAddr = remote_alloc_str(rc, line)
                RootExecutor.rcall(rc, "write", fd, lineAddr, UInt64(line.utf8.count))
                RootExecutor.rcall(rc, "close", fd)
                RootExecutor.rcall(rc, "free", lineAddr)
                
                DispatchQueue.main.async {
                    self.addedHosts.append(entry)
                    self.customHost = ""
                }
            }
            RootExecutor.rcall(rc, "free", hostsPath)
            return (true, "host added", 0)
        }
        #endif
    }
    
    private func blockCommonAds() {
        let adDomains = [
            "ads.google.com",
            "pagead2.googlesyndication.com",
            "ad.doubleclick.net",
            "analytics.google.com",
            "graph.facebook.com",
            "an.facebook.com",
            "ads.facebook.com",
        ]
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "block_ads") { rc in
            let hostsPath = remote_alloc_str(rc, "/etc/hosts")
            let fd = RootExecutor.rcall(rc, "open", hostsPath, UInt64(O_WRONLY | O_APPEND), 0)
            
            if fd != UInt64(bitPattern: -1) {
                var blocked: [String] = []
                for domain in adDomains {
                    let line = "\n0.0.0.0 \(domain)"
                    let lineAddr = remote_alloc_str(rc, line)
                    RootExecutor.rcall(rc, "write", fd, lineAddr, UInt64(line.utf8.count))
                    RootExecutor.rcall(rc, "free", lineAddr)
                    blocked.append("0.0.0.0 \(domain)")
                }
                RootExecutor.rcall(rc, "close", fd)
                
                DispatchQueue.main.async {
                    self.addedHosts.append(contentsOf: blocked)
                }
            }
            RootExecutor.rcall(rc, "free", hostsPath)
            return (true, "ads blocked", 0)
        }
        #endif
    }
}
