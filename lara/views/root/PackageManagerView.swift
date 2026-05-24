//
//  PackageManagerView.swift
//  DSPloit
//
//  Sileo/Zebra-style package manager — download & install .deb packages
//  Uses rootless /var/jb prefix (Dopamine-compatible)
//

import SwiftUI

struct PackageManagerView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    @ObservedObject private var jb = JailbreakEngine.shared
    
    @State private var repos: [RepoInfo] = defaultRepos
    @State private var packages: [PackageInfo] = []
    @State private var installedPackages: [InstalledPackage] = []
    @State private var isRefreshing = false
    @State private var installLog: [String] = []
    @State private var showLog = false
    @State private var showAddRepo = false
    @State private var newRepoURL = ""
    @State private var selectedTab: PMTab = .sources
    @State private var bootstrapReady = false
    @State private var isInstalling = false
    @State private var installProgress: Double = 0
    @State private var bootstrapChecked = false
    
    enum PMTab: String, CaseIterable {
        case sources = "Sources"
        case packages = "Packages"
        case installed = "Installed"
        case queue = "Queue"
    }
    
    struct RepoInfo: Identifiable {
        let id = UUID()
        var name: String
        var url: String
        var icon: String
        var packageCount: Int = 0
        var isRefreshing: Bool = false
    }
    
    struct PackageInfo: Identifiable {
        let id = UUID()
        let name: String
        let bundleId: String
        let version: String
        let description: String
        let author: String
        let repo: String
        let debURL: String
        let size: String
        let section: String
    }
    
    struct InstalledPackage: Identifiable {
        let id = UUID()
        let name: String
        let bundleId: String
        let version: String
        let installedDate: Date
    }
    
    static let defaultRepos: [RepoInfo] = [
        RepoInfo(name: "TIGI Software", url: "https://tigisoftware.com/repo", icon: "folder.circle.fill"),
        RepoInfo(name: "Sileo", url: "https://repo.getsileo.app", icon: "shippingbox.circle.fill"),
        RepoInfo(name: "Chariz", url: "https://repo.chariz.com", icon: "star.circle.fill"),
        RepoInfo(name: "Havoc", url: "https://havoc.app", icon: "bolt.circle.fill"),
        RepoInfo(name: "BigBoss", url: "https://apt.thebigboss.org/repofiles/cydia", icon: "building.2.fill"),
        RepoInfo(name: "Ellekit", url: "https://ellekit.space", icon: "wand.and.stars"),
        RepoInfo(name: "Procursus", url: "https://apt.procurs.us", icon: "shippingbox.circle.fill"),
    ]
    
    var body: some View {
        VStack(spacing: 0) {
            // Tab picker
            Picker("Tab", selection: $selectedTab) {
                ForEach(PMTab.allCases, id: \.self) { tab in
                    Text(tab.rawValue).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            
            // Content
            Group {
                switch selectedTab {
                case .sources: sourcesView
                case .packages: packagesView
                case .installed: installedView
                case .queue: queueView
                }
            }
        }
        .navigationTitle("Package Manager")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button(action: { showAddRepo = true }) {
                        Label("Add Repo", systemImage: "plus.circle")
                    }
                    Button(action: refreshAllRepos) {
                        Label("Refresh All", systemImage: "arrow.clockwise")
                    }
                    Button(action: setupBootstrap) {
                        Label("Setup Bootstrap", systemImage: "shippingbox")
                    }
                    Divider()
                    Button(action: { showLog = true }) {
                        Label("View Log", systemImage: "terminal")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .onAppear {
            if mgr.rcready && !bootstrapChecked {
                bootstrapChecked = true
                checkBootstrap()
            }
        }
        .sheet(isPresented: $showLog) { logSheet }
        .alert("Add Repository", isPresented: $showAddRepo) {
            TextField("https://repo.example.com", text: $newRepoURL)
                .textInputAutocapitalization(.never)
            Button("Add") { addRepo() }
            Button("Cancel", role: .cancel) { newRepoURL = "" }
        }
    }
    
    // MARK: - Sources View
    
    private var sourcesView: some View {
        List {
            // Bootstrap status
            Section {
                HStack(spacing: 12) {
                    Image(systemName: bootstrapReady ? "checkmark.circle.fill" : "xmark.circle")
                        .foregroundStyle(bootstrapReady ? .green : .orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Bootstrap")
                            .font(.subheadline.bold())
                        Text(bootstrapReady ? "Ready" : "Required before installing packages")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if !bootstrapReady {
                        Button("Setup") { setupBootstrap() }
                            .font(.caption.bold())
                            .buttonStyle(.borderedProminent)
                    }
                }
            } footer: {
                if !bootstrapReady {
                    Text("Tap Setup to create /var/jb directory structure. This is needed once.")
                }
            }
            
            // Only show repos and quick install after bootstrap
            if bootstrapReady {
                // Debug experiments (isolate panic cause)
                Section("Experiments") {
                    Button(action: testRegisterDummy) {
                        HStack {
                            Image(systemName: "flask.fill").foregroundStyle(.yellow).frame(width: 24)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Test Register (dummy)").font(.subheadline.bold())
                                Text("Fake bundle ID, no real files").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                    }
                    Button(action: testRegisterReal) {
                        HStack {
                            Image(systemName: "flask.fill").foregroundStyle(.orange).frame(width: 24)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Test Register (real path)").font(.subheadline.bold())
                                Text("No MCM container (safe)").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                    }
                    Button(action: testSpawnBinary) {
                        HStack {
                            Image(systemName: "terminal.fill").foregroundStyle(.green).frame(width: 24)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Test Spawn Binary").font(.subheadline.bold())
                                Text("chmod + posix_spawn Filza").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                    }
                    Button(action: testDiskImageRegister) {
                        HStack {
                            Image(systemName: "opticaldiscdrive.fill").foregroundStyle(.purple).frame(width: 24)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Test DiskImage Register").font(.subheadline.bold())
                                Text("Simulate DDI app registration path").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }
                    }
                }
                // Repos
                Section("Repositories") {
                    ForEach(repos) { repo in
                        HStack(spacing: 12) {
                            Image(systemName: repo.icon)
                                .font(.title3)
                                .foregroundStyle(.blue)
                                .frame(width: 30)
                            
                            VStack(alignment: .leading, spacing: 2) {
                                Text(repo.name)
                                    .font(.subheadline.bold())
                                Text(repo.url)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                            
                            Spacer()
                            
                            if repo.isRefreshing {
                                ProgressView()
                                    .scaleEffect(0.7)
                            } else if repo.packageCount > 0 {
                                Text("\(repo.packageCount)")
                                    .font(.caption.bold())
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                repos.removeAll { $0.id == repo.id }
                            } label: {
                                Label("Remove", systemImage: "trash")
                            }
                        }
                    }
                }
                
                // Quick install
                Section("Quick Install") {
                    quickInstallRow("Filza", "Root file manager", "folder.fill", .blue) {
                        installFromURL(name: "Filza", url: "https://tigisoftware.com/cydia/com.tigisoftware.filza_4.0.1-2_iphoneos-arm.deb")
                    }
                    quickInstallRow("Sileo", "Package manager GUI", "shippingbox.fill", .purple) {
                        installFromURL(name: "Sileo", url: "https://repo.getsileo.app/pool/org.coolstar.sileo_2.5.1_iphoneos-arm.deb")
                    }
                    quickInstallRow("TrollStore", "Install IPAs permanently", "app.badge.checkmark", .cyan) {
                        installFromURL(name: "TrollStore", url: "https://havoc.app/api/download/package/66d4ee514ce732df1fd8b283/com.opa334.trollstorehelper_2.1_iphoneos-arm.deb")
                    }
                    quickInstallRow("Ellekit", "Tweak injection library", "wand.and.stars", .pink) {
                        installFromURL(name: "Ellekit", url: "https://apt.autotouch.net/debs/iphoneos-arm/ellekit_1.1.3_iphoneos-arm.deb")
                    }
                    quickInstallRow("Frida", "Dynamic instrumentation", "ant.fill", .orange) {
                        installFromURL(name: "Frida", url: "https://build.frida.re/pool/main/r/re.frida.server/re.frida.server_17.9.10_iphoneos-arm.deb")
                    }
                }
            }
        }
    }
    
    private func quickInstallRow(_ name: String, _ desc: String, _ icon: String, _ color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .foregroundStyle(color)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text(name).font(.subheadline.bold())
                    Text(desc).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "arrow.down.circle")
                    .foregroundStyle(.blue)
            }
        }
        .disabled(isInstalling || !bootstrapReady)
    }
    
    // MARK: - Packages View
    
    private var packagesView: some View {
        Group {
            if packages.isEmpty {
                VStack(spacing: 16) {
                    Spacer()
                    Image(systemName: "shippingbox")
                        .font(.system(size: 44))
                        .foregroundStyle(.secondary)
                    Text("No Packages")
                        .font(.headline)
                    Text("Refresh sources to load packages")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("Refresh") { refreshAllRepos() }
                        .buttonStyle(.bordered)
                    Spacer()
                }
            } else {
                List(packages) { pkg in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(pkg.name)
                                .font(.subheadline.bold())
                            Spacer()
                            Text(pkg.version)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                        Text(pkg.description)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                        HStack {
                            Text(pkg.author)
                                .font(.system(size: 9))
                                .foregroundStyle(.tertiary)
                            Spacer()
                            Text(pkg.section)
                                .font(.system(size: 9))
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Capsule().fill(Color.blue.opacity(0.1)))
                                .foregroundStyle(.blue)
                            Button("Install") {
                                installFromURL(name: pkg.name, url: pkg.debURL)
                            }
                            .font(.caption.bold())
                            .buttonStyle(.borderedProminent)
                            .controlSize(.mini)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }
    
    // MARK: - Installed View
    
    private var installedView: some View {
        Group {
            if installedPackages.isEmpty {
                VStack(spacing: 16) {
                    Spacer()
                    Image(systemName: "checkmark.circle")
                        .font(.system(size: 44))
                        .foregroundStyle(.secondary)
                    Text("No Installed Packages")
                        .font(.headline)
                    Text("Install packages from Sources tab")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
            } else {
                List(installedPackages) { pkg in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(pkg.name).font(.subheadline.bold())
                            Text(pkg.bundleId)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(pkg.version)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
    
    // MARK: - Queue View
    
    private var queueView: some View {
        VStack(spacing: 16) {
            if isInstalling {
                VStack(spacing: 12) {
                    ProgressView(value: installProgress)
                        .progressViewStyle(.linear)
                        .padding(.horizontal, 32)
                    Text("Installing...")
                        .font(.subheadline.bold())
                    Text("\(Int(installProgress * 100))%")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 32)
            }
            
            if !installLog.isEmpty {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(installLog.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(line.contains("✅") ? .green : (line.contains("❌") ? .red : .primary))
                        }
                    }
                    .padding(12)
                }
                .background(Color(.systemGroupedBackground))
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .padding(.horizontal, 16)
            } else {
                Spacer()
                Text("Queue is empty")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Spacer()
            }
        }
    }
    
    // MARK: - Log Sheet
    
    private var logSheet: some View {
        NavigationStack {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(installLog.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(line.contains("✅") ? .green : (line.contains("❌") ? .red : .primary))
                    }
                }
                .padding(12)
            }
            .navigationTitle("Install Log")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { showLog = false }
                }
                ToolbarItem(placement: .topBarLeading) {
                    Button("Clear") { installLog.removeAll() }
                }
            }
        }
    }
    
    // MARK: - Actions
    
    private func checkBootstrap() {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "check_jb") { rc in
            let pathAddr = remote_alloc_str(rc, "/var/jb")
            let exists = RootExecutor.rcall(rc, "access", pathAddr, 0) == 0
            RootExecutor.rcall(rc, "free", pathAddr)
            DispatchQueue.main.async { self.bootstrapReady = exists }
            return (true, "bootstrap: \(exists)", exists ? 1 : 0)
        }
        #endif
    }
    
    private func setupBootstrap() {
        installLog.append("[bootstrap] Setting up /var/jb...")
        selectedTab = .queue
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "setup_bootstrap") { rc in
            let dirs = [
                "/var/jb", "/var/jb/usr", "/var/jb/usr/bin", "/var/jb/usr/lib",
                "/var/jb/usr/sbin", "/var/jb/usr/local", "/var/jb/usr/local/bin",
                "/var/jb/etc", "/var/jb/tmp", "/var/jb/var", "/var/jb/var/lib",
                "/var/jb/var/lib/dpkg", "/var/jb/var/lib/dpkg/info",
                "/var/jb/var/cache", "/var/jb/var/cache/apt",
                "/var/jb/var/cache/apt/archives",
                "/var/jb/Library", "/var/jb/Library/LaunchDaemons",
                "/var/jb/Library/TweakInject",
                "/var/jb/Library/MobileSubstrate",
                "/var/jb/Library/MobileSubstrate/DynamicLibraries",
                "/var/jb/Library/PreferenceBundles",
                "/var/jb/Library/PreferenceLoader",
                "/var/jb/Library/Frameworks",
                "/var/jb/Library/dpkg",
            ]
            
            for dir in dirs {
                let pathAddr = remote_alloc_str(rc, dir)
                RootExecutor.rcall(rc, "mkdir", pathAddr, 0o755)
                RootExecutor.rcall(rc, "free", pathAddr)
            }
            
            // Create dpkg status file
            let statusPath = remote_alloc_str(rc, "/var/jb/var/lib/dpkg/status")
            let fd = RootExecutor.rcall(rc, "open", statusPath, UInt64(O_WRONLY | O_CREAT), 0o644)
            if fd != UInt64(bitPattern: -1) { RootExecutor.rcall(rc, "close", fd) }
            RootExecutor.rcall(rc, "free", statusPath)
            
            // Create available file
            let availPath = remote_alloc_str(rc, "/var/jb/var/lib/dpkg/available")
            let fd2 = RootExecutor.rcall(rc, "open", availPath, UInt64(O_WRONLY | O_CREAT), 0o644)
            if fd2 != UInt64(bitPattern: -1) { RootExecutor.rcall(rc, "close", fd2) }
            RootExecutor.rcall(rc, "free", availPath)
            
            DispatchQueue.main.async {
                self.installLog.append("[bootstrap] ✅ Created \(dirs.count) directories")
                self.bootstrapReady = true
            }
            return (true, "Bootstrap created", UInt64(dirs.count))
        }
        #endif
    }
    
    private func addRepo() {
        guard !newRepoURL.isEmpty else { return }
        let url = newRepoURL.hasPrefix("http") ? newRepoURL : "https://\(newRepoURL)"
        repos.append(RepoInfo(name: URL(string: url)?.host ?? "Custom", url: url, icon: "globe"))
        newRepoURL = ""
    }
    
    private func refreshAllRepos() {
        isRefreshing = true
        installLog.append("[refresh] Refreshing \(repos.count) repos...")
        
        // Download Packages files from repos
        for i in repos.indices {
            repos[i].isRefreshing = true
            let url = repos[i].url
            
            // Try to fetch Packages file
            let packagesURL = "\(url)/Packages"
            installLog.append("[refresh] Fetching \(packagesURL)...")
            
            guard let fetchURL = URL(string: packagesURL) else {
                repos[i].isRefreshing = false
                continue
            }
            
            URLSession.shared.dataTask(with: fetchURL) { data, response, error in
                DispatchQueue.main.async {
                    if let idx = self.repos.firstIndex(where: { $0.url == url }) {
                        self.repos[idx].isRefreshing = false
                    }
                    
                    if let data = data, let content = String(data: data, encoding: .utf8) {
                        let pkgs = self.parsePackagesFile(content, repoURL: url)
                        self.packages.append(contentsOf: pkgs)
                        if let idx = self.repos.firstIndex(where: { $0.url == url }) {
                            self.repos[idx].packageCount = pkgs.count
                        }
                        self.installLog.append("[refresh] ✅ \(url): \(pkgs.count) packages")
                    } else {
                        self.installLog.append("[refresh] ❌ \(url): \(error?.localizedDescription ?? "failed")")
                    }
                    
                    if self.repos.allSatisfy({ !$0.isRefreshing }) {
                        self.isRefreshing = false
                    }
                }
            }.resume()
        }
    }
    
    private func parsePackagesFile(_ content: String, repoURL: String) -> [PackageInfo] {
        var packages: [PackageInfo] = []
        let blocks = content.components(separatedBy: "\n\n")
        
        for block in blocks {
            var name = "", bundleId = "", version = "", desc = ""
            var author = "", filename = "", size = "", section = ""
            
            for line in block.components(separatedBy: "\n") {
                if line.hasPrefix("Package: ") { bundleId = String(line.dropFirst(9)) }
                else if line.hasPrefix("Name: ") { name = String(line.dropFirst(6)) }
                else if line.hasPrefix("Version: ") { version = String(line.dropFirst(9)) }
                else if line.hasPrefix("Description: ") { desc = String(line.dropFirst(13)) }
                else if line.hasPrefix("Author: ") { author = String(line.dropFirst(8)) }
                else if line.hasPrefix("Filename: ") { filename = String(line.dropFirst(10)) }
                else if line.hasPrefix("Size: ") { size = String(line.dropFirst(6)) }
                else if line.hasPrefix("Section: ") { section = String(line.dropFirst(9)) }
            }
            
            guard !bundleId.isEmpty else { continue }
            if name.isEmpty { name = bundleId }
            
            let debURL = filename.hasPrefix("http") ? filename : "\(repoURL)/\(filename)"
            packages.append(PackageInfo(
                name: name, bundleId: bundleId, version: version,
                description: desc, author: author, repo: repoURL,
                debURL: debURL, size: size, section: section
            ))
        }
        
        return packages
    }
    
    private func installFromURL(name: String, url: String) {
        guard bootstrapReady else {
            installLog.append("[install] ❌ Bootstrap not ready — setup first")
            selectedTab = .queue
            return
        }
        
        isInstalling = true
        installProgress = 0
        selectedTab = .queue
        installLog.append("[install] Downloading \(name)...")
        installLog.append("[install] URL: \(url)")
        
        guard let downloadURL = URL(string: url) else {
            installLog.append("[install] ❌ Invalid URL")
            isInstalling = false
            return
        }
        
        // Download .deb file
        URLSession.shared.dataTask(with: downloadURL) { [self] data, response, error in
            DispatchQueue.main.async {
                self.installProgress = 0.4
                
                guard let data = data, !data.isEmpty else {
                    self.installLog.append("[install] ❌ Download failed: \(error?.localizedDescription ?? "no data")")
                    self.isInstalling = false
                    return
                }
                
                self.installLog.append("[install] ✅ Downloaded \(data.count) bytes")
                self.installProgress = 0.5
                
                // Validate it's actually a .deb (ar archive starts with "!<arch>\n")
                if data.count < 100 || String(data: data.prefix(8), encoding: .ascii) != "!<arch>\n" {
                    self.installLog.append("[install] ❌ Downloaded file is not a valid .deb (got HTML/redirect?)")
                    self.installLog.append("[install] ℹ️ First bytes: \(String(data: data.prefix(min(50, data.count)), encoding: .utf8) ?? "binary")")
                    self.isInstalling = false
                    return
                }
                
                // Skip writing .deb to cache — we already have data in memory
                // Writing 14MB via launchd causes watchdog panic
                // Just pass data directly to DebInstaller
                self.installLog.append("[install] Skipping cache write (direct extract)...")
                self.installProgress = 0.7
                
                // Extract .deb directly from memory
                self.extractDeb(name: name, debPath: "", data: data)
            }
        }.resume()
    }
    
    private func extractDeb(name: String, debPath: String, data: Data) {
        installLog.append("[install] Extracting \(name).deb with DebInstaller...")
        installProgress = 0.8
        
        let installer = DebInstaller { msg in
            DispatchQueue.main.async {
                self.installLog.append(msg)
            }
        }
        
        installer.install(debData: data, name: name) { success, fileCount in
            DispatchQueue.main.async {
                self.installProgress = 1.0
                self.isInstalling = false
                
                if success {
                    self.installLog.append("[install] ✅ \(name) installed (\(fileCount) files extracted)")
                    self.installLog.append("[install] ℹ️ If app was installed, respring to see icon on Home Screen")
                    self.installedPackages.append(InstalledPackage(
                        name: name, bundleId: name.lowercased().replacingOccurrences(of: " ", with: "."),
                        version: "1.0", installedDate: Date()
                    ))
                    UINotificationFeedbackGenerator().notificationOccurred(.success)
                } else {
                    self.installLog.append("[install] ❌ \(name) extraction failed")
                    UINotificationFeedbackGenerator().notificationOccurred(.error)
                }
            }
        }
    }
    
    // MARK: - Debug Experiments
    
    private func testRegisterDummy() {
        installLog.append("[exp] Test Register DUMMY — fake bundle ID, no files...")
        selectedTab = .queue
        
        DispatchQueue.global(qos: .userInitiated).async {
            dlopen("/System/Library/PrivateFrameworks/MobileContainerManager.framework/MobileContainerManager", RTLD_NOW)
            dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_NOW)
            
            guard let wsClass = NSClassFromString("LSApplicationWorkspace") else {
                DispatchQueue.main.async { self.installLog.append("[exp] ❌ LSApplicationWorkspace not found") }
                return
            }
            
            let sel = NSSelectorFromString("defaultWorkspace")
            guard let method = class_getClassMethod(wsClass, sel) else {
                DispatchQueue.main.async { self.installLog.append("[exp] ❌ defaultWorkspace not found") }
                return
            }
            typealias WSFunc = @convention(c) (AnyClass, Selector) -> AnyObject?
            let wsFn = unsafeBitCast(method_getImplementation(method), to: WSFunc.self)
            guard let workspace = wsFn(wsClass, sel) else {
                DispatchQueue.main.async { self.installLog.append("[exp] ❌ workspace nil") }
                return
            }
            
            // Dummy dictionary — fake path that doesn't exist
            let dict: NSDictionary = [
                "ApplicationType": "System",
                "CFBundleIdentifier": "com.test.dummy.doesnotexist",
                "Path": "/var/jb/Applications/DOESNOTEXIST.app",
                "BundleNameIsLocalized": 1,
                "CompatibilityState": 0,
                "IsDeletable": 0,
                "_LSBundlePlugins": [:] as [String: Any],
            ]
            
            let regSel = NSSelectorFromString("registerApplicationDictionary:")
            guard let regMethod = class_getInstanceMethod(type(of: workspace), regSel) else {
                DispatchQueue.main.async { self.installLog.append("[exp] ❌ registerApplicationDictionary not found") }
                return
            }
            typealias RegFunc = @convention(c) (AnyObject, Selector, NSDictionary) -> Bool
            let regFn = unsafeBitCast(method_getImplementation(regMethod), to: RegFunc.self)
            let result = regFn(workspace, regSel, dict)
            
            DispatchQueue.main.async {
                self.installLog.append("[exp] ✅ Dummy register returned: \(result)")
                self.installLog.append("[exp] If you see this = register call itself doesn't panic")
            }
        }
    }
    
    private func testRegisterReal() {
        installLog.append("[exp] Test Register REAL — without MCM container (safe)...")
        selectedTab = .queue
        
        DispatchQueue.global(qos: .userInitiated).async {
            dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_NOW)
            
            guard let wsClass = NSClassFromString("LSApplicationWorkspace") else {
                DispatchQueue.main.async { self.installLog.append("[exp] ❌ LSApplicationWorkspace not found") }
                return
            }
            
            let sel = NSSelectorFromString("defaultWorkspace")
            guard let method = class_getClassMethod(wsClass, sel) else { return }
            typealias WSFunc = @convention(c) (AnyClass, Selector) -> AnyObject?
            let wsFn = unsafeBitCast(method_getImplementation(method), to: WSFunc.self)
            guard let workspace = wsFn(wsClass, sel) else { return }
            
            let appPath = ("/var/jb/Applications/Filza.app" as NSString).resolvingSymlinksInPath
            
            // Register WITHOUT MCM container (MCM causes panic)
            let dict: NSDictionary = [
                "ApplicationType": "System",
                "BundleNameIsLocalized": 1,
                "CFBundleIdentifier": "com.tigisoftware.Filza",
                "CodeInfoIdentifier": "com.tigisoftware.Filza",
                "CompatibilityState": 0,
                "IsDeletable": 0,
                "IsContainerized": 0,  // NO container
                "Path": appPath,
                "SignerOrganization": "Apple Inc.",
                "SignatureVersion": 132352,
                "SignerIdentity": "Apple iPhone OS Application Signing",
                "IsAdHocSigned": true,
                "LSInstallType": 1,
                "HasMIDBasedSINF": 0,
                "MissingSINF": 0,
                "FamilyID": 0,
                "IsOnDemandInstallCapable": 0,
                "_LSBundlePlugins": [:] as [String: Any],
            ]
            
            let regSel = NSSelectorFromString("registerApplicationDictionary:")
            guard let regMethod = class_getInstanceMethod(type(of: workspace), regSel) else {
                DispatchQueue.main.async { self.installLog.append("[exp] ❌ method not found") }
                return
            }
            typealias RegFunc = @convention(c) (AnyObject, Selector, NSDictionary) -> Bool
            let regFn = unsafeBitCast(method_getImplementation(regMethod), to: RegFunc.self)
            let result = regFn(workspace, regSel, dict)
            
            DispatchQueue.main.async {
                self.installLog.append("[exp] ✅ Register returned: \(result)")
                if result {
                    self.installLog.append("[exp] 🎉 SUCCESS! Check Home Screen!")
                } else {
                    self.installLog.append("[exp] Returned false — lsd rejected (but no panic)")
                }
            }
        }
    }
    
    private func testSpawnBinary() {
        installLog.append("[exp] Test Spawn — chmod + posix_spawn Filza binary from launchd...")
        selectedTab = .queue
        
        #if !DISABLE_REMOTECALL
        // First chmod the binary to ensure it's executable
        root.executeAsRoot(operation: "chmod_spawn") { rc in
            let binPath = remote_alloc_str(rc, "/var/jb/Applications/Filza.app/Filza")
            RootExecutor.rcall(rc, "chmod", binPath, 0o755)
            RootExecutor.rcall(rc, "free", binPath)
            return (true, "chmod done", 0)
        }
        
        // Then spawn after chmod completes
        DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
            self.root.executeAsRoot(operation: "spawn_filza") { rc in
                let mem = rc.trojanMem
                let binPath = "/var/jb/Applications/Filza.app/Filza"
                let binAddr = remote_alloc_str(rc, binPath)
                
                let argvBase = mem + 0x400
                rc[argvBase].setValue64(binAddr)
                rc[argvBase + 8].setValue64(0)
                
                let pidAddr = mem + 0x300
                rc[pidAddr].setValue32(0)
                
                let ret = RootExecutor.rcall(rc, "posix_spawn", pidAddr, binAddr, 0, 0, argvBase, 0)
                let pid = rc[pidAddr].value32()
                
                RootExecutor.rcall(rc, "free", binAddr)
                
                DispatchQueue.main.async {
                    self.installLog.append("[exp] posix_spawn ret=\(ret), pid=\(pid)")
                    if ret == 0 && pid != 0 {
                        self.installLog.append("[exp] ✅ BINARY SPAWNED! PID=\(pid)")
                        self.installLog.append("[exp] AMFI disable works for installed binaries!")
                    } else {
                        self.installLog.append("[exp] ❌ Spawn failed (ret=\(ret))")
                        self.installLog.append("[exp] 1=EPERM, 2=ENOENT, 13=EACCES")
                    }
                }
                return (ret == 0, "spawn ret=\(ret) pid=\(pid)", UInt64(pid))
            }
        }
        #endif
    }
    
    // MARK: - Experiment: DiskImage Registration Path
    
    private func testDiskImageRegister() {
        installLog.append("[exp] Test: copy to /var/containers/Bundle/Application/<UUID>/ + registerApplication:")
        selectedTab = .queue
        
        #if !DISABLE_REMOTECALL
        // Key insight: lsd only accepts paths in /var/containers/Bundle/Application/<UUID>/
        // NOT /var/jb/Applications/. We need to symlink/move there first.
        
        let uuid = UUID().uuidString
        let containerBase = "/var/containers/Bundle/Application/\(uuid)"
        let destPath = "\(containerBase)/Filza.app"
        let srcPath = "/var/jb/Applications/Filza.app"
        
        installLog.append("[exp] Creating container: \(containerBase)")
        installLog.append("[exp] Symlinking \(srcPath) → \(destPath)")
        
        // Step 1: Create UUID directory and symlink via launchd
        root.executeAsRoot(operation: "create_container") { rc in
            // mkdir -p /var/containers/Bundle/Application/<UUID>
            let dirAddr = remote_alloc_str(rc, containerBase)
            RootExecutor.rcall(rc, "mkdir", dirAddr, 0o755)
            RootExecutor.rcall(rc, "free", dirAddr)
            
            // symlink /var/jb/Applications/Filza.app → /var/containers/Bundle/Application/<UUID>/Filza.app
            let srcAddr = remote_alloc_str(rc, srcPath)
            let dstAddr = remote_alloc_str(rc, destPath)
            let ret = RootExecutor.rcall(rc, "symlink", srcAddr, dstAddr)
            RootExecutor.rcall(rc, "free", srcAddr)
            RootExecutor.rcall(rc, "free", dstAddr)
            
            DispatchQueue.main.async {
                self.installLog.append("[exp] symlink ret=\(ret) (0=success)")
            }
            return (ret == 0, "symlink created", ret)
        }
        
        // Step 2: After symlink created, call registerApplication: from SpringBoard
        DispatchQueue.main.asyncAfter(deadline: .now() + 4.0) {
            guard let sb = dspmgr.shared.sbProc else {
                self.installLog.append("[exp] ❌ SpringBoard RC not available")
                return
            }
            
            self.installLog.append("[exp] Calling registerApplication: with container path...")
            
            let wsClass = remote_getClass(sb, "LSApplicationWorkspace")
            let defaultWS = remote_msg(sb, wsClass, remote_sel(sb, "defaultWorkspace"), 0, 0, 0, 0)
            
            guard defaultWS != 0 else {
                self.installLog.append("[exp] ❌ defaultWorkspace nil")
                return
            }
            
            // Create NSURL for container path
            let nsStr = remote_getClass(sb, "NSString")
            let pathStr = remote_msg(sb, nsStr, remote_sel(sb, "stringWithUTF8String:"),
                remote_alloc_str(sb, destPath), 0, 0, 0)
            let nsURL = remote_getClass(sb, "NSURL")
            let urlObj = remote_msg(sb, nsURL, remote_sel(sb, "fileURLWithPath:"), pathStr, 0, 0, 0)
            
            guard urlObj != 0 else {
                self.installLog.append("[exp] ❌ NSURL creation failed")
                return
            }
            
            // registerApplication:(NSURL*)
            let regResult = remote_msg(sb, defaultWS, remote_sel(sb, "registerApplication:"), urlObj, 0, 0, 0)
            self.installLog.append("[exp] registerApplication: returned \(regResult)")
            
            if regResult != 0 {
                self.installLog.append("[exp] ✅ SUCCESS! App should appear on Home Screen!")
            } else {
                self.installLog.append("[exp] ⚠️ returned 0 — trying _LSPrivateSyncWithMobileInstallation...")
                remote_msg(sb, defaultWS, remote_sel(sb, "_LSPrivateSyncWithMobileInstallation"), 0, 0, 0, 0)
                self.installLog.append("[exp] Sync called")
            }
        }
        #endif
    }
}
