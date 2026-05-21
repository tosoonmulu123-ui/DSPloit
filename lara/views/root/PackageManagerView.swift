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
            
            URLSession.shared.dataTask(with: fetchURL) { [self] data, response, error in
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
}
