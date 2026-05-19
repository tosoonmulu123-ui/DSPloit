//
//  RootFileManagerView.swift
//  DSPloit
//
//  File manager with root access — visual design
//

import SwiftUI

struct RootFileManagerView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var currentPath = "/var"
    @State private var entries: [FileEntry] = []
    @State private var isLoading = false
    @State private var fileContent = ""
    @State private var showingFile = false
    @State private var selectedFile = ""
    @State private var searchText = ""
    
    // Write mode
    @State private var writePath = "/var/root/test.txt"
    @State private var writeContent = "written by DSPloit"
    @State private var writeResult = ""
    @State private var showWrite = false
    
    struct FileEntry: Identifiable {
        let id = UUID()
        let name: String
        let isDir: Bool
    }
    
    var body: some View {
        VStack(spacing: 0) {
            // Path bar
            HStack {
                Image(systemName: "folder.fill")
                    .foregroundStyle(.blue)
                Text(currentPath)
                    .font(.system(size: 12, design: .monospaced))
                    .lineLimit(1)
                Spacer()
                Button(action: {
                    UIPasteboard.general.string = currentPath
                }) {
                    Image(systemName: "doc.on.doc")
                        .font(.caption)
                }
                .foregroundStyle(.secondary)
                Button(action: goUp) {
                    Image(systemName: "arrow.up.circle")
                }
                .disabled(currentPath == "/")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .background(.ultraThinMaterial)
            
            // Content
            if isLoading {
                Spacer()
                ProgressView("Loading...")
                Spacer()
            } else if entries.isEmpty {
                Spacer()
                VStack(spacing: 8) {
                    Image(systemName: "folder.badge.questionmark")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("Empty or not loaded")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("Load Directory") { loadDirectory() }
                        .buttonStyle(.bordered)
                }
                Spacer()
            } else {
                List(filteredEntries) { entry in
                    Button(action: { tapEntry(entry) }) {
                        HStack(spacing: 12) {
                            Image(systemName: entry.isDir ? "folder.fill" : fileIcon(entry.name))
                                .foregroundStyle(entry.isDir ? .blue : .secondary)
                                .frame(width: 20)
                            Text(entry.name)
                                .font(.system(size: 14))
                                .foregroundStyle(.primary)
                            Spacer()
                            if entry.isDir {
                                Image(systemName: "chevron.right")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            } else if entry.name.hasSuffix(".plist") {
                                Text("plist")
                                    .font(.system(size: 9))
                                    .foregroundStyle(.orange)
                            }
                        }
                    }
                }
                .listStyle(.plain)
                .searchable(text: $searchText, prompt: "Filter files")
            }
        }
        .navigationTitle("Files")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button(action: { showWrite.toggle() }) {
                        Label("Write File", systemImage: "square.and.pencil")
                    }
                    Button(action: loadDirectory) {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .onAppear { loadDirectory() }
        .sheet(isPresented: $showingFile) {
            FileContentSheet(path: selectedFile, content: fileContent)
        }
        .sheet(isPresented: $showWrite) {
            WriteFileSheet(root: root, mgr: mgr)
        }
    }
    
    // MARK: - Actions
    
    private var filteredEntries: [FileEntry] {
        if searchText.isEmpty { return entries }
        return entries.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }
    
    private func loadDirectory() {
        guard mgr.dsready else { return }
        isLoading = true
        entries.removeAll()
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "ls") { rc in
            let pathAddr = remote_alloc_str(rc, self.currentPath)
            let dir = RootExecutor.rcall(rc, "opendir", pathAddr)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            guard dir != 0 else {
                DispatchQueue.main.async { self.isLoading = false }
                return (false, "opendir failed", 0)
            }
            
            var items: [FileEntry] = []
            for _ in 0..<50 { // limit to 50 entries to prevent watchdog
                let dirent = RootExecutor.rcall(rc, "readdir", dir)
                if dirent == 0 { break }
                
                var nameBuf = [UInt8](repeating: 0, count: 256)
                rc.remoteRead(dirent + 21, to: &nameBuf, size: 256)
                let name = String(cString: nameBuf + [0])
                
                if name != "." && name != ".." {
                    var dtype: UInt8 = 0
                    rc.remoteRead(dirent + 20, to: &dtype, size: 1)
                    items.append(FileEntry(name: name, isDir: dtype == 4))
                }
            }
            
            RootExecutor.rcall(rc, "closedir", dir)
            
            DispatchQueue.main.async {
                self.entries = items.sorted { a, b in
                    if a.isDir != b.isDir { return a.isDir }
                    return a.name.lowercased() < b.name.lowercased()
                }
                self.isLoading = false
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
            }
            
            return (true, "\(items.count) entries", UInt64(items.count))
        }
        #endif
    }
    
    private func tapEntry(_ entry: FileEntry) {
        if entry.isDir {
            currentPath = currentPath == "/" ? "/\(entry.name)" : "\(currentPath)/\(entry.name)"
            loadDirectory()
        } else {
            // Read file
            let path = currentPath == "/" ? "/\(entry.name)" : "\(currentPath)/\(entry.name)"
            selectedFile = path
            readFile(path: path)
        }
    }
    
    private func readFile(path: String) {
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "cat") { rc in
            let pathAddr = remote_alloc_str(rc, path)
            let fd = RootExecutor.rcall(rc, "open", pathAddr, UInt64(O_RDONLY), 0)
            RootExecutor.rcall(rc, "free", pathAddr)
            
            guard fd != UInt64(bitPattern: -1) else {
                DispatchQueue.main.async {
                    self.fileContent = "(cannot open: errno=\(remote_errno(rc)))"
                    self.showingFile = true
                }
                return (false, "open failed", 0)
            }
            
            // Read up to 8KB for plists, 4KB for other files
            let maxRead: UInt64 = path.hasSuffix(".plist") ? 8000 : 4000
            let bufAddr = rc.trojanMem + 0x800
            let n = RootExecutor.rcall(rc, "read", fd, bufAddr, maxRead)
            RootExecutor.rcall(rc, "close", fd)
            
            if n > 0 && n <= maxRead {
                var buf = [UInt8](repeating: 0, count: Int(n))
                rc.remoteRead(bufAddr, to: &buf, size: n)
                let content = String(bytes: buf, encoding: .utf8) ?? "(binary: \(n) bytes)"
                DispatchQueue.main.async {
                    self.fileContent = content
                    self.showingFile = true
                }
            } else {
                DispatchQueue.main.async {
                    self.fileContent = "(empty or too large)"
                    self.showingFile = true
                }
            }
            
            return (true, "\(n) bytes", n)
        }
        #endif
    }
    
    private func goUp() {
        let components = currentPath.split(separator: "/")
        if components.count > 1 {
            currentPath = "/" + components.dropLast().joined(separator: "/")
        } else {
            currentPath = "/"
        }
        loadDirectory()
    }
    
    private func fileIcon(_ name: String) -> String {
        if name.hasSuffix(".plist") { return "slider.horizontal.3" }
        if name.hasSuffix(".txt") || name.hasSuffix(".log") { return "doc.plaintext" }
        if name.hasSuffix(".dylib") || name.hasSuffix(".so") { return "puzzlepiece" }
        if name.hasSuffix(".framework") { return "shippingbox" }
        if name.hasSuffix(".png") || name.hasSuffix(".jpg") || name.hasSuffix(".jpeg") { return "photo" }
        if name.hasSuffix(".db") || name.hasSuffix(".sqlite") || name.hasSuffix(".sqlitedb") { return "cylinder" }
        if name.hasSuffix(".app") { return "app" }
        if name.hasSuffix(".ipa") { return "archivebox" }
        if name.hasSuffix(".json") { return "curlybraces" }
        if name.hasSuffix(".xml") { return "chevron.left.forwardslash.chevron.right" }
        return "doc"
    }
}

// MARK: - File Content Sheet

struct FileContentSheet: View {
    let path: String
    let content: String
    let isPlist: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var plistEntries: [(String, String)] = []
    
    init(path: String, content: String) {
        self.path = path
        self.content = content
        self.isPlist = path.hasSuffix(".plist")
    }
    
    var body: some View {
        NavigationStack {
            Group {
                if isPlist && !plistEntries.isEmpty {
                    // Plist viewer — parsed key-value
                    List(plistEntries, id: \.0) { key, value in
                        VStack(alignment: .leading, spacing: 3) {
                            Text(key)
                                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                .foregroundStyle(.blue)
                            Text(value)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.primary)
                                .textSelection(.enabled)
                                .lineLimit(5)
                        }
                        .padding(.vertical, 2)
                    }
                    .listStyle(.plain)
                } else if isPlist && content.contains("bplist") {
                    // Binary plist — show raw hex info
                    VStack(spacing: 12) {
                        Image(systemName: "doc.badge.gearshape")
                            .font(.largeTitle)
                            .foregroundStyle(.orange)
                        Text("Binary Plist")
                            .font(.headline)
                        Text("\(content.count) bytes")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("Binary plists cannot be displayed as text.\nUse 'plutil' or view on Mac.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding()
                } else {
                    // Raw text viewer
                    ScrollView {
                        Text(content)
                            .font(.system(size: 12, design: .monospaced))
                            .textSelection(.enabled)
                            .padding()
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .navigationTitle(URL(fileURLWithPath: path).lastPathComponent)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .topBarLeading) {
                    HStack(spacing: 12) {
                        Button(action: {
                            UIPasteboard.general.string = content
                        }) {
                            Image(systemName: "doc.on.doc")
                        }
                        ShareLink(item: content) {
                            Image(systemName: "square.and.arrow.up")
                        }
                    }
                }
            }
            .onAppear { parsePlist() }
        }
    }
    
    private func parsePlist() {
        guard isPlist else { return }
        
        // Try to parse XML plist from content
        if let data = content.data(using: .utf8),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) {
            plistEntries = flattenPlist(plist, prefix: "")
        } else {
            // Try parsing as if content might have been read as raw bytes
            // Just show as text if parsing fails
            plistEntries = []
        }
    }
    
    private func flattenPlist(_ obj: Any, prefix: String) -> [(String, String)] {
        var result: [(String, String)] = []
        
        if let dict = obj as? [String: Any] {
            for (key, value) in dict.sorted(by: { $0.key < $1.key }) {
                let fullKey = prefix.isEmpty ? key : "\(prefix).\(key)"
                if let subDict = value as? [String: Any] {
                    result.append((fullKey, "{\(subDict.count) keys}"))
                    result.append(contentsOf: flattenPlist(subDict, prefix: fullKey))
                } else if let arr = value as? [Any] {
                    result.append((fullKey, "[\(arr.count) items]"))
                    for (i, item) in arr.prefix(10).enumerated() {
                        result.append(("  \(fullKey)[\(i)]", "\(item)"))
                    }
                } else {
                    result.append((fullKey, "\(value)"))
                }
            }
        } else if let arr = obj as? [Any] {
            for (i, item) in arr.prefix(20).enumerated() {
                result.append(("[\(i)]", "\(item)"))
            }
        } else {
            result.append(("value", "\(obj)"))
        }
        
        return result
    }
}

// MARK: - Write File Sheet

struct WriteFileSheet: View {
    let root: RootExecutor
    let mgr: dspmgr
    @Environment(\.dismiss) private var dismiss
    @State private var path = "/var/root/test.txt"
    @State private var content = "written by DSPloit"
    @State private var result = ""
    
    var body: some View {
        NavigationStack {
            List {
                Section("Path") {
                    TextField("/var/root/file.txt", text: $path)
                        .font(.system(.body, design: .monospaced))
                }
                Section("Content") {
                    TextEditor(text: $content)
                        .font(.system(size: 13, design: .monospaced))
                        .frame(minHeight: 100)
                }
                Section {
                    Button("Write as Root") {
                        root.writeFileAsRoot(path: path, content: Data(content.utf8))
                        result = "Writing..."
                        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                            result = root.lastResult?.message ?? "done"
                        }
                    }
                    .disabled(path.isEmpty)
                    
                    if !result.isEmpty {
                        Text(result)
                            .font(.caption)
                            .foregroundStyle(.green)
                    }
                }
            }
            .navigationTitle("Write File")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}
