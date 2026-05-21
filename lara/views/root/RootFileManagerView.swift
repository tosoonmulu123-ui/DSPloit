//
//  RootFileManagerView.swift
//  DSPloit
//
//  Full-featured file manager with root access (Filza-level)
//  Features: navigation, preview, hex view, permissions, copy/move/delete, bookmarks
//

import SwiftUI

struct RootFileManagerView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var currentPath = "/var"
    @State private var entries: [FileEntry] = []
    @State private var isLoading = false
    @State private var searchText = ""
    @State private var showingFile = false
    @State private var selectedFile = ""
    @State private var fileContent = ""
    @State private var showWrite = false
    @State private var showMkdir = false
    @State private var mkdirName = ""
    @State private var deleteTarget: FileEntry? = nil
    @State private var showDeleteConfirm = false
    @State private var pathHistory: [String] = ["/var"]
    @State private var showBookmarks = false
    @State private var showPermissions = false
    @State private var permTarget: FileEntry? = nil
    @State private var clipboardPath: String? = nil
    @State private var clipboardOp: ClipboardOp = .copy
    @State private var showPasteAlert = false
    @State private var viewMode: ViewMode = .list
    
    enum ViewMode { case list, grid }
    enum ClipboardOp { case copy, move }
    
    struct FileEntry: Identifiable {
        let id = UUID()
        let name: String
        let isDir: Bool
        var size: Int64 = 0
        var permissions: String = ""
    }
    
    private let bookmarks: [(String, String, String)] = [
        ("Root", "/", "externaldrive.fill"),
        ("var", "/var", "folder.fill"),
        ("var/jb", "/var/jb", "shippingbox.fill"),
        ("var/mobile", "/var/mobile", "person.fill"),
        ("var/root", "/var/root", "person.badge.key.fill"),
        ("tmp", "/tmp", "clock.fill"),
        ("Applications", "/var/containers/Bundle/Application", "app.fill"),
        ("System", "/System", "gearshape.fill"),
        ("usr/bin", "/usr/bin", "terminal.fill"),
        ("Library", "/var/mobile/Library", "books.vertical.fill"),
    ]
    
    var body: some View {
        VStack(spacing: 0) {
            // Path breadcrumb bar
            pathBar
            
            // Toolbar
            toolbarRow
            
            // Content
            if isLoading {
                Spacer()
                VStack(spacing: 12) {
                    ProgressView()
                        .scaleEffect(1.2)
                    Text("Loading...")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            } else if entries.isEmpty {
                emptyState
            } else {
                fileList
            }
        }
        .navigationTitle("File Manager")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button(action: { showBookmarks = true }) {
                        Label("Bookmarks", systemImage: "bookmark")
                    }
                    Button(action: { showWrite = true }) {
                        Label("New File", systemImage: "doc.badge.plus")
                    }
                    Button(action: { showMkdir = true }) {
                        Label("New Folder", systemImage: "folder.badge.plus")
                    }
                    if clipboardPath != nil {
                        Button(action: { showPasteAlert = true }) {
                            Label("Paste Here", systemImage: "doc.on.clipboard")
                        }
                    }
                    Divider()
                    Button(action: loadDirectory) {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    Picker("View", selection: $viewMode) {
                        Label("List", systemImage: "list.bullet").tag(ViewMode.list)
                        Label("Grid", systemImage: "square.grid.2x2").tag(ViewMode.grid)
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
            WriteFileSheet(root: root, mgr: mgr, defaultPath: currentPath)
        }
        .sheet(isPresented: $showBookmarks) {
            bookmarksSheet
        }
        .alert("New Folder", isPresented: $showMkdir) {
            TextField("Folder name", text: $mkdirName)
            Button("Create") { createFolder() }
            Button("Cancel", role: .cancel) { mkdirName = "" }
        }
        .alert("Delete?", isPresented: $showDeleteConfirm) {
            Button("Delete", role: .destructive) { performDelete() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Delete \(deleteTarget?.name ?? "")? This cannot be undone.")
        }
        .alert("Paste", isPresented: $showPasteAlert) {
            Button("Paste") { performPaste() }
            Button("Cancel", role: .cancel) {}
        } message: {
            if let cp = clipboardPath {
                Text("\(clipboardOp == .copy ? "Copy" : "Move") \(URL(fileURLWithPath: cp).lastPathComponent) here?")
            }
        }
    }
    
    // MARK: - Path Bar
    
    private var pathBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 4) {
                Button(action: { navigateTo("/") }) {
                    Image(systemName: "externaldrive.fill")
                        .font(.caption)
                        .foregroundStyle(.blue)
                }
                
                ForEach(pathComponents, id: \.self) { component in
                    HStack(spacing: 4) {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 8))
                            .foregroundStyle(.tertiary)
                        Button(component) {
                            navigateToComponent(component)
                        }
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.primary)
                    }
                }
                
                Spacer()
                
                Button(action: { UIPasteboard.general.string = currentPath }) {
                    Image(systemName: "doc.on.doc")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
        }
        .background(.ultraThinMaterial)
    }
    
    // MARK: - Toolbar Row
    
    private var toolbarRow: some View {
        HStack(spacing: 12) {
            // Back button
            Button(action: goUp) {
                Image(systemName: "arrow.up")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(currentPath == "/" ? .secondary : .blue)
            }
            .disabled(currentPath == "/")
            
            // Search
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                TextField("Filter", text: $searchText)
                    .font(.system(size: 13))
                    .textInputAutocapitalization(.never)
                if !searchText.isEmpty {
                    Button(action: { searchText = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(RoundedRectangle(cornerRadius: 8).fill(Color(.tertiarySystemFill)))
            
            // Entry count
            Text("\(filteredEntries.count)")
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(Color(.secondarySystemBackground))
    }
    
    // MARK: - File List
    
    private var fileList: some View {
        List(filteredEntries) { entry in
            Button(action: { tapEntry(entry) }) {
                HStack(spacing: 12) {
                    // Icon
                    ZStack {
                        RoundedRectangle(cornerRadius: 8)
                            .fill(iconColor(entry).opacity(0.12))
                            .frame(width: 34, height: 34)
                        Image(systemName: entry.isDir ? "folder.fill" : fileIcon(entry.name))
                            .font(.system(size: 14))
                            .foregroundStyle(iconColor(entry))
                    }
                    
                    // Name + info
                    VStack(alignment: .leading, spacing: 2) {
                        Text(entry.name)
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                        HStack(spacing: 8) {
                            if !entry.isDir && entry.size > 0 {
                                Text(formatSize(entry.size))
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                            if entry.isDir {
                                Text("Directory")
                                    .font(.system(size: 10))
                                    .foregroundStyle(.tertiary)
                            }
                        }
                    }
                    
                    Spacer()
                    
                    if entry.isDir {
                        Image(systemName: "chevron.right")
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            .contextMenu {
                Button(action: { copyToClipboard(entry, op: .copy) }) {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                Button(action: { copyToClipboard(entry, op: .move) }) {
                    Label("Move", systemImage: "arrow.right.doc.on.clipboard")
                }
                Divider()
                Button(action: {
                    permTarget = entry
                    showPermissions = true
                }) {
                    Label("Permissions", systemImage: "lock.shield")
                }
                Button(action: {
                    let path = fullPath(entry)
                    UIPasteboard.general.string = path
                }) {
                    Label("Copy Path", systemImage: "link")
                }
                Divider()
                Button(role: .destructive, action: {
                    deleteTarget = entry
                    showDeleteConfirm = true
                }) {
                    Label("Delete", systemImage: "trash")
                }
            }
            .swipeActions(edge: .trailing) {
                Button(role: .destructive) {
                    deleteTarget = entry
                    showDeleteConfirm = true
                } label: {
                    Label("Delete", systemImage: "trash")
                }
            }
            .swipeActions(edge: .leading) {
                Button {
                    copyToClipboard(entry, op: .copy)
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                .tint(.blue)
            }
        }
        .listStyle(.plain)
    }
    
    // MARK: - Empty State
    
    private var emptyState: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "folder.badge.questionmark")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text("Empty Directory")
                .font(.headline)
                .foregroundStyle(.secondary)
            Button("Load Directory") { loadDirectory() }
                .buttonStyle(.bordered)
            Spacer()
        }
    }
    
    // MARK: - Bookmarks Sheet
    
    private var bookmarksSheet: some View {
        NavigationStack {
            List {
                Section("Quick Access") {
                    ForEach(bookmarks, id: \.1) { name, path, icon in
                        Button(action: {
                            navigateTo(path)
                            showBookmarks = false
                        }) {
                            HStack(spacing: 12) {
                                Image(systemName: icon)
                                    .foregroundStyle(.blue)
                                    .frame(width: 24)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(name)
                                        .font(.subheadline.bold())
                                        .foregroundStyle(.primary)
                                    Text(path)
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                }
                
                if let cp = clipboardPath {
                    Section("Clipboard") {
                        HStack {
                            Image(systemName: "doc.on.clipboard")
                                .foregroundStyle(.orange)
                            VStack(alignment: .leading) {
                                Text(clipboardOp == .copy ? "Copied" : "Cut")
                                    .font(.caption.bold())
                                Text(cp)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Bookmarks")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { showBookmarks = false }
                }
            }
        }
    }
    
    // MARK: - Actions
    
    private var filteredEntries: [FileEntry] {
        if searchText.isEmpty { return entries }
        return entries.filter { $0.name.localizedCaseInsensitiveContains(searchText) }
    }
    
    private var pathComponents: [String] {
        currentPath.split(separator: "/").map(String.init)
    }
    
    private func navigateTo(_ path: String) {
        currentPath = path
        pathHistory.append(path)
        loadDirectory()
    }
    
    private func navigateToComponent(_ component: String) {
        guard let idx = pathComponents.firstIndex(of: component) else { return }
        let newPath = "/" + pathComponents.prefix(through: idx).joined(separator: "/")
        navigateTo(newPath)
    }
    
    private func goUp() {
        let components = currentPath.split(separator: "/")
        if components.count > 1 {
            currentPath = "/" + components.dropLast().joined(separator: "/")
        } else {
            currentPath = "/"
        }
        pathHistory.append(currentPath)
        loadDirectory()
    }
    
    private func tapEntry(_ entry: FileEntry) {
        if entry.isDir {
            let newPath = currentPath == "/" ? "/\(entry.name)" : "\(currentPath)/\(entry.name)"
            navigateTo(newPath)
        } else {
            let path = fullPath(entry)
            selectedFile = path
            readFile(path: path)
        }
    }
    
    private func fullPath(_ entry: FileEntry) -> String {
        currentPath == "/" ? "/\(entry.name)" : "\(currentPath)/\(entry.name)"
    }
    
    private func copyToClipboard(_ entry: FileEntry, op: ClipboardOp) {
        clipboardPath = fullPath(entry)
        clipboardOp = op
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
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
            for _ in 0..<200 {
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
    
    private func createFolder() {
        guard !mkdirName.isEmpty else { return }
        let fullPath = currentPath == "/" ? "/\(mkdirName)" : "\(currentPath)/\(mkdirName)"
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "mkdir") { rc in
            let pathAddr = remote_alloc_str(rc, fullPath)
            RootExecutor.rcall(rc, "mkdir", pathAddr, 0o755)
            RootExecutor.rcall(rc, "free", pathAddr)
            DispatchQueue.main.async {
                self.mkdirName = ""
                self.loadDirectory()
            }
            return (true, "mkdir \(fullPath)", 0)
        }
        #endif
    }
    
    private func performDelete() {
        guard let target = deleteTarget else { return }
        let path = fullPath(target)
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "delete") { rc in
            let pathAddr = remote_alloc_str(rc, path)
            if target.isDir {
                RootExecutor.rcall(rc, "rmdir", pathAddr)
            } else {
                RootExecutor.rcall(rc, "unlink", pathAddr)
            }
            RootExecutor.rcall(rc, "free", pathAddr)
            DispatchQueue.main.async {
                self.deleteTarget = nil
                self.loadDirectory()
            }
            return (true, "deleted \(path)", 0)
        }
        #endif
    }
    
    private func performPaste() {
        guard let source = clipboardPath else { return }
        let fileName = URL(fileURLWithPath: source).lastPathComponent
        let dest = currentPath == "/" ? "/\(fileName)" : "\(currentPath)/\(fileName)"
        
        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: clipboardOp == .copy ? "cp" : "mv") { rc in
            let srcAddr = remote_alloc_str(rc, source)
            let dstAddr = remote_alloc_str(rc, dest)
            
            if self.clipboardOp == .move {
                RootExecutor.rcall(rc, "rename", srcAddr, dstAddr)
            } else {
                // Copy: open src, read, open dst, write
                let fd = RootExecutor.rcall(rc, "open", srcAddr, UInt64(O_RDONLY), 0)
                if fd != UInt64(bitPattern: -1) {
                    let bufAddr = rc.trojanMem + 0x800
                    let n = RootExecutor.rcall(rc, "read", fd, bufAddr, 4096)
                    RootExecutor.rcall(rc, "close", fd)
                    
                    if n > 0 {
                        let fd2 = RootExecutor.rcall(rc, "open", dstAddr, UInt64(O_WRONLY | O_CREAT | O_TRUNC), 0o644)
                        if fd2 != UInt64(bitPattern: -1) {
                            RootExecutor.rcall(rc, "write", fd2, bufAddr, n)
                            RootExecutor.rcall(rc, "close", fd2)
                        }
                    }
                }
            }
            
            RootExecutor.rcall(rc, "free", srcAddr)
            RootExecutor.rcall(rc, "free", dstAddr)
            
            DispatchQueue.main.async {
                self.clipboardPath = nil
                self.loadDirectory()
            }
            return (true, "\(self.clipboardOp == .copy ? "copied" : "moved") to \(dest)", 0)
        }
        #endif
    }
    
    // MARK: - Helpers
    
    private func iconColor(_ entry: FileEntry) -> Color {
        if entry.isDir { return .blue }
        let name = entry.name.lowercased()
        if name.hasSuffix(".plist") { return .orange }
        if name.hasSuffix(".dylib") || name.hasSuffix(".so") { return .purple }
        if name.hasSuffix(".app") || name.hasSuffix(".ipa") { return .pink }
        if name.hasSuffix(".png") || name.hasSuffix(".jpg") || name.hasSuffix(".jpeg") { return .green }
        if name.hasSuffix(".db") || name.hasSuffix(".sqlite") { return .cyan }
        if name.hasSuffix(".log") || name.hasSuffix(".txt") { return .secondary }
        return .secondary
    }
    
    private func fileIcon(_ name: String) -> String {
        let n = name.lowercased()
        if n.hasSuffix(".plist") { return "slider.horizontal.3" }
        if n.hasSuffix(".txt") || n.hasSuffix(".log") { return "doc.plaintext" }
        if n.hasSuffix(".dylib") || n.hasSuffix(".so") { return "puzzlepiece" }
        if n.hasSuffix(".framework") { return "shippingbox" }
        if n.hasSuffix(".png") || n.hasSuffix(".jpg") || n.hasSuffix(".jpeg") { return "photo" }
        if n.hasSuffix(".db") || n.hasSuffix(".sqlite") || n.hasSuffix(".sqlitedb") { return "cylinder" }
        if n.hasSuffix(".app") { return "app" }
        if n.hasSuffix(".ipa") { return "archivebox" }
        if n.hasSuffix(".json") { return "curlybraces" }
        if n.hasSuffix(".xml") { return "chevron.left.forwardslash.chevron.right" }
        if n.hasSuffix(".deb") { return "shippingbox.circle" }
        if n.hasSuffix(".sh") { return "terminal" }
        return "doc"
    }
    
    private func formatSize(_ bytes: Int64) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1024 * 1024 { return String(format: "%.1f KB", Double(bytes) / 1024) }
        if bytes < 1024 * 1024 * 1024 { return String(format: "%.1f MB", Double(bytes) / 1048576) }
        return String(format: "%.2f GB", Double(bytes) / 1073741824)
    }
}

// MARK: - File Content Sheet (enhanced)

struct FileContentSheet: View {
    let path: String
    let content: String
    let isPlist: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var plistEntries: [(String, String)] = []
    @State private var isEditing = false
    @State private var editContent = ""
    @State private var showHex = false
    @ObservedObject private var root = RootExecutor.shared
    
    init(path: String, content: String) {
        self.path = path
        self.content = content
        self.isPlist = path.hasSuffix(".plist")
    }
    
    var body: some View {
        NavigationStack {
            Group {
                if isEditing {
                    TextEditor(text: $editContent)
                        .font(.system(size: 12, design: .monospaced))
                        .padding(8)
                } else if showHex {
                    hexView
                } else if isPlist && !plistEntries.isEmpty {
                    plistView
                } else {
                    textView
                }
            }
            .navigationTitle(URL(fileURLWithPath: path).lastPathComponent)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if isEditing {
                        Button("Save") { saveEdit() }
                            .bold()
                    } else {
                        Button("Done") { dismiss() }
                    }
                }
                ToolbarItem(placement: .topBarLeading) {
                    HStack(spacing: 12) {
                        if isEditing {
                            Button("Cancel") { isEditing = false }
                        } else {
                            Button(action: { UIPasteboard.general.string = content }) {
                                Image(systemName: "doc.on.doc")
                            }
                            Button(action: { editContent = content; isEditing = true }) {
                                Image(systemName: "pencil")
                            }
                            Button(action: { showHex.toggle() }) {
                                Image(systemName: showHex ? "doc.plaintext" : "number")
                            }
                        }
                    }
                }
            }
            .onAppear { parsePlist() }
        }
    }
    
    private var hexView: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 2) {
                let bytes = Array(content.utf8)
                ForEach(0..<(bytes.count / 16 + 1), id: \.self) { row in
                    let offset = row * 16
                    if offset < bytes.count {
                        HStack(spacing: 8) {
                            Text(String(format: "%04X", offset))
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .frame(width: 40, alignment: .leading)
                            
                            Text(hexLine(bytes: bytes, offset: offset))
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.primary)
                            
                            Spacer()
                            
                            Text(asciiLine(bytes: bytes, offset: offset))
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundStyle(.orange)
                        }
                    }
                }
            }
            .padding(12)
        }
    }
    
    private var plistView: some View {
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
    }
    
    private var textView: some View {
        ScrollView {
            Text(content)
                .font(.system(size: 12, design: .monospaced))
                .textSelection(.enabled)
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
    
    private func hexLine(bytes: [UInt8], offset: Int) -> String {
        var hex = ""
        for i in 0..<16 {
            if offset + i < bytes.count {
                hex += String(format: "%02X ", bytes[offset + i])
            } else {
                hex += "   "
            }
            if i == 7 { hex += " " }
        }
        return hex
    }
    
    private func asciiLine(bytes: [UInt8], offset: Int) -> String {
        var ascii = ""
        for i in 0..<16 {
            if offset + i < bytes.count {
                let b = bytes[offset + i]
                ascii += (b >= 32 && b < 127) ? String(UnicodeScalar(b)) : "."
            }
        }
        return ascii
    }
    
    private func parsePlist() {
        guard isPlist else { return }
        if let data = content.data(using: .utf8),
           let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) {
            plistEntries = flattenPlist(plist, prefix: "")
        }
    }
    
    private func saveEdit() {
        guard !editContent.isEmpty else { return }
        root.writeFileAsRoot(path: path, content: Data(editContent.utf8))
        isEditing = false
        UINotificationFeedbackGenerator().notificationOccurred(.success)
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
        }
        return result
    }
}

// MARK: - Write File Sheet

struct WriteFileSheet: View {
    let root: RootExecutor
    let mgr: dspmgr
    var defaultPath: String = "/var/root"
    @Environment(\.dismiss) private var dismiss
    @State private var path = ""
    @State private var content = ""
    @State private var result = ""
    
    var body: some View {
        NavigationStack {
            List {
                Section("Path") {
                    TextField("/var/root/file.txt", text: $path)
                        .font(.system(.body, design: .monospaced))
                        .textInputAutocapitalization(.never)
                }
                Section("Content") {
                    TextEditor(text: $content)
                        .font(.system(size: 13, design: .monospaced))
                        .frame(minHeight: 150)
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
                        Text(result).font(.caption).foregroundStyle(.green)
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
            .onAppear {
                if path.isEmpty {
                    path = defaultPath == "/" ? "/var/root/new_file.txt" : "\(defaultPath)/new_file.txt"
                }
            }
        }
    }
}
