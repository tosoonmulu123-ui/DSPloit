//
//  RootFileManagerView.swift
//  DSPloit
//
//  File manager with root access — read/write anywhere
//

import SwiftUI

struct RootFileManagerView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var currentPath = "/var"
    @State private var writePath = "/var/root/test.txt"
    @State private var writeContent = "written by DSPloit as root"
    @State private var readPath = "/etc/passwd"
    @State private var readOutput = ""
    @State private var mkdirPath = "/var/root/dsploit"
    
    var body: some View {
        List {
            // Write
            Section {
                TextField("Path", text: $writePath)
                    .font(.system(.caption, design: .monospaced))
                TextField("Content", text: $writeContent)
                    .font(.system(.caption, design: .monospaced))
                Button(action: {
                    root.writeFileAsRoot(path: writePath, content: Data(writeContent.utf8))
                }) {
                    Label("Write", systemImage: "square.and.pencil")
                }
                .disabled(!mgr.rcready || root.isExecuting)
            } header: {
                Label("Write File (root)", systemImage: "doc.badge.plus")
            }
            
            // Read
            Section {
                TextField("Path", text: $readPath)
                    .font(.system(.caption, design: .monospaced))
                Button(action: {
                    root.readFileAsRoot(path: readPath) { data in
                        if let data, let str = String(data: data, encoding: .utf8) {
                            readOutput = str
                        } else {
                            readOutput = data != nil ? "(binary: \(data!.count) bytes)" : "(failed)"
                        }
                    }
                }) {
                    Label("Read", systemImage: "doc.text.magnifyingglass")
                }
                .disabled(!mgr.rcready || root.isExecuting)
                
                if !readOutput.isEmpty {
                    Text(readOutput)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.green)
                        .textSelection(.enabled)
                        .lineLimit(30)
                }
            } header: {
                Label("Read File (root)", systemImage: "doc.text")
            }
            
            // mkdir / chmod / chown
            Section {
                TextField("Path", text: $mkdirPath)
                    .font(.system(.caption, design: .monospaced))
                HStack {
                    Button("mkdir") { root.mkdirAsRoot(path: mkdirPath) }
                        .buttonStyle(.bordered).font(.caption)
                    Button("chmod 755") { root.chmodAsRoot(path: mkdirPath, mode: 0o755) }
                        .buttonStyle(.bordered).font(.caption)
                    Button("chown root") { root.chownAsRoot(path: mkdirPath, uid: 0, gid: 0) }
                        .buttonStyle(.bordered).font(.caption)
                }
                .disabled(!mgr.rcready || root.isExecuting)
            } header: {
                Label("Permissions", systemImage: "lock.open")
            }
            
            // Result
            if let r = root.lastResult {
                Section {
                    HStack {
                        Image(systemName: r.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                            .foregroundStyle(r.success ? .green : .red)
                        Text(r.message)
                            .font(.system(size: 11, design: .monospaced))
                    }
                } header: {
                    Label("Result", systemImage: "info.circle")
                }
            }
        }
        .navigationTitle("File Manager")
        .navigationBarTitleDisplayMode(.inline)
    }
}
