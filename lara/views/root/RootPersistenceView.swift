//
//  RootPersistenceView.swift
//  DSPloit
//
//  Persistence — survive reboot, LaunchDaemons, KRW stash
//

import SwiftUI

struct RootPersistenceView: View {
    @ObservedObject private var root = RootExecutor.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var daemonLabel = "com.dsploit.helper"
    @State private var daemonProgram = "/var/jb/usr/bin/dsploit_helper"
    @State private var stashResult = ""
    @State private var recoverResult = ""
    
    var body: some View {
        List {
            // KRW Stash (survive app restart)
            Section {
                Button(action: {
                    #if !DISABLE_REMOTECALL
                    DispatchQueue.global(qos: .userInitiated).async {
                        let ok = transfer_krw_to_launchd()
                        DispatchQueue.main.async {
                            stashResult = ok ? "✅ KRW stashed to launchd" : "❌ Stash failed"
                        }
                    }
                    #endif
                }) {
                    Label("Stash KRW Ports", systemImage: "tray.and.arrow.down.fill")
                }
                .disabled(!mgr.dsready || !mgr.rcready)
                
                Button(action: {
                    DispatchQueue.global(qos: .userInitiated).async {
                        let ok = recover_krw_primitives()
                        DispatchQueue.main.async {
                            if ok {
                                recoverResult = "✅ KRW recovered"
                                mgr.dsready = true
                                mgr.kernbase = ds_get_kernel_base()
                                mgr.kernslide = ds_get_kernel_slide()
                            } else {
                                recoverResult = "❌ Recovery failed (reboot clears ports)"
                            }
                        }
                    }
                }) {
                    Label("Recover KRW", systemImage: "arrow.uturn.backward.circle")
                }
                
                if !stashResult.isEmpty {
                    Text(stashResult).font(.caption).foregroundStyle(.secondary)
                }
                if !recoverResult.isEmpty {
                    Text(recoverResult).font(.caption).foregroundStyle(.secondary)
                }
            } header: {
                Label("KRW Persistence (app restart)", systemImage: "arrow.clockwise")
            } footer: {
                Text("Stash saves KRW ports to launchd bootstrap. Survives app kill but NOT reboot.")
            }
            
            // LaunchDaemon (survive reboot)
            Section {
                TextField("Label", text: $daemonLabel)
                    .font(.system(.caption, design: .monospaced))
                TextField("Program", text: $daemonProgram)
                    .font(.system(.caption, design: .monospaced))
                
                Button(action: {
                    root.installLaunchDaemonAsRoot(label: daemonLabel, program: daemonProgram)
                }) {
                    Label("Install LaunchDaemon (root)", systemImage: "plus.circle.fill")
                        .foregroundStyle(.red)
                }
                .disabled(!mgr.rcready || root.isExecuting)
            } header: {
                Label("LaunchDaemon (reboot)", systemImage: "power")
            } footer: {
                Text("Writes plist to /Library/LaunchDaemons as root. Binary must exist at program path and be in trust cache.")
            }
            
            // Info
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Persistence Levels:")
                        .font(.caption.bold())
                    
                    HStack {
                        Circle().fill(.green).frame(width: 8, height: 8)
                        Text("KRW Stash — survives app restart")
                            .font(.caption)
                    }
                    HStack {
                        Circle().fill(.orange).frame(width: 8, height: 8)
                        Text("LaunchDaemon — survives reboot (needs binary + trust cache)")
                            .font(.caption)
                    }
                    HStack {
                        Circle().fill(.red).frame(width: 8, height: 8)
                        Text("Full persistence — needs signed helper binary")
                            .font(.caption)
                    }
                }
            } header: {
                Label("Info", systemImage: "info.circle")
            }
        }
        .navigationTitle("Persistence")
        .navigationBarTitleDisplayMode(.inline)
    }
}
