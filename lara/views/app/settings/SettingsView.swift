//
//  SettingsView.swift
//  DSPloit
//

import SwiftUI
import UIKit
import UniformTypeIdentifiers

enum method: String, CaseIterable {
    case vfs = "VFS"
    case sbx = "SBX"
    case hybrid = "Hybrid"
}

enum fmAppsDisplayMode: String, CaseIterable {
    case UUID = "UUID"
    case bundleID = "Bundle ID"
    case appName = "App Name"
}

enum logsdisplaymode: String, CaseIterable {
    case toolbar = "Toolbar Button"
}

struct SettingsView: View {
    @EnvironmentObject var mgr: dspmgr
    @Environment(\.dismiss) private var dismiss
    
    @AppStorage("selectedMethod") private var selectedMethod: method = .hybrid
    @AppStorage("keepAlive") private var keepAlive: Bool = false
    @AppStorage("stashKRW") private var stashKRW: Bool = false
    @AppStorage("logsdisplaymode") private var selectedlogdisplaymode: logsdisplaymode = .toolbar
    @AppStorage("loggernobullshit") private var plainLogsMode: Bool = false
    @AppStorage("rcDockUnlimited") private var rcDockUnlimited: Bool = false
    
    @State private var dlingkcache = false
    @State private var showkcacheimport = false
    @State private var importingkcache = false
    @State private var showkcachetips = false
    
    var body: some View {
        NavigationStack {
            List {
                // About
                Section {
                    AppInfoCell()
                    NavigationLink { GuideView() } label: {
                        row("book.fill", "Guide")
                    }
                    NavigationLink(destination: CreditsView()) {
                        row("heart.fill", "Credits")
                    }
                } header: { sectionHeader("About") }
                
                // Exploit
                Section {
                    Picker("Method", selection: $selectedMethod) {
                        ForEach(method.allCases, id: \.self) { m in
                            Text(m.rawValue).tag(m)
                        }
                    }
                    .pickerStyle(.segmented)
                    NavigationLink(destination: OffsetManagementView()) {
                        row("slider.horizontal.3", "Offsets")
                    }
                } header: { sectionHeader("Exploit") }
                
                // Kernelcache
                Section {
                    if mgr.hasOffsets {
                        HStack {
                            Text("Kernelcache + XPF")
                                .font(.system(size: 13))
                            Spacer()
                            Text("●")
                                .font(.system(size: 8))
                                .foregroundStyle(.green)
                        }
                    }
                    
                    Button {
                        guard !dlingkcache else { return }
                        dlingkcache = true
                        DispatchQueue.global(qos: .userInitiated).async {
                            let ok = ensureKernelcacheResolved()
                            DispatchQueue.main.async {
                                mgr.hasOffsets = ok
                                dlingkcache = false
                            }
                        }
                    } label: {
                        HStack {
                            Text(mgr.hasOffsets ? "Re-verify" : "Fetch Kernelcache")
                                .font(.system(size: 13))
                            Spacer()
                            if dlingkcache { ProgressView().scaleEffect(0.7) }
                        }
                    }
                    .disabled(dlingkcache || !mgr.dsready)
                    
                    Button("Import from file") { showkcacheimport = true }
                        .font(.system(size: 13))
                        .disabled(dlingkcache || importingkcache)
                    
                    if mgr.hasOffsets {
                        Button("Remove Kernelcache") { clearKcacheData() }
                            .font(.system(size: 13))
                            .foregroundStyle(.red)
                    }
                } header: { sectionHeader("Kernelcache") }
                
                // App
                Section {
                    Toggle("Keep Alive", isOn: $keepAlive)
                        .font(.system(size: 13))
                        .onChange(of: keepAlive) { _ in
                            if keepAlive { if !kaenabled { toggleka() } }
                            else { if kaenabled { toggleka() } }
                        }
                    Toggle("Plain logs (no color)", isOn: $plainLogsMode)
                        .font(.system(size: 13))
                } header: { sectionHeader("App") }
                
                #if !DISABLE_REMOTECALL
                // RemoteCall
                Section {
                    Toggle("Stash KRW primitives", isOn: $stashKRW)
                        .font(.system(size: 13))
                    Toggle("Allow >10 dock icons", isOn: $rcDockUnlimited)
                        .font(.system(size: 13))
                } header: { sectionHeader("RemoteCall") }
                #endif
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                        .font(.system(size: 14, weight: .medium))
                }
            }
            .fileImporter(isPresented: $showkcacheimport, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
                handleKcacheImport(result)
            }
        }
    }
    
    // MARK: - Components
    
    private func sectionHeader(_ title: String) -> some View {
        Text(title.uppercased())
            .font(.system(size: 11, weight: .semibold, design: .monospaced))
            .foregroundStyle(.secondary)
    }
    
    private func row(_ icon: String, _ title: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 14))
                .foregroundStyle(.secondary)
                .frame(width: 20)
            Text(title)
                .font(.system(size: 14))
        }
    }
    
    // MARK: - Logic
    
    private func handleKcacheImport(_ result: Result<[URL], Error>) {
        guard case .success(let urls) = result, let url = urls.first else { return }
        importingkcache = true
        DispatchQueue.global(qos: .userInitiated).async {
            var ok = false
            let shouldStopAccess = url.startAccessingSecurityScopedResource()
            defer { if shouldStopAccess { url.stopAccessingSecurityScopedResource() } }
            let fm = FileManager.default
            if let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first {
                let dest = docs.appendingPathComponent("kernelcache")
                do {
                    if fm.fileExists(atPath: dest.path) { try fm.removeItem(at: dest) }
                    try fm.copyItem(at: url, to: dest)
                    ok = dlkcache()
                } catch { print("import failed: \(error)") }
            }
            DispatchQueue.main.async {
                mgr.hasOffsets = ok
                importingkcache = false
            }
        }
    }
    
    private func clearKcacheData() {
        let fm = FileManager.default
        ds_kcache_symbol_cache_clear()
        ds_kcache_trust_slots_clear()
        UserDefaults.standard.removeObject(forKey: "dsploit.kernelcache_path")
        UserDefaults.standard.removeObject(forKey: "dsploit.kernelcache_size")
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        try? fm.removeItem(at: docs.appendingPathComponent("kernelcache"))
        mgr.hasOffsets = false
    }
}
