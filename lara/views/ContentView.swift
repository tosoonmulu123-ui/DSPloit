//
//  ContentView.swift
//  lara
//
//  Created by ruter on 23.03.26.
//

import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @AppStorage("showfmintabs") private var showfmintabs: Bool = true
    @ObservedObject private var mgr = laramgr.shared
    @State private var hasoffsets = haskernproc()
    @State private var showsettings = false
    @State private var selectedmethod: method = .hybrid
    
    var body: some View {
        NavigationStack {
            List {
                if !hasoffsets {
                    Section("Setup") {
                        Text(L("Kernelcache offsets are missing. Download them in Settings.", "Offset Kernelcache belum ada. Unduh di Pengaturan."))
                            .foregroundColor(.secondary)
                        Button(L("Open Settings", "Buka Pengaturan")) {
                            showsettings = true
                        }
                    }
                } else {
                    Section {
                        Button {
                            offsets_init()
                            mgr.run()
                        } label: {
                            if mgr.dsrunning {
                                HStack {
                                    ProgressView(value: mgr.dsprogress)
                                        .progressViewStyle(.circular)
                                        .frame(width: 18, height: 18)
                                    Text(L("Running...", "Menjalankan..."))
                                    Spacer()
                                    Text("\(Int(mgr.dsprogress * 100))%")
                                }
                            } else {
                                if mgr.dsready {
                                    HStack {
                                        Text(L("Ran Exploit", "Exploit Berhasil"))
                                        Spacer()
                                        Image(systemName: "checkmark.circle")
                                            .foregroundColor(.green)
                                    }
                                } else if mgr.dsattempted && mgr.dsfailed {
                                    HStack {
                                        Text(L("Exploit Failed", "Exploit Gagal"))
                                        Spacer()
                                        Image(systemName: "xmark.circle")
                                            .foregroundColor(.red)
                                    }
                                } else {
                                    Text(L("Run Exploit", "Jalankan Exploit"))
                                }
                            }
                        }
                        .disabled(mgr.dsrunning)
                        .disabled(mgr.dsready)
                        
                        HStack {
                            Text("kernproc:")
                            Spacer()
                            Text(String(format: "0x%llx", getrootvnode()))
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        
                        HStack {
                            Text("rootvnode:")
                            Spacer()
                            Text(String(format: "0x%llx", getkernproc()))
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        
                        if mgr.dsready {
                            HStack {
                                Text("kernel_base:")
                                Spacer()
                                Text(String(format: "0x%llx", mgr.kernbase))
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                            
                            HStack {
                                Text("kernel_slide:")
                                Spacer()
                                Text(String(format: "0x%llx", mgr.kernslide))
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                        }
                    } header: {
                        Text(L("Kernel Read Write", "Kernel Baca Tulis"))
                    } footer: {
                        if g_isunsupported {
                            Text(L("Your device/installation method may not be supported.", "Perangkat/metode instalasi kamu mungkin belum didukung."))
                        }
                    }

                    Section {
                        if selectedmethod == .vfs {
                            Button {
                                mgr.vfsinit()
                            } label: {
                                if mgr.vfsrunning {
                                    HStack {
                                        ProgressView(value: mgr.vfsprogress)
                                            .progressViewStyle(.circular)
                                            .frame(width: 18, height: 18)
                                        Text(L("Initialising VFS...", "Menginisialisasi VFS..."))
                                        Spacer()
                                        Text("\(Int(mgr.vfsprogress * 100))%")
                                    }
                                } else if !mgr.vfsready {
                                    if mgr.vfsattempted && mgr.vfsfailed {
                                        HStack {
                                            Text(L("VFS Init Failed", "Init VFS Gagal"))
                                            Spacer()
                                            Image(systemName: "xmark.circle")
                                                .foregroundColor(.red)
                                        }
                                    } else {
                                        Text(L("Initialise VFS", "Inisialisasi VFS"))
                                    }
                                } else {
                                    HStack {
                                        Text(L("Initialised VFS", "VFS Siap"))
                                        Spacer()
                                        Image(systemName: "checkmark.circle")
                                            .foregroundColor(.green)
                                    }
                                }
                            }
                            .disabled(!mgr.dsready || mgr.vfsready || mgr.vfsrunning)
                            
                            if mgr.vfsready {
                                NavigationLink("Tweaks") {
                                    List {
                                        NavigationLink(L("Font Overwrite", "Overwrite Font")) {
                                            FontPicker(mgr: mgr)
                                        }
                                        
                                        NavigationLink(L("Card Overwrite", "Overwrite Kartu")) {
                                            CardView()
                                        }
                                        
                                        NavigationLink(L("Custom Overwrite", "Overwrite Kustom")) {
                                            CustomView(mgr: mgr)
                                        }
                                        
                                        NavigationLink(L("DirtyZero (Broken)", "DirtyZero (Rusak)")) {
                                            ZeroView(mgr: mgr)
                                        }
                                        
                                        if !showfmintabs {
                                            NavigationLink(L("File Manager", "Manajer File")) {
                                                SantanderView(startPath: "/")
                                            }
                                        }
                                    }
                                    .navigationTitle(Text("Tweaks"))
                                }
                            }
                        } else if selectedmethod == .sbx {
                            Button {
                                mgr.sbxescape()
                                // mgr.sbxelevate()
                            } label: {
                                if mgr.sbxrunning {
                                    HStack {
                                        ProgressView()
                                            .progressViewStyle(.circular)
                                            .frame(width: 18, height: 18)
                                        Text(L("Escaping Sandbox...", "Melewati Sandbox..."))
                                    }
                                } else if !mgr.sbxready {
                                    if mgr.sbxattempted && mgr.sbxfailed {
                                        HStack {
                                            Text(L("Sandbox Escape Failed", "Sandbox Escape Gagal"))
                                            Spacer()
                                            Image(systemName: "xmark.circle")
                                                .foregroundColor(.red)
                                        }
                                    } else {
                                        Text(L("Escape Sandbox", "Lepas Sandbox"))
                                    }
                                } else {
                                    HStack {
                                        Text(L("Sandbox Escaped", "Sandbox Terlewati"))
                                        Spacer()
                                        Image(systemName: "checkmark.circle")
                                            .foregroundColor(.green)
                                    }
                                }
                            }
                            .disabled(!mgr.dsready || mgr.sbxready || mgr.sbxrunning)
                            
                            if mgr.sbxready {
                                NavigationLink("Tweaks") {
                                    List {
                                        if !showfmintabs {
                                            NavigationLink("File Manager") {
                                                SantanderView(startPath: "/")
                                            }
                                        }
                                        
                                        NavigationLink("Card Overwrite") {
                                            CardView()
                                        }
                                        
                                        NavigationLink("3 App Bypass") {
                                            AppsView(mgr: mgr)
                                        }
                                        
                                        NavigationLink("Unblacklist (Broken?)") {
                                            WhitelistView()
                                        }
                                        
                                        if 1 == 2 {
                                            NavigationLink("MobileGestalt") {
                                                EditorView()
                                            }
                                            
                                            NavigationLink("Passcode Theme") {
                                                PasscodeView(mgr: mgr)
                                            }
                                        }
                                    }
                                    .navigationTitle(Text("Tweaks"))
                                }
                            }
                        } else {
                            if !mgr.sbxattempted {
                                Button {
                                    mgr.sbxescape()
                                } label: {
                                    if mgr.sbxrunning {
                                        HStack {
                                            ProgressView()
                                                .progressViewStyle(.circular)
                                                .frame(width: 18, height: 18)
                                            Text("Escaping Sandbox...")
                                        }
                                    } else if !mgr.sbxready {
                                        if mgr.sbxattempted && mgr.sbxfailed {
                                            HStack {
                                                Text("Sandbox Escape Failed")
                                                Spacer()
                                                Image(systemName: "xmark.circle")
                                                    .foregroundColor(.red)
                                            }
                                        } else {
                                            Text("Escape Sandbox")
                                        }
                                    } else {
                                        HStack {
                                            Text("Sandbox Escaped")
                                            Spacer()
                                            Image(systemName: "checkmark.circle")
                                                .foregroundColor(.green)
                                        }
                                    }
                                }
                                .disabled(!mgr.dsready || mgr.sbxready || mgr.sbxrunning)
                            } else {
                                Button {
                                    mgr.vfsinit()
                                } label: {
                                    if mgr.vfsrunning {
                                        HStack {
                                            ProgressView(value: mgr.vfsprogress)
                                                .progressViewStyle(.circular)
                                                .frame(width: 18, height: 18)
                                            Text("Initialising VFS...")
                                            Spacer()
                                            Text("\(Int(mgr.vfsprogress * 100))%")
                                        }
                                    } else if !mgr.vfsready {
                                        if mgr.vfsattempted && mgr.vfsfailed {
                                            HStack {
                                                Text("VFS Init Failed")
                                                Spacer()
                                                Image(systemName: "xmark.circle")
                                                    .foregroundColor(.red)
                                            }
                                        } else {
                                            Text("Initialise VFS")
                                        }
                                    } else {
                                        HStack {
                                            Text("Initialised Hybrid")
                                            Spacer()
                                            Image(systemName: "checkmark.circle")
                                                .foregroundColor(.green)
                                        }
                                    }
                                }
                                .disabled(!mgr.dsready || mgr.vfsready || mgr.vfsrunning)
                            }
                            
                            if mgr.vfsready && mgr.sbxready {
                                NavigationLink("Tweaks") {
                                    List {
                                        if !showfmintabs {
                                            NavigationLink("File Manager") {
                                                SantanderView(startPath: "/")
                                            }
                                        }
                                        
                                        NavigationLink("Font Overwrite") {
                                            FontPicker(mgr: mgr)
                                        }
                                        
                                        NavigationLink("Card Overwrite") {
                                            CardView()
                                        }
                                        
                                        NavigationLink("Custom Overwrite") {
                                            CustomView(mgr: mgr)
                                        }
                                        
                                        NavigationLink("MobileGestalt") {
                                            EditorView()
                                        }
                                        
                                        NavigationLink("Whitelist") {
                                            WhitelistView()
                                        }
                                        
                                        NavigationLink("DirtyZero") {
                                            ZeroView(mgr: mgr)
                                        }
                                        
                                        NavigationLink("3 App Bypass") {
                                            AppsView(mgr: mgr)
                                        }
                                        
                                        if 1 == 2 {
                                            NavigationLink("Passcode Theme") {
                                                PasscodeView(mgr: mgr)
                                            }
                                            
                                            NavigationLink("3 App Bypass") {
                                                AppsView(mgr: mgr)
                                            }
                                        }
                                    }
                                    .navigationTitle(Text("Tweaks"))
                                }
                            }
                        }
                    } header: {
                        Text(selectedmethod == .vfs ? "Virtual File System" : (selectedmethod == .sbx ? "Sandbox Escape" : "Hybrid (SBX + VFS)"))
                    } footer: {
                        if selectedmethod == .sbx {
                            Text("Font Overwrite is only available in VFS or Hybrid mode. (Settings -> Method -> VFS/Hybrid)")
                        }
                    }
                    
                    Section {
                        Button(L("Init RemoteCall", "Inisialisasi RemoteCall")) {
                            mgr.logmsg("T")
                            mgr.rcinit(process: "springboard", migbypass: false) { success in
                                if success {
                                    mgr.logmsg("rc init succeeded!")
                                    let pid = mgr.rccall(name: "getpid")
                                    mgr.logmsg("remote getpid() returned: \(pid)")
                                } else {
                                    mgr.logmsg("rc init failed")
                                }
                            }
                        }
                        .disabled(!mgr.dsready || mgr.remotecallrunning)
                        
                        if mgr.remotecallrunning {
                            Button(L("Destroy RemoteCall", "Hentikan RemoteCall")) {
                                mgr.rcdestroy()
                            }
                        }
                    } header: {
                        Text("RemoteCall")
                    }
                    
                    Section {
                        if mgr.dsready {
                            NavigationLink(L("Tools", "Alat")) {
                                ToolsView()
                            }
                        }
            
                        Button(L("Respring", "Respring")) {
                            mgr.respring()
                        }
                        
                        Button(L("Panic!", "Panic!")) {
                            mgr.panic()
                        }
                        .disabled(!mgr.dsready)
                    } header: {
                        Text(L("Other", "Lainnya"))
                    }
                }
                
            }
            .navigationTitle("lara")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showsettings = true
                    } label: {
                        Image(systemName: "gear")
                    }
                }
            }
        }
        .sheet(isPresented: $showsettings) {
            SettingsView(mgr: mgr, hasoffsets: $hasoffsets)
        }
        .onAppear {
            refreshselectedmethod()
        }
        .onReceive(NotificationCenter.default.publisher(for: UserDefaults.didChangeNotification)) { _ in
            refreshselectedmethod()
        }
    }
    
    private func refreshselectedmethod() {
        if let raw = UserDefaults.standard.string(forKey: "selectedmethod"),
           let m = method(rawValue: raw) {
            selectedmethod = m
        }
    }
}
