//
//  JitView.swift
//  lara
//
//  Created by ruter on 06.04.26.
//

import SwiftUI

struct proc: Identifiable {
    let id = UUID()
    let name: String
    let bundle: String
    let path: String
    let icon: UIImage?
}

struct JitView: View {
    @State private var query = ""
    @State private var processes: [proc] = []
    @State private var issetup = false
    @State private var showsetup = false
    @State private var showresetup = false
    
    var body: some View {
        NavigationStack {
            List {
                if !issetup {
                    Section(L("Setup", "Setup")) {
                        Text(L("Initial setup is required before listing applications.", "Setup awal wajib dilakukan sebelum menampilkan daftar aplikasi."))
                        
                        Button(L("Run Setup", "Jalankan Setup")) {
                            showsetup = true
                        }
                    }
                } else {
                    HStack {
                        TextField(L("Search", "Cari"), text: $query)
                        
                        Button {
                            loadprocs()
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                    }
                    
                    Section {
                        ForEach(processes) { proc in
                            HStack {
                                if let icon = proc.icon {
                                    Image(uiImage: icon)
                                        .resizable()
                                        .frame(width: 32, height: 32)
                                        .cornerRadius(6)
                                } else {
                                    Image("unknown")
                                        .resizable()
                                        .frame(width: 32, height: 32)
                                        .cornerRadius(6)
                                }

                                VStack(alignment: .leading) {
                                    Text(proc.name)
                                        .font(.headline)
                                    Text(proc.bundle)
                                        .font(.caption)
                                        .foregroundColor(.gray)
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("LaraJIT")
        }
        .onAppear {
            if issetup {
                loadprocs()
            }
        }
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button {
                    showresetup = true
                } label: {
                    Image(systemName: "arrow.triangle.2.circlepath")
                }
            }
        }
        .alert(L("Reset setup?", "Reset setup?"), isPresented: $showresetup) {
            Button(L("Cancel", "Batal"), role: .cancel) { }
            Button(L("Reset", "Reset"), role: .destructive) {
                issetup = false
                processes.removeAll()
            }
        } message: {
            Text(L("This will reset the setup and require running it again.", "Ini akan mereset setup dan kamu perlu menjalankannya lagi."))
        }
        .sheet(isPresented: $showsetup) {
            NavigationView {
                List {
                    Section(header: Text("Step 1")) {
                        Text("Download the latest .zip file from the link below then extract the contents to a place you like. We will need this later.")
                        Button("Go to Link") {
                            UIApplication.shared.open(URL(string: "https://github.com/haxi0/WDBDDISSH/releases")!)
                        }
                    }
                    
                    Section(header: Text("Step 2")) {
                        Text("Download the file from the link below. It should appear in Settings. Install it, disconnect your phone from your PC if you haven't yet and then reboot your device.")
                        Button("Install Profile") {
                            UIApplication.shared.open(URL(string: "https://roooot.dev/lara/jit/cert.pem")!)
                        }
                    }
                    
                    Section(header: Text("Step 3")) {
                        Text("After rebooting, press the button below to replace iPhoneDebug.pem with cert.pem. Make sure you are NOT connected to a PC!")
                        Button("Replace File") {
                            replacedebug()
                        }
                    }
                    
                    Section(header: Text("Step 4")) {
                        Text("After replacing the file, connect your device to your PC. Run the commands below to mount the image from the first step.")
                        VStack {
                            Text("ideviceimagemounter DeveloperDiskImageModified_YourVersionHere.dmg DeveloperDiskImageModified_YourVersionHere.dmg.signature")
                                .font(.custom("Menlo", size: 15))
                                .foregroundColor(.white)
                                .padding()
                        }
                        .textSelection(.enabled)
                        .background(
                            Color.black
                                .cornerRadius(5)
                        )
                    }
                    
                    Section(header: Text("Step 5")) {
                        Text("Congratulations! If you haven't encountered any errors, you have finished the setup.")
                        Button("Go to Discord Server") {
                            UIApplication.shared.open(URL(string: "https://dsc.gg/haxi0sm")!)
                        }
                    }
                }
                .navigationTitle(L("Setup", "Setup"))
                .environment(\.defaultMinListRowHeight, 50)
                .toolbar {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button(L("Done", "Selesai")) {
                            issetup = true
                            showsetup = false
                            loadprocs()
                        }
                    }
                }
            }
        }
    }
    
    func replacedebug() {
        guard let certURL = Bundle.main.url(forResource: "cert", withExtension: "pem") else {
            DispatchQueue.main.async {
                globallogger.log("cert.pem not found")
            }
            return
        }
        
        do {
            let fileData = try Data(contentsOf: certURL)
            let result = laramgr.shared.lara_writeexpandsafe(
                target: "/System/Library/Lockdown/iPhoneDebug.pem",
                data: fileData
            )
            
            DispatchQueue.main.async {
                if result.ok {
                    globallogger.log("overwrite success (\(result.message))")
                } else {
                    globallogger.log("overwrite failed (\(result.message))")
                }
            }
        } catch {
            DispatchQueue.main.async {
                globallogger.log("failed to read cert.pem")
            }
        }
    }
        
    func loadprocs() {
        DispatchQueue.global(qos: .userInitiated).async {
            var apps: [proc] = []
            let paths = ["/Applications", "/var/containers/Bundle/Application"]
            
            for path in paths {
                guard let items = try? FileManager.default.contentsOfDirectory(atPath: path) else { continue }
                
                for item in items {
                    let itempath = path + "/" + item
                    var isdir: ObjCBool = false
                    if FileManager.default.fileExists(atPath: itempath, isDirectory: &isdir), isdir.boolValue {
                        
                        if path == "/var/containers/Bundle/Application" {
                            guard let uuiditems = try? FileManager.default.contentsOfDirectory(atPath: itempath) else { continue }
                            
                            for uuidItem in uuiditems {
                                let appbundlepath = itempath + "/" + uuidItem
                                if appbundlepath.hasSuffix(".app") {
                                    addapp(atPath: appbundlepath, to: &apps)
                                }
                            }
                        } else {
                            if itempath.hasSuffix(".app") {
                                addapp(atPath: itempath, to: &apps)
                            }
                        }
                    }
                }
            }
            
            if !query.isEmpty {
                apps = apps.filter { $0.name.lowercased().contains(query.lowercased()) }
            }
            
            apps.sort { $0.name.lowercased() < $1.name.lowercased() }
            
            DispatchQueue.main.async {
                processes = apps
            }
        }
    }
        
    func addapp(atPath apppath: String, to apps: inout [proc]) {
        let infopath = apppath + "/Info.plist"
        var name = (apppath as NSString).lastPathComponent
        var bundle = "unknown"
        var icon: UIImage? = nil
        
        if let info = NSDictionary(contentsOfFile: infopath) {
            
            if let displayname = info["CFBundleDisplayName"] as? String {
                name = displayname
            } else if let bundlename = info["CFBundleName"] as? String {
                name = bundlename
            }
            
            if let bid = info["CFBundleIdentifier"] as? String {
                bundle = bid
            }
            
            if let icons = info["CFBundleIcons"] as? [String: Any],
               let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
               let iconfiles = primary["CFBundleIconFiles"] as? [String],
               let iconname = iconfiles.last {
                
                let iconpath = apppath + "/" + iconname
                
                if let image = UIImage(contentsOfFile: iconpath) {
                    icon = image
                } else if let image = UIImage(contentsOfFile: iconpath + "@2x.png") {
                    icon = image
                } else if let image = UIImage(contentsOfFile: iconpath + ".png") {
                    icon = image
                }
            }
        }
        
        let finalicon = icon ?? UIImage(named: "unknown")
        apps.append(proc(name: name, bundle: bundle, path: apppath, icon: finalicon))
    }
}
