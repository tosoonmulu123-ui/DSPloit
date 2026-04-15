//
//  SettingsView.swift
//  lara
//
//  Created by ruter on 29.03.26.
//

import SwiftUI
import UIKit

struct SettingsView: View {
    @ObservedObject var mgr: laramgr
    @Binding var hasoffsets: Bool
    @State private var showresetalert: Bool = false
    @State private var downloadingkernelcache = false
    @AppStorage("loggernobullshit") private var loggernobullshit: Bool = true
    @AppStorage("keepalive") private var iskeepalive: Bool = true
    @AppStorage("showfmintabs") private var showfmintabs: Bool = true
    @AppStorage("selectedmethod") private var selectedmethod: method = .hybrid
    @AppStorage("app_language") private var appLanguage: String = AppLanguage.english.rawValue
    
    var appname: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
        ?? Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String
        ?? "Unknown App"
    }
    var appversion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
    }
    var appicon: UIImage {
        if let icons = Bundle.main.infoDictionary?["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String],
           let last = files.last,
           let image = UIImage(named: last) {
            return image
        }
        
        return UIImage(named: "unknown") ?? UIImage()
    }
    
    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(spacing: 12) {
                        Image(uiImage: appicon)
                            .resizable()
                            .frame(width: 40, height: 40)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                        
                        VStack(alignment: .leading) {
                            Text(appname)
                                .font(.headline)
                            
                            Text("\(L("Version", "Versi")) \(appversion)")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                        }
                    }
                } header: {
                    Text("Lara")
                }
                
                Section {
                    Picker("", selection: $appLanguage) {
                        ForEach(AppLanguage.allCases) { lang in
                            Text(lang.label).tag(lang.rawValue)
                        }
                    }
                    .pickerStyle(.segmented)
                } header: {
                    Text(L("Language", "Bahasa"))
                } footer: {
                    Text(L("UI and error messages will follow your selected language.", "UI dan pesan error akan mengikuti bahasa yang kamu pilih."))
                }
                
                
                Section {
                    Picker("", selection: $selectedmethod) {
                        ForEach(method.allCases, id: \.self) { method in
                            Text(method.rawValue).tag(method)
                        }
                    }
                    .pickerStyle(.segmented)
                } header: {
                    Text(L("Method", "Metode"))
                } footer: {
                    if selectedmethod == .vfs {
                        Text(L("VFS only.", "Hanya VFS."))
                    } else if selectedmethod == .sbx {
                        Text(L("SBX only.", "Hanya SBX."))
                    } else {
                        Text(L("Hybrid: SBX for read, VFS for write.\nBest method ever. (Thanks Huy)", "Hybrid: SBX untuk baca, VFS untuk tulis.\nMetode terbaik. (Thanks Huy)"))
                    }
                }
                
                Section {
                    Toggle(L("Disable log dividers", "Nonaktifkan pemisah log"), isOn: $loggernobullshit)
                        .onChange(of: loggernobullshit) { _ in
                            globallogger.clear()
                        }
                    
                    Toggle(L("Keep Alive", "Keep Alive"), isOn: $iskeepalive)
                        .onChange(of: iskeepalive) { _ in
                            if iskeepalive {
                                if !kaenabled { toggleka() }
                            } else {
                                if kaenabled { toggleka() }
                            }
                        }
                    
                    Toggle(L("Show File Manager in Tabs", "Tampilkan File Manager di Tab"), isOn: $showfmintabs)

                } header: {
                    Text(L("Lara Settings", "Pengaturan Lara"))
                } footer: {
                    Text(L("Keep Alive keeps the app running in the background when it is minimized (not closed from app switcher).", "Keep Alive menjaga aplikasi tetap berjalan di background saat diminimalkan (bukan ditutup dari app switcher)."))
                }

                Section {
                    if !hasoffsets {
                        Button(L("Download Kernelcache", "Unduh Kernelcache")) {
                            guard !downloadingkernelcache else { return }
                            downloadingkernelcache = true
                            DispatchQueue.global(qos: .userInitiated).async {
                                let ok = dlkerncache()
                                DispatchQueue.main.async {
                                    hasoffsets = ok
                                    downloadingkernelcache = false
                                }
                            }
                        }
                        .disabled(downloadingkernelcache)
                        
                        Button(L("Fetch Kernelcache", "Ambil Kernelcache")) {
                            mgr.run()
                        }
                    }
                    
                    Button {
                        showresetalert = true
                    } label: {
                        Text(L("Delete Kernelcache Data", "Hapus Data Kernelcache"))
                            .foregroundColor(.red)
                    }
                } header: {
                    Text("Kernelcache")
                } footer: {
                    Text(L("Deleting and redownloading Kernelcache can fix a lot of issues. Try this before making a github Issue.", "Menghapus lalu mengunduh ulang Kernelcache bisa memperbaiki banyak masalah. Coba ini sebelum membuat issue di GitHub."))
                }
                
                Section {
                    HStack(alignment: .top) {
                        AsyncImage(url: URL(string: "https://github.com/rooootdev.png")) { image in
                            image
                                .resizable()
                                .scaledToFill()
                        } placeholder: {
                            ProgressView()
                        }
                        .frame(width: 40, height: 40)
                        .clipShape(Circle())
                        
                        VStack(alignment: .leading) {
                            Text("roooot")
                                .font(.headline)
                            
                            Text(L("Main Developer", "Developer Utama"))
                                .font(.subheadline)
                                .foregroundColor(Color.secondary)
                        }
                        
                        Spacer()
                    }
                    .onTapGesture {
                        if let url = URL(string: "https://github.com/rooootdev"),
                           UIApplication.shared.canOpenURL(url) {
                            UIApplication.shared.open(url)
                        }
                    }
                    
                    HStack(alignment: .top) {
                        AsyncImage(url: URL(string: "https://github.com/wh1te4ever.png")) { image in
                            image
                                .resizable()
                                .scaledToFill()
                        } placeholder: {
                            ProgressView()
                        }
                        .frame(width: 40, height: 40)
                        .clipShape(Circle())
                        
                        VStack(alignment: .leading) {
                            Text("wh1te4ever")
                                .font(.headline)
                            
                            Text(L("Made darksword-kexploit-fun.", "Membuat darksword-kexploit-fun."))
                                .font(.subheadline)
                                .foregroundColor(Color.secondary)
                        }
                        
                        Spacer()
                    }
                    .onTapGesture {
                        if let url = URL(string: "https://github.com/wh1te4ever"),
                           UIApplication.shared.canOpenURL(url) {
                            UIApplication.shared.open(url)
                        }
                    }
                    
                    HStack(alignment: .top) {
                        AsyncImage(url: URL(string: "https://github.com/AppInstalleriOSGH.png")) { image in
                            image
                                .resizable()
                                .scaledToFill()
                        } placeholder: {
                            ProgressView()
                        }
                        .frame(width: 40, height: 40)
                        .clipShape(Circle())
                        
                        VStack(alignment: .leading) {
                            Text("AppInstaller iOS")
                                .font(.headline)
                            
                            Text(L("Helped me with offsets and lots of other stuff. This project wouldnt have been possible without him!", "Membantu offset dan banyak hal lainnya. Proyek ini tidak akan bisa tanpa dia!"))
                                .font(.subheadline)
                                .foregroundColor(Color.secondary)
                        }
                        
                        Spacer()
                    }
                    .onTapGesture {
                        if let url = URL(string: "https://github.com/AppInstalleriOSGH"),
                           UIApplication.shared.canOpenURL(url) {
                            UIApplication.shared.open(url)
                        }
                    }
                    
                    HStack(alignment: .top) {
                        AsyncImage(url: URL(string: "https://github.com/jailbreakdotparty.png")) { image in
                            image
                                .resizable()
                                .scaledToFill()
                        } placeholder: {
                            ProgressView()
                        }
                        .frame(width: 40, height: 40)
                        .clipShape(Circle())
                        
                        VStack(alignment: .leading) {
                            Text("jailbreak.party")
                                .font(.headline)
                            
                            Text(L("All of the DirtyZero tweaks and emotional support.", "Semua tweak DirtyZero dan dukungan moral."))
                                .font(.subheadline)
                                .foregroundColor(Color.secondary)
                        }
                        
                        Spacer()
                    }
                    .onTapGesture {
                        if let url = URL(string: "https://github.com/jailbreakdotparty"),
                           UIApplication.shared.canOpenURL(url) {
                            UIApplication.shared.open(url)
                        }
                    }
                    
                    HStack(alignment: .top) {
                        AsyncImage(url: URL(string: "https://github.com/neonmodder123.png")) { image in
                            image
                                .resizable()
                                .scaledToFill()
                        } placeholder: {
                            ProgressView()
                        }
                        .frame(width: 40, height: 40)
                        .clipShape(Circle())
                        
                        VStack(alignment: .leading) {
                            Text("neon")
                                .font(.headline)
                            
                            Text(L("Made the respring script.", "Membuat script respring."))
                                .font(.subheadline)
                                .foregroundColor(Color.secondary)
                        }
                        
                        Spacer()
                    }
                    .onTapGesture {
                        if let url = URL(string: "https://github.com/neonmodder123"),
                           UIApplication.shared.canOpenURL(url) {
                            UIApplication.shared.open(url)
                        }
                    }
                } header: {
                    Text(L("Credits", "Kredit"))
                }
            }
            .navigationTitle(L("Settings", "Pengaturan"))
        }
        .alert(L("Clear Kernelcache Data?", "Hapus Data Kernelcache?"), isPresented: $showresetalert) {
            Button(L("Cancel", "Batal"), role: .cancel) {}
            Button(L("Delete", "Hapus"), role: .destructive) {
                clearkerncachedata()
                hasoffsets = haskernproc()
            }
        } message: {
            Text(L("This will delete the downloaded kernelcache and remove saved offsets.", "Ini akan menghapus kernelcache yang diunduh dan offset yang tersimpan."))
        }
    }
}

enum method: String, CaseIterable {
    case vfs = "VFS"
    case sbx = "SBX"
    case hybrid = "Hybrid"
}
