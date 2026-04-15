//
//  EditorView.swift
//  lara
//
//  Created by ruter on 27.03.26.
//

// Most of the code is from Duy's SparseBox
// thank you @jurre111

import SwiftUI

struct EditorView: View {
    @ObservedObject private var mgr = laramgr.shared
    @State private var mg: NSMutableDictionary
    @State private var status: String?
    @State private var alert: String?
    @State private var valid: Bool = true
    
    private let path = "/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"
    private let ogmgurl: URL

    init() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        ogmgurl = docs.appendingPathComponent("ogmobilegestalt.plist")
        let sysurl = URL(fileURLWithPath: path)
        do {
            if !FileManager.default.fileExists(atPath: ogmgurl.path) {
                try FileManager.default.copyItem(at: sysurl, to: ogmgurl)
            }
            chmod(ogmgurl.path, 0o644)
            
            _mg = State(initialValue: try NSMutableDictionary(contentsOf: URL(fileURLWithPath: path), error: ()))
        } catch {
            _mg = State(initialValue: [:])
            _status = State(initialValue: "Failed to copy MobileGestalt: \(error)")
        }

    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Toggle(L("Action Button (iOS 17+)", "Tombol Action (iOS 17+)"), isOn: mgkeybinding(["cT44WE1EohiwRzhsZ8xEsw"]))
                    Toggle(L("Allow installing iPadOS apps", "Izinkan instal aplikasi iPadOS"), isOn: mgkeybinding(["9MZ5AdH43csAUajl/dU+IQ"], type: [Int].self, default: [1], enable: [1, 2]))
                    Toggle(L("Always on Display (18.0+)", "Always on Display (18.0+)"), isOn: mgkeybinding(["j8/Omm6s1lsmTDFsXjsBfA", "2OOJf1VhaM7NxfRok3HbWQ"]))
                    // Toggle("Apple Intelligence", isOn: bindingForAppleIntelligence())
                    //    .disabled(requiresVersion(18))
                    Toggle(L("Apple Pencil", "Apple Pencil"), isOn: mgkeybinding(["yhHcB0iH0d1XzPO/CFd3ow"]))
                    Toggle(L("Boot chime", "Suara boot"), isOn: mgkeybinding(["QHxt+hGLaBPbQJbXiUJX3w"]))
                    Toggle(L("Camera button (18.0rc+)", "Tombol kamera (18.0rc+)"), isOn: mgkeybinding(["CwvKxM2cEogD3p+HYgaW0Q", "oOV1jhJbdV3AddkcCg0AEA"]))
                    Toggle(L("Charge limit (iOS 17+)", "Batas pengisian daya (iOS 17+)"), isOn: mgkeybinding(["37NVydb//GP/GrhuTN+exg"]))
                    Toggle(L("Crash Detection (might not work)", "Deteksi tabrakan (mungkin tidak berfungsi)"), isOn: mgkeybinding(["HCzWusHQwZDea6nNhaKndw"]))
                    Toggle(L("Dynamic Island (17.4+, might not work)", "Dynamic Island (17.4+, mungkin tidak berfungsi)"), isOn: mgkeybinding(["YlEtTtHlNesRBMal1CqRaA"]))
                    // Toggle("Disable region restrictions", isOn: bindingForRegionRestriction())
                    Toggle(L("Internal Storage info", "Info Storage Internal"), isOn: mgkeybinding(["LBJfwOEzExRxzlAnSuI7eg"]))
                    // Toggle("Internal stuff", isOn: bindingForInternalStuff())
                    Toggle(L("Security Research Device", "Perangkat Riset Keamanan"), isOn: mgkeybinding(["XYlJKKkj2hztRP1NWWnhlw"]))
                    Toggle(L("Metal HUD for all apps", "Metal HUD untuk semua aplikasi"), isOn: mgkeybinding(["EqrsVvjcYDdxHBiQmGhAWw"]))
                    Toggle(L("Stage Manager (iPad Only?)", "Stage Manager (khusus iPad?)"), isOn: mgkeybinding(["qeaj75wk3HF4DwQ8qbIi7g"]))
                } header: {
                    Text("MobileGestalt")
                } footer: {
                    Text(L("Note: some tweaks may not work or cause instability.\nWARNING: Never enable features your device doesn't support.", "Catatan: beberapa tweak mungkin tidak berfungsi atau menyebabkan tidak stabil.\nPERINGATAN: Jangan aktifkan fitur yang tidak didukung perangkatmu."))
                }
                Section {
                    HStack {
                        Text(L("Status", "Status"))
                        
                        Spacer()
                        
                        if valid {
                            Text(L("valid!", "valid!"))
                                .monospaced(true)
                                .foregroundColor(.green)
                        } else {
                            Text(L("invalid.", "tidak valid."))
                                .monospaced(true)
                                .foregroundColor(.red)
                        }
                    }
                    
                    Button() {
                        apply()
                    } label: {
                        Text(L("Apply Modified MobileGestalt", "Terapkan MobileGestalt yang Dimodifikasi"))
                    }
                    .disabled(!valid)
                } header: {
                    Text(L("Apply", "Terapkan"))
                } footer: {
                    Text(L("Use at your own risk.", "Gunakan dengan risiko sendiri."))
                }
                
                HStack(alignment: .top) {
                    AsyncImage(url: URL(string: "https://github.com/jurre111.png")) { image in
                        image
                            .resizable()
                            .scaledToFill()
                    } placeholder: {
                        ProgressView()
                    }
                    .frame(width: 40, height: 40)
                    .clipShape(Circle())
                    
                    VStack(alignment: .leading) {
                        Text("Jurre")
                            .font(.headline)
                        
                            Text(L("The entire EditorView.", "Seluruh EditorView."))
                            .font(.subheadline)
                            .foregroundColor(Color.secondary)
                    }
                    
                    Spacer()
                }
                .onTapGesture {
                    if let url = URL(string: "https://github.com/jurre111"),
                       UIApplication.shared.canOpenURL(url) {
                        UIApplication.shared.open(url)
                    }
                }
            }
            .navigationTitle("MobileGestalt")
            .alert(L("Status", "Status"), isPresented: .constant(status != nil)) {
                Button("OK") { status = nil }
            } message: {
                Text(status ?? "")
            }
            .alert(L("Done", "Selesai"), isPresented: .constant(alert != nil)) {
                Button(L("Cancel", "Batal")) { alert = nil }
                Button(L("Respring", "Respring")) { mgr.respring() }
            } message: {
                Text(alert ?? "uhh...")
            }
            .onAppear(perform: load)
        }
    }
    
    private func validate(_ dict: NSMutableDictionary) -> Bool {
        guard let cacheExtra = dict["CacheExtra"] as? NSMutableDictionary else { return false }
        return !cacheExtra.allKeys.isEmpty
    }

    private func load() {
        do {
            mg = try NSMutableDictionary(contentsOf: URL(fileURLWithPath: path), error: ())
        } catch {
            status = L("Failed to load mobilegestalt", "Gagal memuat mobilegestalt")
        }
    }

    private func apply() {
        let fm = FileManager.default
        do {
            try mg.write(to: URL(fileURLWithPath: path))
            mgr.logmsg("wrote custom mbgestalt to \(path)")
            alert = L("Applied modified mobilegestalt, respring to see changes.", "Mobilegestalt termodifikasi berhasil diterapkan, respring untuk melihat perubahan.")
            return
        } catch {
            status = L("failed to write plist:", "gagal menulis plist:") + " \(error.localizedDescription)"
            return
        }
    }
    
    private func mgkeybinding<T: Equatable>(_ keys: [String], type: T.Type = Int.self, default: T? = 0, enable: T? = 1) -> Binding<Bool> {
        guard let cachextra = mg["CacheExtra"] as? NSMutableDictionary else {
            return State(initialValue: false).projectedValue
        }
        
        return Binding(
            get: {
                if let value = cachextra[keys.first!] as? T?, let enable {
                    return value == enable
                }
                return false
            },
            set: { enabled in
                for key in keys {
                    if enabled {
                        cachextra[key] = enable
                    } else {
                        cachextra.removeObject(forKey: key)
                    }
                }
                
                valid = validate(mg)
            }
        )
    }
}
