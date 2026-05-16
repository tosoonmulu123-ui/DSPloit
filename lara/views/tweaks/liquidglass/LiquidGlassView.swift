//
//  LGView.swift
//  DSPloit
//
//  Created by jurre111 on 24.04.26.
//

// Credits to leminlimez and Duy Tran for most of the code
// thank you lunginspector for the rewrite

import SwiftUI

let gpCurrentPath = "/var/Managed Preferences/mobile/.GlobalPreferences.plist"

struct LiquidGlassView: View {
    @EnvironmentObject private var mgr: dspmgr
    
    @State private var gpCurrentDict: NSMutableDictionary = NSMutableDictionary()
    @State private var trueBool: Bool = true
    
    @State private var dumbassToggleThatMakesTheViewUpdate: Bool = false
    
    var body: some View {
        NavigationStack {
            List {
                Section(header: HeaderLabel(text: "Applying", icon: "checkmark")) {
                    Button("Apply Tweaks", action: { applyLiquidGlass() })
                    Button("Reset Tweaks", action: { restoreLiquidGlass() })
                }
                
                Section(header: HeaderLabel(text: "Preview", icon: "eye")) {
                    LiquidGlassPreview(lgDisabled: gpKeyBinding("com.apple.SwiftUI.DisableSolarium"), lgFallback: gpKeyBinding("SolariumForceFallback"))
                        .listRowInsets(EdgeInsets())
                }
                
                Section(header: HeaderLabel(text: "User Interface", icon: "iphone"), footer: Text("Solarium Fallback - This will give all liquid glass elements a gray background.\n\nDisable Liquid Glass - This will actually disable liquid glass, reverting back to the iOS 18 UI, with some major visual bugs (especially in the Control Center).")) {
                    Toggle("Enable Solarium Fallback", isOn: gpKeyBinding("SolariumForceFallback"))
                    Toggle("Disable Liquid Glass", isOn: gpKeyBinding("com.apple.SwiftUI.DisableSolarium"))
                }
                
                Section(header: HeaderLabel(text: "Liquid Glass", icon: "square.on.square.intersection.dashed")) {
                    Toggle("Disable Specular Motion", isOn: gpKeyBinding("SBDisableSpecularEverywhereUsingLSSAssertion"))
                    Toggle("Disable Outer Refraction", isOn: gpKeyBinding("SolariumDisableOuterRefraction"))
                    Toggle("Disable Solarium HDR", isOn: gpKeyBinding("SolariumAllowHDR", default: true, enable: false))
                }
                
                Section(header: HeaderLabel(text: "Visibility", icon: "loupe")) {
                    Toggle("Ignore Liquid Glass App Build Check", isOn: gpKeyBinding("com.apple.SwiftUI.IgnoreSolariumLinkedOnCheck"))
                    Toggle("Disable Liquid Glass on LS Clock", isOn: gpKeyBinding("SBDisallowGlassTime"))
                    Toggle("Disable Liquid Glass on Dock", isOn: gpKeyBinding("SBDisableGlassDock"))
                }
            }
            .navigationTitle("Liquid Glass")
            .onAppear {
                loadGPData()
            }
        }
    }
    
    // MARK: file loading functions. root you said that making my comments uppercase sounds like i'm vibecoding so this will all be lowercase from now on.
    private func loadGPData() {
        let docsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let gpSavedURL = docsDir.appendingPathComponent("SavedGlobalPrefs.plist")
        let gpCurrentURL = URL(fileURLWithPath: gpCurrentPath)
        
        do {
            if !FileManager.default.fileExists(atPath: gpSavedURL.path) {
                try FileManager.default.copyItem(at: gpCurrentURL, to: gpSavedURL)
            }
            chmod(gpSavedURL.path, 0o644)
            
            gpCurrentDict = try NSMutableDictionary(contentsOf: URL(fileURLWithPath: gpCurrentPath), error: ())
        } catch {
            Alertinator.shared.alert(title: "Failed to load Global Preferences data!", body: "Please restart the app and try again.")
        }
    }
    
    // MARK: applying/reloading functions
    func applyLiquidGlass() {
        do {
            let gpData = try verifyPlist(gpCurrentDict, targetPath: gpCurrentPath)
            let result = mgr.dsploit_overwritefile(target: gpCurrentPath, data: gpData)
            
            if result.ok {
                Alertinator.shared.alert(title: "Successfully applied Liquid Glass Tweaks!", body: "Reboot your device to see any changes")
            } else {
                throw "Overwrite failed: \(result.message)"
            }
        } catch {
            Alertinator.shared.alert(title: "Failed to enable Liquid Glass Tweaks!", body: "\(error)")
        }
    }
    
    func restoreLiquidGlass() {
        do {
            let docsDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            let gpSavedURL = docsDir.appendingPathComponent("SavedGlobalPrefs.plist")
            
            if FileManager.default.fileExists(atPath: gpSavedURL.path) {
                let restored = try NSMutableDictionary(contentsOf: gpSavedURL, error: ())
                _ = try verifyPlist(restored, targetPath: mgCurrentPath)
                gpCurrentDict = restored
            } else {
                throw "No Global Prefs file found!"
            }
        } catch {
            Alertinator.shared.alert(title: "Failed to restore Liquid Glass!", body: "\(error)")
        }
    }
    
    // MARK: bindings
    private func gpKeyBinding(_ key: String, default defaultValue: Bool = false, enable enableValue: Bool = true) -> Binding<Bool> {
        return _gpKeyBinding(key, type: Bool.self, defaultValue: defaultValue, enableValue: enableValue)
    }

    private func _gpKeyBinding<T: Equatable>(_ key: String, type: T.Type, defaultValue: T?, enableValue: T?) -> Binding<Bool> {
        return Binding(get: {
            _ = dumbassToggleThatMakesTheViewUpdate
            if let value = gpCurrentDict[key] as? T?, let enableValue {
                return value == enableValue
            }
            return false
        }, set: { enabled in
            if enabled {
                dumbassToggleThatMakesTheViewUpdate.toggle()
                gpCurrentDict[key] = enableValue
            } else {
                dumbassToggleThatMakesTheViewUpdate.toggle()
                gpCurrentDict.removeObject(forKey: key)
            }
        })
    }
}

#Preview {
    LiquidGlassView()
}
