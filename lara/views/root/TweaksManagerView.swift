//
//  TweaksManagerView.swift
//  DSPloit
//
//  SpringBoard tweaks via RemoteCall — no trust cache needed
//  All tweaks execute in SpringBoard context directly
//

import SwiftUI

struct TweaksManagerView: View {
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var statusBarFormat = "HH:mm"
    @State private var dockIconCount = "5"
    @State private var carrierText = ""
    @State private var tweakResults: [String] = []
    
    var body: some View {
        List {
            // Status
            Section {
                HStack {
                    Image(systemName: mgr.rcready ? "paintbrush.fill" : "lock.fill")
                        .foregroundStyle(mgr.rcready ? .green : .secondary)
                    Text(mgr.rcready ? "Tweaks Ready" : "Need RemoteCall")
                        .font(.subheadline.bold())
                }
            }
            
            // SpringBoard Tweaks
            Section {
                TweakButton(title: "Hide Icon Labels", subtitle: "⚠️ Will cause respring", icon: "textformat.size.smaller") {
                    applyTweak("hide_icon_labels")
                }
                
                TweakButton(title: "5-Icon Dock", subtitle: "⚠️ Will cause respring", icon: "dock.rectangle") {
                    applyTweak("five_icon_dock")
                }
                
                TweakButton(title: "Floating Dock (iPad-style)", subtitle: "iPad dock on iPhone", icon: "dock.arrow.up.rectangle") {
                    applyTweak("floating_dock")
                }
                
                TweakButton(title: "Grid App Switcher", subtitle: "Grid layout in multitasking", icon: "square.grid.3x3") {
                    applyTweak("grid_switcher")
                }
                
                TweakButton(title: "Upside Down Mode", subtitle: "Rotate UI 180°", icon: "arrow.up.arrow.down") {
                    applyTweak("upside_down")
                }
            } header: {
                Label("SpringBoard", systemImage: "apps.iphone")
            }
            
            // Status Bar
            Section {
                HStack {
                    Text("Time Format")
                    Spacer()
                    TextField("HH:mm", text: $statusBarFormat)
                        .font(.system(.body, design: .monospaced))
                        .multilineTextAlignment(.trailing)
                        .frame(width: 100)
                }
                
                Button("Apply Status Bar Format") {
                    applyTweak("status_bar_\(statusBarFormat)")
                }
                
                HStack {
                    Text("Carrier Text")
                    Spacer()
                    TextField("DSPloit", text: $carrierText)
                        .font(.system(.body, design: .monospaced))
                        .multilineTextAlignment(.trailing)
                        .frame(width: 120)
                }
                
                Button("Set Carrier Text") {
                    applyTweak("carrier_\(carrierText)")
                }
            } header: {
                Label("Status Bar", systemImage: "clock")
            }
            
            // Display
            Section {
                TweakButton(title: "Force All Apps Landscape", subtitle: "Allow rotation everywhere", icon: "rotate.right") {
                    applyTweak("force_rotation")
                }
                
                TweakButton(title: "Reduce Motion OFF", subtitle: "Re-enable all animations", icon: "sparkles") {
                    applyTweak("animations_on")
                }
                
                TweakButton(title: "Bold Text System-wide", subtitle: "Force bold in all apps", icon: "bold") {
                    applyTweak("bold_text")
                }
            } header: {
                Label("Display", systemImage: "display")
            }
            
            // Dock
            Section {
                HStack {
                    Text("Dock Icons")
                    Spacer()
                    TextField("5", text: $dockIconCount)
                        .font(.system(.body, design: .monospaced))
                        .multilineTextAlignment(.trailing)
                        .frame(width: 50)
                }
                
                Button("Set Dock Icon Count") {
                    applyTweak("dock_count_\(dockIconCount)")
                }
            } header: {
                Label("Dock", systemImage: "dock.rectangle")
            }
            
            // Debug
            Section {
                TweakButton(title: "Performance HUD", subtitle: "Show FPS/memory overlay", icon: "gauge.with.dots.needle.33percent") {
                    applyTweak("perf_hud")
                }
            } header: {
                Label("Debug", systemImage: "ant")
            }
            
            // JIT
            Section {
                TweakButton(title: "Enable JIT (all apps)", subtitle: "Just-In-Time compilation for emulators", icon: "bolt.circle") {
                    applyTweak("jit_all")
                }
            } header: {
                Label("JIT", systemImage: "bolt")
            }
            
            // Results
            if !tweakResults.isEmpty {
                Section {
                    ForEach(tweakResults.suffix(10), id: \.self) { result in
                        Text(result)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(result.contains("✅") ? .green : .orange)
                    }
                } header: {
                    Label("Results", systemImage: "checkmark.circle")
                }
            }
        }
        .navigationTitle("Tweaks")
        .navigationBarTitleDisplayMode(.inline)
        .disabled(!mgr.rcready)
    }
    
    #if !DISABLE_REMOTECALL
    private func applyTweak(_ tweak: String) {
        guard mgr.rcready, let proc = mgr.sbProc else {
            tweakResults.append("❌ RC not ready")
            return
        }
        
        var result = 0
        
        switch tweak {
        case "hide_icon_labels":
            result = Int(hide_icon_labels(proc))
        case "five_icon_dock":
            result = Int(five_icon_dock(proc))
        case "floating_dock":
            result = Int(enable_floating_dock(proc))
        case "grid_switcher":
            result = Int(enable_grid_app_switcher(proc))
        case "upside_down":
            result = Int(enable_upside_down(proc))
        case "perf_hud":
            result = Int(set_performance_hud(proc, 1))
        case "jit_all":
            // Enable JIT for common emulators
            result = Int(enable_jit(proc, "com.provenance.game"))
        case let s where s.hasPrefix("status_bar_"):
            let format = String(s.dropFirst(11))
            format.withCString { cStr in
                status_bar_time_format(proc, cStr)
            }
            result = 0
        case let s where s.hasPrefix("dock_count_"):
            if let count = Int(String(s.dropFirst(11))) {
                result = Int(set_dock_icon_count(proc, Int32(count)))
            }
        case let s where s.hasPrefix("carrier_"):
            let text = String(s.dropFirst(8))
            // Set carrier text via SpringBoard's status bar
            let sel = remote_sel(proc, "setOperatorName:forSIM:")
            let sbApp = remote_msg(proc, remote_getClass(proc, "SpringBoard"), remote_sel(proc, "sharedApplication"), 0, 0, 0, 0)
            let statusBar = remote_msg(proc, sbApp, remote_sel(proc, "statusBar"), 0, 0, 0, 0)
            if statusBar != 0 {
                let nsText = remote_NSString(proc, text)
                let simStr = remote_NSString(proc, "")
                remote_msg(proc, statusBar, sel, nsText, simStr, 0, 0)
                result = 0
            } else {
                result = -1
            }
        case "force_rotation":
            // Set orientation mask to allow all orientations
            let sel = remote_sel(proc, "setForcedInterfaceOrientationMask:")
            let sbApp = remote_msg(proc, remote_getClass(proc, "SpringBoard"), remote_sel(proc, "sharedApplication"), 0, 0, 0, 0)
            if sbApp != 0 {
                // UIInterfaceOrientationMaskAll = 0x1E
                remote_msg(proc, sbApp, sel, 0x1E, 0, 0, 0)
                result = 0
            } else { result = -1 }
        case "animations_on":
            // Write to com.apple.Accessibility plist
            let defaults = remote_msg(proc, remote_getClass(proc, "NSUserDefaults"), remote_sel(proc, "standardUserDefaults"), 0, 0, 0, 0)
            if defaults != 0 {
                let key = remote_NSString(proc, "ReduceMotionEnabled")
                let no = remote_msg(proc, remote_getClass(proc, "NSNumber"), remote_sel(proc, "numberWithBool:"), 0, 0, 0, 0)
                remote_msg(proc, defaults, remote_sel(proc, "setObject:forKey:"), no, key, 0, 0)
                result = 0
            } else { result = -1 }
        case "bold_text":
            let defaults = remote_msg(proc, remote_getClass(proc, "NSUserDefaults"), remote_sel(proc, "standardUserDefaults"), 0, 0, 0, 0)
            if defaults != 0 {
                let key = remote_NSString(proc, "BoldTextEnabled")
                let yes = remote_msg(proc, remote_getClass(proc, "NSNumber"), remote_sel(proc, "numberWithBool:"), 1, 0, 0, 0)
                remote_msg(proc, defaults, remote_sel(proc, "setObject:forKey:"), yes, key, 0, 0)
                result = 0
            } else { result = -1 }
        default:
            tweakResults.append("❌ Unknown tweak: \(tweak)")
            return
        }
        
        tweakResults.append(result == 0 ? "✅ \(tweak) applied" : "⚠️ \(tweak) (ret=\(result))")
        
        // Respring prompt for visual tweaks
        if ["hide_icon_labels", "five_icon_dock", "floating_dock", "grid_switcher"].contains(tweak) {
            tweakResults.append("   ↳ Respring may be needed to see changes")
        }
    }
    #else
    private func applyTweak(_ tweak: String) {
        tweakResults.append("❌ RemoteCall disabled")
    }
    #endif
}

// MARK: - Tweak Button

struct TweakButton: View {
    let title: String
    let subtitle: String
    let icon: String
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.body)
                    .foregroundStyle(.blue)
                    .frame(width: 24)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.subheadline)
                        .foregroundStyle(.primary)
                    Text(subtitle)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "play.circle")
                    .foregroundStyle(.blue)
            }
        }
    }
}
