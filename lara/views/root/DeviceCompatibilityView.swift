//
//  DeviceCompatibilityView.swift
//  DSPloit
//
//  Multi-device compatibility checker — shows supported devices & current status
//

import SwiftUI
import UIKit

struct DeviceCompatibilityView: View {
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var currentDevice = ""
    @State private var currentiOS = ""
    @State private var currentChip = ""
    @State private var isSupported = false
    
    struct DeviceGroup: Identifiable {
        let id = UUID()
        let chip: String
        let devices: [DeviceEntry]
        let color: Color
    }
    
    struct DeviceEntry: Identifiable {
        let id = UUID()
        let name: String
        let model: String
        let supported: Bool
        let notes: String
    }
    
    private let deviceGroups: [DeviceGroup] = [
        DeviceGroup(chip: "A11 Bionic", devices: [
            DeviceEntry(name: "iPhone 8", model: "iPhone10,1/10,4", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 8 Plus", model: "iPhone10,2/10,5", supported: true, notes: ""),
            DeviceEntry(name: "iPhone X", model: "iPhone10,3/10,6", supported: true, notes: ""),
        ], color: .orange),
        DeviceGroup(chip: "A12 Bionic", devices: [
            DeviceEntry(name: "iPhone XR", model: "iPhone11,8", supported: true, notes: "✅ CONFIRMED"),
            DeviceEntry(name: "iPhone XS", model: "iPhone11,2", supported: true, notes: ""),
            DeviceEntry(name: "iPhone XS Max", model: "iPhone11,4/11,6", supported: true, notes: ""),
            DeviceEntry(name: "iPad Air 3", model: "iPad11,3/11,4", supported: true, notes: ""),
            DeviceEntry(name: "iPad mini 5", model: "iPad11,1/11,2", supported: true, notes: ""),
        ], color: .blue),
        DeviceGroup(chip: "A13 Bionic", devices: [
            DeviceEntry(name: "iPhone 11", model: "iPhone12,1", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 11 Pro", model: "iPhone12,3", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 11 Pro Max", model: "iPhone12,5", supported: true, notes: ""),
            DeviceEntry(name: "iPhone SE (2nd)", model: "iPhone12,8", supported: true, notes: ""),
        ], color: .green),
        DeviceGroup(chip: "A14 Bionic", devices: [
            DeviceEntry(name: "iPhone 12", model: "iPhone13,2", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 12 mini", model: "iPhone13,1", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 12 Pro", model: "iPhone13,3", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 12 Pro Max", model: "iPhone13,4", supported: true, notes: ""),
            DeviceEntry(name: "iPad Air 4", model: "iPad13,1/13,2", supported: true, notes: ""),
        ], color: .purple),
        DeviceGroup(chip: "A15 Bionic", devices: [
            DeviceEntry(name: "iPhone 13", model: "iPhone14,5", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 13 Pro", model: "iPhone14,2", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 13 Pro Max", model: "iPhone14,3", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 14", model: "iPhone14,7", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 14 Plus", model: "iPhone14,8", supported: true, notes: ""),
            DeviceEntry(name: "iPhone SE (3rd)", model: "iPhone14,6", supported: true, notes: ""),
        ], color: .cyan),
        DeviceGroup(chip: "A16 Bionic", devices: [
            DeviceEntry(name: "iPhone 14 Pro", model: "iPhone15,2", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 14 Pro Max", model: "iPhone15,3", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 15", model: "iPhone15,4", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 15 Plus", model: "iPhone15,5", supported: true, notes: ""),
        ], color: .pink),
        DeviceGroup(chip: "A17 Pro", devices: [
            DeviceEntry(name: "iPhone 15 Pro", model: "iPhone16,1", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 15 Pro Max", model: "iPhone16,2", supported: true, notes: ""),
        ], color: .indigo),
        DeviceGroup(chip: "A18 / A18 Pro", devices: [
            DeviceEntry(name: "iPhone 16", model: "iPhone17,3", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 16 Plus", model: "iPhone17,4", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 16 Pro", model: "iPhone17,1", supported: true, notes: ""),
            DeviceEntry(name: "iPhone 16 Pro Max", model: "iPhone17,2", supported: true, notes: ""),
        ], color: .mint),
        DeviceGroup(chip: "M1 / M2", devices: [
            DeviceEntry(name: "iPad Pro 11\" (M1)", model: "iPad13,4-7", supported: true, notes: ""),
            DeviceEntry(name: "iPad Pro 12.9\" (M1)", model: "iPad13,8-11", supported: true, notes: ""),
            DeviceEntry(name: "iPad Air (M1)", model: "iPad13,16/17", supported: true, notes: ""),
            DeviceEntry(name: "iPad Pro (M2)", model: "iPad14,3-6", supported: true, notes: ""),
        ], color: .teal),
    ]
    
    var body: some View {
        List {
            // Current device section
            Section {
                VStack(spacing: 12) {
                    HStack(spacing: 16) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 16)
                                .fill(isSupported ? Color.green.opacity(0.12) : Color.red.opacity(0.12))
                                .frame(width: 60, height: 60)
                            Image(systemName: isSupported ? "checkmark.shield.fill" : "xmark.shield.fill")
                                .font(.system(size: 28))
                                .foregroundStyle(isSupported ? .green : .red)
                        }
                        
                        VStack(alignment: .leading, spacing: 4) {
                            Text(currentDevice)
                                .font(.headline)
                            Text("iOS \(currentiOS)")
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                            Text(currentChip)
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                        }
                        
                        Spacer()
                        
                        VStack {
                            Text(isSupported ? "SUPPORTED" : "UNSUPPORTED")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundStyle(isSupported ? .green : .red)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(
                                    Capsule().fill((isSupported ? Color.green : Color.red).opacity(0.12))
                                )
                        }
                    }
                }
                .padding(.vertical, 4)
            } header: {
                Label("This Device", systemImage: "iphone")
            }
            
            // iOS version support
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Supported iOS Versions")
                            .font(.subheadline.bold())
                        Spacer()
                    }
                    
                    HStack(spacing: 8) {
                        versionBadge("16.0", .green)
                        Text("—")
                            .foregroundStyle(.secondary)
                        versionBadge("18.2", .green)
                    }
                    
                    HStack(spacing: 8) {
                        versionBadge("18.3+", .red)
                        Text("PATCHED")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(.red)
                    }
                    
                    Text("darksword exploit patched in iOS 18.3 beta 1. Devices on 18.2 or below are supported.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            } header: {
                Label("iOS Versions", systemImage: "apps.iphone")
            }
            
            // Exploit details
            Section {
                exploitRow("Kernel Exploit", "darksword (socket KRW)", "Universal A11–A18", .orange)
                exploitRow("Offsets", "XPF dynamic (no hardcode)", "Auto-resolve per device", .blue)
                exploitRow("Trust Cache", "MSM XPC inject", "Universal (not device-specific)", .green)
                exploitRow("KASLR", "Random per boot", "Auto-detected at runtime", .purple)
            } header: {
                Label("Exploit Components", systemImage: "cpu")
            } footer: {
                Text("All exploit components are universal. Only KASLR slide varies per boot and is auto-detected.")
            }
            
            // Device list
            ForEach(deviceGroups) { group in
                Section {
                    ForEach(group.devices) { device in
                        HStack(spacing: 12) {
                            Image(systemName: device.supported ? "checkmark.circle.fill" : "xmark.circle")
                                .foregroundStyle(device.supported ? .green : .red)
                                .frame(width: 20)
                            
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(device.name)
                                        .font(.subheadline)
                                    if !device.notes.isEmpty {
                                        Text(device.notes)
                                            .font(.system(size: 9, weight: .bold))
                                            .foregroundStyle(.green)
                                    }
                                }
                                Text(device.model)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                            
                            Spacer()
                        }
                    }
                } header: {
                    HStack {
                        Image(systemName: "cpu")
                            .foregroundStyle(group.color)
                        Text(group.chip)
                            .foregroundStyle(group.color)
                    }
                }
            }
        }
        .navigationTitle("Device Compatibility")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { detectDevice() }
    }
    
    // MARK: - Helpers
    
    private func versionBadge(_ version: String, _ color: Color) -> some View {
        Text(version)
            .font(.system(size: 12, weight: .bold, design: .monospaced))
            .foregroundStyle(color)
            .padding(.horizontal, 10)
            .padding(.vertical, 4)
            .background(RoundedRectangle(cornerRadius: 6).fill(color.opacity(0.12)))
    }
    
    private func exploitRow(_ name: String, _ detail: String, _ scope: String, _ color: Color) -> some View {
        HStack(spacing: 12) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(name)
                    .font(.subheadline.bold())
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(scope)
                .font(.system(size: 9))
                .foregroundStyle(.tertiary)
                .multilineTextAlignment(.trailing)
        }
    }
    
    private func detectDevice() {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machine = withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
        
        currentDevice = deviceName(from: machine)
        currentiOS = UIDevice.current.systemVersion
        currentChip = chipName(from: machine)
        
        // Check if supported (iOS 16.0 - 18.2)
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let major = version.majorVersion
        let minor = version.minorVersion
        
        if major == 16 || major == 17 || (major == 18 && minor <= 2) {
            isSupported = true
        } else {
            isSupported = false
        }
    }
    
    private func deviceName(from machine: String) -> String {
        let map: [String: String] = [
            "iPhone10,1": "iPhone 8", "iPhone10,4": "iPhone 8",
            "iPhone10,2": "iPhone 8 Plus", "iPhone10,5": "iPhone 8 Plus",
            "iPhone10,3": "iPhone X", "iPhone10,6": "iPhone X",
            "iPhone11,2": "iPhone XS", "iPhone11,4": "iPhone XS Max",
            "iPhone11,6": "iPhone XS Max", "iPhone11,8": "iPhone XR",
            "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro",
            "iPhone12,5": "iPhone 11 Pro Max", "iPhone12,8": "iPhone SE (2nd)",
            "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
            "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
            "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
            "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
            "iPhone14,6": "iPhone SE (3rd)", "iPhone14,7": "iPhone 14",
            "iPhone14,8": "iPhone 14 Plus",
            "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max",
            "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus",
            "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
            "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max",
            "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus",
        ]
        return map[machine] ?? machine
    }
    
    private func chipName(from machine: String) -> String {
        if machine.hasPrefix("iPhone10,") { return "A11 Bionic" }
        if machine.hasPrefix("iPhone11,") { return "A12 Bionic" }
        if machine.hasPrefix("iPhone12,") { return "A13 Bionic" }
        if machine.hasPrefix("iPhone13,") { return "A14 Bionic" }
        if machine.hasPrefix("iPhone14,") { return "A15 Bionic" }
        if machine.hasPrefix("iPhone15,") { return "A16 Bionic" }
        if machine.hasPrefix("iPhone16,") { return "A17 Pro" }
        if machine.hasPrefix("iPhone17,") { return "A18" }
        if machine.hasPrefix("iPad13,") { return "M1" }
        if machine.hasPrefix("iPad14,") { return "M2" }
        return "Unknown"
    }
}
