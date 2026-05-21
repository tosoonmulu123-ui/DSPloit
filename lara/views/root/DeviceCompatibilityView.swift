//
//  DeviceCompatibilityView.swift
//  DSPloit
//
//  Auto-detect device & iOS — shows compatibility status instantly
//  Uses DeviceCompat.shared singleton (no user action needed)
//

import SwiftUI

struct DeviceCompatibilityView: View {
    private let compat = DeviceCompat.shared
    
    var body: some View {
        List {
            // Current device — auto detected
            Section {
                HStack(spacing: 16) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 16)
                            .fill(compat.canJailbreak ? Color.green.opacity(0.12) : Color.red.opacity(0.12))
                            .frame(width: 60, height: 60)
                        Image(systemName: compat.canJailbreak ? "checkmark.shield.fill" : "xmark.shield.fill")
                            .font(.system(size: 28))
                            .foregroundStyle(compat.canJailbreak ? .green : .red)
                    }
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text(compat.deviceName)
                            .font(.headline)
                        Text("iOS \(compat.iosString)")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                        Text(compat.chip.rawValue)
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }
                    
                    Spacer()
                    
                    Text(compat.canJailbreak ? "SUPPORTED" : (compat.isPatched ? "PATCHED" : "UNSUPPORTED"))
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(compat.canJailbreak ? .green : .red)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(
                            Capsule().fill((compat.canJailbreak ? Color.green : Color.red).opacity(0.12))
                        )
                }
                .padding(.vertical, 4)
                
                if let reason = compat.unsupportedReason {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        Text(reason)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                Label("This Device (Auto-Detect)", systemImage: "iphone")
            }
            
            // iOS version support
            Section {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        versionBadge("16.0", .green)
                        Text("—").foregroundStyle(.secondary)
                        versionBadge("18.2", .green)
                        Text("✅").font(.caption)
                    }
                    HStack(spacing: 8) {
                        versionBadge("18.3+", .red)
                        Text("PATCHED").font(.system(size: 9, weight: .bold)).foregroundStyle(.red)
                    }
                    Text("darksword exploit patched in iOS 18.3 beta 1.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)
            } header: {
                Label("iOS Support", systemImage: "apps.iphone")
            }
            
            // Exploit info
            Section {
                exploitRow("Kernel", "darksword (socket KRW)", "A11–A18 universal", .orange)
                exploitRow("Offsets", "XPF dynamic resolve", "No hardcoded offsets", .blue)
                exploitRow("Trust Cache", "MSM XPC inject", "Universal", .green)
                exploitRow("KASLR", "Auto-detect per boot", "Random slide", .purple)
            } header: {
                Label("Exploit Components", systemImage: "cpu")
            } footer: {
                Text("All components are universal. Only KASLR slide is random per boot (auto-detected).")
            }
            
            // Supported devices
            Section {
                deviceRow("A11", "iPhone 8, 8 Plus, X", .orange)
                deviceRow("A12", "iPhone XR, XS, XS Max", .blue)
                deviceRow("A13", "iPhone 11 series, SE 2", .green)
                deviceRow("A14", "iPhone 12 series", .purple)
                deviceRow("A15", "iPhone 13/14, SE 3", .cyan)
                deviceRow("A16", "iPhone 14 Pro, 15/15+", .pink)
                deviceRow("A17 Pro", "iPhone 15 Pro/Max", .indigo)
                deviceRow("A18", "iPhone 16 series", .mint)
                deviceRow("M1/M2", "iPad Pro/Air", .teal)
            } header: {
                Label("Supported Chips", systemImage: "cpu")
            }
            
            // Raw info
            Section {
                HStack {
                    Text("Machine")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Text(compat.machine)
                        .font(.system(size: 11, design: .monospaced))
                }
                HStack {
                    Text("iOS")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Text("\(compat.iosVersion.major).\(compat.iosVersion.minor).\(compat.iosVersion.patch)")
                        .font(.system(size: 11, design: .monospaced))
                }
                HStack {
                    Text("Chip")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Text(compat.chip.rawValue)
                        .font(.system(size: 11, design: .monospaced))
                }
                HStack {
                    Text("Exploitable")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Text(compat.chip.isExploitable ? "Yes" : "No")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundStyle(compat.chip.isExploitable ? .green : .red)
                }
            } header: {
                Label("Raw Detection", systemImage: "wrench")
            }
        }
        .navigationTitle("Compatibility")
        .navigationBarTitleDisplayMode(.inline)
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
            Circle().fill(color).frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(.subheadline.bold())
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Text(scope)
                .font(.system(size: 9))
                .foregroundStyle(.tertiary)
        }
    }
    
    private func deviceRow(_ chip: String, _ devices: String, _ color: Color) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(color)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(chip).font(.subheadline.bold())
                Text(devices).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}
