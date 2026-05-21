//
//  DeviceCompat.swift
//  DSPloit
//
//  Auto device detection + compatibility check
//  Dipakai di seluruh app sebagai gate sebelum exploit
//

import UIKit
import Darwin

/// Singleton device compatibility checker
/// Auto-detect device, chip, iOS version saat init
final class DeviceCompat {
    static let shared = DeviceCompat()
    
    // MARK: - Detected values
    
    let machine: String        // e.g. "iPhone11,8"
    let deviceName: String     // e.g. "iPhone XR"
    let chip: ChipType         // e.g. .a12
    let iosVersion: (major: Int, minor: Int, patch: Int)
    let iosString: String      // e.g. "18.2"
    
    // MARK: - Compatibility result
    
    let isSupported: Bool
    let isPatched: Bool
    let unsupportedReason: String?
    
    // MARK: - Chip enum
    
    enum ChipType: String, CaseIterable {
        case a11 = "A11 Bionic"
        case a12 = "A12 Bionic"
        case a13 = "A13 Bionic"
        case a14 = "A14 Bionic"
        case a15 = "A15 Bionic"
        case a16 = "A16 Bionic"
        case a17pro = "A17 Pro"
        case a18 = "A18"
        case m1 = "M1"
        case m2 = "M2"
        case unknown = "Unknown"
        
        var isExploitable: Bool {
            switch self {
            case .a11, .a12, .a13, .a14, .a15, .a16, .a17pro, .a18, .m1, .m2:
                return true
            case .unknown:
                return false
            }
        }
    }
    
    // MARK: - Init (auto-detect everything)
    
    private init() {
        // Detect machine
        var sysinfo = utsname()
        uname(&sysinfo)
        let m = Mirror(reflecting: sysinfo.machine)
        self.machine = m.children.reduce("") { id, el in
            guard let value = el.value as? Int8, value != 0 else { return id }
            return id + String(UnicodeScalar(UInt8(value)))
        }
        
        // Detect iOS version
        let v = ProcessInfo.processInfo.operatingSystemVersion
        self.iosVersion = (v.majorVersion, v.minorVersion, v.patchVersion)
        self.iosString = "\(v.majorVersion).\(v.minorVersion)"
        
        // Detect chip
        self.chip = DeviceCompat.detectChip(machine: self.machine)
        
        // Detect device name
        self.deviceName = DeviceCompat.detectName(machine: self.machine)
        
        // Check compatibility
        let (supported, patched, reason) = DeviceCompat.checkCompat(
            chip: self.chip,
            major: v.majorVersion,
            minor: v.minorVersion,
            patch: v.patchVersion,
            machine: self.machine
        )
        self.isSupported = supported
        self.isPatched = patched
        self.unsupportedReason = reason
    }
    
    // MARK: - Compatibility Check Logic
    
    /// Core compatibility check:
    /// - Chip must be A11-A18 or M1/M2
    /// - iOS must be 16.0-18.2 (darksword patched in 18.3+)
    /// - NOT MIE devices (A19+)
    /// - NOT debugger attached
    private static func checkCompat(
        chip: ChipType,
        major: Int, minor: Int, patch: Int,
        machine: String
    ) -> (supported: Bool, patched: Bool, reason: String?) {
        
        // Check chip
        guard chip.isExploitable else {
            return (false, false, "Unsupported chip (\(chip.rawValue)). Requires A11–A18 or M1/M2.")
        }
        
        // Check MIE (A19+ / iPhone18,x)
        if machine.contains("iPhone18,") {
            return (false, false, "Device has MIE (Memory Isolation Engine). Cannot be exploited.")
        }
        
        // Check iOS version
        // Supported: 16.0 - 18.2
        // Patched: 18.3+
        // Also supported: 26.0 - 26.0.1 (special case from isunsupported)
        
        if major < 16 {
            return (false, false, "iOS \(major).\(minor) is too old. Minimum iOS 16.0.")
        }
        
        if major >= 16 && major <= 17 {
            // iOS 16.x and 17.x — all supported
            return (true, false, nil)
        }
        
        if major == 18 {
            if minor <= 2 {
                // iOS 18.0, 18.1, 18.2 — supported
                return (true, false, nil)
            } else {
                // iOS 18.3+ — PATCHED
                return (false, true, "iOS 18.\(minor) is patched. darksword exploit fixed in 18.3 beta 1.")
            }
        }
        
        if major >= 19 && major <= 25 {
            // Hypothetical future versions — patched
            return (false, true, "iOS \(major).\(minor) is patched.")
        }
        
        if major == 26 {
            // iOS 26.0 - 26.0.1 supported (from existing code)
            if minor == 0 && patch <= 1 {
                return (true, false, nil)
            }
            return (false, true, "iOS 26.\(minor).\(patch) is not supported.")
        }
        
        return (false, true, "iOS \(major).\(minor) is not supported.")
    }
    
    // MARK: - Chip Detection
    
    private static func detectChip(machine: String) -> ChipType {
        // iPhone
        if machine.hasPrefix("iPhone10,") { return .a11 }
        if machine.hasPrefix("iPhone11,") { return .a12 }
        if machine.hasPrefix("iPhone12,") { return .a13 }
        if machine.hasPrefix("iPhone13,") { return .a14 }
        if machine.hasPrefix("iPhone14,") { return .a15 }
        if machine.hasPrefix("iPhone15,") { return .a16 }
        if machine.hasPrefix("iPhone16,") { return .a17pro }
        if machine.hasPrefix("iPhone17,") { return .a18 }
        
        // iPad
        if machine.hasPrefix("iPad11,") { return .a12 }   // iPad Air 3, mini 5
        if machine.hasPrefix("iPad12,") { return .a13 }   // iPad 9th gen
        if machine.hasPrefix("iPad13,1") || machine.hasPrefix("iPad13,2") { return .a14 } // iPad Air 4
        if machine.hasPrefix("iPad13,4") || machine.hasPrefix("iPad13,5") ||
           machine.hasPrefix("iPad13,6") || machine.hasPrefix("iPad13,7") ||
           machine.hasPrefix("iPad13,8") || machine.hasPrefix("iPad13,9") ||
           machine.hasPrefix("iPad13,10") || machine.hasPrefix("iPad13,11") ||
           machine.hasPrefix("iPad13,16") || machine.hasPrefix("iPad13,17") { return .m1 }
        if machine.hasPrefix("iPad14,") { return .m2 }
        
        return .unknown
    }
    
    // MARK: - Device Name Detection
    
    private static func detectName(machine: String) -> String {
        let map: [String: String] = [
            // A11
            "iPhone10,1": "iPhone 8", "iPhone10,4": "iPhone 8",
            "iPhone10,2": "iPhone 8 Plus", "iPhone10,5": "iPhone 8 Plus",
            "iPhone10,3": "iPhone X", "iPhone10,6": "iPhone X",
            // A12
            "iPhone11,2": "iPhone XS",
            "iPhone11,4": "iPhone XS Max", "iPhone11,6": "iPhone XS Max",
            "iPhone11,8": "iPhone XR",
            // A13
            "iPhone12,1": "iPhone 11",
            "iPhone12,3": "iPhone 11 Pro",
            "iPhone12,5": "iPhone 11 Pro Max",
            "iPhone12,8": "iPhone SE (2nd)",
            // A14
            "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12",
            "iPhone13,3": "iPhone 12 Pro", "iPhone13,4": "iPhone 12 Pro Max",
            // A15
            "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
            "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
            "iPhone14,6": "iPhone SE (3rd)",
            "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
            // A16
            "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max",
            "iPhone15,4": "iPhone 15", "iPhone15,5": "iPhone 15 Plus",
            // A17 Pro
            "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
            // A18
            "iPhone17,1": "iPhone 16 Pro", "iPhone17,2": "iPhone 16 Pro Max",
            "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus",
        ]
        return map[machine] ?? machine
    }
    
    // MARK: - Convenience Methods
    
    /// Quick check — bisa dipanggil dari mana aja
    /// Usage: if DeviceCompat.shared.canJailbreak { ... }
    var canJailbreak: Bool {
        return isSupported && !isPatched
    }
    
    /// Status string untuk UI
    var statusEmoji: String {
        if canJailbreak { return "✅" }
        if isPatched { return "🔒" }
        return "❌"
    }
    
    /// One-line summary
    var summary: String {
        "\(deviceName) • \(chip.rawValue) • iOS \(iosString) • \(canJailbreak ? "Supported" : (isPatched ? "Patched" : "Unsupported"))"
    }
}
