//
//  DpkgStatus.swift
//  DSPloit
//
//  Track installed packages via /var/jb/var/lib/dpkg/status
//  Compatible with dpkg/apt ecosystem (Sileo, Zebra, Cydia)
//

import Foundation

final class DpkgStatus {
    static let shared = DpkgStatus()
    
    private let statusPath = "/var/jb/var/lib/dpkg/status"
    private let root = RootExecutor.shared
    
    struct Package: Identifiable {
        let id = UUID()
        let bundleId: String
        let name: String
        let version: String
        let architecture: String
        let description: String
        let section: String
        let installedSize: Int
        let status: String // "install ok installed"
    }
    
    private(set) var packages: [Package] = []
    
    // MARK: - Read
    
    /// Load installed packages from dpkg status file
    func reload(completion: @escaping ([Package]) -> Void) {
        #if !DISABLE_REMOTECALL
        root.readFileAsRoot(path: statusPath, maxSize: 65536) { [weak self] data in
            guard let self, let data, let content = String(data: data, encoding: .utf8) else {
                completion([])
                return
            }
            self.packages = self.parseStatusFile(content)
            completion(self.packages)
        }
        #else
        // Fallback: try reading directly (works if sandbox escaped)
        if let data = try? Data(contentsOf: URL(fileURLWithPath: statusPath)),
           let content = String(data: data, encoding: .utf8) {
            packages = parseStatusFile(content)
        }
        completion(packages)
        #endif
    }
    
    /// Check if a package is installed
    func isInstalled(_ bundleId: String) -> Bool {
        return packages.contains { $0.bundleId == bundleId && $0.status.contains("installed") }
    }
    
    /// Get installed version of a package
    func installedVersion(_ bundleId: String) -> String? {
        return packages.first { $0.bundleId == bundleId }?.version
    }
    
    // MARK: - Write
    
    /// Register a newly installed package
    func registerPackage(
        bundleId: String,
        name: String,
        version: String,
        architecture: String = "iphoneos-arm",
        description: String = "",
        section: String = "System",
        installedSize: Int = 0,
        completion: @escaping (Bool) -> Void
    ) {
        // Build dpkg status entry
        let entry = buildEntry(
            bundleId: bundleId,
            name: name,
            version: version,
            architecture: architecture,
            description: description,
            section: section,
            installedSize: installedSize
        )
        
        // Read current status, append new entry, write back
        #if !DISABLE_REMOTECALL
        root.readFileAsRoot(path: statusPath, maxSize: 65536) { [weak self] data in
            guard let self else { completion(false); return }
            
            var content = ""
            if let data, let existing = String(data: data, encoding: .utf8) {
                content = existing
                // Remove existing entry for same bundleId if present
                content = self.removeEntry(from: content, bundleId: bundleId)
            }
            
            // Append new entry
            if !content.hasSuffix("\n\n") {
                if !content.hasSuffix("\n") { content += "\n" }
                content += "\n"
            }
            content += entry
            
            // Write back
            let newData = Data(content.utf8)
            self.root.writeFileAsRoot(path: self.statusPath, content: newData)
            
            // Update local cache
            DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                self.packages.append(Package(
                    bundleId: bundleId, name: name, version: version,
                    architecture: architecture, description: description,
                    section: section, installedSize: installedSize,
                    status: "install ok installed"
                ))
                completion(true)
            }
        }
        #else
        completion(false)
        #endif
    }
    
    /// Remove a package from status
    func unregisterPackage(bundleId: String, completion: @escaping (Bool) -> Void) {
        #if !DISABLE_REMOTECALL
        root.readFileAsRoot(path: statusPath, maxSize: 65536) { [weak self] data in
            guard let self, let data, var content = String(data: data, encoding: .utf8) else {
                completion(false)
                return
            }
            
            content = self.removeEntry(from: content, bundleId: bundleId)
            let newData = Data(content.utf8)
            self.root.writeFileAsRoot(path: self.statusPath, content: newData)
            
            DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                self.packages.removeAll { $0.bundleId == bundleId }
                completion(true)
            }
        }
        #else
        completion(false)
        #endif
    }
    
    // MARK: - Parse
    
    private func parseStatusFile(_ content: String) -> [Package] {
        let blocks = content.components(separatedBy: "\n\n")
        var result: [Package] = []
        
        for block in blocks {
            guard !block.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { continue }
            
            var bundleId = "", name = "", version = "", arch = ""
            var desc = "", section = "", status = ""
            var installedSize = 0
            
            for line in block.components(separatedBy: "\n") {
                if line.hasPrefix("Package: ") { bundleId = String(line.dropFirst(9)) }
                else if line.hasPrefix("Name: ") { name = String(line.dropFirst(6)) }
                else if line.hasPrefix("Version: ") { version = String(line.dropFirst(9)) }
                else if line.hasPrefix("Architecture: ") { arch = String(line.dropFirst(14)) }
                else if line.hasPrefix("Description: ") { desc = String(line.dropFirst(13)) }
                else if line.hasPrefix("Section: ") { section = String(line.dropFirst(9)) }
                else if line.hasPrefix("Status: ") { status = String(line.dropFirst(8)) }
                else if line.hasPrefix("Installed-Size: ") { installedSize = Int(line.dropFirst(16)) ?? 0 }
            }
            
            guard !bundleId.isEmpty else { continue }
            if name.isEmpty { name = bundleId }
            if status.isEmpty { status = "install ok installed" }
            
            result.append(Package(
                bundleId: bundleId, name: name, version: version,
                architecture: arch, description: desc, section: section,
                installedSize: installedSize, status: status
            ))
        }
        
        return result
    }
    
    private func buildEntry(
        bundleId: String, name: String, version: String,
        architecture: String, description: String,
        section: String, installedSize: Int
    ) -> String {
        var lines: [String] = []
        lines.append("Package: \(bundleId)")
        lines.append("Status: install ok installed")
        lines.append("Name: \(name)")
        lines.append("Version: \(version)")
        lines.append("Architecture: \(architecture)")
        if !section.isEmpty { lines.append("Section: \(section)") }
        if installedSize > 0 { lines.append("Installed-Size: \(installedSize)") }
        if !description.isEmpty { lines.append("Description: \(description)") }
        lines.append("") // trailing newline
        return lines.joined(separator: "\n")
    }
    
    private func removeEntry(from content: String, bundleId: String) -> String {
        let blocks = content.components(separatedBy: "\n\n")
        let filtered = blocks.filter { block in
            !block.contains("Package: \(bundleId)\n") && !block.contains("Package: \(bundleId)\r")
        }
        return filtered.joined(separator: "\n\n")
    }
}
