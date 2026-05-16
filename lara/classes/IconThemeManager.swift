import Combine
import Compression
import Foundation
import SwiftUI
import UIKit

private let iconThemeStorageRoot = URL(fileURLWithPath: "/var/mobile/.DO-NOT-DELETE-dsploit/IconThemes", isDirectory: true)
private let rawThemesDir = iconThemeStorageRoot.appendingPathComponent("RawThemes", isDirectory: true)
private let processedThemesDir = iconThemeStorageRoot.appendingPathComponent("ProcessedThemes", isDirectory: true)
private let originalIconsDir = iconThemeStorageRoot.appendingPathComponent("OriginalIconsBackup", isDirectory: true)

struct DSPIconTheme: Identifiable, Equatable, Hashable {
    let name: String
    let iconCount: Int

    var id: String { name }
    var url: URL { rawThemesDir.appendingPathComponent(name, isDirectory: true) }
    var cacheURL: URL { processedThemesDir.appendingPathComponent(name, isDirectory: true) }
}

struct DSPThemedIcon: Codable {
    let appID: String
    let themeName: String

    var rawThemeIconURL: URL {
        rawThemesDir.appendingPathComponent(themeName).appendingPathComponent(appID + ".png")
    }

    func cachedThemeIconURL(fileName: String) -> URL {
        processedThemesDir.appendingPathComponent(themeName).appendingPathComponent(appID + "----" + fileName)
    }
}

struct DSPThemedApp: Identifiable, Hashable {
    let bundleIdentifier: String
    var name: String
    let version: String
    let bundleURL: URL
    var pngIconPaths: [String]
    var hiddenFromSpringboard: Bool

    var id: String { bundleIdentifier + "|" + bundleURL.path }

    struct BackedUpPNG {
        let bundleIdentifier: String
        let iconName: String
        let data: Data
    }

    func loadPreviewIcon() -> UIImage? {
        guard let bundle = Bundle(path: bundleURL.path) else { return nil }
        if let icons = bundle.infoDictionary?["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String] {
            for name in files.reversed() {
                if let image = UIImage(named: name, in: bundle, compatibleWith: nil) {
                    return image
                }
            }
        }
        if let name = bundle.infoDictionary?["CFBundleIconFile"] as? String,
           let image = UIImage(named: name, in: bundle, compatibleWith: nil) {
            return image
        }
        return nil
    }

    func backupIconURL(fileName: String) -> URL {
        originalIconsDir.appendingPathComponent(bundleIdentifier + "----" + version + "----" + fileName)
    }

    func backedUpIconURL(fileName: String) -> URL? {
        let fm = FileManager.default
        let newURL = backupIconURL(fileName: fileName)
        let oldURL = originalIconsDir.appendingPathComponent(bundleIdentifier + "----" + fileName)

        if fm.fileExists(atPath: newURL.path) {
            return newURL
        } else if fm.fileExists(atPath: oldURL.path) {
            return oldURL
        }
        return nil
    }

    func backUpPNGIcons() {
        let fm = FileManager.default
        for pngIconPath in pngIconPaths {
            let legacyURL = originalIconsDir.appendingPathComponent(bundleIdentifier + "----" + pngIconPath)
            let newURL = backupIconURL(fileName: pngIconPath)
            let sourceURL = bundleURL.appendingPathComponent(pngIconPath)

            guard fm.fileExists(atPath: sourceURL.path) else { continue }
            if fm.fileExists(atPath: newURL.path) {
                continue
            } else if fm.fileExists(atPath: legacyURL.path) {
                try? fm.moveItem(at: legacyURL, to: newURL)
            } else {
                try? fm.copyItem(at: sourceURL, to: newURL)
            }
        }
    }

    func restorePNGIcons() throws {
        for iconName in pngIconPaths {
            guard let originalURL = backedUpIconURL(fileName: iconName) else { continue }
            let iconURL = bundleURL.appendingPathComponent(iconName)
            let data = try Data(contentsOf: originalURL)
            let result = dspmgr.shared.dsploit_overwritefile(target: iconURL.path, data: data)
            if !result.ok {
                throw NSError(domain: "IconThemer", code: 2, userInfo: [NSLocalizedDescriptionKey: "\(bundleIdentifier): \(result.message)"])
            }
        }
    }

    func setPNGIcons(icon: DSPThemedIcon) throws {
        let fm = FileManager.default
        for iconName in pngIconPaths {
            let iconURL = bundleURL.appendingPathComponent(iconName)
            guard fm.fileExists(atPath: iconURL.path) else { continue }

            let cachedIconURL = icon.cachedThemeIconURL(fileName: iconName)
            var cachedIcon = try? Data(contentsOf: cachedIconURL)

            if cachedIcon == nil {
                let imgData = try Data(contentsOf: icon.rawThemeIconURL)
                guard let themeIcon = UIImage(data: imgData) else {
                    throw NSError(domain: "IconThemer", code: 3, userInfo: [NSLocalizedDescriptionKey: "Could not read themed icon image at \(icon.rawThemeIconURL.path)"])
                }

                let origImageData = try Data(contentsOf: iconURL)
                guard let origImage = UIImage(data: origImageData) else {
                    throw NSError(domain: "IconThemer", code: 4, userInfo: [NSLocalizedDescriptionKey: "Could not read original icon image at \(iconURL.path)"])
                }

                var processedImage: Data?
                var resScale: CGFloat = 1.0
                let width = max(origImage.size.width / 2.0, 8.0)

                while resScale > 0.01 {
                    let size = CGSize(width: width * resScale, height: width * resScale)
                    let rendered = UIGraphicsImageRenderer(size: size).image { _ in
                        themeIcon.draw(in: CGRect(origin: .zero, size: size))
                    }
                    processedImage = try? rendered.resizeToApprox(allowedSizeInBytes: origImageData.count)
                    if processedImage != nil {
                        break
                    }
                    resScale *= 0.75
                }

                guard let processedImage else {
                    throw NSError(domain: "IconThemer", code: 5, userInfo: [NSLocalizedDescriptionKey: "\(bundleIdentifier): Could not fit icon \(iconName) inside original size budget"])
                }

                try? FileManager.default.createDirectory(at: cachedIconURL.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: nil)
                try processedImage.write(to: cachedIconURL)
                cachedIcon = processedImage
            }

            guard let cachedIcon else { continue }
            let result = dspmgr.shared.dsploit_overwritefile(target: iconURL.path, data: cachedIcon)
            if !result.ok {
                throw NSError(domain: "IconThemer", code: 6, userInfo: [NSLocalizedDescriptionKey: "\(bundleIdentifier): \(result.message)"])
            }
        }
    }
}

struct DSPAppIconChange {
    let app: DSPThemedApp
    let icon: DSPThemedIcon?
}

final class IconThemeManager: ObservableObject {
    static let shared = IconThemeManager()

    @Published var themes: [DSPIconTheme] = []
    @Published var selectedThemeNames: [String]
    @Published var installedApps: [DSPThemedApp] = []
    @Published var isApplying = false
    @Published var applyProgress: Double = 0
    @Published var applyMessage = ""
    @Published var isFixingUp = false
    @Published var fixupProgress: Double = 0
    @Published var fixupMessage = ""
    @Published var showFixupSheet = false

    private let fm = FileManager.default
    private let selectedThemesKey = "dsploit.iconThemes.selectedThemes"
    private let iconOverridesKey = "dsploit.iconThemes.iconOverrides"
    private let pendingFixupKey = "dsploit.iconThemes.pendingFixup"
    private init() {
        self.selectedThemeNames = UserDefaults.standard.stringArray(forKey: selectedThemesKey) ?? []
        refreshThemes()
    }

    var hasPendingFixup: Bool {
        UserDefaults.standard.bool(forKey: pendingFixupKey)
    }

    var iconOverrides: [String: String] {
        get { UserDefaults.standard.dictionary(forKey: iconOverridesKey) as? [String: String] ?? [:] }
        set { UserDefaults.standard.set(newValue, forKey: iconOverridesKey) }
    }

    var selectedThemes: [DSPIconTheme] {
        selectedThemeNames.compactMap { name in
            themes.first(where: { $0.name == name })
        }
    }

    var preferredIcons: [String: DSPThemedIcon] {
        var result: [String: DSPThemedIcon] = [:]
        for theme in selectedThemes {
            if let icons = try? fm.contentsOfDirectory(at: theme.url, includingPropertiesForKeys: nil) {
                for icon in icons {
                    let appID = appIDFromIcon(url: icon)
                    result[appID] = DSPThemedIcon(appID: appID, themeName: theme.name)
                }
            }
        }
        for (bundleID, themeName) in iconOverrides {
            result[bundleID] = DSPThemedIcon(appID: bundleID, themeName: themeName)
        }
        return result
    }

    func theme(named name: String) -> DSPIconTheme? {
        themes.first(where: { $0.name == name })
    }

    func saveSelection() {
        UserDefaults.standard.set(selectedThemeNames, forKey: selectedThemesKey)
    }

    func toggleThemeSelection(_ theme: DSPIconTheme) {
        if let idx = selectedThemeNames.firstIndex(of: theme.name) {
            selectedThemeNames.remove(at: idx)
        } else {
            selectedThemeNames.append(theme.name)
        }
        saveSelection()
    }

    func removeOverride(for bundleID: String) {
        var overrides = iconOverrides
        overrides[bundleID] = nil
        iconOverrides = overrides
    }

    func setOverride(bundleID: String, themeName: String) {
        var overrides = iconOverrides
        overrides[bundleID] = themeName
        iconOverrides = overrides
    }

    func createDirectoriesIfNeeded() {
        try? fm.createDirectory(at: rawThemesDir, withIntermediateDirectories: true, attributes: nil)
        try? fm.createDirectory(at: processedThemesDir, withIntermediateDirectories: true, attributes: nil)
        try? fm.createDirectory(at: originalIconsDir, withIntermediateDirectories: true, attributes: nil)
    }

    func refreshThemes() {
        createDirectoriesIfNeeded()
        let contents = (try? fm.contentsOfDirectory(at: rawThemesDir, includingPropertiesForKeys: nil)) ?? []
        themes = contents
            .filter { $0.hasDirectoryPath }
            .map { url in
                DSPIconTheme(name: url.lastPathComponent, iconCount: ((try? fm.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)) ?? []).filter { $0.pathExtension.lowercased() == "png" }.count)
            }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }

        selectedThemeNames.removeAll { selected in
            !themes.contains(where: { $0.name == selected })
        }
        saveSelection()
    }

    func refreshApps() throws {
        let systemApplicationsURL = URL(fileURLWithPath: "/Applications", isDirectory: true)
        let userApplicationsURL = URL(fileURLWithPath: "/var/containers/Bundle/Application", isDirectory: true)
        var dotAppDirs: [URL] = []

        dotAppDirs += (try? fm.contentsOfDirectory(at: systemApplicationsURL, includingPropertiesForKeys: nil)) ?? []
        let userAppsDir = (try? fm.contentsOfDirectory(at: userApplicationsURL, includingPropertiesForKeys: nil)) ?? []
        for folder in userAppsDir {
            let contents = (try? fm.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)) ?? []
            if let dotApp = contents.first(where: { $0.absoluteString.hasSuffix(".app/") }) {
                dotAppDirs.append(dotApp)
            }
        }

        var apps: [DSPThemedApp] = []
        for bundleURL in dotAppDirs {
            let infoPlistURL = bundleURL.appendingPathComponent("Info.plist")
            guard fm.fileExists(atPath: infoPlistURL.path) else { continue }
            guard let infoPlist = NSDictionary(contentsOf: infoPlistURL) as? [String: AnyObject],
                  let bundleID = infoPlist["CFBundleIdentifier"] as? String else { continue }

            var app = DSPThemedApp(
                bundleIdentifier: bundleID,
                name: (infoPlist["CFBundleDisplayName"] as? String) ?? (infoPlist["CFBundleName"] as? String) ?? bundleURL.lastPathComponent,
                version: (infoPlist["CFBundleShortVersionString"] as? String) ?? (infoPlist["CFBundleVersion"] as? String) ?? "1",
                bundleURL: bundleURL,
                pngIconPaths: [],
                hiddenFromSpringboard: false
            )

            if bundleID == "com.apple.mobiletimer" {
                app.pngIconPaths.append("circle_borderless@2x~iphone.png")
            }

            if let icons = infoPlist["CFBundleIcons"] as? [String: AnyObject],
               let primary = icons["CFBundlePrimaryIcon"] as? [String: AnyObject] {
                if let iconFiles = primary["CFBundleIconFiles"] as? [String] {
                    app.pngIconPaths += iconFiles.map { $0.hasSuffix(".png") ? $0 : $0 + "@2x.png" }
                }
            }

            if let bundleIconFile = infoPlist["CFBundleIconFile"] as? String {
                app.pngIconPaths.append(bundleIconFile.hasSuffix(".png") ? bundleIconFile : bundleIconFile + ".png")
            }
            if let bundleIconFiles = infoPlist["CFBundleIconFiles"] as? [String], !bundleIconFiles.isEmpty {
                app.pngIconPaths += bundleIconFiles.map { $0.hasSuffix(".png") ? $0 : $0 + ".png" }
            }
            if let tags = infoPlist["SBAppTags"] as? [String], tags.contains("hidden") {
                app.hiddenFromSpringboard = true
            }

            app.pngIconPaths = Array(NSOrderedSet(array: app.pngIconPaths)) as? [String] ?? app.pngIconPaths
            apps.append(app)
        }

        installedApps = apps.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    func icons(forAppIDs appIDs: [String], from theme: DSPIconTheme) -> [UIImage?] {
        appIDs.map { try? icon(forAppID: $0, from: theme) }
    }

    func icon(forAppID appID: String, from theme: DSPIconTheme) throws -> UIImage {
        let path = theme.url.appendingPathComponent(appID + ".png").path
        guard let image = UIImage(contentsOfFile: path) else {
            throw NSError(domain: "IconThemer", code: 7, userInfo: [NSLocalizedDescriptionKey: "Could not open image"])
        }
        return image
    }

    func availableOverrideChoices(for bundleID: String) -> [(theme: DSPIconTheme, image: UIImage)] {
        themes.compactMap { theme in
            guard let image = try? icon(forAppID: bundleID, from: theme) else { return nil }
            return (theme, image)
        }
    }

    func importTheme(from importURL: URL) throws {
        try importTheme(from: importURL, preferredName: nil)
    }

    func importTheme(from importURL: URL, preferredName: String?) throws {
        createDirectoriesIfNeeded()

        let workingURL = importURL.resolvingSymlinksInPath()
        let derivedThemeName = workingURL.deletingPathExtension().lastPathComponent
        let finalThemeName = sanitizedThemeName(preferredName ?? derivedThemeName)

        let sourceDirectory: URL
        if workingURL.hasDirectoryPath {
            sourceDirectory = try resolveThemeSourceDirectory(from: workingURL)
        } else {
            let ext = workingURL.pathExtension.lowercased()
            if ext == "theme" || ext == "zip" {
                let tempDir = fm.temporaryDirectory.appendingPathComponent("theme_import_\(UUID().uuidString)", isDirectory: true)
                try fm.createDirectory(at: tempDir, withIntermediateDirectories: true, attributes: nil)
                defer { try? fm.removeItem(at: tempDir) }

                let archivePath = tempDir.appendingPathComponent("import.\(ext == "zip" ? "zip" : "theme")")
                try Data(contentsOf: workingURL).write(to: archivePath)
                try unzipFile(at: archivePath, to: tempDir)
                sourceDirectory = try resolveThemeSourceDirectory(from: tempDir)
            } else {
                throw NSError(domain: "IconThemer", code: 8, userInfo: [NSLocalizedDescriptionKey: "Unsupported theme import type: \(workingURL.lastPathComponent)"])
            }
        }

        let themeURL = rawThemesDir.appendingPathComponent(finalThemeName, isDirectory: true)
        try? fm.removeItem(at: themeURL)
        try fm.createDirectory(at: themeURL, withIntermediateDirectories: true, attributes: nil)

        for icon in (try? fm.contentsOfDirectory(at: sourceDirectory, includingPropertiesForKeys: nil)) ?? [] {
            guard icon.pathExtension.lowercased() == "png" else { continue }
            let appID = appIDFromIcon(url: icon)
            let destination = themeURL.appendingPathComponent(appID + ".png")
            try? fm.removeItem(at: destination)
            try fm.copyItem(at: icon, to: destination)
        }

        let importedIcons = ((try? fm.contentsOfDirectory(at: themeURL, includingPropertiesForKeys: nil)) ?? []).filter { $0.pathExtension.lowercased() == "png" }
        if importedIcons.isEmpty {
            try? fm.removeItem(at: themeURL)
            throw NSError(domain: "IconThemer", code: 9, userInfo: [NSLocalizedDescriptionKey: "No icons were found in the imported theme. Expected `IconBundles/<bundle-id>.png`."])
        }

        refreshThemes()
    }

    func removeTheme(_ theme: DSPIconTheme) throws {
        try? fm.removeItem(at: theme.cacheURL)
        try fm.removeItem(at: theme.url)
        selectedThemeNames.removeAll { $0 == theme.name }
        saveSelection()

        var overrides = iconOverrides
        overrides = overrides.filter { $0.value != theme.name }
        iconOverrides = overrides

        refreshThemes()
    }

    func neededChanges() throws -> [DSPAppIconChange] {
        if installedApps.isEmpty {
            try refreshApps()
        }

        let preferredIcons = preferredIcons
        return installedApps
            .filter { !$0.hiddenFromSpringboard && !$0.pngIconPaths.isEmpty }
            .map { app in
                if let themedIcon = preferredIcons[app.bundleIdentifier] {
                    return DSPAppIconChange(app: app, icon: themedIcon)
                }

                var bundleComponents = app.bundleIdentifier.components(separatedBy: ".")
                if bundleComponents.count > 2 {
                    bundleComponents.removeLast()
                    let parentBundleID = bundleComponents.joined(separator: ".")
                    if let themedIcon = preferredIcons[parentBundleID] {
                        return DSPAppIconChange(app: app, icon: themedIcon)
                    }
                }

                return DSPAppIconChange(app: app, icon: nil)
            }
    }

    @discardableResult
    func applyThemes() throws -> [String] {
        createDirectoriesIfNeeded()
        let changes = try neededChanges()
        let changeCount = max(Double(changes.count), 1.0)
        var errors: [String] = []
        var themedCount = 0

        DispatchQueue.main.async {
            self.isApplying = true
            self.applyProgress = 0
            self.applyMessage = "Preparing icon changes..."
        }

        defer {
            DispatchQueue.main.async {
                self.isApplying = false
            }
        }

        for (index, change) in changes.enumerated() {
            autoreleasepool {
                DispatchQueue.main.async {
                    self.applyProgress = Double(index) / changeCount
                    self.applyMessage = "Applying \(change.app.name)"
                }

                do {
                    if let icon = change.icon {
                        themedCount += 1
                        change.app.backUpPNGIcons()
                        try? fm.createDirectory(at: processedThemesDir.appendingPathComponent(icon.themeName), withIntermediateDirectories: true, attributes: nil)
                        try change.app.setPNGIcons(icon: icon)
                    } else {
                        try change.app.restorePNGIcons()
                    }
                } catch {
                    errors.append(error.localizedDescription)
                }
            }
        }

        DispatchQueue.main.async {
            self.applyProgress = 1.0
            self.applyMessage = "Clearing icon cache..."
        }
        clearIconCache()

        UserDefaults.standard.set(themedCount > 0, forKey: pendingFixupKey)
        return errors
    }

    func startPendingFixupIfPossible() {
        guard hasPendingFixup, !isFixingUp, dspmgr.shared.sbxready else { return }
        showFixupSheet = true
        startPendingFixup()
    }

    func startPendingFixup() {
        guard hasPendingFixup, !isFixingUp else { return }
        if installedApps.isEmpty {
            try? refreshApps()
        }

        isFixingUp = true
        fixupProgress = 0
        fixupMessage = "Restoring original app icons..."

        let apps = installedApps.filter { !$0.hiddenFromSpringboard && !$0.pngIconPaths.isEmpty }
        let appCount = max(Double(apps.count), 1.0)

        DispatchQueue.global(qos: .userInitiated).async {
            var errors: [String] = []
            for (index, app) in apps.enumerated() {
                DispatchQueue.main.async {
                    self.fixupProgress = Double(index) / appCount
                    self.fixupMessage = "Fixing \(app.name)"
                }
                do {
                    try app.restorePNGIcons()
                } catch {
                    errors.append(error.localizedDescription)
                }
            }

            DispatchQueue.main.async {
                self.fixupProgress = 1.0
                self.fixupMessage = errors.isEmpty ? "Your apps should now function properly." : errors.joined(separator: "\n\n")
                self.isFixingUp = false
                UserDefaults.standard.set(false, forKey: self.pendingFixupKey)
            }
        }
    }

    func dismissFixupSheet() {
        showFixupSheet = false
    }

    func clearSelectionsForFullReset() {
        selectedThemeNames = []
        saveSelection()
        iconOverrides = [:]
    }

    private func iconFileEnding(iconFilename: String) -> String {
        if iconFilename.contains("-large@2x.png") {
            return "-large@2x"
        } else if iconFilename.contains("-large.png") {
            return "-large"
        } else if iconFilename.contains("@2x.png") {
            return "@2x"
        } else if iconFilename.contains("@3x.png") {
            return "@3x"
        }
        return ""
    }

    private func appIDFromIcon(url: URL) -> String {
        url.deletingPathExtension().lastPathComponent.replacingOccurrences(of: iconFileEnding(iconFilename: url.lastPathComponent), with: "")
    }

    private func resolveThemeSourceDirectory(from url: URL) throws -> URL {
        if url.lastPathComponent == "IconBundles" {
            return url
        }

        let iconBundlesURL = url.appendingPathComponent("IconBundles", isDirectory: true)
        if fm.fileExists(atPath: iconBundlesURL.path) {
            return iconBundlesURL
        }

        if let nested = try findIconBundlesDirectory(in: url) {
            return nested
        }

        let pngs = ((try? fm.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)) ?? []).filter { $0.pathExtension.lowercased() == "png" }
        if !pngs.isEmpty {
            return url
        }

        throw NSError(domain: "IconThemer", code: 10, userInfo: [NSLocalizedDescriptionKey: "Could not find `IconBundles` in \(url.lastPathComponent)"])
    }

    private func sanitizedThemeName(_ name: String) -> String {
        let invalidCharacterSet = CharacterSet(charactersIn: "/:")
            .union(.newlines)
            .union(.illegalCharacters)
            .union(.controlCharacters)
        let cleaned = name.components(separatedBy: invalidCharacterSet).joined(separator: "_").trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? "Imported Theme" : cleaned
    }

    private func findIconBundlesDirectory(in root: URL) throws -> URL? {
        guard let enumerator = fm.enumerator(at: root, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else {
            return nil
        }

        for case let fileURL as URL in enumerator {
            if fileURL.lastPathComponent == "IconBundles" {
                return fileURL
            }
        }
        return nil
    }

    private func unzipFile(at source: URL, to destination: URL) throws {
        let fileData = try Data(contentsOf: source)
        var offset = 0

        while offset < fileData.count - 4 {
            let signature = fileData.subdata(in: offset..<offset + 4).withUnsafeBytes { $0.load(as: UInt32.self) }
            guard signature == 0x04034b50 else { break }
            guard let entry = readLocalFileEntry(data: fileData, offset: offset) else { break }

            let nameRange = offset + 30..<(offset + 30 + entry.nameLength)
            let entryName = String(data: fileData.subdata(in: nameRange), encoding: .utf8) ?? ""
            let contentOffset = offset + 30 + entry.nameLength + entry.extraLength

            if !entryName.hasSuffix("/") {
                let entryDestination = destination.appendingPathComponent(entryName)
                let parentDir = entryDestination.deletingLastPathComponent()
                try fm.createDirectory(at: parentDir, withIntermediateDirectories: true, attributes: nil)

                let fileRange = contentOffset..<(contentOffset + entry.compressedSize)
                if entry.compressionMethod == 0 {
                    let fileEntryData = fileData.subdata(in: fileRange)
                    try fileEntryData.write(to: entryDestination)
                } else if entry.compressionMethod == 8 {
                    let compressedData = fileData.subdata(in: fileRange)
                    guard let decompressed = decompress(deflate: compressedData, originalSize: entry.uncompressedSize) else {
                        throw NSError(domain: "IconThemer", code: 11, userInfo: [NSLocalizedDescriptionKey: "Failed to decompress \(entryName)"])
                    }
                    try decompressed.write(to: entryDestination)
                }
            }

            offset += 30 + entry.nameLength + entry.extraLength + entry.compressedSize
        }
    }

    private struct ZipEntry {
        let compressionMethod: UInt16
        let compressedSize: Int
        let uncompressedSize: Int
        let nameLength: Int
        let extraLength: Int
    }

    private func readLocalFileEntry(data: Data, offset: Int) -> ZipEntry? {
        guard offset + 30 <= data.count else { return nil }

        let compressionMethod = data.subdata(in: offset + 8..<offset + 10).withUnsafeBytes { $0.load(as: UInt16.self) }
        let compressedSize = Int(data.subdata(in: offset + 18..<offset + 22).withUnsafeBytes { $0.load(as: UInt32.self) })
        let uncompressedSize = Int(data.subdata(in: offset + 22..<offset + 26).withUnsafeBytes { $0.load(as: UInt32.self) })
        let nameLength = Int(data.subdata(in: offset + 26..<offset + 28).withUnsafeBytes { $0.load(as: UInt16.self) })
        let extraLength = Int(data.subdata(in: offset + 28..<offset + 30).withUnsafeBytes { $0.load(as: UInt16.self) })

        return ZipEntry(compressionMethod: compressionMethod, compressedSize: compressedSize, uncompressedSize: uncompressedSize, nameLength: nameLength, extraLength: extraLength)
    }

    private func decompress(deflate data: Data, originalSize: Int) -> Data? {
        guard originalSize > 0 else { return Data() }

        let destinationBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: originalSize)
        defer { destinationBuffer.deallocate() }

        let result = data.withUnsafeBytes { sourceBuffer -> Int in
            guard let baseAddress = sourceBuffer.baseAddress else { return 0 }
            return compression_decode_buffer(
                destinationBuffer,
                originalSize,
                baseAddress.assumingMemoryBound(to: UInt8.self),
                data.count,
                nil,
                COMPRESSION_ZLIB
            )
        }

        return result == originalSize ? Data(bytes: destinationBuffer, count: originalSize) : nil
    }

    private func clearIconCache() {
        DSPClearIconCache()
    }
}

struct IconThemeFixupView: View {
    @ObservedObject var manager = IconThemeManager.shared

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Spacer()
                Image(systemName: manager.isFixingUp ? "gear" : "checkmark.seal")
                    .font(.system(size: 64))
                    .foregroundStyle(manager.isFixingUp ? .orange : .green)

                Text(manager.isFixingUp ? "Fixing apps..." : "Fixup complete")
                    .font(.title2.bold())

                Text(manager.fixupMessage.isEmpty ? "Reopen DSPloit after respring and initialize SBX so icon backups can be restored." : manager.fixupMessage)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal)

                ProgressView(value: manager.fixupProgress, total: 1.0)
                    .padding(.horizontal)

                Spacer()

                Button(manager.isFixingUp ? "Please wait" : "Close") {
                    manager.dismissFixupSheet()
                }
                .buttonStyle(.borderedProminent)
                .disabled(manager.isFixingUp)
                .padding(.bottom)
            }
            .navigationTitle("Icon Fixup")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}
