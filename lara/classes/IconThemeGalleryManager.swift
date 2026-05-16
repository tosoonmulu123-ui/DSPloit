import Foundation
import Combine

enum IconThemeGalleryFilter: String, CaseIterable, Identifiable {
    case random = "Random"
    case newest = "Newest"
    case oldest = "Oldest"

    var id: String { rawValue }
}

struct GalleryThemeContact: Codable, Hashable {
    let values: [String: String]

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        values = try container.decode([String: String].self)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(values)
    }

    var displayName: String {
        values.values.first ?? "Unknown author"
    }
}

struct GalleryTheme: Identifiable, Codable, Hashable {
    let name: String
    let description: String
    let url: String
    let preview: String
    let contact: GalleryThemeContact
    let version: String

    var id: String { name }
}

@MainActor
final class IconThemeGalleryManager: ObservableObject {
    static let shared = IconThemeGalleryManager()

    @Published var themes: [GalleryTheme] = []
    @Published var isLoading = false
    @Published var loadError: String?
    @Published var downloadingThemeNames: Set<String> = []

    private let session = URLSession.shared
    private let decoder = JSONDecoder()
    private var serverBaseURL: URL?

    private init() {}

    func loadThemes(forceRefresh: Bool = false) async {
        if isLoading { return }
        isLoading = true
        loadError = nil
        defer { isLoading = false }

        do {
            let baseURL = try await fetchServerBaseURL(forceRefresh: forceRefresh)
            let url = baseURL.appendingPathComponent("icon-themes.json")
            let (data, response) = try await session.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                throw NSError(domain: "IconThemeGallery", code: 1, userInfo: [NSLocalizedDescriptionKey: "Could not fetch the Cowabunga theme gallery."])
            }
            themes = try decoder.decode([GalleryTheme].self, from: data)
        } catch {
            themes = []
            loadError = error.localizedDescription
        }
    }

    func filteredThemes(searchTerm: String, filter: IconThemeGalleryFilter) -> [GalleryTheme] {
        let trimmedSearch = searchTerm.trimmingCharacters(in: .whitespacesAndNewlines)
        var filtered = themes

        if !trimmedSearch.isEmpty {
            filtered = filtered.filter {
                $0.name.localizedCaseInsensitiveContains(trimmedSearch) ||
                $0.contact.displayName.localizedCaseInsensitiveContains(trimmedSearch) ||
                $0.description.localizedCaseInsensitiveContains(trimmedSearch)
            }
        }

        switch filter {
        case .random:
            return filtered.shuffled()
        case .newest:
            return Array(filtered.reversed())
        case .oldest:
            return filtered
        }
    }

    func previewURL(for theme: GalleryTheme) -> URL? {
        guard let serverBaseURL else {
            return URL(string: theme.preview)
        }
        return URL(string: theme.preview, relativeTo: serverBaseURL)?.absoluteURL
    }

    func isDownloading(_ theme: GalleryTheme) -> Bool {
        downloadingThemeNames.contains(theme.name)
    }

    func downloadAndImport(_ theme: GalleryTheme, importer: IconThemeManager? = nil) async throws {
        let actualImporter = importer ?? IconThemeManager.shared
        if downloadingThemeNames.contains(theme.name) { return }
        downloadingThemeNames.insert(theme.name)
        defer { downloadingThemeNames.remove(theme.name) }

        let remoteURL = try await absoluteURL(for: theme.url)
        let (temporaryURL, response) = try await session.download(from: remoteURL)
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            throw NSError(domain: "IconThemeGallery", code: 2, userInfo: [NSLocalizedDescriptionKey: "Could not download \(theme.name)."])
        }

        let fileExtension = remoteURL.pathExtension.isEmpty ? "zip" : remoteURL.pathExtension
        let importURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).appendingPathExtension(fileExtension)
        try? FileManager.default.removeItem(at: importURL)
        try FileManager.default.moveItem(at: temporaryURL, to: importURL)
        defer { try? FileManager.default.removeItem(at: importURL) }

        try actualImporter.importTheme(from: importURL, preferredName: theme.name)
    }

    private func absoluteURL(for relativePath: String) async throws -> URL {
        let baseURL = try await fetchServerBaseURL(forceRefresh: false)
        guard let url = URL(string: relativePath, relativeTo: baseURL)?.absoluteURL else {
            throw NSError(domain: "IconThemeGallery", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid gallery URL for \(relativePath)."])
        }
        return url
    }

    private func fetchServerBaseURL(forceRefresh: Bool) async throws -> URL {
        if let serverBaseURL, !forceRefresh {
            return serverBaseURL
        }

        let commitURL = URL(string: "https://api.github.com/repos/leminlimez/Cowabunga-explore-repo/commits/main")!
        let (data, response) = try await session.data(from: commitURL)
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            throw NSError(domain: "IconThemeGallery", code: 4, userInfo: [NSLocalizedDescriptionKey: "Could not reach the Cowabunga gallery repository."])
        }

        guard
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            let sha = json["sha"] as? String,
            let baseURL = URL(string: "https://raw.githubusercontent.com/leminlimez/Cowabunga-explore-repo/\(sha)/")
        else {
            throw NSError(domain: "IconThemeGallery", code: 5, userInfo: [NSLocalizedDescriptionKey: "Could not resolve the Cowabunga gallery version."])
        }

        serverBaseURL = baseURL
        return baseURL
    }
}
