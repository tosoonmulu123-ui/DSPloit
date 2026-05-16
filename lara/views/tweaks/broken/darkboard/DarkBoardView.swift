//
//  DarkBoard.swift
//  DSPloit
//
//  Created by ruter on 24.04.26.
//  skidded from Cowabunga, credit goes to lemin and co.
//

import SwiftUI
import UniformTypeIdentifiers
import UIKit

private struct DarkBoardAlert: Identifiable {
    let id = UUID()
    let message: String
}

private struct OverrideChoice: Identifiable {
    let theme: DSPIconTheme
    let image: UIImage

    var id: String { theme.name }
}

struct DarkBoardView: View {
    @ObservedObject private var manager = IconThemeManager.shared
    @ObservedObject private var mgr = dspmgr.shared

    @State private var showImporter = false
    @State private var alert: DarkBoardAlert?
    @State private var pendingImportURL: URL?

    private let previewBundleIDs = [
        "com.apple.mobilephone",
        "com.apple.mobilesafari",
        "com.apple.mobileslideshow",
        "com.apple.camera",
        "com.apple.AppStore",
        "com.apple.Preferences",
        "com.apple.Music",
        "com.apple.calculator",
    ]

    private let grid = [GridItem(.adaptive(minimum: 160), spacing: 12)]

    var body: some View {
        ZStack(alignment: .bottom) {
            ScrollView {
                VStack(spacing: 16) {
                    helperCards
                    themeGrid
                }
                .padding()
                .padding(.bottom, 90)
            }

            if !manager.themes.isEmpty {
                Button {
                    applyThemes()
                } label: {
                    Text("Apply Themes")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(manager.selectedThemeNames.isEmpty ? Color.secondary.opacity(0.25) : Color.accentColor)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .padding()
                }
                .disabled(manager.selectedThemeNames.isEmpty || manager.isApplying)
            }
        }
        .navigationTitle("DarkBoard")
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button(role: .destructive) {
                    manager.clearSelectionsForFullReset()
                    applyThemes()
                } label: {
                    Image(systemName: "arrow.counterclockwise")
                }
                .disabled(manager.isApplying)
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showImporter = true
                } label: {
                    Image(systemName: "square.and.arrow.down")
                }
                .disabled(manager.isApplying)
            }
        }
        .sheet(isPresented: $showImporter) {
            ThemeImportPicker(selectedURL: $pendingImportURL)
        }
        .alert(item: $alert) { alert in
            Alert(title: Text("DarkBoard"), message: Text(alert.message), dismissButton: .default(Text("OK")))
        }
        .overlay {
            if manager.isApplying {
                progressOverlay(title: "Applying Icons", message: manager.applyMessage, progress: manager.applyProgress)
            }
        }
        .onAppear {
            manager.refreshThemes()
            try? manager.refreshApps()
            manager.startPendingFixupIfPossible()
        }
        .onChange(of: pendingImportURL) { url in
            guard let url else { return }
            handleImport(url)
            pendingImportURL = nil
        }
    }

    private var helperCards: some View {
        VStack(spacing: 12) {
            if !mgr.sbxready {
                Text("Initialize SBX first. This icon themer uses SBX-backed file reads and writes, then restores backups after the respring fixup.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.thinMaterial)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
            }

            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Themes")
                        .font(.headline)
                    Text("\(manager.themes.count) imported")
                        .foregroundStyle(.secondary)
                        .font(.caption)
                }
                Spacer()
                NavigationLink("Explore") {
                    DarkBoardExploreView()
                }
                .buttonStyle(.bordered)
                NavigationLink("Overrides") {
                    IconOverridesView()
                }
                .buttonStyle(.bordered)
            }
            .padding()
            .background(.thinMaterial)
            .clipShape(RoundedRectangle(cornerRadius: 16))

            if manager.themes.isEmpty {
                Text("Import a folder, `.theme`, or `.zip` containing `IconBundles/<bundle-id>.png` icons.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.thinMaterial)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
            }
        }
    }

    private var themeGrid: some View {
        LazyVGrid(columns: grid, spacing: 12) {
            ForEach(manager.themes) { theme in
                ThemeCardView(
                    theme: theme,
                    previews: manager.icons(forAppIDs: previewBundleIDs, from: theme),
                    selectionIndex: manager.selectedThemeNames.firstIndex(of: theme.name),
                    onToggle: { manager.toggleThemeSelection(theme) },
                    onDelete: { removeTheme(theme) }
                )
            }
        }
    }

    private func applyThemes() {
        guard mgr.sbxready else {
            alert = DarkBoardAlert(message: "SBX is not initialized. Run the exploit, initialize SBX, then apply again.")
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let errors = try manager.applyThemes()
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                    if errors.isEmpty {
                        alert = DarkBoardAlert(message: "Icons applied. Respring now. After reopening DSPloit, initialize SBX again so the post-respring icon fixup can restore the original bundle files.")
                    } else {
                        alert = DarkBoardAlert(message: "Applied with some errors:\n\n" + errors.joined(separator: "\n\n"))
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    alert = DarkBoardAlert(message: error.localizedDescription)
                }
            }
        }
    }

    private func handleImport(_ url: URL) {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed {
                url.stopAccessingSecurityScopedResource()
            }
        }

        do {
            try manager.importTheme(from: url)
        } catch {
            alert = DarkBoardAlert(message: error.localizedDescription)
        }
    }

    private func removeTheme(_ theme: DSPIconTheme) {
        do {
            try manager.removeTheme(theme)
        } catch {
            alert = DarkBoardAlert(message: error.localizedDescription)
        }
    }

    @ViewBuilder
    private func progressOverlay(title: String, message: String, progress: Double) -> some View {
        ZStack {
            Color.black.opacity(0.15).ignoresSafeArea()
            VStack(spacing: 12) {
                ProgressView(value: progress, total: 1.0)
                Text(title).font(.headline)
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(20)
            .frame(maxWidth: 320)
            .background(.regularMaterial)
            .clipShape(RoundedRectangle(cornerRadius: 18))
        }
    }
}

private struct ThemeCardView: View {
    let theme: DSPIconTheme
    let previews: [UIImage?]
    let selectionIndex: Int?
    let onToggle: () -> Void
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color.secondary.opacity(0.15))
                    .frame(height: 94)

                if previews.compactMap({ $0 }).count >= 4 {
                    VStack(spacing: 4) {
                        HStack(spacing: 4) {
                            ForEach(0..<4, id: \.self) { idx in
                                previewCell(previews[safe: idx] ?? nil)
                            }
                        }
                        HStack(spacing: 4) {
                            ForEach(4..<8, id: \.self) { idx in
                                previewCell(previews[safe: idx] ?? nil)
                            }
                        }
                    }
                } else {
                    Text("Not enough icons for preview")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }

            HStack {
                Text(theme.name)
                    .font(.headline)
                    .lineLimit(1)
                Spacer()
                Text("\(theme.iconCount)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Button(action: onToggle) {
                Text(selectionIndex == nil ? "Select" : "Selected: \(selectionIndex! + 1)")
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(selectionIndex == nil ? Color.secondary.opacity(0.2) : Color.accentColor)
                    .foregroundStyle(selectionIndex == nil ? Color.primary : Color.white)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
            }

            Button(role: .destructive, action: onDelete) {
                Text("Remove")
                    .font(.caption)
            }
        }
        .padding()
        .background(.thinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 18))
    }

    @ViewBuilder
    private func previewCell(_ image: UIImage?) -> some View {
        if let image {
            Image(uiImage: image)
                .resizable()
                .frame(width: 28, height: 28)
                .clipShape(RoundedRectangle(cornerRadius: 7))
        } else {
            RoundedRectangle(cornerRadius: 7)
                .fill(Color.clear)
                .frame(width: 28, height: 28)
        }
    }
}

struct IconOverridesView: View {
    @ObservedObject private var manager = IconThemeManager.shared

    @State private var search = ""

    var body: some View {
        List {
            ForEach(filteredApps, id: \.id) { app in
                NavigationLink {
                    OverrideSelectionView(app: app)
                } label: {
                    HStack(spacing: 12) {
                        if let icon = app.loadPreviewIcon() {
                            Image(uiImage: icon)
                                .resizable()
                                .frame(width: 40, height: 40)
                                .clipShape(RoundedRectangle(cornerRadius: 9))
                        } else {
                            Image("unknown")
                                .resizable()
                                .frame(width: 40, height: 40)
                                .clipShape(RoundedRectangle(cornerRadius: 9))
                        }
                        VStack(alignment: .leading) {
                            Text(app.name)
                            Text(app.bundleIdentifier)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if manager.iconOverrides[app.bundleIdentifier] != nil {
                            Image(systemName: "lock.fill")
                                .foregroundStyle(Color.accentColor)
                        }
                    }
                }
            }
        }
        .navigationTitle("Overrides")
        .searchable(text: $search)
        .onAppear {
            try? manager.refreshApps()
        }
    }

    private var filteredApps: [DSPThemedApp] {
        let visibleApps = manager.installedApps.filter { !$0.hiddenFromSpringboard }
        guard !search.isEmpty else { return visibleApps }
        return visibleApps.filter {
            $0.name.localizedCaseInsensitiveContains(search) || $0.bundleIdentifier.localizedCaseInsensitiveContains(search)
        }
    }
}

private struct OverrideSelectionView: View {
    @ObservedObject private var manager = IconThemeManager.shared

    let app: DSPThemedApp

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            if manager.iconOverrides[app.bundleIdentifier] != nil {
                Button(role: .destructive) {
                    manager.removeOverride(for: app.bundleIdentifier)
                    dismiss()
                } label: {
                    Text("Remove Override")
                }
            }

            ForEach(choices) { choice in
                Button {
                    manager.setOverride(bundleID: app.bundleIdentifier, themeName: choice.theme.name)
                    dismiss()
                } label: {
                    HStack(spacing: 12) {
                        Image(uiImage: choice.image)
                            .resizable()
                            .frame(width: 60, height: 60)
                            .clipShape(RoundedRectangle(cornerRadius: 14))
                        VStack(alignment: .leading) {
                            Text(choice.theme.name)
                            Text(choice.theme.name == manager.iconOverrides[app.bundleIdentifier] ? "Current override" : "Tap to set")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                }
            }
        }
        .navigationTitle(app.name)
        .navigationBarTitleDisplayMode(.inline)
    }

    private var choices: [OverrideChoice] {
        manager.availableOverrideChoices(for: app.bundleIdentifier).map { OverrideChoice(theme: $0.theme, image: $0.image) }
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}

private struct ThemeImportPicker: UIViewControllerRepresentable {
    @Binding var selectedURL: URL?
    @Environment(\.dismiss) private var dismiss

    func makeCoordinator() -> Coordinator {
        Coordinator(selectedURL: $selectedURL, dismiss: dismiss)
    }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        var contentTypes: [UTType] = [.folder, .zip]
        if let themeType = UTType(filenameExtension: "theme") {
            contentTypes.append(themeType)
        }

        let picker = UIDocumentPickerViewController(forOpeningContentTypes: contentTypes, asCopy: false)
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = false
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        @Binding var selectedURL: URL?
        let dismissAction: DismissAction

        init(selectedURL: Binding<URL?>, dismiss: DismissAction) {
            self._selectedURL = selectedURL
            self.dismissAction = dismiss
        }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            selectedURL = urls.first
            dismissAction()
        }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
            dismissAction()
        }
    }
}
