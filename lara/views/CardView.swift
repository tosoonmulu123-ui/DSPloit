//
//  CardView.swift
//  lara
//
//  Created by ruter on 29.03.26.
//

import SwiftUI
import PDFKit
import UniformTypeIdentifiers

enum ReplaceOption: String, CaseIterable, Identifiable {
    case photos = "Photos"
    case files = "Files"
    
    var id: String { self.rawValue }
}

struct CardView: View {
    @ObservedObject private var mgr = laramgr.shared
    @State private var cards: [CardItem] = []
    @State private var status: String?
    @State private var working = false
    @State private var showimgpicker = false
    @State private var showDocPicker = false
    @State private var pendingCard: CardItem?
    @State private var pickedImageData: Data?
    @State private var showCardNumberEditor = false
    @State private var cardNumberInput = ""
    @State private var currentCardNumber = ""
    @State private var pendingNumberCard: CardItem?
    @State private var pendingRestoreCard: CardItem?
    @State private var selectedOption: ReplaceOption? = nil

    private struct CardItem: Identifiable {
        let id: String
        let imagePath: String
        let directoryPath: String
        let bundleName: String
        let backgroundFileName: String
    }

    var body: some View {
        List {
            Section {
                Button {
                    refreshCards()
                } label: {
                    if working {
                        HStack {
                            ProgressView()
                            Text(L("Scanning...", "Memindai..."))
                        }
                    } else {
                        Text(L("Refresh", "Muat Ulang"))
                    }
                }
                .disabled(working)
            } header: {
                Text(L("Actions", "Aksi"))
            } footer: {
                Text(L("Uses SBX first and falls back to VFS for overwrite.\nGet card images [here](https://dynalist.io/d/ldKY6rbMR3LPnWz4fTvf_HCh).", "Menggunakan SBX terlebih dahulu lalu fallback ke VFS untuk overwrite.\nAmbil gambar kartu [di sini](https://dynalist.io/d/ldKY6rbMR3LPnWz4fTvf_HCh)."))
            }

            if cards.isEmpty {
                Section {
                    Text(L("No cards found.", "Tidak ada kartu ditemukan."))
                        .foregroundColor(.secondary)
                }
            } else {
                ForEach(cards) { card in
                    Section {
                        HStack(spacing: 12) {
                            if let img = previewImage(for: card) {
                                Image(uiImage: img)
                                    .resizable()
                                    .scaledToFit()
                                    .frame(width: 140, height: 90)
                                    .cornerRadius(8)
                            } else {
                                RoundedRectangle(cornerRadius: 8)
                                    .fill(Color.gray.opacity(0.2))
                                    .frame(width: 140, height: 90)
                                    .overlay(
                                        Image(systemName: "creditcard.fill")
                                            .foregroundColor(.secondary)
                                    )
                            }
                            
                            VStack(alignment: .leading, spacing: 6) {
                                Text(card.bundleName)
                                    .font(.headline)
                                Text(card.imagePath)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .lineLimit(2)
                            }
                            
                            Spacer()
                        }
                        
                        Picker(L("Replace", "Ganti"), selection: $selectedOption) {
                            Text(L("Select…", "Pilih…")).tag(ReplaceOption?.none)
                            ForEach(ReplaceOption.allCases) { option in
                                Text(option.rawValue).tag(Optional(option))
                            }
                        }
                        .pickerStyle(MenuPickerStyle()) // dropdown style
                        .onChange(of: selectedOption) { option in
                            guard let option = option else { return }
                            pendingCard = card // your current card
                            switch option {
                            case .photos:
                                showimgpicker = true
                            case .files:
                                showDocPicker = true
                            }
                            
                            selectedOption = nil
                        }
                            
                            Button(L("Restore", "Pulihkan")) {
                                pendingRestoreCard = card
                                restoreImage(card: card)
                            }
                            .foregroundColor(.red)
                        
                        Button(L("Edit Card Number", "Ubah Nomor Kartu")) {
                            pendingNumberCard = card
                            currentCardNumber = readCardNumber(for: card) ?? ""
                            cardNumberInput = currentCardNumber
                            showCardNumberEditor = true
                        }
                    } header: {
                        Text(card.backgroundFileName)
                    }
                    
                    Section {
                        HStack(alignment: .top) {
                            AsyncImage(url: URL(string: "https://github.com/drkm9743.png")) { image in
                                image
                                    .resizable()
                                    .scaledToFill()
                            } placeholder: {
                                ProgressView()
                            }
                            .frame(width: 40, height: 40)
                            .clipShape(Circle())
                            
                            VStack(alignment: .leading) {
                                Text("drkm9743")
                                    .font(.headline)
                                
                                Text(L("Inspiration.", "Inspirasi."))
                                    .font(.subheadline)
                                    .foregroundColor(Color.secondary)
                            }
                            
                            Spacer()
                        }
                        .onTapGesture {
                            if let url = URL(string: "https://github.com/drkm9743"),
                               UIApplication.shared.canOpenURL(url) {
                                UIApplication.shared.open(url)
                            }
                        }
                    } header: {
                        Text(L("Credits", "Kredit"))
                    }
                }
            }
        }
        .navigationTitle(L("Card Overwrite", "Overwrite Kartu"))
        .alert(L("Status", "Status"), isPresented: .constant(status != nil)) {
            Button("OK") { status = nil }
        } message: {
            Text(status ?? "")
        }
        .alert(L("Edit Card Number", "Ubah Nomor Kartu"), isPresented: $showCardNumberEditor) {
            TextField(L("Suffix", "Akhiran"), text: $cardNumberInput)
            Button(L("Save", "Simpan")) {
                if let card = pendingNumberCard {
                    applyCardNumber(card: card, newSuffix: cardNumberInput)
                }
            }
            if let card = pendingNumberCard, hasPassJsonBackup(card: card) {
                Button(L("Restore Original", "Pulihkan Asli"), role: .destructive) {
                    restorePassJson(card: card)
                }
            }
            Button(L("Cancel", "Batal"), role: .cancel) {}
        } message: {
            Text(currentCardNumber.isEmpty ? L("Current suffix: (none)", "Akhiran saat ini: (tidak ada)") : L("Current suffix:", "Akhiran saat ini:") + " \(currentCardNumber)")
        }
        .sheet(isPresented: $showimgpicker) {
            ImagePicker(imageData: $pickedImageData)
        }
        .sheet(isPresented: $showDocPicker) {
            CardImageDocumentPicker(imageData: $pickedImageData)
        }
        .onChange(of: pickedImageData) { _ in
            guard let card = pendingCard, let data = pickedImageData else { return }
            pendingCard = nil
            pickedImageData = nil
            applyReplacement(card: card, imageData: data)
        }
        .onAppear {
            refreshCards()
        }
    }

    private func refreshCards() {
        guard !working else { return }
        working = true
        DispatchQueue.global(qos: .userInitiated).async {
            let items = scanCards()
            DispatchQueue.main.async {
                self.cards = items
                self.working = false
            }
        }
    }

    private func scanCards() -> [CardItem] {
        let candidates = [
            "/var/mobile/Library/Passes/Cards",
            "/private/var/mobile/Library/Passes/Cards",
            "/var/mobile/Library/Passes/Passes/Cards",
            "/private/var/mobile/Library/Passes/Passes/Cards"
        ]

        for root in candidates {
            let bundles = collectCardBundles(in: root)
            if !bundles.isEmpty {
                return bundles
            }
        }

        let passContainers = ["/var/mobile/Library/Passes", "/private/var/mobile/Library/Passes"]
        for container in passContainers {
            let topEntries = listDirectory(container)
            for primary in ["Cards", "Passes", "Wallet"] where topEntries.contains(primary) {
                let candidate = joinPath(container, primary)
                let bundles = collectCardBundles(in: candidate)
                if !bundles.isEmpty { return bundles }
                let nested = joinPath(candidate, "Cards")
                let nestedBundles = collectCardBundles(in: nested)
                if !nestedBundles.isEmpty { return nestedBundles }
            }
        }

        return []
    }

    private func collectCardBundles(in cardsRoot: String) -> [CardItem] {
        let entries = listDirectory(cardsRoot)
        guard !entries.isEmpty else { return [] }

        var bundles: [CardItem] = []
        var seenDirectories: Set<String> = []

        for entry in entries where entry != "." && entry != ".." {
            let candidateDirectory = joinPath(cardsRoot, entry)
            if let backgroundFile = cardBackgroundFile(in: candidateDirectory) {
                if !seenDirectories.contains(candidateDirectory) {
                    bundles.append(CardItem(
                        id: candidateDirectory,
                        imagePath: joinPath(candidateDirectory, backgroundFile),
                        directoryPath: candidateDirectory,
                        bundleName: entry,
                        backgroundFileName: backgroundFile
                    ))
                    seenDirectories.insert(candidateDirectory)
                }
                continue
            }

            let nestedEntries = listDirectory(candidateDirectory)
            for nested in nestedEntries where nested != "." && nested != ".." {
                let nestedDirectory = joinPath(candidateDirectory, nested)
                if let backgroundFile = cardBackgroundFile(in: nestedDirectory),
                   !seenDirectories.contains(nestedDirectory) {
                    bundles.append(CardItem(
                        id: nestedDirectory,
                        imagePath: joinPath(nestedDirectory, backgroundFile),
                        directoryPath: nestedDirectory,
                        bundleName: "\(entry)/\(nested)",
                        backgroundFileName: backgroundFile
                    ))
                    seenDirectories.insert(nestedDirectory)
                }
            }
        }

        return bundles
    }

    private func cardBackgroundFile(in cardDirectory: String) -> String? {
        let files = listDirectory(cardDirectory)
        guard !files.isEmpty else { return nil }

        let preferred = [
            "cardBackgroundCombined@2x.png",
            "cardBackgroundCombined@3x.png",
            "cardBackgroundCombined.png",
            "cardBackgroundCombined.pdf"
        ]
        for name in preferred where files.contains(name) {
            return name
        }
        return files.first { file in
            let lower = file.lowercased()
            return lower.hasPrefix("cardbackgroundcombined") && (lower.hasSuffix(".png") || lower.hasSuffix(".pdf"))
        }
    }

    private func listDirectory(_ path: String) -> [String] {
        let fm = FileManager.default
        for variant in pathVariants(for: path) {
            if let direct = try? fm.contentsOfDirectory(atPath: variant) {
                return direct
            }
        }

        guard mgr.vfsready else { return [] }
        for variant in pathVariants(for: path) {
            _ = access(variant, F_OK)
        }
        for variant in pathVariants(for: path) {
            if let entries = mgr.vfslistdir(path: variant) {
                return entries.map { $0.name }
            }
        }

        return []
    }

    private func pathVariants(for path: String) -> [String] {
        var variants: [String] = [path]
        if path.hasPrefix("/private/var/") {
            variants.append(String(path.dropFirst("/private".count)))
        } else if path.hasPrefix("/var/") {
            variants.append("/private" + path)
        }
        var unique: [String] = []
        for variant in variants where !unique.contains(variant) {
            unique.append(variant)
        }
        return unique
    }

    private func joinPath(_ parent: String, _ child: String) -> String {
        if parent.hasSuffix("/") { return parent + child }
        return parent + "/" + child
    }

    private func previewImage(for card: CardItem) -> UIImage? {
        let lower = card.backgroundFileName.lowercased()
        if lower.hasSuffix(".pdf") {
            if let doc = PDFDocument(url: URL(fileURLWithPath: card.imagePath)),
               let page = doc.page(at: 0) {
                return page.thumbnail(of: CGSize(width: 640, height: 400), for: .cropBox)
            }
        } else if let img = UIImage(contentsOfFile: card.imagePath) {
            return img
        }

        if mgr.vfsready, let data = mgr.vfsread(path: card.imagePath, maxSize: 8 * 1024 * 1024) {
            if lower.hasSuffix(".pdf") {
                if let doc = PDFDocument(data: data),
                   let page = doc.page(at: 0) {
                    return page.thumbnail(of: CGSize(width: 640, height: 400), for: .cropBox)
                }
            } else {
                return UIImage(data: data)
            }
        }
        return nil
    }

    private func applyReplacement(card: CardItem, imageData: Data) {
        guard let image = UIImage(data: imageData) else {
            status = "Invalid image data"
            return
        }

        let lower = card.backgroundFileName.lowercased()
        var payload: Data?
        if lower.hasSuffix(".png") {
            payload = image.pngData()
        } else if lower.hasSuffix(".pdf") {
            let pdf = PDFDocument()
            if let page = PDFPage(image: image) {
                pdf.insert(page, at: 0)
                payload = pdf.dataRepresentation()
            }
        } else {
            payload = image.pngData()
        }

        guard let data = payload else {
            status = "Failed to encode image"
            return
        }

        backupIfNeeded(card: card)
        if writePreferSBX(path: card.imagePath, data: data) {
            clearCache(for: card)
            status = "Card updated"
        } else {
            status = "Failed to overwrite card"
        }
    }

    private func backupIfNeeded(card: CardItem) {
        let backupPath = card.imagePath + ".backup"
        let fm = FileManager.default
        if fm.fileExists(atPath: backupPath) { return }
        if let data = readPreferSBX(path: card.imagePath, maxSize: 16 * 1024 * 1024) {
            _ = writePreferSBX(path: backupPath, data: data)
        }
    }

    private func restoreImage(card: CardItem) {
        let backupPath = card.imagePath + ".backup"
        guard FileManager.default.fileExists(atPath: backupPath) else {
            status = "No backup found"
            return
        }
        guard let data = readPreferSBX(path: backupPath, maxSize: 16 * 1024 * 1024) else {
            status = "Failed to read backup"
            return
        }
        if writePreferSBX(path: card.imagePath, data: data) {
            clearCache(for: card)
            status = "Restored card image"
        } else {
            status = "Restore failed"
        }
    }

    private func passJsonPath(for card: CardItem) -> String {
        card.directoryPath + "/pass.json"
    }

    private func passJsonBackupPath(for card: CardItem) -> String {
        card.directoryPath + "/pass.json.backup"
    }

    private func hasPassJsonBackup(card: CardItem) -> Bool {
        FileManager.default.fileExists(atPath: passJsonBackupPath(for: card))
    }

    private func readPassJson(for card: CardItem) -> Data? {
        if let data = readPreferSBX(path: passJsonPath(for: card), maxSize: 512 * 1024) {
            return data
        }
        return nil
    }

    private func readCardNumber(for card: CardItem) -> String? {
        guard let data = readPassJson(for: card),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let suffix = json["primaryAccountSuffix"] as? String else {
            return nil
        }
        return suffix
    }

    private func backupPassJsonIfNeeded(card: CardItem) {
        let src = passJsonPath(for: card)
        let backup = passJsonBackupPath(for: card)
        guard !FileManager.default.fileExists(atPath: backup) else { return }
        guard let data = readPreferSBX(path: src, maxSize: 512 * 1024) else { return }
        _ = writePreferSBX(path: backup, data: data)
    }

    private func applyCardNumber(card: CardItem, newSuffix: String) {
        guard var json = (readPassJson(for: card)).flatMap({ try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }) else {
            status = "Failed to read pass.json"
            return
        }
        backupPassJsonIfNeeded(card: card)
        let trimmed = newSuffix.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            json.removeValue(forKey: "primaryAccountSuffix")
        } else {
            json["primaryAccountSuffix"] = trimmed
        }
        guard let data = try? JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys]) else {
            status = "Failed to encode pass.json"
            return
        }
        if writePreferSBX(path: passJsonPath(for: card), data: data) {
            clearCache(for: card)
            currentCardNumber = trimmed
            status = "Card number updated"
        } else {
            status = "Failed to update pass.json"
        }
    }

    private func restorePassJson(card: CardItem) {
        let backup = passJsonBackupPath(for: card)
        guard FileManager.default.fileExists(atPath: backup) else {
            status = "No pass.json backup"
            return
        }
        guard let data = readPreferSBX(path: backup, maxSize: 512 * 1024) else {
            status = "Failed to read backup"
            return
        }
        if writePreferSBX(path: passJsonPath(for: card), data: data) {
            clearCache(for: card)
            currentCardNumber = readCardNumber(for: card) ?? ""
            status = "Restored pass.json"
        } else {
            status = "Failed to restore pass.json"
        }
    }

    private func clearCache(for card: CardItem) {
        let fm = FileManager.default
        let dir = card.directoryPath
        let cachePath: String
        if dir.lowercased().hasSuffix(".pkpass") {
            cachePath = dir.replacingOccurrences(of: "pkpass", with: "cache")
        } else {
            cachePath = dir + ".cache"
        }
        if fm.fileExists(atPath: cachePath) {
            try? fm.removeItem(atPath: cachePath)
        }
    }

    private func readPreferSBX(path: String, maxSize: Int) -> Data? {
        if let data = try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe) {
            return data.count > maxSize ? data.prefix(maxSize) : data
        }
        if mgr.vfsready {
            return mgr.vfsread(path: path, maxSize: maxSize)
        }
        return nil
    }

    private func writePreferSBX(path: String, data: Data) -> Bool {
        do {
            try data.write(to: URL(fileURLWithPath: path), options: .atomic)
            return true
        } catch {
            let result = mgr.lara_writeexpandsafe(target: path, data: data)
            if !result.ok {
                mgr.logmsg("card write fallback failed: \(result.message)")
            }
            return result.ok
        }
    }
}

struct CardImageDocumentPicker: UIViewControllerRepresentable {
    @Binding var imageData: Data?

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let types: [UTType] = [.png, .jpeg, .image]
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: types, asCopy: true)
        picker.delegate = context.coordinator
        picker.allowsMultipleSelection = false
        return picker
    }

    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let parent: CardImageDocumentPicker
        init(_ parent: CardImageDocumentPicker) { self.parent = parent }

        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
            guard let url = urls.first else { return }
            _ = url.startAccessingSecurityScopedResource()
            defer { url.stopAccessingSecurityScopedResource() }

            if let data = try? Data(contentsOf: url) {
                parent.imageData = data
            }
        }

        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {}
    }
}
