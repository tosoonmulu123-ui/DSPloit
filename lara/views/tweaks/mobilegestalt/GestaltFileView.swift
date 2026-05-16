//
//  GestaltFileView.swift
//  DSPloit
//
//  Created by lunginspector on 5/11/26.
//

import SwiftUI

struct GestaltFileView: View {
    @State private var mgCurrentDict: NSMutableDictionary = NSMutableDictionary()
    @State private var mgCacheExtra: [String : Any] = [:]
    @Environment(\.dismiss) var dismiss
    
    var body: some View {
        NavigationStack {
            List {
                Section(header: HeaderLabel(text: "Files", icon: "loupe"), footer: Text("Modifying MobileGestalt is INCREDIBLY DANGEROUS and may lead to your device getting bricked. Do NOT touch anything in here unless you are absoluetely sure you know what you are doing!")) {
                    Button("Export Original MobileGestalt", action: {
                        mgSavedExport()
                    })
                    
                    Button("Export MobileGestalt from Filesystem", action: {
                        mgFSExport()
                    })
                    
                    Button("Export Current MobileGestalt", action: {
                        mgCurrentExport()
                    })
                }
                
                Section(header: HeaderLabel(text: "CacheExtra", icon: "doc")) {
                    ForEach(mgCacheExtra.keys.sorted(), id: \.self) { key in
                        GestaltKeyRow(key: key, value: mgCacheExtra[key])
                    }
                }
            }
            .navigationTitle("Gestalt File")
            .onAppear {
                do {
                    mgCurrentDict = try NSMutableDictionary(contentsOf: URL(fileURLWithPath: mgCurrentPath), error: ())
                    mgCacheExtra = mgCurrentDict["CacheExtra"] as? [String : Any] ?? [:]
                } catch {
                    Alertinator.shared.alert(title: "Failed to load MobileGestalt!", body: "\(error)")
                }
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button(action: {
                        dismiss()
                    }) {
                        Image(systemName: "xmark")
                    }
                }
            }
        }
    }
    
    func mgSavedExport() {
        let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        let fileURL = documentsURL!.appendingPathComponent("SavedGestalt.plist")
        presentShareSheet(with: fileURL)
    }
    
    func mgFSExport() {
        do {
            let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent("com.apple.MobileGestalt.plist")
            
            if FileManager.default.fileExists(atPath: tempURL.path) {
                try FileManager.default.removeItem(at: tempURL)
            }
            
            try FileManager.default.copyItem(at: URL(fileURLWithPath: mgCurrentPath), to: tempURL)
            presentShareSheet(with: tempURL)
        } catch {
            Alertinator.shared.alert(title: "Failed to export MobileGestalt!", body: "\(error)")
        }
    }
    
    func mgCurrentExport() {
        do {
            let tempURL = FileManager.default.temporaryDirectory.appendingPathComponent("com.apple.MobileGestalt.plist")
            
            if FileManager.default.fileExists(atPath: tempURL.path) {
                try FileManager.default.removeItem(at: tempURL)
            }
            
            let mgCurrentData = try PropertyListSerialization.data(fromPropertyList: mgCurrentDict, format: .binary, options: 0)
            try mgCurrentData.write(to: tempURL)
            presentShareSheet(with: tempURL)
        } catch {
            Alertinator.shared.alert(title: "Failed to export MobileGestalt!", body: "\(error)")
        }
    }
}

struct GestaltKeyRow: View {
    let key: String
    let value: Any?
    @State private var editableText: String = ""
    @State private var nestedDict: [String: Any] = [:]
    @State private var showNestedDict: Bool = false
    
    var body: some View {
        if type == "Dictionary" {
            LabeledContent(content: {
                Button(action: {
                    showNestedDict.toggle()
                }) {
                    HStack {
                        Text("Dictionary")
                        Image(systemName: "chevron.down")
                            .frame(width: 24, height: 24, alignment: .center)
                            .rotationEffect(.degrees(showNestedDict ? 0 : -90))
                            .animation(.easeInOut(duration: 0.2), value: showNestedDict)
                    }
                }
                .foregroundStyle(Color(.label))
            }) {
                Text(key)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .onAppear {
                nestedDict = value as? [String: Any] ?? [:]
            }
            
            if showNestedDict {
                ForEach(nestedDict.keys.sorted(), id: \.self) { nestedKey in
                    GestaltKeyRow(key: nestedKey, value: nestedDict[nestedKey])
                        .listRowBackground(Color(.secondarySystemFill))
                }
            }
        } else {
            LabeledContent(content: {
                Text(readableLabel(value))
                    .foregroundStyle(.secondary)
            }) {
                Text(key)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
    
    private var type: String {
        switch value {
        case is String: return "String"
        case is Bool: return "Bool"
        case is Int: return "Int"
        case is Data: return "Data"
        case is [String : Any]: return "Dictionary"
        default: return "Unknown"
        }
    }
    
    private func readableLabel(_ value: Any?) -> String {
        switch value {
        case let v as String: return v
        case let v as Bool: return v ? "True" : "False"
        case let v as Int: return String(v)
        case let v as Data: return v.base64EncodedString()
        default: return "Unknown"
        }
    }
}
