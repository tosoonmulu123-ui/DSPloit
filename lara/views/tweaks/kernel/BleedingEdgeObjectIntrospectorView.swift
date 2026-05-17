//
//  BleedingEdgeObjectIntrospectorView.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Kernel Object Introspector UI
//  Live object inspection, type detection, field analysis
//  Created by Royan
//

import SwiftUI

struct BleedingEdgeObjectIntrospectorView: View {
    @ObservedObject private var introspector = KernelObjectIntrospector.shared
    @ObservedObject private var mgr = dspmgr.shared
    @State private var addressInput = ""
    @State private var selectedObject: KernelObject?
    @State private var showDetail = false
    
    var body: some View {
        List {
            // Status
            Section {
                HStack(spacing: 14) {
                    ZStack {
                        Circle()
                            .fill((mgr.dsready ? Color.teal : Color.red).opacity(0.15))
                            .frame(width: 50, height: 50)
                        Image(systemName: "cube.transparent.fill")
                            .font(.title2)
                            .foregroundStyle(mgr.dsready ? .teal : .red)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text(mgr.dsready ? "Introspector Ready" : "Kernel Access Required")
                            .font(.headline)
                        Text("\(introspector.inspectedObjects.count) objects inspected")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                HeaderLabel(text: "Object Introspector", icon: "cube.transparent")
            }
            
            // Inspect Input
            Section {
                HStack {
                    TextField("Kernel address (hex)", text: $addressInput)
                        .font(.system(.caption, design: .monospaced))
                        .autocapitalization(.none)
                    
                    Button("Inspect") {
                        guard let addr = UInt64(addressInput.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                        if let obj = introspector.inspectObject(address: addr) {
                            selectedObject = obj
                            showDetail = true
                        }
                    }
                    .disabled(!mgr.dsready || addressInput.isEmpty)
                }
                
                // Quick inspect buttons
                HStack(spacing: 8) {
                    Button("Our Proc") {
                        let addr = ds_get_our_proc()
                        if let obj = introspector.inspectObject(address: addr) {
                            selectedObject = obj
                            showDetail = true
                        }
                    }
                    .font(.caption)
                    .buttonStyle(.bordered)
                    .disabled(!mgr.dsready)
                    
                    Button("Our Task") {
                        let addr = ds_get_our_task()
                        if let obj = introspector.inspectObject(address: addr) {
                            selectedObject = obj
                            showDetail = true
                        }
                    }
                    .font(.caption)
                    .buttonStyle(.bordered)
                    .disabled(!mgr.dsready)
                    
                    Button("Kernel Base") {
                        if let obj = introspector.inspectObject(address: mgr.kernbase) {
                            selectedObject = obj
                            showDetail = true
                        }
                    }
                    .font(.caption)
                    .buttonStyle(.bordered)
                    .disabled(!mgr.dsready)
                }
            } header: {
                HeaderLabel(text: "Inspect", icon: "magnifyingglass")
            }
            
            // Inspected Objects
            if !introspector.inspectedObjects.isEmpty {
                Section {
                    ForEach(introspector.inspectedObjects) { obj in
                        Button(action: {
                            selectedObject = obj
                            showDetail = true
                        }) {
                            HStack(spacing: 12) {
                                Image(systemName: obj.type.icon)
                                    .font(.body)
                                    .foregroundStyle(colorForType(obj.type))
                                    .frame(width: 24)
                                
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(String(format: "0x%016llx", obj.address))
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundStyle(.cyan)
                                    
                                    HStack(spacing: 8) {
                                        Text(obj.type.rawValue)
                                            .font(.caption2.bold())
                                            .padding(.horizontal, 4)
                                            .padding(.vertical, 1)
                                            .background(colorForType(obj.type).opacity(0.15))
                                            .foregroundStyle(colorForType(obj.type))
                                            .clipShape(Capsule())
                                        
                                        Text("\(obj.size) bytes")
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                        
                                        if obj.refCount > 0 {
                                            Text("ref:\(obj.refCount)")
                                                .font(.caption2)
                                                .foregroundStyle(.secondary)
                                        }
                                    }
                                }
                                
                                Spacer()
                                
                                Text("\(obj.fields.count) fields")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    
                    Button("Clear Cache") {
                        introspector.clearCache()
                    }
                    .foregroundStyle(.red)
                    .font(.caption)
                } header: {
                    HeaderLabel(text: "Objects (\(introspector.inspectedObjects.count))", icon: "cube.fill")
                }
            }
            
            // Relationships
            if !introspector.relationships.isEmpty {
                Section {
                    ForEach(introspector.relationships.prefix(20)) { rel in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 4) {
                                Text(rel.sourceType.rawValue)
                                    .font(.caption2.bold())
                                    .foregroundStyle(colorForType(rel.sourceType))
                                Image(systemName: "arrow.right")
                                    .font(.system(size: 8))
                                    .foregroundStyle(.secondary)
                                Text(rel.targetType.rawValue)
                                    .font(.caption2.bold())
                                    .foregroundStyle(colorForType(rel.targetType))
                            }
                            
                            Text("\(rel.fieldName): \(String(format: "0x%llx", rel.sourceAddr)) → \(String(format: "0x%llx", rel.targetAddr))")
                                .font(.system(size: 9, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    HeaderLabel(text: "Relationships (\(introspector.relationships.count))", icon: "arrow.triangle.branch")
                }
            }
            
            // Type Legend
            Section {
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                    ForEach(KernelObjectType.allCases, id: \.self) { type in
                        HStack(spacing: 4) {
                            Image(systemName: type.icon)
                                .font(.caption2)
                                .foregroundStyle(colorForType(type))
                            Text(type.rawValue)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            } header: {
                HeaderLabel(text: "Type Legend", icon: "paintpalette")
            }
        }
        .navigationTitle("Object Introspector")
        .premiumStyling()
        .sheet(isPresented: $showDetail) {
            if let obj = selectedObject {
                ObjectDetailView(object: obj, introspector: introspector)
            }
        }
    }
    
    private func colorForType(_ type: KernelObjectType) -> Color {
        switch type {
        case .proc: return .blue
        case .task: return .purple
        case .thread: return .pink
        case .ipcPort: return .indigo
        case .ipcSpace: return .cyan
        case .vmMap: return .green
        case .vmMapEntry: return .mint
        case .vmObject: return .teal
        case .vnode: return .orange
        case .ucred: return .yellow
        case .fileproc: return .brown
        case .socket: return .red
        case .pipe: return .gray
        case .ioSurface: return .blue
        case .osObject: return .purple
        case .unknown: return .gray
        }
    }
}

// MARK: - Object Detail View

struct ObjectDetailView: View {
    let object: KernelObject
    @ObservedObject var introspector: KernelObjectIntrospector
    @Environment(\.dismiss) private var dismiss
    
    var body: some View {
        NavigationStack {
            List {
                // Header
                Section {
                    LabeledContent("Address") {
                        Text(String(format: "0x%016llx", object.address))
                            .font(.system(.caption, design: .monospaced))
                    }
                    LabeledContent("Type") {
                        HStack {
                            Image(systemName: object.type.icon)
                            Text(object.type.rawValue)
                        }
                    }
                    LabeledContent("Size") { Text("\(object.size) bytes") }
                    LabeledContent("Ref Count") { Text("\(object.refCount)") }
                    if let zone = object.zone {
                        LabeledContent("Zone") { Text(zone) }
                    }
                    if let vtable = object.vtableAddr {
                        LabeledContent("VTable") {
                            Text(String(format: "0x%016llx", vtable))
                                .font(.system(.caption, design: .monospaced))
                        }
                    }
                } header: {
                    HeaderLabel(text: "Object Info", icon: "info.circle")
                }
                
                // Fields
                Section {
                    ForEach(object.fields) { field in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(field.name)
                                    .font(.system(.caption, design: .monospaced).bold())
                                Spacer()
                                Text("+0x\(String(format: "%x", field.offset))")
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundStyle(.secondary)
                            }
                            
                            HStack {
                                Text(field.type.rawValue)
                                    .font(.system(size: 9, design: .monospaced))
                                    .padding(.horizontal, 4)
                                    .padding(.vertical, 1)
                                    .background(Color.blue.opacity(0.15))
                                    .clipShape(Capsule())
                                
                                Text(String(format: "0x%016llx", field.value))
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(field.type == .pointer ? .cyan : .primary)
                                    .textSelection(.enabled)
                            }
                            
                            if !field.description.isEmpty {
                                Text(field.description)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                } header: {
                    HeaderLabel(text: "Fields (\(object.fields.count))", icon: "list.bullet.rectangle")
                }
                
                // Actions
                Section {
                    Button("Discover Relationships") {
                        introspector.discoverRelationships(for: object)
                    }
                    
                    Button("Copy Address") {
                        UIPasteboard.general.string = String(format: "0x%016llx", object.address)
                    }
                    
                    Button("Copy All Fields") {
                        var text = "Object: \(object.type.rawValue) @ 0x\(String(format: "%016llx", object.address))\n"
                        for field in object.fields {
                            text += "\(field.name) (+0x\(String(format: "%x", field.offset))): 0x\(String(format: "%016llx", field.value))\n"
                        }
                        UIPasteboard.general.string = text
                    }
                } header: {
                    HeaderLabel(text: "Actions", icon: "bolt.fill")
                }
            }
            .navigationTitle("\(object.type.rawValue)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}
