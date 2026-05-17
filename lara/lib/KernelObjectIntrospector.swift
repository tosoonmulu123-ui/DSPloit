//
//  KernelObjectIntrospector.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Kernel Object Introspection Engine
//  Live object inspection, type detection, reference counting,
//  vtable analysis, and object relationship mapping
//  Created by Royan
//

import Foundation
import Combine

// MARK: - Kernel Object Types

enum KernelObjectType: String, CaseIterable {
    case proc = "proc"
    case task = "task"
    case thread = "thread"
    case ipcPort = "ipc_port"
    case ipcSpace = "ipc_space"
    case vmMap = "vm_map"
    case vmMapEntry = "vm_map_entry"
    case vmObject = "vm_object"
    case vnode = "vnode"
    case ucred = "ucred"
    case fileproc = "fileproc"
    case socket = "socket"
    case pipe = "pipe"
    case ioSurface = "IOSurface"
    case osObject = "OSObject"
    case unknown = "unknown"
    
    var icon: String {
        switch self {
        case .proc: return "person.crop.square"
        case .task: return "square.stack.3d.up"
        case .thread: return "arrow.triangle.2.circlepath"
        case .ipcPort: return "circle.grid.3x3"
        case .ipcSpace: return "rectangle.grid.3x2"
        case .vmMap: return "map"
        case .vmMapEntry: return "rectangle.split.3x1"
        case .vmObject: return "cube"
        case .vnode: return "doc"
        case .ucred: return "key"
        case .fileproc: return "doc.badge.gearshape"
        case .socket: return "network"
        case .pipe: return "pipe.and.drop"
        case .ioSurface: return "rectangle.on.rectangle"
        case .osObject: return "cube.transparent"
        case .unknown: return "questionmark.circle"
        }
    }
    
    var color: String {
        switch self {
        case .proc: return "blue"
        case .task: return "purple"
        case .thread: return "pink"
        case .ipcPort: return "indigo"
        case .ipcSpace: return "cyan"
        case .vmMap: return "green"
        case .vmMapEntry: return "mint"
        case .vmObject: return "teal"
        case .vnode: return "orange"
        case .ucred: return "yellow"
        case .fileproc: return "brown"
        case .socket: return "red"
        case .pipe: return "gray"
        case .ioSurface: return "blue"
        case .osObject: return "purple"
        case .unknown: return "gray"
        }
    }
}

// MARK: - Kernel Object

struct KernelObject: Identifiable {
    let id = UUID()
    let address: UInt64
    let type: KernelObjectType
    let size: UInt32
    let refCount: UInt32
    let fields: [ObjectField]
    let vtableAddr: UInt64?
    let zone: String?
    
    struct ObjectField: Identifiable {
        let id = UUID()
        let name: String
        let offset: UInt32
        let value: UInt64
        let type: FieldType
        let description: String
        
        enum FieldType: String {
            case pointer = "ptr"
            case integer = "int"
            case flags = "flags"
            case string = "str"
            case unknown = "?"
        }
    }
}

// MARK: - Object Relationship

struct ObjectRelationship: Identifiable {
    let id = UUID()
    let sourceAddr: UInt64
    let sourceType: KernelObjectType
    let targetAddr: UInt64
    let targetType: KernelObjectType
    let relationship: String // "owns", "references", "contains"
    let fieldName: String
}

// MARK: - Kernel Object Introspector

class KernelObjectIntrospector: ObservableObject {
    @Published var inspectedObjects: [KernelObject] = []
    @Published var relationships: [ObjectRelationship] = []
    @Published var isInspecting: Bool = false
    @Published var objectCache: [UInt64: KernelObject] = [:]
    
    static let shared = KernelObjectIntrospector()
    private let mgr = dspmgr.shared
    
    // MARK: - Object Inspection
    
    func inspectObject(address: UInt64) -> KernelObject? {
        guard mgr.dsready, address != 0 else { return nil }
        
        // Try to detect object type
        let type = detectObjectType(address: address)
        
        // Read fields based on type
        let fields: [KernelObject.ObjectField]
        let size: UInt32
        let refCount: UInt32
        let vtable: UInt64?
        
        switch type {
        case .proc:
            fields = inspectProc(address: address)
            size = 960
            refCount = 1
            vtable = nil
            
        case .task:
            fields = inspectTask(address: address)
            size = 1280
            refCount = ds_kread32(address + 0x10)
            vtable = nil
            
        case .ipcPort:
            fields = inspectIPCPort(address: address)
            size = 168
            refCount = ds_kread32(address + 0x04)
            vtable = nil
            
        case .vnode:
            fields = inspectVnode(address: address)
            size = 480
            refCount = ds_kread32(address + 0x20)
            vtable = nil
            
        case .osObject:
            vtable = ds_kread64(address)
            fields = inspectOSObject(address: address)
            size = 256
            refCount = ds_kread32(address + 0x0C)
            
        default:
            fields = inspectGeneric(address: address)
            size = 256
            refCount = 0
            vtable = ds_kread64(address) // First pointer might be vtable
        }
        
        let obj = KernelObject(
            address: address,
            type: type,
            size: size,
            refCount: refCount,
            fields: fields,
            vtableAddr: vtable,
            zone: zoneForType(type)
        )
        
        DispatchQueue.main.async {
            self.objectCache[address] = obj
            if !self.inspectedObjects.contains(where: { $0.address == address }) {
                self.inspectedObjects.insert(obj, at: 0)
                if self.inspectedObjects.count > 50 {
                    self.inspectedObjects.removeLast()
                }
            }
        }
        
        return obj
    }
    
    // MARK: - Type Detection
    
    func detectObjectType(address: UInt64) -> KernelObjectType {
        guard mgr.dsready else { return .unknown }
        
        let kernelBase = mgr.kernbase
        
        // Read first few qwords for heuristic analysis
        let q0 = ds_kread64(address)
        let q1 = ds_kread64(address + 8)
        let _ = ds_kread64(address + 16)
        
        // Check if it's a proc (has linked list pointers and PID)
        if isKernelPointer(q0) && isKernelPointer(q1) {
            let possiblePid = ds_kread32(address + UInt64(off_proc_p_pid))
            if possiblePid > 0 && possiblePid < 100000 {
                return .proc
            }
        }
        
        // Check if it's an OSObject (vtable pointer to __DATA_CONST)
        if q0 >= kernelBase + 0x800000 && q0 < kernelBase + 0xC00000 {
            return .osObject
        }
        
        // Check if it's an ipc_port (specific structure pattern)
        let possibleRefCount = ds_kread32(address + 0x04)
        if possibleRefCount > 0 && possibleRefCount < 10000 {
            let possibleReceiver = ds_kread64(address + 0x60)
            if isKernelPointer(possibleReceiver) {
                return .ipcPort
            }
        }
        
        // Check for vnode (has v_type field)
        let possibleVtype = ds_kread32(address + 0x70)
        if possibleVtype >= 1 && possibleVtype <= 15 { // VNON to VBAD
            let possibleMount = ds_kread64(address + 0x78)
            if isKernelPointer(possibleMount) {
                return .vnode
            }
        }
        
        return .unknown
    }
    
    // MARK: - Type-Specific Inspection
    
    private func inspectProc(address: UInt64) -> [KernelObject.ObjectField] {
        var fields: [KernelObject.ObjectField] = []
        
        let pid = ds_kread32(address + UInt64(off_proc_p_pid))
        fields.append(.init(name: "p_pid", offset: UInt32(off_proc_p_pid), value: UInt64(pid), type: .integer, description: "Process ID"))
        
        let procRo = ds_kread64(address + UInt64(off_proc_p_proc_ro))
        fields.append(.init(name: "p_proc_ro", offset: UInt32(off_proc_p_proc_ro), value: procRo, type: .pointer, description: "Read-only proc data"))
        
        let task = ds_kread64(address + 0x10)
        fields.append(.init(name: "task", offset: 0x10, value: task, type: .pointer, description: "Associated task"))
        
        let pFlag = ds_kread32(address + UInt64(off_proc_p_flag))
        fields.append(.init(name: "p_flag", offset: UInt32(off_proc_p_flag), value: UInt64(pFlag), type: .flags, description: "Process flags"))
        
        if procRo != 0 {
            let ucred = ds_kread64(procRo + UInt64(off_proc_ro_p_ucred))
            fields.append(.init(name: "p_ucred", offset: UInt32(off_proc_ro_p_ucred), value: ucred, type: .pointer, description: "Credentials"))
        }
        
        return fields
    }
    
    private func inspectTask(address: UInt64) -> [KernelObject.ObjectField] {
        var fields: [KernelObject.ObjectField] = []
        
        let refCount = ds_kread32(address + 0x10)
        fields.append(.init(name: "ref_count", offset: 0x10, value: UInt64(refCount), type: .integer, description: "Reference count"))
        
        let vmMap = ds_kread64(address + 0x28)
        fields.append(.init(name: "map", offset: 0x28, value: vmMap, type: .pointer, description: "VM map"))
        
        let threadCount = ds_kread32(address + 0x58)
        fields.append(.init(name: "thread_count", offset: 0x58, value: UInt64(threadCount), type: .integer, description: "Thread count"))
        
        let threads = ds_kread64(address + 0x60)
        fields.append(.init(name: "threads", offset: 0x60, value: threads, type: .pointer, description: "Thread list head"))
        
        let itkSpace = ds_kread64(address + 0x330)
        fields.append(.init(name: "itk_space", offset: 0x330, value: itkSpace, type: .pointer, description: "IPC space"))
        
        return fields
    }
    
    private func inspectIPCPort(address: UInt64) -> [KernelObject.ObjectField] {
        var fields: [KernelObject.ObjectField] = []
        
        let ipObject = ds_kread64(address)
        fields.append(.init(name: "ip_object", offset: 0, value: ipObject, type: .pointer, description: "IPC object header"))
        
        let refCount = ds_kread32(address + 0x04)
        fields.append(.init(name: "io_references", offset: 0x04, value: UInt64(refCount), type: .integer, description: "Reference count"))
        
        let msgCount = ds_kread32(address + 0x18)
        fields.append(.init(name: "ip_messages.imq_msgcount", offset: 0x18, value: UInt64(msgCount), type: .integer, description: "Queued messages"))
        
        let receiver = ds_kread64(address + 0x60)
        fields.append(.init(name: "ip_receiver", offset: 0x60, value: receiver, type: .pointer, description: "Receiver task"))
        
        let kobject = ds_kread64(address + 0x68)
        fields.append(.init(name: "ip_kobject", offset: 0x68, value: kobject, type: .pointer, description: "Kernel object"))
        
        return fields
    }
    
    private func inspectVnode(address: UInt64) -> [KernelObject.ObjectField] {
        var fields: [KernelObject.ObjectField] = []
        
        let vType = ds_kread32(address + 0x70)
        fields.append(.init(name: "v_type", offset: 0x70, value: UInt64(vType), type: .integer, description: "Vnode type"))
        
        let vFlag = ds_kread32(address + 0x54)
        fields.append(.init(name: "v_flag", offset: 0x54, value: UInt64(vFlag), type: .flags, description: "Vnode flags"))
        
        let useCount = ds_kread32(address + 0x20)
        fields.append(.init(name: "v_usecount", offset: 0x20, value: UInt64(useCount), type: .integer, description: "Use count"))
        
        let mount = ds_kread64(address + 0x78)
        fields.append(.init(name: "v_mount", offset: 0x78, value: mount, type: .pointer, description: "Mount point"))
        
        let data = ds_kread64(address + 0xE0)
        fields.append(.init(name: "v_data", offset: 0xE0, value: data, type: .pointer, description: "Private data"))
        
        return fields
    }
    
    private func inspectOSObject(address: UInt64) -> [KernelObject.ObjectField] {
        var fields: [KernelObject.ObjectField] = []
        
        let vtable = ds_kread64(address)
        fields.append(.init(name: "vtable", offset: 0, value: vtable, type: .pointer, description: "Virtual function table"))
        
        let retainCount = ds_kread32(address + 0x0C)
        fields.append(.init(name: "retainCount", offset: 0x0C, value: UInt64(retainCount), type: .integer, description: "Retain count"))
        
        return fields
    }
    
    private func inspectGeneric(address: UInt64) -> [KernelObject.ObjectField] {
        var fields: [KernelObject.ObjectField] = []
        
        // Read first 16 qwords
        for i in 0..<16 {
            let offset = UInt32(i * 8)
            let value = ds_kread64(address + UInt64(offset))
            let fieldType: KernelObject.ObjectField.FieldType = isKernelPointer(value) ? .pointer : .integer
            fields.append(.init(
                name: "+0x\(String(format: "%02x", offset))",
                offset: offset,
                value: value,
                type: fieldType,
                description: isKernelPointer(value) ? "Kernel pointer" : "Value"
            ))
        }
        
        return fields
    }
    
    // MARK: - Relationship Discovery
    
    func discoverRelationships(for object: KernelObject) {
        for field in object.fields where field.type == .pointer && field.value != 0 {
            let targetType = detectObjectType(address: field.value)
            
            let rel = ObjectRelationship(
                sourceAddr: object.address,
                sourceType: object.type,
                targetAddr: field.value,
                targetType: targetType,
                relationship: "references",
                fieldName: field.name
            )
            
            DispatchQueue.main.async {
                self.relationships.append(rel)
            }
        }
    }
    
    // MARK: - Helpers
    
    private func isKernelPointer(_ value: UInt64) -> Bool {
        return value >= 0xFFFFFFF000000000 && value <= 0xFFFFFFF0FFFFFFFF
    }
    
    private func zoneForType(_ type: KernelObjectType) -> String? {
        switch type {
        case .proc: return "proc"
        case .task: return "task"
        case .thread: return "thread"
        case .ipcPort: return "ipc_ports"
        case .vmMapEntry: return "vm_map_entry"
        case .vmObject: return "vm_object"
        case .vnode: return "vnode"
        case .socket: return "socket"
        case .pipe: return "pipe"
        default: return nil
        }
    }
    
    func clearCache() {
        inspectedObjects.removeAll()
        relationships.removeAll()
        objectCache.removeAll()
    }
}
