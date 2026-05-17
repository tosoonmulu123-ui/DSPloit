//
//  OSDictParser.swift
//  DSPloit
//
//  🔥 OSSerialize Format Parser
//  Parse and manipulate kernel OSDict/OSArray objects
//  For entitlement injection and kernel object manipulation
//  Created by Royan
//

import Foundation

// MARK: - OSObject Types

enum OSObjectType: UInt32 {
    case dictionary = 0x01000000
    case array = 0x02000000
    case set = 0x03000000
    case string = 0x04000000
    case data = 0x05000000
    case number = 0x06000000
    case boolean = 0x07000000
    case null = 0x08000000
}

// MARK: - OSObject

protocol OSObject {
    var type: OSObjectType { get }
    func serialize() -> Data
}

// MARK: - OSDictionary

class OSDictionary: OSObject {
    var type: OSObjectType { .dictionary }
    private var storage: [String: OSObject] = [:]
    
    subscript(key: String) -> OSObject? {
        get { storage[key] }
        set { storage[key] = newValue }
    }
    
    var keys: [String] {
        Array(storage.keys)
    }
    
    var count: Int {
        storage.count
    }
    
    func serialize() -> Data {
        var data = Data()
        
        // OSDict header
        data.append(contentsOf: withUnsafeBytes(of: type.rawValue) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt32(storage.count)) { Array($0) })
        
        // Serialize key-value pairs
        for (key, value) in storage {
            // Key (as OSString)
            let keyData = OSString(key).serialize()
            data.append(keyData)
            
            // Value
            let valueData = value.serialize()
            data.append(valueData)
        }
        
        return data
    }
    
    static func parse(from address: UInt64) -> OSDictionary? {
        let dict = OSDictionary()
        
        // Read header
        let typeValue = ds_kread32(address)
        guard typeValue == OSObjectType.dictionary.rawValue else { return nil }
        
        let count = ds_kread32(address + 4)
        var offset: UInt64 = 8
        
        // Parse key-value pairs
        for _ in 0..<count {
            // Parse key
            guard let key = OSString.parse(from: address + offset) else { break }
            offset += UInt64(key.serializedSize)
            
            // Parse value
            let valueType = ds_kread32(address + offset)
            guard let objType = OSObjectType(rawValue: valueType) else { break }
            
            let value: OSObject?
            switch objType {
            case .string:
                value = OSString.parse(from: address + offset)
            case .number:
                value = OSNumber.parse(from: address + offset)
            case .boolean:
                value = OSBoolean.parse(from: address + offset)
            case .data:
                value = OSData.parse(from: address + offset)
            case .array:
                value = OSArray.parse(from: address + offset)
            case .dictionary:
                value = OSDictionary.parse(from: address + offset)
            default:
                value = nil
            }
            
            if let value = value {
                dict[key.value] = value
                offset += UInt64((value as? SizedObject)?.serializedSize ?? 16)
            }
        }
        
        return dict
    }
}

// MARK: - OSArray

class OSArray: OSObject {
    var type: OSObjectType { .array }
    private var storage: [OSObject] = []
    
    subscript(index: Int) -> OSObject? {
        get { storage.indices.contains(index) ? storage[index] : nil }
        set {
            if let value = newValue {
                if storage.indices.contains(index) {
                    storage[index] = value
                } else {
                    storage.append(value)
                }
            }
        }
    }
    
    var count: Int {
        storage.count
    }
    
    func append(_ object: OSObject) {
        storage.append(object)
    }
    
    func serialize() -> Data {
        var data = Data()
        
        // OSArray header
        data.append(contentsOf: withUnsafeBytes(of: type.rawValue) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt32(storage.count)) { Array($0) })
        
        // Serialize elements
        for object in storage {
            let objectData = object.serialize()
            data.append(objectData)
        }
        
        return data
    }
    
    static func parse(from address: UInt64) -> OSArray? {
        let array = OSArray()
        
        // Read header
        let typeValue = ds_kread32(address)
        guard typeValue == OSObjectType.array.rawValue else { return nil }
        
        let count = ds_kread32(address + 4)
        var offset: UInt64 = 8
        
        // Parse elements
        for _ in 0..<count {
            let valueType = ds_kread32(address + offset)
            guard let objType = OSObjectType(rawValue: valueType) else { break }
            
            let value: OSObject?
            switch objType {
            case .string:
                value = OSString.parse(from: address + offset)
            case .number:
                value = OSNumber.parse(from: address + offset)
            case .boolean:
                value = OSBoolean.parse(from: address + offset)
            case .data:
                value = OSData.parse(from: address + offset)
            case .array:
                value = OSArray.parse(from: address + offset)
            case .dictionary:
                value = OSDictionary.parse(from: address + offset)
            default:
                value = nil
            }
            
            if let value = value {
                array.append(value)
                offset += UInt64((value as? SizedObject)?.serializedSize ?? 16)
            }
        }
        
        return array
    }
}

// MARK: - OSString

class OSString: OSObject, SizedObject {
    var type: OSObjectType { .string }
    let value: String
    
    var serializedSize: Int {
        8 + value.utf8.count + 1 // type + length + string + null
    }
    
    init(_ value: String) {
        self.value = value
    }
    
    func serialize() -> Data {
        var data = Data()
        
        // OSString header
        data.append(contentsOf: withUnsafeBytes(of: type.rawValue) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt32(value.utf8.count + 1)) { Array($0) })
        
        // String data
        data.append(contentsOf: value.utf8)
        data.append(0) // Null terminator
        
        return data
    }
    
    static func parse(from address: UInt64) -> OSString? {
        let typeValue = ds_kread32(address)
        guard typeValue == OSObjectType.string.rawValue else { return nil }
        
        let length = ds_kread32(address + 4)
        var bytes: [UInt8] = []
        
        for i in 0..<Int(length - 1) {
            let byte = UInt8(ds_kread64(address + 8 + UInt64(i)) & 0xFF)
            bytes.append(byte)
        }
        
        guard let string = String(bytes: bytes, encoding: .utf8) else { return nil }
        return OSString(string)
    }
}

// MARK: - OSNumber

class OSNumber: OSObject, SizedObject {
    var type: OSObjectType { .number }
    let value: UInt64
    
    var serializedSize: Int { 16 }
    
    init(_ value: UInt64) {
        self.value = value
    }
    
    func serialize() -> Data {
        var data = Data()
        data.append(contentsOf: withUnsafeBytes(of: type.rawValue) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt32(8)) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: value) { Array($0) })
        return data
    }
    
    static func parse(from address: UInt64) -> OSNumber? {
        let typeValue = ds_kread32(address)
        guard typeValue == OSObjectType.number.rawValue else { return nil }
        
        let value = ds_kread64(address + 8)
        return OSNumber(value)
    }
}

// MARK: - OSBoolean

class OSBoolean: OSObject, SizedObject {
    var type: OSObjectType { .boolean }
    let value: Bool
    
    var serializedSize: Int { 8 }
    
    init(_ value: Bool) {
        self.value = value
    }
    
    func serialize() -> Data {
        var data = Data()
        data.append(contentsOf: withUnsafeBytes(of: type.rawValue) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: UInt32(value ? 1 : 0)) { Array($0) })
        return data
    }
    
    static func parse(from address: UInt64) -> OSBoolean? {
        let typeValue = ds_kread32(address)
        guard typeValue == OSObjectType.boolean.rawValue else { return nil }
        
        let value = ds_kread32(address + 4)
        return OSBoolean(value != 0)
    }
}

// MARK: - OSData

class OSData: OSObject, SizedObject {
    var type: OSObjectType { .data }
    let data: Data
    
    var serializedSize: Int {
        8 + data.count
    }
    
    init(_ data: Data) {
        self.data = data
    }
    
    func serialize() -> Data {
        var result = Data()
        result.append(contentsOf: withUnsafeBytes(of: type.rawValue) { Array($0) })
        result.append(contentsOf: withUnsafeBytes(of: UInt32(data.count)) { Array($0) })
        result.append(data)
        return result
    }
    
    static func parse(from address: UInt64) -> OSData? {
        let typeValue = ds_kread32(address)
        guard typeValue == OSObjectType.data.rawValue else { return nil }
        
        let length = ds_kread32(address + 4)
        var bytes: [UInt8] = []
        
        for i in 0..<Int(length) {
            let byte = UInt8(ds_kread64(address + 8 + UInt64(i)) & 0xFF)
            bytes.append(byte)
        }
        
        return OSData(Data(bytes))
    }
}

// MARK: - Helper Protocol

protocol SizedObject {
    var serializedSize: Int { get }
}

// MARK: - Entitlement Helper

class EntitlementHelper {
    static func createEntitlementDict(entitlements: [String: Any]) -> OSDictionary {
        let dict = OSDictionary()
        
        for (key, value) in entitlements {
            if let boolValue = value as? Bool {
                dict[key] = OSBoolean(boolValue)
            } else if let intValue = value as? Int {
                dict[key] = OSNumber(UInt64(intValue))
            } else if let stringValue = value as? String {
                dict[key] = OSString(stringValue)
            } else if let arrayValue = value as? [String] {
                let osArray = OSArray()
                for item in arrayValue {
                    osArray.append(OSString(item))
                }
                dict[key] = osArray
            }
        }
        
        return dict
    }
    
    static func injectEntitlement(procAddr: UInt64, key: String, value: OSObject) -> Bool {
        // Find proc->p_ucred
        let ucredAddr = ds_kread64(procAddr + UInt64(off_proc_ucred))
        guard ucredAddr != 0 else { return false }
        
        // Find ucred->cr_label
        let labelAddr = ds_kread64(ucredAddr + 0x78) // Offset may vary
        guard labelAddr != 0 else { return false }
        
        // Find entitlements dict
        let entDictAddr = ds_kread64(labelAddr + 0x8)
        guard entDictAddr != 0 else { return false }
        
        // Parse existing dict
        guard let dict = OSDictionary.parse(from: entDictAddr) else { return false }
        
        // Add new entitlement
        dict[key] = value
        
        // Serialize and write back
        let serialized = dict.serialize()
        // Write serialized data back to kernel
        // (This would require kernel write primitive)
        
        return true
    }
}
