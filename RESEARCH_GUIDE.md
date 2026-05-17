# DSPloit Research Guide

## Kernelcache Analysis Results (deep_analyze_v3.py)

### Key Addresses (file offsets from code base 0xe00000)
| Item | File Offset | Virtual Addr Formula |
|------|-------------|---------------------|
| GXF handler | 0xf0c440 | kernel_base + 0x20c440 |
| PPL check #1 | 0xe33e14 | kernel_base + 0x033e14 |
| pmap_enter (667 branches) | 0x11126c0 | kernel_base + 0x3126c0 |
| Largest func (106KB) | 0x155e280 | kernel_base + 0x75e280 |
| IOSurfaceRoot string | 0x0067d03b | (data section) |

### PPL Protection Summary
- **223** TBNZ/TBZ bit#14 instructions (PPL checks)
- **7** distinct functions contain PPL checks
- **50** GXF register accesses (S3_4_C15_C2_7)
- PPL check pattern: `TBNZ Xn, #14, <ppl_path>`
  - Normal path: permission = 0x1
  - PPL path: permission = 0x81, page_size = 0x4000

### IOSurface Analysis
- **762** IOSurface-related strings
- IOSurfaceRootUserClient at 0x0067d03b
- Key methods: set_surface_handle, allocate client shared id, map shared memory
- AppleAVD uses IOSurface for video decode buffers

### ucred Structure (from type encoding)
```
ucred {
    +0x00: ^ucred_rw     (pointer to ucred_rw)
    +0x08: ^void
    +0x10: uint64
    +0x18: posix_cred {   (IIISS[16I]IIIi)
        +0x18: cr_uid (uint32)
        +0x1c: cr_ruid (uint32)
        +0x20: cr_svuid (uint16)
        +0x22: cr_ngroups (uint16)
        +0x24: cr_groups[16] (uint32 * 16)
        +0x64: cr_rgid (uint32)
        +0x68: cr_svgid (uint32)
        +0x6c: cr_gmuid (uint32)
        +0x70: cr_flags (int32)
    }
    +0x78: ^label        (pointer to mac_label)
    +0x80: au_session
}
```

### Exploitation Vectors
1. **IOSurface DMA** — GPU writes bypass CPU page tables (and PPL)
2. **GXF Entry** — Execute in PPL context via ROP → GXF transition
3. **Race in pmap_enter** — 667 branches = complex logic = timing window
4. **IOSurface property manipulation** — Controlled kernel object read/write

## ⚠️ PENTING: Apa yang Harus Dikirim ke Sini

Setelah menjalankan langkah-langkah di bawah, **KIRIM** data berikut ke chat:

```
=== DSPloit Research Data ===
Date: [tanggal]
Device: [model iPhone]
iOS: [versi]

--- PHASE 1 ---
kernel_base: [hex]
kernel_slide: [hex]
Exploit: SUCCESS/FAIL
VFS: YES/NO
Sandbox Escape: YES/NO

--- PHASE 2 ---
[Copy-paste output dari Object Introspector]
[Copy-paste output dari Memory Scanner]

--- PHASE 3 ---
[Copy-paste PPL region map]
[Copy-paste write test results]

--- PHASE 4 ---
[Copy-paste zone enumeration]
[Copy-paste port spray results]

--- PHASE 5 ---
[Copy-paste gadget list]

--- PHASE 6 ---
[Copy-paste IOKit service list]
[Copy-paste fuzz results jika ada crash]

--- NOTES ---
[Anomali/crash/unexpected behavior]
```

**JANGAN kirim:** screenshot (saya tidak bisa baca), file binary, atau data yang tidak relevan.

---

## Langkah-Langkah Research

### PHASE 1: Setup (Wajib Pertama)

1. Buka app → Tab 1 (Main)
2. Tap **"Run Exploit"** → tunggu sampai checkmark hijau
3. Tap **"Fetch Kernelcache"** → tunggu selesai
4. Tap **"Initialize System"** → tunggu VFS + Sandbox checkmark

**Catat:** kernel_base, kernel_slide (terlihat di Debug section)

---

### PHASE 2: Structure Discovery

5. Tab 2 → **Kernel Exploit Suite** → **Object Introspector**
6. Tap **"Our Proc"** → tap **"Copy All Fields"** → paste ke Notes
7. Tap **"Our Task"** → tap **"Copy All Fields"** → paste ke Notes
8. Back → **Kernel Memory Scanner** → tap **"Auto-Discover All Offsets"**
9. Tap **"Export Offsets"** → **"Copy to Clipboard"** → paste ke Notes

---

### PHASE 3: PPL Research

10. Back → **PPL Bypass Research** → tap **"Map PPL Regions"**
11. Screenshot atau catat semua regions yang muncul
12. Di "Write Testing" section:
    - Address: masukkan address dari __DATA region (dari step 10)
    - Value: `0x4141414141414141`
    - Method: "Direct KRW" → tap "Test Write Primitive"
    - Ulangi dengan method "vm_write"
13. Catat Statistics (Total Attempts, Successful Writes, PPL Blocks)

---

### PHASE 4: Heap Analysis

14. Back → **Heap Visualizer** → tap **"Enumerate All Zones"**
15. Catat top 10 zones dengan usage tertinggi
16. Back → **Mach Port Spray** → tap **"Enumerate Mach Ports"**
17. Catat jumlah ports
18. Tap **"Start Port Spray"** (default config)
19. Catat hasil (ports created, kernel memory used)
20. **PENTING:** Tap **"Destroy Sprayed Ports"** setelah selesai

---

### PHASE 5: Gadget Finding

21. Back → **ROP Chain Builder** → tap **"Locate ROP Gadgets"**
22. Catat top 10 gadgets (address + instructions)
23. Kalau ada tombol "Copy", gunakan

---

### PHASE 6: IOKit (Opsional, Hati-hati)

24. Back → **IOKit Fuzzer** → tap **"Discover IOKit Services"**
25. Catat jumlah services dan nama-nama yang menarik
26. **HANYA jika berani:** Pilih satu service → Fuzz 50 iterations
27. Kalau ada crash/vulnerability detected, catat detailnya

⚠️ **WARNING:** Fuzzing bisa bikin device reboot. Save semua data dulu.

---

## Setelah Selesai

Copy semua data dari Notes app, format seperti template di atas, dan paste ke chat ini. Saya akan:
- Analyze offset patterns
- Identify potential new exploit vectors
- Suggest next research steps
- Help port findings ke iOS version lain
