# DSPloit Research Guide

## Device Info
- **Device:** iPhone XR (N841AP)
- **iOS:** 18.2 (build 22C152)
- **Chip:** A12 Bionic
- **Exploit:** Socket KRW (heap objects only)

---

## Kernelcache Analysis Results

Dari `scripts/deep_analyze_v3.py` pada file `kernelcache.release.iphone11b.decompressed` (52.6 MB).

### Key Addresses

| Item | File Offset | Virtual Address |
|------|-------------|-----------------|
| Code section start | 0xe00000 | kernel_base + 0xe00000 |
| GXF handler | 0xf0c440 | kernel_base + 0xf0c440 - 0xe00000 = kernel_base + 0x10c440 |
| PPL check pertama | 0xe33e14 | kernel_base + 0x33e14 |
| pmap_enter (667 branches) | 0x11126c0 | kernel_base + 0x3126c0 |
| Fungsi terbesar (106KB) | 0x155e280 | kernel_base + 0x75e280 |
| IOSurfaceRootUserClient string | 0x0067d03b | (data section) |

**Rumus:** `virtual_address = kernel_base + file_offset`

### PPL Protection

PPL (Page Protection Layer) melindungi halaman memori tertentu dari penulisan.

**Cara kerja:**
1. Setiap halaman punya atribut di "page attribute table"
2. **Bit 14** di atribut = halaman dilindungi PPL
3. Kernel cek bit ini sebelum menulis: `TBNZ Xn, #14, <ppl_path>`
4. Kalau bit 14 = 1 → kernel pakai permission `0x81` (PPL-protected)
5. Kalau bit 14 = 0 → kernel pakai permission `0x1` (normal)

**Statistik dari kernelcache:**
- 223 instruksi TBNZ/TBZ bit#14 (PPL checks)
- 7 fungsi berbeda mengandung PPL checks
- 50 akses register GXF (S3_4_C15_C2_7)

**Yang dilindungi PPL:**
- ucred (uid/gid) → tidak bisa di-overwrite
- proc_ro → read-only
- Page tables → tidak bisa dimodifikasi
- Kernel __TEXT dan __DATA_CONST

**Yang TIDAK dilindungi PPL:**
- Sandbox label pointer (cr_label → l_perpolicy)
- vm_map entries
- Kernel heap objects (yang kita akses via socket KRW)

### GXF (Guarded Execution Facility)

GXF adalah mekanisme hardware Apple untuk masuk/keluar PPL context.

- Register kontrol: `S3_4_C15_C2_7`
- Handler di file offset: `0xf0c440`
- 50 akses register GXF ditemukan di kernelcache
- Untuk masuk PPL context, harus via GXF entry (tidak bisa langsung)

### IOSurface

IOSurface adalah framework Apple untuk shared memory antara proses dan GPU.

**Kenapa penting untuk exploit:**
- IOSurface bisa map physical memory ke userspace
- GPU (DMA) mengakses physical memory langsung, bypass CPU page tables
- Kalau kita bisa kontrol physical page mana yang di-map → bypass PPL

**Dari kernelcache:**
- 762 string terkait IOSurface
- IOSurfaceRootUserClient di offset 0x0067d03b
- Method: set_surface_handle, allocate client shared id, map shared memory
- AppleAVD (video decoder) pakai IOSurface untuk buffer

### ucred Structure Layout

Dari type encoding string di kernelcache:

```
ucred (total ~0x88 bytes):
    +0x00: pointer ke ucred_rw
    +0x08: pointer (void*)
    +0x10: uint64
    +0x18: posix_cred mulai di sini:
        +0x18: cr_uid      (uint32) ← PPL BLOCKED
        +0x1c: cr_ruid     (uint32) ← PPL BLOCKED
        +0x20: cr_svuid    (uint16)
        +0x22: cr_ngroups  (uint16)
        +0x24: cr_groups   (uint32 × 16 = 64 bytes)
        +0x64: cr_rgid     (uint32)
        +0x68: cr_svgid    (uint32)
        +0x6c: cr_gmuid    (uint32)
        +0x70: cr_flags    (int32)
    +0x78: pointer ke mac_label ← WRITABLE (sandbox escape works here)
    +0x80: au_session
```

**Path dari proc ke sandbox:**
```
proc (+0x18) → proc_ro (+0x20) → ucred (+0x78) → cr_label → l_perpolicy[sandbox_slot]
```

### ROP Gadgets (Confirmed dari kernelcache)

| Offset dari code start | Instruksi | Kegunaan |
|------------------------|-----------|----------|
| +0x0008c0 | STR X9, [X8, #0] ; RET | Arbitrary write |
| +0x0005a8 | MOVZ X0, #0 ; MOVZ X1, #0 ; RET | Return zero |
| +0x00035c | STR X8, [X0, #80] ; STR X31, [X0, #56] ; RET | Double store |
| +0x0158b8 | LDR X1, [X0, #8] ; B ; RET | Load from pointer |
| +0x00c04c | BR X16 ; RET | Indirect branch |
| +0x005984 | ADD X8, X8, #0x80 ; RET | Pointer advance |
| +0x0167fc | ADD X10, X8, #1 ; RET | Increment |

**Virtual address gadget:** `kernel_base + 0xe00000 + offset`

---

## Exploitation Vectors (Ranked by Feasibility)

### 1. IOSurface DMA Bypass (THEORETICAL)
**Ide:** GPU menulis ke physical memory langsung, bypass PPL.
**Langkah:**
1. Buat IOSurface
2. Cari physical page yang backing IOSurface
3. Ganti physical page dengan target (ucred page)
4. GPU write ke surface = write ke ucred

**Status:** Perlu test apakah DART (IOMMU Apple) memblokir ini.

### 2. GXF Entry via ROP (THEORETICAL)
**Ide:** Bangun ROP chain yang trigger GXF entry → execute di PPL context.
**Langkah:**
1. Spray gadgets ke kernel heap
2. Corrupt function pointer ke ROP chain
3. ROP chain setup register untuk GXF entry
4. Di PPL context: modify page table → ucred writable
5. Write uid=0

**Status:** Butuh kernel code execution primitive (belum punya).

### 3. Race Condition di pmap_enter (THEORETICAL)
**Ide:** Fungsi pmap_enter punya 667 branches = complex logic = timing window.
**Langkah:**
1. Trigger pmap_enter dari 2 thread bersamaan
2. Race antara PPL check dan actual write
3. Kalau timing tepat, write lolos tanpa PPL check

**Status:** Sangat sulit, butuh precise timing.

### 4. IOSurface Property Manipulation (MOST PROMISING)
**Ide:** IOSurface properties disimpan sebagai kernel objects di heap.
**Langkah:**
1. Buat IOSurface (sudah bisa setelah sandbox escape)
2. Cari kernel object IOSurface di heap (via socket KRW)
3. Overwrite property dictionary pointer
4. IOSurfaceCopyValue → read dari controlled address
5. IOSurfaceSetValue → write ke controlled address

**Status:** Paling feasible. IOSurface objects ada di heap (yang bisa kita akses).

---

## Apa yang Sudah Berhasil di Device

| Feature | Status | Notes |
|---------|--------|-------|
| Kernel exploit | ✅ | Socket KRW, heap objects only |
| Sandbox escape | ✅ | Nullify sandbox label |
| VFS access | ✅ | Read/write filesystem |
| Process list | ✅ | Via kernel proc iteration |
| Credential read | ✅ | Bisa baca uid/gid |
| Credential write | ❌ | PPL blocks ucred writes |
| Root escalation | ❌ | Butuh PPL bypass |
| Kernel VA read | ❌ | Panic (non-heap address) |

---

## Cara Pakai Scripts

### deep_analyze_v3.py
```
cd d:\Backup\Personal\Hp\iPhone\DSPloit\scripts
python deep_analyze_v3.py
```
Output: PPL functions disassembly, GXF registers, IOSurface handlers, ucred layout.

### analyze_kernelcache.py
```
python analyze_kernelcache.py ..\kernelcache.release.iphone11b.decompressed
```
Output: ROP gadgets, BR gadgets, PPL strings, summary.

---

## Next Steps

1. **Build app** → test 3 crash fixes di device
2. **Buka IOSurface KRW view** → tap "Open IOSurfaceRoot" (setelah sandbox escape)
3. **Kalau IOSurface berhasil dibuat** → cari kernel object-nya di heap
4. **Kalau kernel object ditemukan** → manipulasi property pointer → arbitrary KRW
5. **Kalau arbitrary KRW berhasil** → write ucred uid=0 → ROOT

---

## Catatan Penting

- `kernel_base` berubah setiap reboot (KASLR) — offsets tetap sama
- Socket KRW hanya bisa baca/tulis kernel HEAP objects
- Membaca kernel VA (text/data) langsung → PANIC → device reboot
- Sandbox escape harus dilakukan sebelum IOSurface bisa diakses
- Semua offset di atas relatif terhadap file kernelcache, bukan virtual address
