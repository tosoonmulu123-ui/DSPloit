# DSPloit — Context Transfer (AMFI Lab / Exp 74–91)

**Repo:** `tosoonmulu123-ui/DSPloit`  
**Device:** iPhone XR (A12 T8020), iOS 18.2 (22C152)  
**Status:** Semi-jailbreak achieved — full kernel R/W + root + sandbox escape + spawn system binary. Missing: execute custom unsigned code (blocked by AMFI CDHash validation).

---

## 1. What we achieved (CONFIRMED on device)

| Capability | Status | How |
|---|---|---|
| Kernel exploit (socket KRW) | ✅ | darksword.m |
| Kernel read ANY address | ✅ | ds_kread64 / ds_kread32 |
| VFS + sandbox escape | ✅ | RemoteCall launchd |
| Root access (uid=0) | ✅ | Confirmed via `id` / `whoami` |
| RemoteCall launchd (PID 1) | ✅ | RC established |
| RemoteCall SpringBoard | ✅ | RC established |
| Physmap verified (Exp 74) | ✅ | gVirtBase/gPhysBase saved |
| Trust cache probe (Exp 77) | ✅ | Found at kernel __DATA |
| Spawn system binary via symlink | ✅ | posix_spawn symlink → ret=0, PID assigned |
| Spawn from SpringBoard | ✅ | posix_spawn via SB RC → ret=0 |
| fork() from SpringBoard | ✅ | fork() returns child PID |
| system()/popen() resolved | ✅ | dlsym finds them in shared cache |
| mprotect(RX) on mmap'd page | ✅ | W→X transition allowed in SpringBoard |
| Copy file to /var/tmp | ✅ | open+read+write works |
| Patch binary on /var/tmp | ✅ | NOP 14 instructions in amfid copy |
| Read amfid binary (252KB) | ✅ | Dump + on-device ARM64 analysis |

## 2. What DOESN'T work (all tested, all failed)

| Approach | Result | Root cause |
|---|---|---|
| Write kernel __TEXT_EXEC (Exp 85) | ❌ | KTRR hardware RO |
| Write kernel __DATA (Exp 79) | ❌ | KTRR hardware RO |
| Write proc_ro cs_flags (Exp 83) | ❌ | zone_require_ro hardware |
| Physmap write to kernel text | ❌ | KTRR also blocks physmap |
| Physmap write to amfid text | ❌ | Page table walk fails (userspace pmap) |
| task_for_pid(amfid) | ❌ | ret=5 (KERN_FAILURE) |
| Patch amfid on-disk | ❌ | EROFS (SSV read-only rootfs) |
| Bind mount patched amfid | ❌ | bindfs/nullfs not available iOS 18 |
| Spawn copied binary | ❌ | ret=1/13 (CDHash mismatch) |
| Spawn patched binary | ❌ | ret=13 (CDHash mismatch) |
| DYLD_INSERT_LIBRARIES | ❌ | SIGKILL (stripped by AMFI) |
| ALL DYLD env vars (8 tested) | ❌ | All SIGKILL |
| dlopen unsigned dylib | ❌ | AMFI reject |
| dlopen copied system dylib | ❌ | File not on disk (shared cache only) |
| dlopen via symlink | ❌ | AMFI reject |
| JIT shellcode (mmap+mprotect+call) | ❌ | APRR blocks execute unsigned page |
| MAP_JIT | ❌ | SpringBoard lacks entitlement |
| system() command | ❌ | /bin/sh not found (ret=127) |
| amfid kill race | ❌ | Kernel enforces independently |

## 3. The blocking wall

**AMFI CDHash validation** is the final barrier:
- Every binary must have its CDHash in the **static trust cache** (burned into kernelcache at build time)
- Copying a binary changes its CDHash → rejected
- Patching a binary changes its CDHash → rejected
- No way to add entries to trust cache (KTRR protects it)
- No way to bypass validation (all code paths checked)

**The ONLY way to execute custom code on iOS 18.2 A12:**
1. **CoreTrust certificate bypass** (TrollStore-style) — sign binary with a certificate that CoreTrust accepts without Apple root CA
2. **Find a 0-day** in AMFI/CoreTrust validation logic
3. **Hardware exploit** (silicon bug in KTRR/APRR/PAC)

## 4. Key technical findings

### KTRR (Kernel Text Readonly Region)
- Protects ALL kernel memory: __TEXT, __TEXT_EXEC, __DATA
- Operates at AMCC (memory controller) level
- Physmap write ALSO blocked (same physical pages)
- Only kernel heap (zone allocator) is writable

### zone_require_ro
- iOS 18 protects `proc_ro` struct in hardware RO zone
- Cannot modify cs_flags of any process
- Both heap KRW and physmap write fail

### APRR (Apple Page Protection Layer)
- mprotect(RX) succeeds (page table updated)
- But APRR blocks actual execution from unsigned pages
- Hardware-level enforcement independent of page tables

### AMFI enforcement
- Validates CDHash at posix_spawn time (before process starts)
- Validates CDHash at dlopen time (runtime loading)
- Strips ALL DYLD environment variables for platform binaries
- fork() allowed but exec of unsigned binary still blocked
- Symlink spawn works because AMFI resolves to original (trusted) binary

## 5. Architecture & key files

| File | Role |
|---|---|
| `lara/views/root/AMFIExperimentView.swift` | All experiments (Exp 74-91) |
| `lara/kexploit/darksword.m` | Socket KRW exploit |
| `lara/classes/RootExecutor.swift` | rcall + rcallAddr |
| `lara/classes/dspmgr.swift` | Process management, readCSFlags |
| `scripts/analyze_amfid.py` | Offline amfid binary analysis |
| `scripts/find_amfi_kernel_patch.py` | Kernelcache AMFI function finder |

## 6. Git rules

- Push ke **main** langsung
- **Jangan push dikit-dikit** — selesaikan SEMUA file dulu, baru 1x commit + 1x push
- **Jangan push** sampai semua file dalam batch siap dan diagnostics bersih
- Update conversation.md setiap batch
- Komunikasi Bahasa Indonesia

## 7. Exp 92 — Final Confirmation (Kernel Panic)

**Exp 92 (TC Inject)** menulis test value `0x4141414141414141` ke trust cache slot di `0xfffffff0198819b4`.

**Hasil: KERNEL PANIC**
```
panic(cpu 3): Unexpected fault in kernel static region
  far: 0xfffffff0198819b4  (trust cache address)
  x3:  0x4141414141414141  (our test write value)
  x1:  0xfffffff0198819b4  (destination address)
```

**Konfirmasi definitif:**
- Trust cache ada di kernel `__DATA` segment (bukan heap)
- KTRR (hardware) melindungi SEMUA kernel static region termasuk `__DATA`
- Tidak ada dynamic/heap trust cache yang writable di iOS 18.2
- Write via socket KRW ke alamat KTRR → immediate hardware fault → panic

**Exp 84 (amfid Patch)** menyebabkan respring karena:
- Page table walk ke amfid userspace gagal
- Atau: PPL melindungi amfid text pages dari write via physmap

## 8. Semua jalur yang sudah dicoba dan gagal

| # | Approach | Blocker |
|---|---|---|
| 1 | Write trust cache __DATA | KTRR hardware (panic confirmed) |
| 2 | Write trust cache via physmap | KTRR juga block physmap ke physical pages yang sama |
| 3 | Write proc_ro cs_flags | zone_require_ro hardware |
| 4 | Patch amfid text via physmap | PPL / page table walk gagal |
| 5 | task_for_pid(amfid) | ret=5 KERN_FAILURE |
| 6 | Spawn patched binary | CDHash mismatch → EACCES |
| 7 | Bind mount | bindfs/nullfs not available iOS 18 |
| 8 | DYLD env vars | Stripped by AMFI |
| 9 | JIT shellcode | APRR blocks unsigned execute |
| 10 | dlopen unsigned | AMFI reject |
| 11 | Kernel AMFI patch | KTRR blocks __TEXT_EXEC |
| 12 | Ad-hoc signing | CDHash still not in trust cache |
| 13 | Fork+exec | Child still subject to AMFI |

## 9. Status Final

**Semi-jailbreak achieved:**
- ✅ Root + KRW + sandbox escape + spawn system binary
- ❌ Execute custom unsigned code (blocked by hardware: KTRR + APRR + PPL)

**Jalur baru yang ditemukan (deep_tc_analysis.py + IPSW):**

### Trust Cache v2 Format (CONFIRMED dari IPSW .trustcache files)
```
+0x00: uint32 version = 2
+0x04: uuid[16] (16 bytes)
+0x14: uint32 count
+0x18: entries[count] (24 bytes each)
  Entry: cdhash[20] + hashType(1) + flags(1) + pad(2)
```
NOTE: Exp 92 pakai offset SALAH (count di +0x04, entries di +0x08).

### AMFI __DATA (fileset component — mungkin di luar KTRR!)
- Unslid VA: 0xfffffff00a330098, Size: 0x541
- 10 boolean flags (value=1): 0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408

### Cryptex Trust Caches (loaded RUNTIME → kemungkinan HEAP)
- Cryptex1,SystemTrustCache: 91 entries (IsLoadedByiBoot: False)
- Cryptex1,AppTrustCache: 30 entries (IsLoadedByiBoot: False)
- __DATA zero slots yang mungkin mengarah ke heap TC: +0x3980, +0x38e0, +0x3920, +0x3930

### New Experiments
- **Exp 93**: AMFI __DATA write test (flip boolean flags)
- **Exp 94**: Heap TC scan (baca zero slots → cari Cryptex TC di heap)
- **Exp 95**: cs_enforcement_disable (write ke __DATA+0x45b8)

## 10. Exp 93 BERHASIL — AMFI __DATA WRITABLE!

**BREAKTHROUGH:** Exp 93 membuktikan bahwa AMFI.kext fileset component `__DATA` segment **TIDAK dilindungi KTRR**!

- AMFI __DATA (unslid): `0xfffffff00a330098`, size `0x541`
- 10 boolean flags ditemukan di offsets: `+0x110, +0x160, +0x1b0, +0x200, +0x250, +0x2a0, +0x2f0, +0x340, +0x398, +0x408` (semua value=1)
- Write test: tulis 0 ke `+0x408`, baca kembali 0, restore ke 1 — **SUKSES!**
- Screenshot proof tersedia

**Implikasi:** Fileset component __DATA (AMFI, CoreTrust, dll) berada di physical pages yang BERBEDA dari main kernel __DATA, dan KTRR tidak melindunginya!

## 11. Exp 93b — AMFI Flag Disable + Spawn Test (IMPLEMENTED)

**Exp 93b** melakukan:
1. Baca semua 10 flag (konfirmasi value=1)
2. Write 0 ke SEMUA 10 flag (disable AMFI checks)
3. Test `posix_spawn("/usr/bin/id")` dan `posix_spawn("/bin/ls")`
4. Test `fork() + execve("/usr/bin/id")` sebagai fallback
5. Restore semua flag ke value original

**Jika berhasil:** FULL JAILBREAK — AMFI flags mengontrol code signing enforcement!
**Jika gagal:** Flags mungkin hanya logging/telemetry, bukan enforcement control.

## 12. Exp 94 Fix — Filter 0xffffff8000000000

Panic di Exp 94 disebabkan oleh:
- Slot __DATA berisi value `0xffffff8000000000` (base kernel VA space)
- Value ini lolos `isSafeKernelKreadAddress()` tapi alamatnya unmapped
- Fix: tambah explicit filter untuk skip value ini sebelum kread
- Juga: `isSafeKernelKreadAddress()` sekarang exclude range `0xffffff80_00000000` sampai `0xffffff81_00000000`

## 13. Next Steps

1. **Run Exp 93b** — test apakah AMFI flags mengontrol enforcement
2. Jika berhasil → binary search flag mana yang spesifik
3. Jika gagal → combine dengan heap TC inject (Exp 94 fixed)
4. CoreTrust __DATA (`0xfffffff00a3b1230`, size `0xe8`) juga mungkin writable — test berikutnya

## 14. Exp 93b-93g Results — AMFI Flags = BUKAN Enforcement

**Definitief bewezen:**
- 10 boolean flags di AMFI __DATA BUKAN enforcement flags
- CDHash validation menyebabkan SIGKILL terlepas dari status flag
- `fork+execve` via RC BROKEN (child tidak pernah execve)
- `posix_spawn` dari `/var/containers/Bundle/` = ret=0 tapi SIGKILL
- `posix_spawn` dari `/var/tmp/` = ret=1 (EPERM, sandbox)
- AMFI flags ON vs OFF TIDAK berpengaruh terhadap SIGKILL

**Spawn path discovery:**
- `/var/containers/Bundle/` → spawn BERHASIL (ret=0) tapi SIGKILL oleh AMFI
- `/var/tmp/`, `/var/root/`, `/var/mobile/` → ret=1 (sandbox block)
- `/usr/libexec/amfid` (original) → ret=0 tapi SIGKILL (conflict dengan amfid running)

## 15. Analisis Kernelcache — VECTOR BARU: __DATA_CONST

**Segment AMFI fileset component:**
```
__TEXT           vm=0xfffffff007497c30 size=0xbaf3
__TEXT_EXEC      vm=0xfffffff008f76d10 size=0x263e4  (KTRR, kode enforcement)
__DATA           vm=0xfffffff00a330098 size=0x541    (WRITABLE! terbukti)
__DATA_CONST     vm=0xfffffff007b77a98 size=0x6280   (mac_policy_ops di sini!)
__LINKEDIT       vm=0xfffffff00a450000 size=0x529a1
```

**INSIGHT KUNCI:** `mac_policy_ops` adalah tabel function pointer yang dipanggil setiap kali binary di-spawn. Pointer `mpo_vnode_check_exec` memutuskan apakah binary boleh jalan atau di-SIGKILL.

**Exp 96:** Test write ke AMFI __DATA_CONST. Kalau writable:
1. Cari gadget "MOV W0, #0; RET" di kernel
2. Overwrite `mpo_vnode_check_exec` → gadget
3. Semua binary diizinkan → FULL JAILBREAK

## 16. Exp 96 PANIC — __DATA_CONST juga KTRR Protected

**Hasil:** Kernel panic saat write ke AMFI __DATA_CONST.
Konfirmasi: hanya AMFI __DATA (0x541 bytes) yang writable. Semua segment lain KTRR.

## 17. Exp 97: amfid Kill + Spawn Race (IMPLEMENTED)

**Strategi baru:** Kill amfid → posix_spawn binary dalam window sebelum amfid restart.
- amfid di-restart otomatis oleh launchd (KeepAlive)
- Tapi ada window ~100ms di mana tidak ada amfid
- Kalau kernel default-allow tanpa amfid → binary jalan

**Kemungkinan hasil:**
- Kalau berhasil → race condition exploit, perlu timing yang tepat
- Kalau gagal → kernel enforce CS independently (tanpa amfid)

**RET-0 gadget ditemukan di kernelcache:**
- AMFI __TEXT_EXEC: `0xfffffff008f78e70` (MOV W0,#0; RET)
- Kernel __TEXT_EXEC: `0xfffffff007d90074` (dan 4 lainnya)
- Tapi tidak bisa dipakai karena __DATA_CONST (tempat function pointers) KTRR protected
