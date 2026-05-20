# DSPloit — Context Transfer (AMFI Lab / Exp 74–83)

**Repo:** `tosoonmulu123-ui/DSPloit`  
**Last meaningful commits (May 2026):**
- `(pending push)` — feat(kernel): Exp 83 CS Flags Bypass via physmap — write cs_flags ke proc_ro binary target
- `(prev batch)` — fix(build): hapus duplicate expRCTrustCacheAdd (Opsi C lama) — compile error resolved
- `(prev batch)` — fix(ui): MobileBankingView tombol Sembunyikan/Restore/Scan pakai isHideRestoreRunning
- `1c7f7ce` — fix(kernel): Exp 80 fallback offsets from kernelcache analysis
- `084e50a` — fix(kernel): Exp 80 Opsi C — resolve trust cache fn via kernelcache symtab + rcallAddr

Use this document as **single source of truth** when continuing work in a new chat.

---

## 1. End goal (what we want to achieve)

### Primary
**Full jailbreak on iPhone XR (A12) iOS 18.2 (build 22C152):** run **unsigned / non-App-Store binaries** by bypassing AMFI via **trust cache** (CDHash allow-list).

### Practical milestone chain
| Step | Target | Status (device-tested) |
|------|--------|-------------------------|
| A | Kernel exploit (socket KRW) | ✅ |
| B | VFS + sandbox escape | ✅ |
| C | RemoteCall on launchd / SpringBoard | ✅ |
| D | Kernelcache on device + XPF (`kernproc`, etc.) | ✅ |
| E | **Exp 74** — physmap verified, KRW `__TEXT` | ✅ |
| F | **Exp 77/82 probe** — blind scan memory for trust-cache | ❌ (PPL panic) |
| G | **Exp 79** — KTRR analysis: KRW write ke __DATA → panic | ✅ (confirmed KTRR blocks write) |
| H | **Exp 80 Opsi C** — rcallAddr kernel VA | ❌ PANIC: initproc exited |
| I | **Exp 80 Opsi D** — dlopen userspace libs | ❌ PANIC: SIGBUS (initproc exited) |
| J | **Exp 83** — CS Flags Bypass via physmap | 🟡 Implemented, belum ditest |

### Ultimate technical win
Bypass AMFI via **cs_flags** di `proc_ro` binary target. Karena semua jalur trust cache API gagal:
- **Exp 83 (current):** Write `cs_flags |= CS_VALID | CS_PLATFORM_BINARY` via physmap VA ke `proc_ro`
- Binary dianggap platform binary → AMFI skip signature check

---

## 2. Device & environment

| Item | Value |
|------|--------|
| Device | iPhone XR (`iPhone11,8`), A12 T8020 |
| iOS | 18.2, Darwin 24.2.0, build **22C152** |
| Workspace kernelcache | `kernelcache` (repo root) |
| Latest panic `kernel_base` | `0xfffffff0130ec000` (slide: `0x0c0e8000`) |
| `dataOffsetFromText` | **`0x30dc000`** (confirmed offline + on-device) |
| Physmap (Exp 74 saved) | `gVirtBase ≈ 0xffffffdc00000000`, `gPhysBase = 0x800000000` |
| Trust cache addr (Exp 77) | `0xfffffff026ed01ac` (boot-specific, berubah tiap reboot) |
| Trust cache version/count | version=1, count=256 |

---

## 3. What already works (confirmed in logs/device)

- **Jailbreak chain:** `(jb) 🎉 Jailbreak complete!`, `(kcache) XPF resolve OK`
- **Offsets:** `kernproc: 0x9dd0a8`, T8020 kernel string — matches XR 18.2
- **Sandbox:** `escaped! (verify: /var/mobile/.rooootwashere)`
- **Exp 74:** green — physmap verified (`gVirtBase: 0xffffffdc00000000`)
- **Exp 77 Probe:** ✅ trust cache ditemukan di `__DATA` (bukan PPL region)
  - addr: `0xfffffff026ed01ac`, version=1, count=256
- **KTRR confirmed (Exp 79):** KRW write ke `__DATA` → panic "Unexpected fault in kernel static region"
- **Symtab strip confirmed:** Semua fungsi trust cache `(not in symtab)` — iOS release strip symtab
- **Kernel VA panic confirmed:** `rcallAddr` dengan kernel VA → `initproc exited` panic
- **dlopen panic confirmed:** `dlopen` dari launchd RC → SIGBUS panic

---

## 4. Current state & next step

### Exp 80 Opsi C — FAILED ❌ (PANIC)
`rcallAddr(rc, kernelFnAddr, ...)` → `initproc exited` panic.
Kernel VA `0xfffffff0...` tidak ada di launchd address space.

### Exp 80 Opsi D — FAILED ❌ (SIGBUS PANIC)
`dlopen` dari launchd RC → `initproc exited` panic (exit reason namespace 2 subcode 0xb = SIGBUS).
Library initializer crash di launchd context.

### Exp 83: CS Flags Bypass via Physmap — CURRENT 🎯
**Implementasi selesai, belum ditest di device.**

**Strategi:**
1. Cari `proc` binary target via `procbyname` (atau our proc untuk self-test)
2. Baca `proc_ro` pointer dari `proc` (offset `off_proc_p_proc_ro`)
3. Hitung physical address `proc_ro` → physmap VA
4. Cross-verify: baca cs_flags via physmap VA, bandingkan dengan heap KRW
5. Tulis `cs_flags |= CS_VALID | CS_PLATFORM_BINARY` via physmap VA
6. Verify write berhasil

**Kenapa physmap bypass KTRR:**
- KTRR melindungi VA `__DATA` kernel (static mapping)
- `proc_ro` ada di zone allocator (heap), bukan `__DATA`
- Physmap adalah mapping BERBEDA dari physical memory yang sama
- Write via physmap VA tidak trigger KTRR protection

**proc_ro layout (iOS 18 / A12, confirmed dari kode existing):**
```
proc_ro+0x00: p_list (8B)
proc_ro+0x08: p_proc back pointer (8B)
proc_ro+0x10: p_ucred (8B)
proc_ro+0x18: pr_task (8B)
proc_ro+0x1c: p_csflags (4B) ← target
```
Offset `0x1c` sudah dikonfirmasi dari `dspmgr.swift` `readCSFlags()`.

**CS flags yang diset:**
- `CS_VALID (0x1)` — binary dianggap valid
- `CS_PLATFORM_BINARY (0x100000)` — AMFI skip signature check
- Hapus `CS_HARD (0x40)` dan `CS_KILL (0x80)` — mencegah SIGKILL saat exec

**Cara test:**
1. Jalankan binary target dulu (e.g. `/usr/bin/id` atau binary unsigned)
2. Masukkan path di text field AMFI Lab
3. Tap `③e CS Flags Bypass (Exp 83)`
4. Lihat hasil — jika cross-verify OK dan write verified → lanjut spawn
5. Tap `④ Test Binary Spawn` untuk verifikasi AMFI bypass

**Risiko:**
- Jika `gVirtBase` tidak akurat → physmap VA salah → write ke alamat random → respring
- Jika `proc_ro` di RO zone (iOS 18 memprotect proc_ro) → write gagal silently
- Tidak ada bootloop risk karena proc_ro di heap (bukan kernel static)

---

## 5. Architecture & code map

### Key files
| File | Role |
|------|------|
| `lara/views/root/AMFIExperimentView.swift` | Exp 74/77/79/80/83, probe, KTRR analysis, RC inject |
| `lara/kexploit/kcache_analyze.m` | On-device ADRP scan (A-series + M-series support) |
| `lara/kexploit/kcache_sym.m` | Symtab lookup |
| `lara/kexploit/offsets.m` | XPF resolve; guard file existence |
| `lara/kexploit/TrustCacheInjector.h/.m` | Exp 79 C-level injector (reference) |
| `lara/kexploit/darksword.m` | Socket KRW exploit |
| `lara/kexploit/utils.m` | procbypid/procbyname cycle detection |
| `lara/classes/dspmgr.swift` | `readCSFlags`, `findProc`, `setUID` |
| `scripts/analyze_kernelcache.py` | PC-side analysis; `--trust-cache`, `--deep-probe` |
| `lara/views/root/MobileBankingView.swift` | Hide /var/jb; fix tombol tidak bereaksi |
| `lara/classes/RootExecutor.swift` | `rcall` + `rcallAddr` |

### UI flow (AMFI Lab)
```
① Physmap Verify (Exp 74)
② Trust Cache Probe (Exp 77) — KRW read-only
③ KTRR Analysis (Exp 79) — info only, NO write
③b RC Trust Cache Add (Exp 80) — FAILED (dlopen SIGBUS)
③c Heap TC Analysis (Exp 81)
③d Deep TC Scan (Exp 82)
③e CS Flags Bypass (Exp 83) ← CURRENT TARGET
④ Test Binary Spawn
```

### Exp 83 implementation (AMFIExperimentView.swift)
- Runner: `runExp83CSFlagsBypass()` → KRW-only (tidak perlu RC)
- Function: `expCSFlagsBypass(targetBinary:)` — pure KRW + physmap write
- Target proc: `procbyname(basename(targetBinary))` atau our proc (self-test)
- cs_flags offset: `proc_ro + 0x1c` (confirmed dari dspmgr.swift)
- Write: `safeKwrite32Physmap(csFlagsPhysmapVA, newFlags)`
- Cross-verify: baca via heap KRW dan physmap VA, bandingkan

---

## 6. Bug fixes yang sudah dilakukan

| File | Fix |
|------|-----|
| `darksword.m` | `cmp8_wait_for_change` timeout 5s |
| `darksword.m` | `ds_isvalid` logic VM_MIN/MAX diperbaiki |
| `darksword.m` | `ds_kread64_safe` PPL guard + log |
| `darksword.m` | `get_ios_major_version` pakai `kern.osproductversion` |
| `utils.m` | `procbypid/procbyname` cycle detection + limit 1024 |
| `utils.m` | `kernprocaddress` XPF resolve dulu |
| `kcache_analyze.m` | Support A-series + M-series kernel base |
| `offsets.m` | Guard file existence sebelum XPF |
| `AMFIExperimentView.swift` | Exp 77 entropy check longgar, hdrOff 0/8/0x10/0x18/0x20 |
| `AMFIExperimentView.swift` | Exp 80: gXPF.kernelBase → `kernBase &- kernSlide` (Swift accessible) |
| `AMFIExperimentView.swift` | Exp 80 Opsi D: dlopen userspace libs (bukan kernel VA) |
| `AMFIExperimentView.swift` | **Hapus duplicate expRCTrustCacheAdd (Opsi C lama)** — compile error |
| `AMFIExperimentView.swift` | **Exp 83: CS Flags Bypass via physmap** — implementasi baru |
| `TrustCacheInjector.m` | count >= 255 → count >= 65535 (fix count=256 ditolak) |
| `MobileBankingView.swift` | Fix tombol "Sembunyikan" tidak bereaksi: pisahkan `isHideRestoreRunning` |
| `MobileBankingView.swift` | Fix section kedua: tombol Restore dan Scan pakai `isHideRestoreRunning` |
| `RootExecutor.swift` | Tambah `rcallAddr` (untuk userspace fn ptr, BUKAN kernel VA) |

---

## 7. Physmap / paging reference

| Item | Value / note |
|------|----------------|
| `gPhysBase` | `0x800000000` |
| `gVirtBase` | save per boot after Exp 74 |
| `PhysmapConstants.dataOffsetFromText` | `0x30dc000` |
| `PhysmapConstants.unslidTextBase` | `0xfffffff007004000` (A-series) |
| KTRR | Hardware readonly untuk `__TEXT` + `__DATA` setelah boot di A12 |
| PPL | Proteksi page table — `__DATA.__ppl_data` tidak bisa dibaca/ditulis via KRW |
| Kernel VA dari launchd | **TIDAK BISA** — menyebabkan `initproc exited` panic |
| proc_ro zone | Zone allocator (heap) — bukan `__DATA`, tidak di-protect KTRR |
| Physmap formula | `physmap_VA = phys_addr - gPhysBase + gVirtBase` |

---

## 8. Failure modes to avoid

| Action | Result |
|--------|--------|
| KRW write ke `__DATA` | KTRR panic "Unexpected fault in kernel static region" |
| KRW read `__ppl_data` | PPL panic |
| `rcallAddr` dengan kernel VA `0xfffffff0...` | `initproc exited` panic — launchd crash |
| `dlopen` dari launchd RC | `initproc exited` panic — SIGBUS |
| Exp 77 via launchd + sysctl | Hang / slow |
| Follow pointer tanpa guard | Respring |
| ADRP scan pada fileset entry salah | null pointers |
| Inject sebelum probe green | Panic risk |
| Assume symtab `_trustcache` | Always `(not in symtab)` — iOS release strip symtab |
| Write test ke __DATA | KTRR panic (sudah terbukti) |
| `verifyJbStateViaRoot` di `onAppear` | Block `root.isExecuting` → tombol hide tidak bereaksi |
| Physmap write dengan gVirtBase salah | Write ke alamat random → respring |

---

## 9. Git / CI rules (user preferences)

- Push ke **`main`** langsung (user requested).
- **Jangan push** sampai batch siap — push trigger IPA build.
- Setelah push: beri **tabel** — expected result, next step, impact.
- Komunikasi dalam **Bahasa Indonesia**.
- Hindari bootloop; respring OK.
- Minimize scope; no placeholder features.
- **Update conversation.md setiap batch** — wajib sebagai context untuk AI Agent / New Chat.

---

## 10. Success criteria checklist

- [x] Exp 77 probe green — trust cache addr ditemukan (count=256)
- [x] KTRR confirmed — KRW write tidak mungkin
- [x] Kernel VA panic documented — rcallAddr tidak aman untuk kernel VA
- [x] dlopen panic documented — SIGBUS dari launchd context
- [x] MobileBankingView fix — tombol Sembunyikan bereaksi
- [x] TrustCacheInjector fix — count >= 65535
- [x] Exp 80 Opsi D — FAILED (SIGBUS panic di launchd)
- [ ] **Exp 83 CS Flags Bypass** — write cs_flags via physmap ke proc_ro binary target
- [ ] Test binary spawn berhasil tanpa SIGKILL → AMFI bypass confirmed
- [ ] No regression: JB + XPF + Exp 74 + Import kernelcache + offline 48 slots

---

## 11. One-paragraph summary for quick paste

We have **socket KRW + full in-app jailbreak** on **iPhone XR iOS 18.2**. **Exp 74** (physmap) sudah hijau. KRW write langsung ter-blokir KTRR (Exp 79). Semua jalur trust cache API gagal: Opsi C (rcallAddr kernel VA) → `initproc exited` panic, Opsi D (dlopen) → SIGBUS panic. **Pivot ke Exp 83 (CS Flags Bypass):** write `cs_flags |= CS_VALID | CS_PLATFORM_BINARY` via physmap VA ke `proc_ro` binary target. `proc_ro` ada di zone allocator (heap), bukan `__DATA`, sehingga tidak di-protect KTRR. Physmap formula: `physmap_VA = phys_addr - gPhysBase + gVirtBase`. Implementasi selesai di `AMFIExperimentView.swift` (tombol `③e`), belum ditest di device. Cross-verify step memastikan physmap VA benar sebelum write.
