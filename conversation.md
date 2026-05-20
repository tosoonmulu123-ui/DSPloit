# DSPloit — Context Transfer (AMFI Lab / Exp 74–80)

**Repo:** `tosoonmulu123-ui/DSPloit`  
**Last meaningful commits (May 2026):**
- `1ea2d2c` — fix(kernel): remove probe dependency from Exp 80 allowing direct execution of trust_cache_runtime_add
- `264d465` — fix(kernel): restrict heap read range below 0xffffffe5 to avoid Zone Metadata data aborts
- `c9cee9f` — Exp 79 KTRR analysis + Exp 80 RC trust_cache_runtime_add + Mobile Banking fix

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
| F | **Exp 77/82 probe** — blind scan memory for trust-cache | ❌ (Memicu "Unexpected fault in kernel static region" / PPL panic) |
| G | **Exp 79** — KTRR analysis: KRW write ke __DATA → panic | ✅ (confirmed KTRR blocks write) |
| H | **Exp 80** — RC trust_cache_runtime_add via launchd | 🟡 Belum ditest di device |

### Ultimate technical win
**Exp 80:** Panggil `trust_cache_runtime_add` / `_load_trust_cache` dari launchd RemoteCall context. PPL melakukan write internal — tidak ada KTRR fault. Kita bypass *blind scan* sepenuhnya untuk menghindari PPL panic. Ini satu-satunya jalur yang aman dan tersisa.

---

## 2. Device & environment

| Item | Value |
|------|--------|
| Device | iPhone XR (`iPhone11,8`), A12 T8020 |
| iOS | 18.2, Darwin 24.2.0, build **22C152** |
| Workspace kernelcache | `kernelcache` (repo root) |
| Typical runtime `kernel_base` | ~`0xfffffff0265cc000` (slide varies per boot) |
| Typical `kernel_slide` | e.g. `0x1f5c8000` |
| `dataOffsetFromText` | **`0x30dc000`** (confirmed offline + on-device) |
| Physmap (Exp 74 saved) | `gVirtBase ≈ 0xffffffe400000000`, `gPhysBase = 0x800000000` |
| Trust cache addr (Exp 77) | `0xfffffff0296a80a0` (boot-specific, berubah tiap reboot) |
| Trust cache version/count | version=1, count=23 (atau count=6 false positive) |

---

## 3. What already works (confirmed in logs/device)

- **Jailbreak chain:** `(jb) 🎉 Jailbreak complete!`, `(kcache) XPF resolve OK`
- **Offsets:** `kernproc: 0x9dd0a8`, T8020 kernel string — matches XR 18.2
- **Sandbox:** `escaped! (verify: /var/mobile/.rooootwashere)`
- **Exp 74:** green — physmap verified
- **Exp 77 Probe:** ✅ trust cache ditemukan di `__DATA` (bukan PPL region)
  - addr: `0xfffffff0296a80a0`, version=1, count=23
  - Raw struct dump tersedia untuk diagnosa layout
- **KTRR confirmed (Exp 79):** KRW write ke `__DATA` → panic "Unexpected fault in kernel static region"
  - x3=0xdeadbeefcafebabe (sentinel), x20=target addr → KTRR blocks write
  - KRW direct write ke trust cache **tidak mungkin** di A12

---

## 4. Current state & next step

### Exp 77 / 82 Probe & Scan — ABANDONED ❌
*Blind scan* ke global `__DATA` atau heap memicu PPL panic (`Unexpected fault in kernel static region`). Kita tinggalkan pencarian alamat Trust Cache secara manual karena rentan menyentuh memori terproteksi.

### Exp 79 KTRR Analysis — DONE ✅
Konfirmasi: `__DATA` di A12 di-protect KTRR (hardware readonly setelah boot).
- PPL = proteksi page table (bypass via physmap)
- KTRR = hardware readonly enforcement (tidak bisa bypass via KRW)

### Exp 80 RC Trust Cache Add — Opsi C 🔄
**Hasil device test (Exp 80 lama):** Semua `dlsym` gagal — fungsi trust cache tidak ada di userspace dylib.

**Root cause:** `trust_cache_runtime_add` dll. ada di **kernel**, bukan di dylib yang di-export.

**Opsi C (implementasi baru):**
1. Resolve alamat fungsi dari **kernelcache symtab** via `ds_kcache_symbol_runtime()`
2. Hitung runtime VA = `kernel_base + (unslid - xpf_kernbase)`
3. Panggil via `RootExecutor.rcallAddr(rc, fnAddr, ...)` — function pointer langsung
4. Tidak perlu dlsym, tidak perlu proses lain

**Files yang diubah:**
- `AMFIExperimentView.swift` — `expRCTrustCacheAdd()` diganti total (Opsi C)
- `RootExecutor.swift` — tambah `rcallAddr(_:_:_:)` static func

**Expected results Opsi C:**
- Jika symtab ada → fungsi ditemukan → panggil → ret=0 sukses
- Jika symtab kosong → log "Jalankan Import Kernelcache dulu"
- ret=1 (EPERM) → launchd tidak punya entitlement → coba amfid RC
- ret=22 (EINVAL) → struct layout salah → adjust version/stride

---

## 5. Architecture & code map

### Key files
| File | Role |
|------|------|
| `lara/views/root/AMFIExperimentView.swift` | Exp 74/77/79/80, probe, KTRR analysis, RC inject |
| `lara/kexploit/kcache_analyze.m` | On-device ADRP scan (A-series + M-series support) |
| `lara/kexploit/kcache_sym.m` | Symtab lookup |
| `lara/kexploit/offsets.m` | XPF resolve; guard file existence |
| `lara/kexploit/TrustCacheInjector.h/.m` | Exp 79 C-level injector (reference, tidak dipakai langsung) |
| `lara/kexploit/darksword.m` | Socket KRW exploit; ds_isvalid fix; cmp8_wait timeout |
| `lara/kexploit/utils.m` | procbypid/procbyname cycle detection; kernprocaddress XPF |
| `scripts/analyze_kernelcache.py` | PC-side analysis; `--trust-cache`, `--deep-probe` |
| `lara/views/root/MobileBankingView.swift` | Hide /var/jb; RC status hint |

### UI flow (AMFI Lab)
```
① Physmap Verify (Exp 74)
② Trust Cache Probe (Exp 77) — KRW read-only
③ KTRR Analysis (Exp 79) — info only, NO write
③b RC Trust Cache Add (Exp 80) — launchd RemoteCall
④ Test Binary Spawn
```

### Exp 80 implementation (AMFIExperimentView.swift)
- Runner: `runExp80RCTrustCacheAdd()` → `executeAsRoot` → `expRCTrustCacheAdd(rc:)`
- Struct: `trust_cache_module1` di `trojanMem+0x1000`
  - +0x00: version=1 (uint32)
  - +0x04: num_entries=1 (uint32)
  - +0x08: uuid[16] = zeros
  - +0x18: entry[0] = CDHash(20B) + hashType(1B) + flags(1B) + pad(2B)
- API tried: `_trust_cache_runtime_add`, `_load_trust_cache_with_type`, `_load_trust_cache`, `_load_legacy_trust_cache`

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
| `MobileBankingView.swift` | Tombol tidak block karena jbPathVisible; RC status hint |

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

---

## 8. Failure modes to avoid

| Action | Result |
|--------|--------|
| KRW write ke `__DATA` | KTRR panic "Unexpected fault in kernel static region" |
| KRW read `__ppl_data` | PPL panic |
| Exp 77 via launchd + sysctl | Hang / slow |
| Follow pointer tanpa guard | Respring |
| ADRP scan pada fileset entry salah | null pointers |
| Inject sebelum probe green | Panic risk |
| Assume symtab `_trustcache` | Always `(not in symtab)` |
| Write test ke __DATA | KTRR panic (sudah terbukti) |

---

## 9. Git / CI rules (user preferences)

- Push ke **`main`** langsung (user requested).
- **Jangan push** sampai batch siap — push trigger IPA build.
- Setelah push: beri **tabel** — expected result, next step, impact.
- Komunikasi dalam **Bahasa Indonesia**.
- Hindari bootloop; respring OK.
- Minimize scope; no placeholder features.

---

## 10. Success criteria checklist

- [x] Exp 77 probe green — trust cache addr ditemukan
- [x] KTRR confirmed — KRW write tidak mungkin
- [ ] **Exp 80 RC TC Add** — `trust_cache_runtime_add` berhasil dipanggil dari launchd
- [ ] Test binary spawn berhasil tanpa SIGKILL → AMFI bypass confirmed
- [ ] No regression: JB + XPF + Exp 74 + Import kernelcache + offline 48 slots

---

## 11. One-paragraph summary for quick paste

We have **socket KRW + full in-app jailbreak** on **iPhone XR iOS 18.2**. **Exp 74** (physmap) sudah hijau. *Blind scanning* memori (Exp 77 / Exp 82) terbukti tidak stabil dan memicu PPL panic (`Unexpected fault in kernel static region`), sedangkan KRW write langsung ter-blokir oleh KTRR (Exp 79). Pivot utama saat ini: **Exp 80 (RC TC Add)**. Kita **melewati proses pemindaian** dan langsung memanggil `trust_cache_runtime_add` dari *launchd* RemoteCall context — PPL yang melakukan *write* internal. Implementasi sudah ada di `AMFIExperimentView.swift` (tombol ③b) dan sudah diputus dependensinya dari hasil *probe*. Latest commit: **`1ea2d2c`**.
