# DSPloit — Context Transfer (AMFI Lab / Exp 74–80)

**Repo:** `tosoonmulu123-ui/DSPloit`  
**Last meaningful commits (May 2026):**
- `c9cee9f` — Exp 79 KTRR analysis + Exp 80 RC trust_cache_runtime_add + Mobile Banking fix
- `54a9d2c` — Exp 77 entropy check longgar + hdrOff lebih banyak
- `ede801e` — Exp 79 write test + CDHash inject + bug fixes (ds_isvalid, cmp8_wait, dll)
- `79ad1f4` — fix crash saat kernelcache tidak ada
- `98a99e1` — deep probe script + prioritize 0x39b0/0x38a0

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
| F | **Exp 77 probe** — find trust-cache struct address in live kernel | ✅ (addr ditemukan, count=23) |
| G | **Exp 79** — KTRR analysis: KRW write ke __DATA → panic | ✅ (confirmed KTRR blocks write) |
| H | **Exp 80** — RC trust_cache_runtime_add via launchd | 🟡 Belum ditest di device |

### Ultimate technical win
**Exp 80:** Panggil `trust_cache_runtime_add` / `_load_trust_cache` dari launchd RemoteCall context. PPL melakukan write internal — tidak ada KTRR fault. Ini satu-satunya jalur yang tersisa setelah KTRR confirmed.

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

### Exp 77 Probe — DONE ✅
Trust cache struct ditemukan. Probe berjalan ~1–5s tanpa panic.

### Exp 79 KTRR Analysis — DONE ✅
Konfirmasi: `__DATA` di A12 di-protect KTRR (hardware readonly setelah boot).
- PPL = proteksi page table (bypass via physmap)
- KTRR = hardware readonly enforcement (tidak bisa bypass via KRW)

### Exp 80 RC Trust Cache Add — NEXT 🎯
**Jalur satu-satunya yang tersisa:**
1. Dari launchd RemoteCall context
2. `dlsym(RTLD_DEFAULT, "_trust_cache_runtime_add")` atau `_load_trust_cache`
3. Build `trust_cache_module1` struct di `trojanMem`
4. Panggil API → PPL melakukan write internal
5. Verify via posix_spawn binary unsigned

**Expected results:**
- ret=0 → sukses, lanjut spawn test
- ret=EPERM (1) → butuh entitlement, coba dari amfid context
- ret=EINVAL (22) → format struct salah, adjust layout
- ret=EROFS (26) → KTRR juga block API ini (unlikely tapi mungkin)

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

We have **socket KRW + full in-app jailbreak** on **iPhone XR iOS 18.2**. **Exp 74** (physmap) dan **Exp 77** (trust cache probe) sudah hijau — trust cache struct ditemukan di `__DATA` (bukan PPL region). **Exp 79** mengkonfirmasi bahwa KRW write ke `__DATA` di A12 di-block oleh **KTRR** (hardware readonly enforcement), bukan PPL. Satu-satunya jalur yang tersisa adalah **Exp 80: launchd RemoteCall ke `trust_cache_runtime_add`** — PPL yang melakukan write internal sehingga tidak ada KTRR fault. Implementasi sudah ada di `AMFIExperimentView.swift` (tombol ③b). **Jangan** coba KRW write langsung ke trust cache — akan panic. Latest commit: **`c9cee9f`**.
