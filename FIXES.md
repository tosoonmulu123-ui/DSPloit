cat > /home/claude/DSPloit_fixed/FIXES.md << 'EOF'
# DSPloit — Patch Notes & Fix Log

> **Untuk keperluan pembelajaran iOS kernel security research.**
> Semua perubahan didokumentasikan di sini beserta penjelasan teknis.

---

## Bug Fixes

### Fix 1 — `cmp8_wait_for_change`: Infinite loop → Timeout 5 detik
**File:** `lara/kexploit/darksword.m`

**Sebelum:**
```c
while (*ptr == old_val) ;  // busy-wait tanpa batas
```
**Sesudah:** Timeout 5 detik dengan `usleep(1)` per iterasi.

**Kenapa penting:** Jika `free_thread` crash atau race condition gagal,
fungsi ini loop selamanya → watchdog iOS kill proses → unjailbreak.

---

### Fix 2 — `ds_isvalid`: Logic VM_MIN/MAX selalu true
**File:** `lara/kexploit/darksword.m`

**Sebelum:**
```c
if (VM_MIN_KERNEL_ADDRESS && VM_MAX_KERNEL_ADDRESS) { ... }
```
`VM_MIN_KERNEL_ADDRESS = 0xffff000000000000` → selalu truthy.
Validasi lolos untuk hampir semua uint64_t yang bit tingginya set,
termasuk pointer rusak.

**Sesudah:** Prefix check eksplisit `0xffff...` dan reject nilai terlalu rendah.

---

### Fix 3 — `ds_kread64_safe`: Nama menyesatkan + PPL tidak aman
**File:** `lara/kexploit/darksword.m`

**Masalah:** `@catch (NSException)` TIDAK menangkap PPL hard panic.
Nama "safe" menyebabkan developer menggunakannya di PPL region → panic.

**Sesudah:** Tambah dokumentasi eksplisit + heuristik guard PPL range
+ log peringatan jika ada akses ke range yang mencurigakan.

---

### Fix 4 — `get_ios_major_version`: Build number fragile
**File:** `lara/kexploit/darksword.m`

**Sebelum:** Parse `kern.osversion` ("22C152") → `atoi` → "22" → iOS 18.
Masalah: beta iOS 26 bisa punya build number overlap dengan iOS 18.x.

**Sesudah:** `kern.osproductversion` ("18.2", "26.0") → parse major langsung.
Fallback ke build number jika `osproductversion` gagal.

---

### Fix 5 — `procbypid` / `procbyname`: Infinite loop jika linked list corrupt
**File:** `lara/kexploit/utils.m`

**Sebelum:** `while(1)` tanpa cycle detection. Jika `next == start` (circular)
atau pointer corrupt → loop selamanya.

**Sesudah:** Iteration limit 1024 + cycle detection (`next == start`).

---

### Fix 6 — `kernprocaddress`: Hardcoded fallback terlalu dini
**File:** `lara/kexploit/utils.m`

**Sebelum:** Jika tidak ada cache → langsung pakai hardcoded `0xfffffff0079fd9c8`
(hanya valid untuk iOS 18.2 build 22C152 A12).

**Sesudah:** Urutan lookup:
1. UserDefaults cache
2. XPF runtime resolve (akurat semua firmware)
3. Hardcoded fallback (terakhir, dengan warning)

---

### Fix 7 — `kMainKernelTextUnslid`: Hardcoded A-series only
**File:** `lara/kexploit/kcache_analyze.m`

**Sebelum:** `0xfffffff007004000` hardcoded → M-series iPad (`0xfffffe0007004000`)
selalu gagal scan karena `text.vmaddr != kMainKernelTextUnslid`.

**Sesudah:** Cek kedua kemungkinan (A-series dan M-series).
Fallback scan jika vmaddr terlihat seperti kernel VA tapi tidak cocok keduanya.

---

## Exp 79 — Trust Cache Write Test (BARU)

**File:** `lara/kexploit/TrustCacheInjector.h` + `TrustCacheInjector.m`

Eksperimen kritis berikutnya setelah Exp 77 probe sukses.
Berisi 3 tahap yang harus dilakukan berurutan:

**Tahap 1: Write Test (harmless)**
Tulis nilai dummy ke slot kosong di luar `count` untuk verifikasi
apakah `__DATA` region bisa ditulis via KRW tanpa PPL panic.

**Tahap 2: CDHash Inject**
Jika write test sukses, inject CDHash binary target ke trust cache
dan increment `count`.

**Tahap 3: Verify via posix_spawn**
Spawn binary unsigned via RemoteCall dari launchd. Jika berhasil
tanpa SIGKILL → AMFI bypass confirmed.

---

## Cara Testing

```
1. Jailbreak dulu (Main → Jailbreak)
2. Root → AMFI Lab
3. Run Exp 74 (physmap verify)
4. Run Exp 77 (trust cache probe)
5. Run Exp 79 (trust cache write test) ← BARU
6. Lihat log — apakah write verify == 0xDEADBEEFCAFEBABE?
7. Jika ya → run inject CDHash