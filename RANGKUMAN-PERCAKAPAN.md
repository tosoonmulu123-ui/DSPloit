# Rangkuman Percakapan — DSPloit

_Exported: 20 Mei 2026_

---

## Fokus saat ini (Mei 2026)

**Banking selesai** — hide `/var/jb` works; tidak lagi prioritas riset.

**Target utama:** **Full jailbreak** via AMFI Lab (physmap → trust cache → spawn unsigned binary).

**Langkah berikutnya di device:** Main jailbreak → AMFI ① Exp 74 → ② Exp 77 probe (pakai **kernproc pmap**, bukan our_proc) → ③ inject jika probe OK.

---

## 1. Fitur Mobile Banking (Root tab) — selesai

**Permintaan:** Akses kembali app Mobile Banking yang terblokir (kemungkinan karena `/var/jb`).

**Yang dibuat:**
- `MobileBankingView.swift` — kartu **Banking** di Root tab
- **Scan** jejak jailbreak (`/var/jb`, Cydia, apt, Frida, dll.)
- **Sembunyikan /var/jb** → rename ke `/var/.dsploit_jb_stash` (reversible)
- **Restore /var/jb** setelah selesai banking
- Link ke **VarClean** + **Respring**
- `jb` ditambahkan ke `VarCleanRules.json`

**Cara pakai:** Jailbreak → Root → Banking → Hide → force-quit app bank → buka lagi → Restore setelah selesai.

---

## 2. AMFI Lab — Jailbreak path (setelah Exp 74 sukses)

**Konteks:** User berhasil Physmap Verify (PPL bypass message) dan minta lanjutan.

**Yang dibuat:**
- Section **Jailbreak Path** di AMFI Lab:
  1. Physmap Verify (Exp 74)
  2. Trust Cache Probe (Exp 77 read-only)
  3. Trust Cache Inject (Exp 77 FULL — risiko panic)
  4. Test Binary Spawn
- `PhysmapConstants` — simpan `gVirtBase` / `gPhysBase` ke UserDefaults setelah Exp 74 sukses

---

## 3. Panic Exp 74 — `initproc exited`

**Panic log:** `initproc exited`, task **launchd (PID 1)**.

**Penyebab:** Exp 74 menahan koneksi **launchd** sambil memanggil **IOSurface** di SpringBoard + estimasi zone map salah.

**Perbaikan (`7c4ba25`):**
- Exp 74 & 77 Probe → **KRW-only** (tanpa launchd)
- Hapus IOSurface dari Exp 74
- `gVirtBase` dinamis dari `our_proc`

---

## 4. Compile error GitHub Actions

**Error:** Duplikat kode orphan ~570 baris setelah `expDARTPTEProbe` di `AMFIExperimentView.swift`.

**Fix:** Hapus blok duplikat (`d0daa2f`).

---

## 5. Polish UI — fokus rilis

**Yang dibuat:**
- Tab: **Main** + **Root** saja (hapus Tweaks, Files, Logs tab)
- `GuideView` — panduan first-launch
- `ReleaseUI.swift` — status chip, readiness banner, tool cards
- Root dashboard: Essentials / Advanced
- Hapus `TweaksView.swift` dari navigasi

**Catatan:** File tweak lama masih di `lara/views/tweaks/` tapi tidak terhubung UI.

---

## 6. Hasil Exp 74 terbaru (screenshot user)

### Yang berhasil ✅

| Langkah | Hasil |
|--------|--------|
| KRW baca kernel `__TEXT` | Mach-O `0xFEEDFACF` |
| Pointer chain | proc → task → vm_map → pmap → **tte** |
| vm_map | `task+0x30` |
| pmap / tte | Terbaca |

### Yang gagal ❌

```
zone_from_proc: skip — physmapVA out of range
tte & ~0xFFFFFF: skip — physmapVA out of range
```

**Penyebab:** Validasi `isPhysmapVA` salah — menolak `physmapVA` di `0xfffffff80...` (kernel map) karena memaksa alamat harus ≥ estimasi zone (`0xffffffe2...` dekat proc). Zone map asli biasanya **`0xffffffdc..0xe0`**, bukan dekat proc.

**Perbaikan lanjutan:** Scan `gVirtBase` di rentang physmap `0xdc–0xe2`, hapus guard `physmapVA out of range`, filter kandidat dengan `ttep` fisik masuk akal (`0x800000000–0x900000000`).

---

## 7. Commit penting

| Commit | Isi |
|--------|-----|
| (awal) | Mobile Banking + AMFI path |
| `d0daa2f` | Fix compile orphan Exp 78 |
| `bbbbffd` | Polish UI Main/Root |
| `534d3d3` | Hapus tab Tweaks/Files |
| `7c4ba25` | Fix panic Exp 74 (KRW-only) |

---

## 8. Langkah disarankan user

1. **Main** → Jailbreak (semua langkah hijau)
2. **Root** → AMFI Lab → ① Physmap Verify
3. Jika ① ✅ → ② Trust Cache Probe (kernel pmap) → ③ Inject (hati-hati panic)
4. Jangan tutup app saat eksperimen berjalan
5. Banking (Root) hanya jika perlu hide `/var/jb` lagi — bukan jalur jailbreak

---

## 9. Batasan yang masih ada

- Exp 77 probe: butuh **kernel pmap**; offset `__DATA.__ppl_data` bisa beda per build
- Exp 77 inject bisa panic (APRR/PPL write)
- `gVirtBase` dari Exp 74 perlu divalidasi (bukan sekadar match ke kernBase)
- Reboot = hilang jailbreak
- File tweak lama masih di repo, tidak di UI
