# DSPloit Research Guide

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
