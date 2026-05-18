# DSPloit Research Guide

## Step-by-Step (Kirim Foto Hasilnya ke Chat)

Tunggu build selesai dulu (cek GitHub Actions). Kalau sudah hijau, install IPA ke iPhone, lalu ikuti langkah ini:

---

### STEP 1: Jalankan Exploit

1. Buka app DSPloit
2. Tap **"Run Exploit"**
3. Tunggu sampai muncul ✅ hijau
4. **Foto layar** → kirim ke chat

---

### STEP 2: Initialize System

5. Tap **"Initialize System"** (atau "VFS Init" + "Sandbox Escape" kalau terpisah)
6. Tunggu sampai VFS ✅ dan Sandbox ✅
7. **Foto layar** → kirim ke chat

---

### STEP 3: Test IOSurface KRW (BARU)

8. Pergi ke tab **Kernel Exploit Suite**
9. Scroll ke section **"🔥 Kernel Internals"**
10. Tap **"IOSurface KRW"**
11. Tap **"Open IOSurfaceRoot"**
12. **Foto layar** → kirim ke chat (saya mau lihat apakah berhasil atau error)

---

### STEP 4: Test Sandbox Escape Engine (FIX CRASH)

13. Back ke Kernel Exploit Suite
14. Scroll ke **"🔥 Sandbox & Security"**
15. Tap **"Sandbox Escape Engine"**
16. Kalau TIDAK crash → **foto layar**
17. Kalau crash → bilang "crash"

---

### STEP 5: Test ROP Chain Builder (FIX CRASH)

18. Back ke Kernel Exploit Suite
19. Scroll ke **"🔥 Privilege Escalation"** atau cari **"ROP Chain Builder"**
20. Tap masuk
21. Tap **"Scan for Gadgets"** atau **"Scan Kernel Text"**
22. Kalau TIDAK crash → **foto layar**
23. Kalau crash → bilang "crash"

---

### STEP 6: Test Cheat Engine (FIX CRASH)

24. Back ke Kernel Exploit Suite
25. Cari **"Cheat Engine"**
26. Tap masuk
27. Di "PID or Process Name" ketik: `1` (ini launchd/kernel_task)
28. Tap **"Attach"**
29. Tap **"First Scan"** (biarkan default value)
30. Kalau TIDAK panic/reboot → **foto layar**
31. Kalau device reboot → bilang "panic"

---

## Yang Saya Butuhkan dari Foto

Dari setiap foto, saya akan baca:
- Status indicators (✅ atau ❌)
- Error messages (teks merah)
- Hex addresses (angka 0x...)
- Apakah fitur jalan atau crash

**Kirim foto satu-satu**, saya analisis langsung.

---

## Kalau Build Masih Error

Kalau GitHub Actions masih merah, kirim isi `compile-logs.txt` ke chat. Saya fix dulu sebelum kamu test di device.

---

## Ringkasan Singkat Projek Ini

**Apa yang sudah bisa:**
- Exploit kernel iPhone XR iOS 18.2 ✅
- Baca/tulis memori kernel (terbatas heap) ✅
- Escape sandbox (akses file system) ✅
- IOSurface mapping ✅
- VFS filesystem read/write ✅

**Apa yang belum bisa:**
- Jadi root (uid=0) ❌ — diblokir PPL
- Baca semua memori kernel ❌ — panic kalau baca non-heap

**Eksperimen Baru (v2):**
1. 🔴 Daemon Exploit — exploit installd/SpringBoard/backboardd dari sandbox-escaped state
   - Tab: Kernel Exploit Suite → Next Experiments → Daemon Exploit
   - Butuh: RemoteCall initialized
   - Bisa: execute code di daemon context (getuid, getpid, launch app, install IPA)

2. 🟠 Persistence — survive reboot via VFS LaunchDaemon
   - Tab: Kernel Exploit Suite → Next Experiments → Persistence Engine
   - Butuh: VFS ready
   - Bisa: install LaunchDaemon, stash KRW ports, cron job, DYLD hook

3. 🟣 Alternative KRW — cari primitif baru
   - Tab: Kernel Exploit Suite → Next Experiments → Alternative KRW
   - Butuh: Kernel ready
   - Bisa: pipe buffer KRW, mach_msg OOL research, physmap scan, IOKit research

**Tujuan sekarang:**
- Test daemon exploit (connect ke installd, cek uid)
- Test persistence (stash KRW, install LaunchDaemon)
- Test pipe KRW (find pipe buffer in kernel)
- Kalau pipe KRW works → bisa akses memory region yang socket KRW tidak bisa
