# DSPloit — Context Transfer (AMFI Lab / Exp 74–109)

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
| AMFI __DATA writable | ✅ | Exp 93 confirmed |
| CoreTrust __DATA writable | ✅ | Exp 98 confirmed |
| Sandbox extension issue | ✅ | Exp 102 — sandbox.executable issued! |
| XPC connect MobileStorageMounter | ✅ | Exp 100 — connection established |
| XPC connect cryptexd | ✅ | Exp 101 — connection established |
| XPC connect installd | ✅ | Exp 103 — connection established |

## 2. What DOESN'T work (all tested, all failed)

| Approach | Result | Root cause |
|---|---|---|
| Write kernel __TEXT_EXEC | ❌ | KTRR hardware RO |
| Write kernel __DATA | ❌ | KTRR hardware RO |
| Write kernel __DATA_CONST | ❌ | KTRR hardware RO (panic) |
| Write proc_ro cs_flags | ❌ | zone_require_ro hardware |
| Physmap write to kernel text | ❌ | KTRR also blocks physmap |
| task_for_pid(amfid) | ❌ | ret=5 (KERN_FAILURE) |
| Spawn copied binary | ❌ | CDHash mismatch → SIGKILL |
| DYLD_INSERT_LIBRARIES | ❌ | SIGKILL (stripped by AMFI) |
| JIT shellcode | ❌ | APRR blocks unsigned execute |
| amfid kill race | ❌ | Kernel enforces independently |
| AMFI __DATA flags disable | ❌ | Flags = logging, bukan enforcement |
| CoreTrust __DATA zero | ❌ | Validation di kernel level |

## 3. Architecture & Key Files

| File | Role |
|---|---|
| `lara/views/root/AMFIExperimentView.swift` | All experiments (Exp 74-109) — 5009 lines |
| `lara/kexploit/darksword.m` | Socket KRW exploit |
| `lara/kexploit/TrustCacheInjector.m` | TC inject (FIXED: offset 4→20, 8→24) |
| `lara/classes/RootExecutor.swift` | rcall + rcallAddr (FIXED: addr validation) |
| `lara/classes/dspmgr.swift` | Process management, sbProc |
| `lara/kexploit/kcache_analyze.m` | Kernelcache ADRP scan |
| `lara/kexploit/pe/sbx.m` | Sandbox escape |

## 4. Git Rules

- Push ke **main** langsung
- **Jangan push dikit-dikit** — selesaikan SEMUA file dulu, baru 1x commit + 1x push
- Update conversation.md setiap batch
- Komunikasi **Bahasa Indonesia**

## 5. Bugs yang Sudah Di-fix

| Bug | Root Cause | Fix |
|-----|-----------|-----|
| TrustCacheInjector offset SALAH | count di +4 (harusnya +20), entry di +8 (harusnya +24) | Fixed offset sesuai TC v2 format |
| Exp 100 initproc panic | XPC dari launchd = deadlock (launchd = service manager) | Pindah ke SpringBoard RC |
| xpc_dictionary_create return 0 | `xpc_dictionary_create_empty` tidak ada di iOS 18.2 | Pakai `xpc_dictionary_create(0,0,0)` |
| send_with_reply_sync hang | Blocking call → watchdog kill SB | Pakai `send_message` (fire-and-forget) |
| Terlalu banyak RC calls | 50+ calls = SB main thread busy > watchdog | Minimize calls, hybrid launchd+SB |
| posix_spawn ENOENT dari SB | SB sandbox block /usr/bin/ | Pakai launchd RC untuk file ops |
| rcallAddr invalid address | Tidak ada validation → crash | Tambah range check |

## 6. Reverse Engineering Results

### Deep Reverse v5 (GOD MODE) — 994 findings
- **CRITICAL: 91** | HIGH: 318 | MEDIUM: 333 | LOW: 113
- 71 targets analyzed (binaries + firmware + kernelcache)
- Kernelcache decompressed (55MB) — 188,398 strings extracted

### Top Attack Vectors (dari v5):

| # | Target | Attack | Reliability |
|---|--------|--------|-------------|
| 1 | **keybagd** | XPC → system() (4x) — command injection | HIGH |
| 2 | **securityd** | XPC → system() + sqlite3_exec | HIGH |
| 3 | **MobileStorageMounter** | XPC → IOConnectCallMethod (tainted) + TC load entitlement | HIGH |
| 4 | **amfid** | XPC → memcpy overflow + 49 PAC strip gadgets | MED |
| 5 | **lockdownd** | XPC → strcpy overflow + TCC bypass | HIGH |
| 6 | **cryptexd** | XPC → memcpy + TOCTOU + symlink (15x) | MED |
| 7 | **applekeystored** | system() + IOConnectMapMemory64 (DMA) + 200 PAC gadgets | MED |

### Kernel Findings:
- `cs_enforcement_disable` @ kernel offset 0x498d5d (2 refs)
- `boot-args` (52 refs), `nvram` (62 refs), `IONVRAM` (41 refs)
- AMFI kext @ vmaddr 0xfffffff007497c30
- 362 panic() paths (triggerable from userspace)
- 223 kexts in fileset kernelcache

### Key Taint Chains:
```
keybagd:  xpc_dictionary_get_string → system()
securityd: xpc_dictionary_get_string → system() / sqlite3_exec / NSKeyedUnarchiver
launchd:  xpc_dictionary_get_string → strcpy
lockdownd: xpc_dictionary_get_string → strcpy
amfid:    xpc_dictionary_get_string → memcpy / memmove
MobileStorageMounter: xpc_dictionary_get_data → IOConnectCallMethod
```

## 7. Current Experiments (Active)

| Exp | Name | Status | Result |
|-----|------|--------|--------|
| 74 | Physmap Verify | ✅ Works | gVirt/gPhys saved |
| 77 | Trust Cache Probe | ✅ Works | TC found at __DATA |
| 79 | KTRR Write Test | ✅ Works | Delegates to TrustCacheInjector.m |
| 80 | RC Trust Cache Add | ⚠️ | amfi_load_trust_cache not in shared cache |
| 81 | Heap TC Analysis | ✅ Works | Info only |
| 82 | Deep TC Scan | 🔧 Stub | Not implemented yet |
| 93b | AMFI Flag Disable | ✅ Tested | Flags = logging, bukan enforcement |
| 100 | TC Load XPC (SB) | ✅ Fixed | MSM connected, msg sent |
| 101 | cryptexd TOCTOU | ✅ Fixed | Connected, no reply |
| 102 | xpcproxy Sandbox Ext | ✅ Works! | sandbox.executable issued! |
| 103 | installd Deserialization | ✅ Fixed | Connected, no reply |
| 104 | lockdownd Overflow | ⚠️ | Respring (fixed now) |
| 105 | MSM Deep XPC | ⚠️ | No response to commands |
| 106 | Sandbox Exec Spawn | ✅ Tested | ENOENT (SB can't read rootfs) — fixed with launchd |
| 107 | keybagd XPC→system() | 🆕 | NOT TESTED YET |
| 108 | securityd XPC→system() | 🆕 | NOT TESTED YET |
| 109 | amfid XPC Overflow | 🆕 | NOT TESTED YET |

## 8. Next Steps (Priority Order)

1. **Test Exp 107** — keybagd command injection (PALING MENJANJIKAN)
2. **Test Exp 108** — securityd command injection
3. **Test Exp 109** — amfid XPC overflow probe
4. **Re-test Exp 100** — sekarang pakai fire-and-forget (harusnya tidak respring)
5. **Re-test Exp 106** — sekarang pakai launchd untuk file copy
6. Jika 107/108 berhasil → execute binary via keybagd/securityd context
7. Jika tidak → reverse engineer exact XPC protocol dari binary cards

## 9. Trust Cache v2 Format (CONFIRMED)

```
+0x00: uint32 version = 2
+0x04: uuid[16] (16 bytes)  
+0x14: uint32 count         ← FIXED (sebelumnya salah di +0x04)
+0x18: entries[count]       ← FIXED (sebelumnya salah di +0x08)
  Entry (24 bytes): cdhash[20] + hashType(1) + flags(1) + pad(2)
```

## 10. Writable Memory Map

| Segment | VA (unslid) | Size | Writable | Useful? |
|---------|-------------|------|----------|---------|
| AMFI __DATA | 0xfffffff00a330098 | 0x541 | ✅ | ❌ (logging only) |
| CoreTrust __DATA | 0xfffffff00a3b1230 | 0xe8 | ✅ | ❌ (not enforcement) |
| AMFI __DATA_CONST | 0xfffffff007b77a98 | 0x6280 | ❌ PANIC | - |
| Kernel __DATA | 0xfffffff00a0e0000 | large | ❌ PANIC | - |
| Kernel heap | zone allocator | varies | ✅ | ❌ (proc_ro RO) |
