# DSPloit — Context Transfer Document
## Updated: 2026-05-31 | Session: AMFI Bypass Deep Research + Ghidra RE

## Tujuan Akhir: FULL JAILBREAK ACCESS WITHOUT ANY PROBLEMS

**Target**: iOS 16.0–18.7.1 + 26.0–26.0.1 | A11–A18 + M1/M2 | Semi-tethered | One-tap jailbreak

---

## CURRENT STATUS (2026-05-31)

### What WORKS (confirmed on device — iPhone XR iOS 18.2):
```
✅ Kernel exploit (darksword) — working
✅ Sandbox escape — working
✅ RemoteCall (SpringBoard + launchd) — working
✅ Root (uid=0) — working via launchd RC
✅ VFS filesystem access — working
✅ AMFI 10 flags zeroed — working (writable __DATA)
✅ cs_enforcement_disable = 1 — working (writable)
✅ posix_spawn signed binary (/bin/df) — working (ret=0)
✅ amfid found via procbyname — PID 54
✅ amfid text base found — 0x100104000
✅ exc_guard disabled on amfid — working
```

### What DOESN'T WORK (all approaches tried):
```
❌ posix_spawn UNSIGNED binary — EPERM (AMFI still blocking)
❌ RC to amfid — "restricted exception ports on iOS 18"
❌ task_for_pid from launchd — ret=5 (AMFI denies even from uid=0)
❌ task_for_pid from SpringBoard — respring (no entitlement)
❌ IPC port forge — PAC kills it (Break 0xC472)
❌ Page table walk — physical addresses, ds_kread64 can't read them
❌ cs_flags patch on amfid — PPL blocks (proc_ro protected)
❌ IOKit TC load from SpringBoard — causes respring
❌ RC to cryptexd — fails (restricted exception ports)
❌ RC to MobileStorageMounter — fails
❌ Direct kernel TC write — PPL protected (trust cache in PPL memory)
❌ amfi_only_platform_code flag — __DATA_CONST (KTRR), write causes panic
❌ trust_cache_load_gate — __DATA_CONST (KTRR), causes panic
❌ developer_mode_init — __DATA_CONST (KTRR), causes panic
❌ pmap_cs_enforcement — __DATA_CONST (KTRR), causes panic
```

### Hardware Protections Blocking Us:
```
KTRR: Protects kernel __TEXT and __DATA_CONST (amfi_only_platform_code, tc_load_gate)
PPL:  Protects trust cache memory, proc_ro, page tables
PAC:  Protects IPC entries (can't forge task ports)
```

---

## GHIDRA RE FINDINGS (this session)

### CRITICAL: Kernel amfid callout logic (FUN_fffffff008f86398)
```
vnode_check_signature flow:
1. Check if CDHash is in trust cache (FUN_fffffff008f84198)
   → If YES: skip amfid, mark as "trust-cache", ALLOW
   → If NO: continue to step 2

2. Check DAT_fffffff007b79bd9 (amfi_only_platform_code)
   → If 0: SKIP amfid callout entirely
   → If 1 (default): call amfid via MIG (FUN_fffffff008f8abc4)

3. amfid validates signature → returns valid/invalid
4. Kernel acts on amfid's response
```

### DAT_fffffff007b79bd9 (amfi_only_platform_code)
- Set during AMFI init from device tree property "amfi-only-platform-code"
- Value = 1 on production devices
- Located in __DATA_CONST → KTRR protected → CANNOT WRITE (causes panic)
- If we COULD write it to 0, kernel would never call amfid

### Trust Cache Lookup Path
```
FUN_fffffff008f84198 → FUN_fffffff008f7b564 → FUN_fffffff0082857b4 → FUN_fffffff007da2a6c
→ FUN_fffffff007d9897c (PPL DISPATCH)
```
Trust cache queries go through PPL. The actual TC data is in PPL-guarded memory.
Cannot be written via normal KRW.

### TC Slot Table (0xfffffff00798f600 + slide)
- Scanned on device: no valid TC modules found at expected offsets
- Either the address is wrong or the structure layout differs from what we assumed
- The slot table may be in __DATA_CONST too

### Writable Addresses (confirmed):
```
0xfffffff00a160798 + slide = cs_enforcement_disable (uint32, writable)
0xfffffff00a330098 + slide = AMFI __DATA base (10 flags at offsets, writable)
0xfffffff00a3304c0 + slide = AMFI IOKit object pointer
0xfffffff00a330590 + slide = DAT used in vnode_check_signature
```

### Read-Only Addresses (KTRR/__DATA_CONST — DO NOT WRITE):
```
0xfffffff007b79bd9 + slide = amfi_only_platform_code (PANIC if written)
0xfffffff007b795e8 + slide = trust_cache_load_gate (PANIC if written)
0xfffffff00a0e45b8 + slide = pmap_cs_enforcement (PANIC if written)
0xfffffff00a0e1368 + slide = developer_mode_init (PANIC if written)
0xfffffff00a0e00e0 + slide = PPL dispatch flag
```

---

## AUDIT: DSPloit vs Upstream Lara vs DarkSword

### Upstream rooootdev/lara:
- Customization toolbox ONLY (not a jailbreak)
- Uses darksword for KRW but only does: font overwrite, MobileGestalt, file manager, status bar tweaks
- Does NOT attempt: AMFI bypass, TC injection, unsigned exec, package management, SSH
- Known issues: "remotecall is super bugged"

### DSPloit additions beyond upstream:
- Multi-exploit selector (darksword + 3 skeleton exploits)
- Full AMFI bypass system (5+ strategies, all blocked by hardware)
- Trust cache injection attempts (IOKit, direct write, MSM XPC)
- RootExecutor (launchd operations as uid=0)
- Package manager (dpkg compatible)
- SSH manager (dropbear)
- Tweak loader (dlopen injection)
- App registration (installd XPC)
- KRW persistence
- Dynamic offset resolution (XPF)
- 15+ experiments for AMFI/TC research

### DarkSword (original Russian spyware) approach:
- NEVER patches amfid or loads trust caches
- Runs ALL code inside already-signed processes via RemoteCall
- Uses NSInvocation + JSContext injection for complex operations
- This is the viable path for us too

---

## REMAINING VIABLE APPROACHES

### Option A: RC-Based Jailbreak (DarkSword approach) — MOST REALISTIC
```
Don't spawn unsigned binaries. Instead:
1. Deploy functionality as function calls via RC to SpringBoard/launchd
2. SSH: inject dropbear-equivalent code into launchd via RC
3. Tweaks: call dlopen in SpringBoard (needs signed dylib OR...)
4. Package ops: all via launchd RC (mkdir, write, chmod, etc.)
5. File manager: already working via VFS + RC

Limitation: no standalone binaries in /usr/bin/
But: 95% of jailbreak functionality works
```

### Option B: Find entitled process for TC load
```
Need a process that:
1. Has "com.apple.private.amfi.can-load-trust-cache" entitlement
2. We can connect RemoteCall to (not restricted exception ports)

Known entitled processes:
- cryptexd ← RC fails (restricted)
- MobileStorageMounter ← RC fails
- (need to find others)

If we find one → IOKit selector 2 → TC loaded → full unsigned exec
```

### Option C: Wait for community
```
Wait for opa334, Linus Henze, or others to publish AMFI/PPL bypass for iOS 18.
Then integrate into DSPloit.
```

---

## KEY KERNEL ADDRESSES (iPhone XR iOS 18.2, this boot)

```
Kernel base:           0xfffffff024190000
Kernel slide:          0x1d18c000
amfid proc:            0xffffffdfe8fba148
amfid PID:             54
amfid text base:       0x100104000
amfid patch target:    0x100106ec8 (cbz w22 → NOP)
cs_enforcement_disable: 0xfffffff024190000 + 0x3170798 (writable)
AMFI __DATA base:      0xfffffff024190000 + 0x3540098 (writable)
```

---

## FILES MODIFIED THIS SESSION

```
lara/experiments/exp_amfid_nop_final.swift — fixed brace mismatch + nil param
lara/experiments/exp_tc_direct_inject.swift — NEW: direct TC inject via KRW
lara/experiments/exp_code_exec_proof.swift — NEW: jailbreak proof without binary
lara/views/root/ExperimentsView.swift — added new experiment buttons
```

---

## FLOW CARA PAKAI (USER)

### Untuk iPhone XR iOS 18.2 (device owner):
```
1. Build IPA: ./scripts/build_ipa.sh
2. Sideload ke device via TrollStore / AltStore / Xcode
3. Buka app DSPloit
4. Tap "Jailbreak" (satu tombol)
5. Tunggu ~10-30 detik
6. Status: "Jailbroken ✅" → selesai
7. Tab "Root" → File Manager, Packages, Banking, Daemons
8. Setelah reboot: buka app lagi, tap "Jailbreak" lagi
```

---

## QUICK REFERENCE

```c
// Multi-exploit
exploit_type_t exploit_select_best(void);
int exploit_run_selected(exploit_type_t type);

// Core KRW
int ds_run(void);
bool ds_is_ready(void);
bool ds_krw_ready(void);
uint64_t ds_kread64(uint64_t addr);
void ds_kwrite64(uint64_t addr, uint64_t value);
uint8_t ds_kread8(uint64_t addr);
void ds_kwrite8(uint64_t addr, uint8_t val);

// Process
uint64_t ds_get_our_proc(void);
uint64_t ds_get_kernel_base(void);
uint64_t ds_get_kernel_slide(void);
uint64_t procbypid(pid_t pid);
uint64_t procbyname(const char *name);
uint64_t taskbyproc(uint64_t proc);
uint64_t ds_kreadptr(uint64_t va); // strips PAC

// RemoteCall
RootExecutor.rcall(rc, "functionName", arg0, arg1, ...)
RootExecutor.rcallAddr(rc, fnAddr, arg0, arg1, ...)
remote_alloc_str(rc, "string") → remote address
```

---

## KEY REFERENCES

| Resource | What it provides |
|----------|-----------------|
| [zeroxjf/cyanide-ios](https://github.com/zeroxjf/cyanide-ios) | Working darksword iOS 17–18.7.1 |
| [rooootdev/lara](https://github.com/rooootdev/lara) | Upstream (we are AHEAD — they only do customization) |
| [DarkSword Analysis](https://github.com/AntonioCiolino/DarkSword-Analysis) | Full chain docs |
| opa334/darksword-kexploit | Original PoC (in workspace) |
| CVE-2025-43510/43520 | Kernel CVEs (patched 18.7.2/26.1) |

---

*DSPloit — iOS 16–18.7.1 • A11–A18 • Full Jailbreak*
*Created by Royan | Last updated: 2026-05-31*
