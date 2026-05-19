# DSPloit — iOS 18.2 Full Jailbreak (Context Transfer)

## GOAL: Execute unsigned binaries on iPhone XR (A12, iOS 18.2)

## WHAT WORKS (all confirmed)
- **Socket KRW**: read/write any kernel VA (zone + kernel __TEXT + physmap)
- **Root (uid=0)**: via launchd RemoteCall
- **Sandbox escape**: sbx_escape()
- **RemoteCall**: call ANY C function in SpringBoard/launchd context
- **Physmap formula**: `gVirtBase = 0xffffffde9a094000` (zone_map_base), `gPhysBase = 0x800000000`
- **Page table walk**: L1→L2→L3 via physmap VAs (16KB granule, 3-level)
- **Physmap READ of PPL pages**: WORKS (read trust cache content through physmap VA)

## THE BLOCKER
**Trust cache is in `__DATA.__ppl_data` (PPL-protected).**
- `ds_kwrite64` to PPL VA → PANIC ("Unexpected fault in kernel static region")
- `ds_kwrite64` to physmap VA of same page → **ALSO PANICS** (AMCC/PPL blocks physical writes too)
- PPL on A12 uses APRR (hardware register) — protects BOTH the original VA AND the physmap VA of PPL pages
- This means physmap write bypass does NOT work on A12 with APRR

## WHAT MUST HAPPEN NEXT (Prompt 9 to Claude — awaiting response)
The ONLY remaining paths to write trust cache:

1. **`pmap_cs_associate` / `trust_cache_runtime_add`** — PPL-internal functions that legitimately add trust cache entries. Call from launchd via RemoteCall. PPL code itself does the write. **MOST LIKELY TO WORK.**
2. **`ml_phys_write_data`** — kernel function for physical writes. Might bypass APRR if called from PPL context. Unlikely from EL1.
3. **PTE AP bit modification** — change page table entry to remove PPL protection. But PTEs are ALSO PPL-protected on A12.
4. **GPU DMA** — AGXAccelerator can DMA to physical memory. DART (IOMMU) likely blocks kernel DRAM range.

## KEY TECHNICAL DETAILS
| Item | Value |
|------|-------|
| Device | iPhone XR (A12, T8020) |
| iOS | 18.2 (22C152), xnu-11215.62.3 |
| gPhysBase | 0x800000000 |
| gVirtBase | 0xffffffde9a094000 (= zone_map_base, changes per boot) |
| Kernel base | varies per boot (slide changes) |
| __DATA.__ppl_data | kernBase + 0x30e4000 |
| Trust cache | inside __DATA.__ppl_data (PPL-protected) |
| Page granule | 16KB (14-bit offset) |
| VA bits | L1[38:36], L2[35:25], L3[24:14], offset[13:0] |
| proc→task | `taskbyproc()` C function (handles PAC) |
| task→vm_map | +0x30 |
| vm_map→pmap | +0x50 |
| pmap→tte | +0x00 |

## OFFSETS
- `off_proc_p_proc_ro` — proc to proc_ro (global, set by exploit init)
- `off_proc_ro_pr_task` = 0x08
- ds_kread64 handles PAC internally (no strip needed)
- `ds_kread64_safe` returns 0 on zone violation but PANICS on PPL access

## EXPERIMENT STATUS
- **Exp 74** (physmap discovery): ✅ SUCCESS — physmap formula verified
- **Exp 77** (trust cache write via physmap): ❌ PANIC — APRR blocks physmap writes to PPL pages too
- All other experiments (1-73, 75-76): DISABLED

## AVAILABLE PRIMITIVES FOR NEXT EXPERIMENT
```swift
// From launchd (uid=0, PID 1):
RootExecutor.rcall(rc, "functionName", arg0, arg1, ...) // call ANY C function
// Can call: dlsym, dlopen, posix_spawn, open, write, mach_task_self, etc.
// Can resolve ANY symbol at runtime via dlsym(RTLD_DEFAULT, "name")

// Kernel R/W:
ds_kread64(addr)        // read 8 bytes from kernel VA
ds_kwrite64(addr, val)  // write 8 bytes to kernel VA
ds_kread64_safe(addr)   // returns 0 on fault (but NOT PPL fault!)
ds_kread32_safe(addr)   // same for 32-bit

// Page table walk (working):
// tteBase → L1 entry → L2 phys → physmap VA → L2 entry → L3 phys → physmap VA → L3 entry → page phys
```

## FILE MAP
| File | Purpose |
|------|---------|
| `lara/views/root/AMFIExperimentView.swift` | All experiments (exp 74 + 77 code) |
| `lara/classes/RootExecutor.swift` | Root ops via launchd RemoteCall |
| `lara/classes/dspmgr.swift` | KRW + process management |
| `lara/kexploit/darksword.m` | Socket KRW primitive |
| `lara/kexploit/darksword.h` | KRW API declarations |
| `lara/kexploit/TaskRop/RemoteCall.m` | Thread hijacking for RC |

## RULES FOR AI ASSISTANT
- Push directly to main (no PRs)
- Panic is OK for experiments
- All features must be REAL/functional (no placeholders)
- Bahasa Indonesia for communication
- Don't give "atau" (or) options — pick the best approach
- After git push: provide TABLE with expected hasil + next step + impact
- Don't push until everything is finished (push triggers CI build)
- Kill app = respring (OK). Bootloop = restore = lose jailbreak (AVOID)
- Only active experiment runs (others disabled)
- `ds_kread64_safe` does NOT prevent PPL panics (hard panic, no recovery)
