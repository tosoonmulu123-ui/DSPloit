# DSPloit Research Findings — Mass Scan (2026-05-30)
## All binaries scanned via Ghidra MCP

---

## KERNELCACHE — Critical Paths

### 1. task_for_pid Permission (FUN_fffffff008f89078)
**Allows task_for_pid if:**
- Target has `get-task-allow` AND developer mode ON → return 0 (allow)
- Caller has `com.apple.system-task-ports.control` → allow
- Caller has `task_for_pid-allow` → allow
- param_3 == 3 → allow (special case)

**Implication:** If we patch amfid's cs_flags to add `get-task-allow`, 
task_for_pid from launchd should work (launchd has developer mode ON).

### 2. cs_enforcement_disable Boot-Arg (FUN_fffffff008f852c8)
**AMFI init checks boot-arg `cs_enforcement_disable`:**
```
if boot-arg set AND FUN_fffffff00850817c(0) != 0:
    → CS enforcement DISABLED globally!
else:
    → panic "can't has cs_enforcement_disable"
```
`FUN_fffffff00850817c(0)` likely checks if device is in research/dev mode.
The variable at `0xfffffff00a160798` (cs_enforcement_disable) is the RUNTIME
flag that we successfully write to 1. But the boot-arg path is different.

### 3. Launch Constraints (writable AMFI __DATA)
```
launch_constraints_enforced:        0xfffffff00a330278 (pointer)
launch_constraints_3rd_party_allowed: 0xfffffff00a3303e8 (pointer)
amfi_enforce_launch_constraints:    in AMFI __DATA
amfi_allow_3p_launch_constraints:   in AMFI __DATA
```
These are in the WRITABLE range! Disabling launch constraints might help.

### 4. IOKit AMFI Dispatch Table (confirmed)
```
sel 0: NULL
sel 1: NULL  
sel 2: FUN_fffffff008f76ee4 (TC load — needs entitlement)
sel 3: NULL
sel 4: FUN_fffffff008f77100
sel 5: FUN_fffffff008f7714c (isCdhashInTrustCache — input=20 bytes)
sel 6: FUN_fffffff008f772c4 (loadCompilationServiceCDHash)
sel 7: FUN_fffffff008f76ee4 (TC load with manifest)
sel 9: FUN_fffffff008f77438
sel 11-17: various
```

### 5. pmap_cs_allow_invalid Entitlement Check (FUN_fffffff008f89210)
**Returns 0 (ALLOW) if process has ANY of:**
- `get-task-allow`
- `run-invalid-allow`
- `run-unsigned-code`
- `research.com.apple.license-to-operate`

**Our app already has `get-task-allow` = true!**
This means pmap_cs should allow invalid pages for OUR process.

---

## AMFID — Validation Path

### MIG Handler: verify_code_directory (FUN_100003d08)
- Kernel calls amfid via MIG when binary needs validation
- Calls FUN_100002dd0 (iOS path)
- Creates AMFIPathValidator_ios → validateWithError:
- **cbz w22, 0x100002f74** at offset 0x2ec8 = FAIL branch
- Patching to NOP = ALL binaries pass

### XPC Services:
- `com.apple.amfi.mach` — MIG (kernel → amfid)
- `com.apple.amfi.xpc` — XPC (other daemons → amfid)
- `com.apple.amfi.nsxpc` — NSXPC

### Key Functions (from libmis.dylib):
- `_MISSetProfileTrust` — set trust for provisioning profile
- `_MISRemoveProfileTrust` — remove trust
- `_MISEnumerateTrustedUPPs` — list trusted profiles
- `_MISCopyAuxiliarySignature` — copy aux signature

### Entitlement-gated XPC methods:
- `setTrustForUuid:` — needs `com.apple.private.amfi.set-trust`
- `setSupervisedState:` — needs `com.apple.private.amfi.set-supervised`
- `setDemoState:` — needs `com.apple.private.amfi.set-demo`
- `initiateDeveloperModeDaemonsWithReply:` — needs `com.apple.private.amfi.developer-mode-control`

---

## LAUNCHD — Spawn Path

### Key Entitlements:
- `com.apple.private.spawn-driver` — allows spawning services
- `com.apple.xpc.launchd.spawn` — XPC spawn service

### AMFI Integration:
- `_amfi_launch_constraint_set_spawnattr` — sets AMFI constraints on spawn
- Launch constraints checked before every spawn

### posix_spawn:
- launchd calls posix_spawn() for all service launches
- Has full spawn attribute control (uid, gid, flags, etc.)

---

## INSTALLD — App Installation

### Key Finding:
```
"System app upgrade is missing upgrade entitlement 
(disable code signing enforcement via boot-args to avoid this)."
```
installd has a path that skips CS checks if boot-args disable enforcement!

### Entitlement Validation:
- `_ValidateMIAllowedSPIEntitlement` — checks caller entitlement
- `MIGetBooleanEntitlement` — reads entitlements from bundles
- Has extensive entitlement validation for installed apps

---

## MOBILE STORAGE MOUNTER — Trust Cache Loading

### Trust Cache Paths:
- `ImageTrustCache` — XPC key for TC data
- `%s/.TrustCache` — file path pattern for TC files
- `"Failed to load trust cache."` — error message
- `"Personalized trust cache required"` — needs personalization

### Key: MSM loads TC from DISK PATH
The function at FUN_10000f008 loads trust caches from a directory.
If we can write a TC file to the right path AND trigger MSM to load it...

---

## CRYPTEXD — Trust Cache via IOKit

### Confirmed Path (from RE):
1. `IOServiceMatching("AppleMobileFileIntegrity")`
2. `IOServiceOpen(service, task_self, 0, &conn)`
3. `IOConnectCallMethod(conn, 7, NULL, 0, buffer, size, ...)`
4. Buffer: [uint64 tc_size][uint64 manifest_size][tc_data][manifest_data]

### Has Entitlement: `com.apple.private.amfi.can-load-trust-cache`
### RC Connection: FAILED (restricted exception ports)

---

## APPROACH PRIORITY (based on findings)

### A. amfid NOP Patch (HIGHEST — no PPL, no KTRR)
1. amfi_bypass_hijack_amfid() finds amfid + patches cs_flags ✅ (C code works)
2. task_for_pid from launchd (uid=0) → get amfid task port
3. mach_vm_region → find __TEXT base
4. mach_vm_protect(VM_PROT_ALL) → make writable
5. mach_vm_write(NOP) at offset 0x2ec8
6. ALL binaries pass validation

### B. IOKit Trust Cache (PROVEN once — inconsistent)
- IOServiceOpen succeeded once (selector 1 = SUCCESS)
- But inconsistent (sometimes 0xe00002c2)
- Need to understand what state makes it work

### C. Launch Constraint Disable (NEW — writable flags)
- Zero `amfi_enforce_launch_constraints` in AMFI __DATA
- May allow spawning without constraint checks
- Worth trying alongside other approaches

### D. MISSetProfileTrust via amfid XPC (NEW)
- If we can call amfid's XPC with `set-trust` entitlement
- Could register our binary's profile as trusted
- Needs: entitlement injection or find process that has it

### E. cs_enforcement_disable + research mode (PARTIAL)
- We can write cs_enforcement_disable = 1 ✅
- But the AMFI init check (boot-arg path) is separate
- The runtime flag alone may not be enough
- Combined with other flags → might work
