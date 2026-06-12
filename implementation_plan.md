# DSPloit — New AMFI Bypass: Ghidra RE Deep Dive

## Goal
Find a **new approach with high success chance** to bypass AMFI on iOS 18.2, based on deep reverse engineering of the decrypted kernelcache and userland binaries in Ghidra.

---

## 🔥 3 NEW Approaches (Not Previously Attempted)

### Approach 1: cryptexd Trust Cache Load via IOKit Selector 7 ⭐ HIGHEST CHANCE

> [!IMPORTANT]
> This is the most promising path. `cryptexd` is the **official** process that loads trust caches on iOS 18. It uses IOKit selector **7** (not 2, which we tried before). We need to hijack cryptexd's execution to call this for us.

**Full Attack Chain:**
1. Use KRW to **clear `hardened_exception_action`** in cryptexd's `task` struct (this is what blocks RC)
2. Connect RemoteCall to cryptexd (no longer restricted)
3. Use RC to call cryptexd's internal `amfi_load_trust_cache()` function
4. This function calls `IOConnectCallMethod(conn, 7, ...)` — the exact API Apple uses
5. Kernel validates entitlement on **cryptexd** (which HAS `can-load-trust-cache`) → PASSES
6. Our CDHash enters the trust cache → unsigned binary execution is UNLOCKED

**Why This Has High Chance:**
- We're not fighting hardware (KTRR/PPL) — we're using the **legal API path**
- cryptexd already has the correct entitlements
- The only blocker is `hardened_exception_action` — a **software** flag in the `task` struct
- `task` struct is in **kernel heap** (writable via KRW!)

---

### Approach 2: Developer Mode Resolved Flag (Writable Gate)

> [!NOTE]
> Setting `DAT_fffffff00a330574` to `1` opens a critical gate in `vnode_check_signature`. Without this, ALL non-trust-cache binaries are rejected before any other check.

**What We Found:**
- `DAT_fffffff00a330574` = `developer_mode_resolved` — located in AMFI `__DATA` (WRITABLE!)
- Currently `0` on the device → kernel says "only platform binaries until developer mode status has been resolved"
- Setting to `1` via KRW opens the gate for developer-signed binaries

**Limitation:** This alone doesn't bypass AMFI for *unsigned* binaries, but it's **required** for Approach 1 to work fully (trust cache entries need developer mode resolved).

---

### Approach 3: Developer Mode Enable via AMFI __DATA Flags

> [!NOTE]
> Multiple writable flags in AMFI __DATA control developer mode behavior. Combined with Approach 1, this creates a complete bypass.

**Writable Flags Found:**
| Address (unslid) | Name | Current Value | Effect |
|---|---|---|---|
| `0xfffffff00a330574` | developer_mode_resolved | `0` | Gate for all non-TC binaries |
| `0xfffffff00a33044f` | developer_mode_requested | `1` ✅ | Already set! |
| `0xfffffff00a3304c0` | AMFI IOKit object ptr | valid | IOKit connection target |
| `0xfffffff00a3304e8` | AMFI provider | valid | Service object |
| `0xfffffff00a330590` | AMFI vnode data ptr | valid | Used in signature check |

---

## Ghidra RE Findings Detail

### 1. Trust Cache Load Flow (Kernel)

```
FUN_fffffff008f76ee4  ← IOKit external method handler (TC load request)
  │
  ├─ Check entitlement: "com.apple.private.amfi.can-load-trust-cache"
  │   └─ cryptexd HAS this ✅
  │
  ├─ Check IOKit selector:
  │   ├─ selector == 7 → FUN_fffffff008f858c4 (with manifest)
  │   └─ selector == 2 → FUN_fffffff008f858b4 (without manifest)
  │
  └─ FUN_fffffff008f7b744  ← Trust cache gate
      │
      ├─ Check DAT_fffffff007b795e8 (trust_cache_load_gate)
      │   └─ In __DATA_CONST → KTRR → can't change
      │   └─ BUT: if device is UNLOCKED → gate bypassed! ✅
      │
      └─ FUN_fffffff0082850f0  ← PPL dispatch
          │
          ├─ FUN_fffffff00828516c  ← Actual PPL handler
          │   ├─ Check "com.apple.private.pmap.load-trust-cache"
          │   ├─ Read TC slot from DAT_fffffff00798f600
          │   └─ FUN_fffffff0082853dc → Load TC into PPL memory
          │
          └─ Returns 0 on success
```

### 2. cryptexd amfi_load_trust_cache() (Userland)

```c
// Decompiled from cryptexd binary — FUN_10002d45c
void amfi_load_trust_cache(tc_data, manifest, log) {
    service = IOServiceMatching("AppleMobileFileIntegrity");
    IOServiceOpen(service, mach_task_self(), 0, &connection);
    
    // Build buffer: [manifest_size | tc_size | manifest_data | tc_data]
    buffer = mmap(manifest_size + tc_size + 16);
    buffer[0] = manifest_size;
    buffer[1] = tc_size;
    fwrite(manifest_data, manifest_size);
    fwrite(tc_data, tc_size);
    
    // THE KEY CALL — selector 7!
    IOConnectCallMethod(connection, 7, NULL, 0, buffer, total_size, 
                        NULL, NULL, NULL, NULL);
}
```

### 3. vnode_check_signature Flow (FUN_fffffff008f86398)

```
vnode_check_signature(proc, vnode, ...)
  │
  ├─ 1. Trust Cache lookup (FUN_fffffff008f84198)
  │     └─ If CDHash in TC → ALLOW immediately ← OUR GOAL
  │
  ├─ 2. CoreTrust evaluation 
  │     └─ Apple/developer cert signature check
  │
  ├─ 3. Developer mode check
  │     ├─ FUN_fffffff008285e3c → reads 0xfffffff00a0e45b8 (PPL)
  │     └─ If dev sig + dev mode off → REJECT
  │
  ├─ 4. Developer mode RESOLVED check ← WE CAN CONTROL THIS
  │     ├─ FUN_fffffff008f7dc24 → reads DAT_fffffff00a330574 (WRITABLE!)
  │     └─ If NOT resolved → REJECT "only platform binaries"
  │
  └─ 5. If all pass → ALLOW with flag 0x20000000
```

### 4. Exception Port Restriction Mechanism

```
task struct contains:
  - exception_action[14]                    ← normal exception ports
  - hardened_exception_action               ← RESTRICTS who can set ports
    ├─ exception_action (port, 4 ints, label)
    ├─ uint flags_1                         ← hardened flags
    └─ uint flags_2                         ← hardened flags

When RemoteCall tries to set exception ports on cryptexd:
  FUN_fffffff007ded23c checks:
    1. Does caller have "com.apple.private.set-exception-port"?
    2. Does target have "com.apple.security.only-one-exception-port"?
    3. FUN_fffffff007ded404 → audit/restrict check
    
The restriction comes from hardened_exception_action being set.
If we ZERO OUT these fields in the task struct → RC should connect!
```

---

## Proposed Implementation Plan

### Step 1: Find hardened_exception_action offset in task struct
- Use `procbypid()` → `taskbyproc()` to get cryptexd's task
- Scan task struct for the `hardened_exception_action` pattern
- Expected location: after the 14 `exception_action` entries + 4 ipc_port pointers
- Each `exception_action` = 32 bytes (ptr + 4*int + ptr = 8+16+8)
- Array of 14 = 448 bytes
- Total offset estimate: ~0x200-0x400 from task base

### Step 2: Clear hardened_exception_action
```swift
// Pseudo-code
let task = taskbyproc(cryptexd_proc)
// Zero the hardened_exception_action struct (40 bytes)
for offset in stride(from: hea_offset, to: hea_offset + 40, by: 8) {
    ds_kwrite64(task + offset, 0)
}
```

### Step 3: Set developer_mode_resolved
```swift
let amfi_data_base = kernel_base + 0x3540098  // AMFI __DATA
let dev_resolved = amfi_data_base + 0x4DC     // offset to 0a330574
ds_kwrite32(dev_resolved, 1)
```

### Step 4: Connect RC to cryptexd and load TC
```swift
// Connect RC to cryptexd (should work after clearing hardened EA)
dspmgr.shared.rcinitDaemon("com.apple.cryptexd", ...) { rc in
    // Call amfi_load_trust_cache via RC
    // Build TC buffer with our binary's CDHash
    // IOConnectCallMethod(conn, 7, ...)
}
```

---

## Open Questions

> [!IMPORTANT]
> 1. **Task struct layout**: The exact offset of `hardened_exception_action` needs to be determined dynamically by scanning the task struct. Should we scan for a known pattern (e.g., the exception port pointer pattern)?

> [!IMPORTANT]  
> 2. **cryptexd availability**: Is cryptexd always running, or does it need to be triggered? We need to verify it's alive via `procbyname("cryptexd")`.

> [!WARNING]
> 3. **Fallback**: If clearing `hardened_exception_action` triggers a panic (because it's monitored by watchdog), we should try a gentler approach — just clearing the flags (last 8 bytes) instead of the full struct.

---

## Verification Plan

### Automated Tests
- Build and deploy to iPhone XR iOS 18.2
- Run the experiment from the Experiments tab
- Check log output for each step

### Manual Verification
1. Tap "MSM Unrestrict (TC)" experiment button
2. If RC to cryptexd succeeds → proceed with TC load
3. Verify with `posix_spawn` of unsigned binary → should return 0
4. If binary runs → **FULL JAILBREAK ACHIEVED** 🎉

---

## Key Kernel Addresses Reference (unslid)

| Address | Section | Writable? | Purpose |
|---|---|---|---|
| `0xfffffff00a330574` | AMFI __DATA | ✅ YES | developer_mode_resolved |
| `0xfffffff00a33044f` | AMFI __DATA | ✅ YES | developer_mode_requested |
| `0xfffffff00a3304c0` | AMFI __DATA | ✅ YES | IOKit object pointer |
| `0xfffffff00a0e45b8` | pmap __DATA | ❌ PPL | developer_mode_enabled byte |
| `0xfffffff007b795e8` | __DATA_CONST | ❌ KTRR | trust_cache_load_gate |
| `0xfffffff007b79bd9` | __DATA_CONST | ❌ KTRR | amfi_only_platform_code |
| `0xfffffff00798f600` | PPL __DATA | ❌ PPL | TC slot table |

> At runtime: add kernel_slide (`0x1d18c000` on test device)
