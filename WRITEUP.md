# DSPloit — Full Jailbreak Write-Up

## iPhone XR (iPhone11,8) • iOS 18.2 (22C152) • A12 Bionic

---

## Summary

DSPloit is a full jailbreak for iOS 16–18.2 on A11–A18 devices. Built from scratch over weeks of research, reverse engineering, and trial-and-error. Semi-tethered (survives until reboot).

**Capabilities achieved:**
- Kernel Read/Write (arbitrary)
- Root access (uid=0) via launchd
- AMFI bypass (unsigned binary execution)
- Sandbox escape
- Trust cache injection via MobileStorageMounter
- File system read/write anywhere
- .deb package installation
- Daemon control

---

## The Journey

### Phase 1: Kernel Exploit (darksword)

The foundation. A socket-based kernel vulnerability that gives us arbitrary kernel read/write (KRW). This is the "key to the kingdom" — once you have KRW, everything else is possible.

- **Exploit**: darksword (socket KRW)
- **Target**: All A11–A18 chips, iOS 16.0–18.2
- **Patched in**: iOS 18.3 beta 1
- **Offsets**: XPF dynamic resolve (no hardcoded offsets per device)
- **KASLR**: Auto-detected per boot

### Phase 2: System Initialization

After KRW, we need to escape the app sandbox and set up VFS access:

1. **VFS Init** — Virtual File System access from our app process
2. **Sandbox Escape** — Break out of the app container to access full filesystem

### Phase 3: RemoteCall (RC)

The breakthrough that makes everything possible. RemoteCall lets us hijack threads in other processes to execute arbitrary function calls:

- **SpringBoard RC** — Persistent connection to SpringBoard (for UI operations, uicache)
- **launchd RC** — Connect to PID 1 for root operations (uid=0)

Key insight: launchd runs as root. If we can execute functions in launchd's context, we ARE root.

**Critical constraint discovered**: launchd has a 5-second watchdog timer. Hold its thread longer than that → kernel panic (initproc exited). This shaped ALL our file I/O design.

### Phase 4: Root Access Verification

Connect to launchd → call `getuid()` → returns 0 → we are root.

Simple, but this confirms the entire chain works end-to-end.

### Phase 5: AMFI Bypass (Experiment 93b)

The hardest part. Apple's AMFI (Apple Mobile File Integrity) kills any unsigned binary with SIGKILL. Even with root, you can't execute anything that's not in the trust cache.

**Research path (weeks of dead ends):**
- Exp 54–73: IOKit probes, CoreTrust, PPL, physical memory — all failed due to KTRR/PPL hardware protection
- Exp 74: Physmap direct access — found gVirtBase/gPhysBase constants
- Exp 77: Trust cache probe (read-only) — located kernel trust cache structures
- Exp 79: KTRR analysis — confirmed hardware write protection on trust cache
- Exp 80: RC Trust Cache Add — `amfi_load_trust_cache` not in shared cache
- Exp 81–82: Heap TC analysis, deep scan — mapped trust cache layout

**The breakthrough — Exp 93b:**

Found 10 boolean flags in AMFI's `__DATA` segment that control code signing enforcement. Writing 0 to all 10 flags → `posix_spawn` of system binaries succeeds without SIGKILL.

```
AMFI __DATA base (unslid): 0xfffffff00a330098
Flag offsets: 0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408
Action: Write 0 to all → AMFI enforcement disabled
```

Result: 🎉 FULL JAILBREAK ACHIEVED

### Phase 6: Trust Cache Injection

Via MobileStorageMounter (MSM) XPC service from SpringBoard context. Sends a `LoadTrustCache` command with CDHash data to register new binaries as trusted.

### Phase 7: Bootstrap

Create `/var/jb/` directory structure (rootless, Dopamine-compatible):
- `/var/jb/usr/bin/`, `/var/jb/usr/lib/`
- `/var/jb/Library/LaunchDaemons/`
- `/var/jb/var/lib/dpkg/` (for package management)

---

## Key Technical Discoveries

### 1. iOS 18 Rootfs is Stripped

Extracted rootfs via `ipsw` tool. iOS 18.2 has almost NO userland binaries:
- No `tar`, `sh`, `bash`, `ls`, `cp`, `cat`, `rm`, `id`
- Only diagnostic tools and system daemons remain
- This means `posix_spawn` is useless for utility operations
- All file I/O must be done via direct syscalls from launchd context

### 2. launchd Watchdog (5s)

PID 1 has a hardware watchdog. If its main thread is blocked >5 seconds, kernel panics with "initproc exited". This means:
- Every launchd operation must be fast (<3s ideally)
- Large file writes must be split into chunks
- 2s delay between operations to let watchdog reset
- Queue guard to prevent overlapping connections

### 3. SpringBoard Cannot Write to /var/jb

SpringBoard's sandbox profile blocks writes to `/var/jb/` even after our app's sandbox escape. Only launchd (uid=0, no sandbox) can write there.

### 4. AMFI Flags are Per-Boot

The 10 AMFI flags reset to 1 on every reboot. This makes DSPloit semi-tethered — user must re-jailbreak after restart.

---

## Architecture

```
┌─────────────────────────────────────────┐
│              DSPloit App                  │
├─────────────────────────────────────────┤
│  ContentView (Main Tab)                  │
│  ├── Jailbreak Button → JailbreakEngine │
│  └── Safe Respring                       │
├─────────────────────────────────────────┤
│  RootDashboardView (Root Tab)            │
│  ├── File Manager (RootFileManagerView)  │
│  ├── Packages (PackageManagerView)       │
│  ├── Banking (MobileBankingView)         │
│  └── Daemons (DaemonDisableView)         │
├─────────────────────────────────────────┤
│  JailbreakEngine (one-tap chain)         │
│  Step 1: Kernel exploit (darksword)      │
│  Step 2: VFS + Sandbox escape            │
│  Step 3: RemoteCall (SpringBoard)        │
│  Step 4: Root verify (launchd uid=0)     │
│  Step 5: Bootstrap (/var/jb)             │
│  Step 6: AMFI disable (10 flags → 0)    │
│  Step 7: Trust cache inject (MSM XPC)    │
├─────────────────────────────────────────┤
│  RootExecutor                            │
│  ├── executeAsRoot() — launchd RC       │
│  ├── writeFileAsRoot()                   │
│  ├── spawnAsRoot()                       │
│  └── Queue guard (prevent overlap)       │
├─────────────────────────────────────────┤
│  DebInstaller (.deb package installer)   │
│  ├── Parse ar archive                    │
│  ├── Decompress gzip                     │
│  ├── Parse tar                           │
│  └── Write per-file via launchd (2s)     │
└─────────────────────────────────────────┘
```

---

## .deb Installation Flow

Since iOS 18 has no `tar` binary, we implement everything in-memory:

1. Download .deb from URL
2. Parse ar archive → extract `data.tar.gz`
3. Decompress gzip in memory (auto-grow buffer for large files)
4. Parse tar headers → get file list
5. Create all directories (single launchd call)
6. Write each file individually via launchd (2s delay between calls)
7. Run uicache via SpringBoard (register .app bundles)

For Filza (~1573 files): ~52 minutes install time. Safe from panic.

---

## Device Compatibility

| Chip | Devices | Status |
|------|---------|--------|
| A11 | iPhone 8/X | ✅ Supported |
| A12 | iPhone XR/XS | ✅ Supported |
| A13 | iPhone 11 | ✅ Supported |
| A14 | iPhone 12 | ✅ Supported |
| A15 | iPhone 13/14 | ✅ Supported |
| A16 | iPhone 14 Pro/15 | ✅ Supported |
| A17 Pro | iPhone 15 Pro | ✅ Supported |
| A18 | iPhone 16 | ✅ Supported |
| A19+ | iPhone 18+ | ❌ MIE protection |

iOS: 16.0–18.2 supported. 18.3+ patched.

---

## Credits

- **Royan** — Lead developer, exploit research, AMFI bypass discovery
- **darksword** — Kernel exploit (socket KRW)
- **XPF** — Dynamic offset resolution framework
- Built with assistance from AI pair programming

---

## Timeline

- Initial exploit integration and basic jailbreak flow
- Weeks of AMFI bypass research (Exp 54–93b)
- Physmap discovery → trust cache probing → AMFI flag discovery
- Full jailbreak chain automated (one-tap)
- Package manager with .deb installer
- File manager (Filza-level)
- Daemon control
- Banking app hide/restore
- UI polish (minimalist iOS native)
- Rootfs analysis confirming no spawn approach possible
- Final architecture: direct syscall via launchd for all operations

---

*DSPloit — iOS 16–18.2 • A11–A18 • Full Jailbreak*
