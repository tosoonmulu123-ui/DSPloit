# DSPloit — iOS Jailbreak

**Full jailbreak for iOS 16.0–18.7.1 & 26.0–26.0.1 on A11–A18 + M1/M2 devices.**

Semi-tethered jailbreak with multi-exploit support, MIG filter bypass, and trust cache injection via MobileStorageMounter XPC.

## Supported Devices

| Chip | Devices | Status |
|------|---------|--------|
| A11 | iPhone 8, iPhone X | ✅ Supported |
| A12 | iPhone XR, XS, XS Max | ✅ Confirmed |
| A13 | iPhone 11 series | ✅ Supported |
| A14 | iPhone 12 series | ✅ Supported |
| A15 | iPhone 13/14 series | ✅ Supported |
| A16 | iPhone 14 Pro, 15 series | ✅ Supported |
| A17 Pro | iPhone 15 Pro/Max | ✅ Supported |
| A18 | iPhone 16 series | ✅ Supported |
| M1/M2 | iPad Pro/Air | ✅ Supported |
| A19+ | iPhone 18+ | ❌ MIE protection |

## Supported iOS Versions

| Version | Status |
|---------|--------|
| iOS 16.0–16.x | ✅ Supported |
| iOS 17.0–17.x | ✅ Supported |
| iOS 18.0–18.7.1 | ✅ Supported |
| iOS 18.7.2+ | ❌ Patched |
| iOS 26.0–26.0.1 | ✅ Supported |
| iOS 26.1+ | ❌ Patched |

## How It Works

```
1. Multi-exploit selector → picks best exploit for device/iOS
2. Kernel exploit (darksword) → full kernel R/W
3. VFS init + Sandbox escape → filesystem access
4. RemoteCall → execute code in system processes (MIG bypass for iOS 18.4+)
5. Root verification → launchd getuid()=0
6. Bootstrap → /var/jb directory structure
7. AMFI disable → 10 enforcement flags zeroed
8. Trust cache inject → MSM XPC LoadTrustCache
```

## Features

- 🔓 **1-Tap Jailbreak** — single button, auto-fallback on failure
- 📦 **Package Manager** — .deb installer with CDHash trust cache injection
- 📁 **File Manager** — full filesystem R/W (Filza-level)
- 🏦 **Banking Mode** — hide jailbreak from detection
- ⚙️ **Daemon Control** — disable/enable system services
- 🔄 **Semi-tethered** — survives respring, re-run after reboot
- 💾 **KRW Persistence** — faster re-jailbreak via parked sockets in launchd
- 🛡️ **MIG Filter Bypass** — RemoteCall works on iOS 18.4+

## Technical Details

### Exploit Chain
1. **darksword.m** — Socket-based kernel R/W via ICMPv6 race condition (CVE-2025-43510/43520)
2. **sbx.m** — Sandbox escape via extension data patching
3. **vfs.m** — Virtual filesystem access via namecache + vm_map patching
4. **RemoteCall** — Thread hijacking via Mach exception ports + MIG bypass
5. **AMFI Bypass** — 10 boolean flags in AMFI __DATA zeroed (Experiment 93b)
6. **Trust Cache** — XPC to MobileStorageMounter with trust cache v2 data

### Multi-Exploit System
| Exploit | iOS Range | Status |
|---------|-----------|--------|
| darksword (socket KRW) | 16.0–18.7.1, 26.0–26.0.1 | ✅ Working |
| AppleJPEGDriver UAF (CVE-2026-20687) | 18.3–26.3 | ⚠️ Skeleton |
| AppleSEPKeyStore UAF (CVE-2026-20637) | 26.1–26.2 | ⚠️ Skeleton |
| AppleKeyStore close UAF | ≤26.2.1 | ⚠️ Skeleton |

### A18/M4 Support
Dedicated `pe_a18()` path with:
- 2GB wired page marker technique
- Targeted physical page deallocation + socket spray
- Safety limits (max freed pages, mapping recycles, socket preflight)

### Key Discoveries
- MobileStorageMounter has `pmap.load-trust-cache` entitlement — accessible without entitlement check
- AMFI has 10 boolean enforcement flags in `__DATA` that control code signing
- launchd has 5-second watchdog — all root operations must complete in <3s
- iOS 18 rootfs has no userland binaries — all I/O via direct syscalls from launchd

## Building

Requirements:
- Xcode 15+ (tested with Xcode 16.4)
- macOS (CI uses macos-26)
- `ldid` for entitlement signing
- arm64e architecture

```bash
git clone https://github.com/tosoonmulu123-ui/DSPloit.git
cd DSPloit
./scripts/build_ipa.sh
# Output: build/dsploit.ipa
```

## Usage

1. Install DSPloit on device (sideload via TrollStore, AltStore, or Xcode)
2. Open app → tap "Jailbreak"
3. Wait for exploit to complete (~10-30 seconds)
4. Device is jailbroken!
5. After reboot: re-open app and tap "Jailbreak" again

## Credits

- [opa334](https://github.com/opa334) — darksword kernel exploit PoC, ChOma, XPF
- [rooootdev/lara](https://github.com/rooootdev/lara) — base foundation
- [wh1te4ever](https://github.com/wh1te4ever) — RemoteCall implementation
- [zeroxjf](https://github.com/zeroxjf) — Cyanide reliability improvements, CVE research
- [AlfieCG](https://github.com/AlfieC) — libgrabkernel2
- DarkSword Analysis community — full chain documentation
- Apple Security Research community

## License

AGPL-3.0 — For research and educational purposes.
