# DSPloit — iOS 18 Jailbreak

**Full jailbreak for iOS 16.0–18.2 on A11–A18 devices.**

Semi-tethered jailbreak with trust cache injection via MobileStorageMounter XPC.

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

## Supported iOS Versions

- iOS 16.0 – 18.2 (builds where darksword exploit works)
- NOT patched in iOS 18.3+ (kernel vuln fixed)

## How It Works

```
1. Kernel exploit (darksword) → full kernel R/W
2. Sandbox escape → filesystem access
3. RemoteCall → execute code in system processes
4. XPC to MobileStorageMounter → LoadTrustCache
5. Trust cache injected → unsigned code execution
6. Bootstrap installed → full jailbreak
```

## Features

- 🔓 **1-Tap Jailbreak** — single button to jailbreak
- 📦 **Package Manager** — Sileo/Zebra support
- 📁 **File Manager** — full filesystem access
- 🔧 **Tweak Support** — Substrate/ElleKit compatible
- 🖥️ **SSH** — remote terminal access
- 🔄 **Semi-tethered** — survives respring, re-run after reboot

## Technical Details

### Exploit Chain
1. **darksword.m** — Socket-based kernel R/W via ICMPv6 race condition
2. **RemoteCall** — Thread hijacking via Mach exception ports
3. **Trust Cache Injection** — XPC to MobileStorageMounter (has `pmap.load-trust-cache` entitlement)
4. **AMFI Bypass** — CDHash added to runtime trust cache → kernel accepts binary

### Key Discovery
MobileStorageMounter daemon:
- Has `com.apple.private.amfi.can-load-trust-cache` entitlement
- Has `com.apple.private.pmap.load-trust-cache` entitlement
- XPC service accessible WITHOUT entitlement check
- Responds to `LoadTrustCache` command with raw trust cache data
- Successfully loads trust cache entries into kernel

## Building

Requirements:
- Xcode 15+ (tested with Xcode 16.4)
- iOS 16.0+ deployment target
- arm64e architecture

```bash
git clone https://github.com/tosoonmulu123-ui/DSPloit.git
cd DSPloit
# Open lara.xcodeproj in Xcode
# Build & run on device
```

## Usage

1. Install DSPloit on device (sideload via TrollStore, AltStore, or Xcode)
2. Open app → tap "Jailbreak"
3. Wait for exploit to complete (~10 seconds)
4. Device is jailbroken!
5. After reboot: re-open app and tap "Jailbreak" again

## Credits

- darksword kernel exploit
- XPF/ChOma for kernel symbol resolution
- img4helper for IMG4 parsing
- Community research on MobileStorageMounter trust cache loading

## License

For research and educational purposes only.
