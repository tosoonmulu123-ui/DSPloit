<div align="center">
  <br>
  <img src="https://github.com/royan/dsploit/blob/main/dsploit.png?raw=true" alt="DSPloit Logo" width="200">
  <br>
  <h1>DSPloit</h1>

  <p>Advanced iOS kernel exploitation suite powered by DarkSword.<br>
  Root access, system tweaks, and security research — all from your device.</p>
  
  <p><b>iOS 17.0 – 18.7.1 & iOS 26.0 – 26.0.1</b> • A10 – A18 & M1 – M4</p>
</div>

<p align="center">
  <a href="https://github.com/royan/dsploit/releases">
    <img src="https://img.shields.io/github/v/release/royan/dsploit" alt="Release">
  </a>
  <a href="https://github.com/royan/dsploit/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/royan/dsploit/build.yml?branch=main&style=flat&logo=github" alt="Build">
  </a>
  <a href="https://github.com/royan/dsploit/stargazers">
    <img src="https://img.shields.io/github/stars/royan/dsploit?style=social" alt="Stars">
  </a>
  <a href="https://discord.gg/gw8PcRF3Jr">
    <img src="https://img.shields.io/badge/Discord-Join-7289DA.svg" alt="Discord">
  </a>
</p>

---

## What is DSPloit?

DSPloit is a rootless jailbreak tool that achieves **root-level access (uid=0)** on supported iOS devices through a kernel exploit chain. It provides a full suite of root tools without requiring a computer after initial installation.

**Exploit Chain:** Socket KRW → Sandbox Escape → VFS Init → RemoteCall (SpringBoard + launchd) → Root Access

---

## Compatibility

| iOS Version | Status |
|-------------|--------|
| iOS 16.x | Not supported (no offsets) |
| **iOS 17.0 – 18.7.1** | ✅ Supported |
| iOS 18.7.2+ | Not supported |
| **iOS 26.0 – 26.0.1** | ✅ Supported |
| iOS 26.1+ | Not supported |

| Chip | Status |
|------|--------|
| A10 – A18 | ✅ Supported |
| M1 – M4 (iPad) | ✅ Supported |
| A19 / M5+ | ❌ Blocked (MIE) |

---

## Features

### One-Tap Jailbreak
- Visual progress circle with 5-step chain
- Auto-reconnect if RemoteCall dies
- Haptic feedback on success/failure

### Root Tools (12 tools)

| Tool | Description |
|------|-------------|
| **Shell** | Root command execution (uid=0). Direct C calls + binary spawn with output capture |
| **Files** | Full filesystem browser with root access. Plist viewer with parsed key-value display |
| **Processes** | Process list, spawn binaries, kill processes. Pull-to-refresh |
| **Tweaks** | SpringBoard modifications via RemoteCall — no reboot needed for most |
| **Daemons** | Enable/disable system daemons. Write directly to disabled.plist |
| **Prefs** | Hidden iOS features, Screen Time bypass, preference editor |
| **Network** | DNS info, hosts file editor, system-wide ad blocking |
| **Bootstrap** | Directory structure setup for rootless environment |
| **Persist** | Persistence tools |
| **System** | Device info, kernel addresses, jailbreak status, storage |
| **AMFI Lab** | Security research experiments (65+ conducted) |

### SpringBoard Tweaks
- Hide icon labels
- 5-icon dock / floating dock
- Custom carrier text
- Status bar time format
- Grid app switcher
- Performance HUD
- Force rotation
- Bold text system-wide
- JIT enabler

### Daemon Manager
- Disable crash reporters, analytics, OTA updates
- Disable Screen Time, Siri, Spotlight
- Disable Apple Intelligence / photo analysis
- Safe defaults — critical daemons protected
- Changes apply after reboot

### Security Research
- 65+ AMFI bypass experiments documented
- IOKit driver probing (AMFI, KeyStore, IOSurface, CredentialManager)
- CoreTrust certificate analysis
- SSV/mount research
- Kernel memory analysis tools

---

## Installation

1. Download the latest `.ipa` from [Releases](https://github.com/royan/dsploit/releases)
2. Sideload via AltStore, TrollStore, or your preferred method
3. Open DSPloit → tap "Jailbreak"
4. Wait for all 5 steps to complete
5. Access Root Tools from the second tab

---

## Known Issues

- Kernel may panic when DSPloit is closed from app switcher (kill = unjailbreak via respring)
- RemoteCall may occasionally disconnect — use "Re-init RemoteCall" button
- Some tweaks require respring to take effect
- Process list output depends on timing (pull-to-refresh if empty)

---

## Tips

- **Don't kill the app from background** while jailbroken — causes respring/panic
- **Re-jailbreak after reboot** — exploit is not persistent
- If kernelcache download fails, manually place it in Files → On My iPhone → DSPloit
- Respring needed for visual SpringBoard tweaks
- Daemon changes only apply after reboot

---

## Credits

- **Royan** — Lead Developer & DSPloit Creator
- opa334 — Kernel exploit PoC, ChOma, and XPF
- AppInstaller iOS — Offset assistance
- AlfieCG — libgrabkernel2
- [All contributors](https://github.com/royan/dsploit/graphs/contributors)

---

<div align="center">
  <sub>Built with persistence and 65 experiments worth of kernel research ❤️</sub>
</div>
