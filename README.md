<div align="center">
  <br>
  <a href="https://discord.gg/gw8PcRF3Jr"><img src="https://github.com/royan/dsploit/blob/main/dsploit.png?raw=true" alt="DSPloit Logo" width="200"></a>
  <br>
  <h1>DSPloit</h1>

  <p>An advanced kernel exploitation suite that utilizes DarkSword. iOS 16.0 - iOS 18.7.1 & iOS 26.0.x, excluding M5 and A19.</p>
  <p>star this repo please :P</p>
</div>

<p align="center">
  <a href="https://discord.gg/gw8PcRF3Jr">
    <img src="https://img.shields.io/badge/Discord-Join%20Server-7289DA.svg" alt="Discord">
  </a>
  <a href="https://github.com/royan/dsploit/stargazers">
    <img src="https://img.shields.io/github/stars/royan/dsploit?style=social" alt="GitHub stars">
  </a>
  <a href="https://github.com/royan/dsploit/issues">
    <img src="https://img.shields.io/github/issues/royan/dsploit" alt="GitHub issues">
  </a>
  <a href="https://github.com/royan/dsploit/releases">
    <img src="https://img.shields.io/github/v/release/royan/dsploit" alt="Release">
  </a>
  <a href="https://github.com/royan/dsploit/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/royan/dsploit/build.yml?branch=main&style=flat&logo=github" alt="GitHub Actions">
  </a>
</p>

<p align="center">
  <a href="#support">support</a> •
  <a href="#features">features</a> •
  <a href="#known-issues">known issues</a> •
  <a href="#tips">tips</a> •
  <a href="#credits">credits</a>
</p>

> [!NOTE]
> DSPloit is still in a super rough state and is undergoing a rewrite. If you are experiencing any issues, it is best to simply wait instead of opening issues or asking for support in the Discord. If you would like to contribute, it is best to wait after the rewrite. We will not be accepting PRs during this time or resolving/responding to any issues. Thank you for your understanding!

## Support
| iOS Version | Support Status |
| - | - |
| iOS 16.x |  Not Supported ¹ |
| iOS 17.0 - iOS 18.7.1 | Supported |
| iOS 18.7.2+ | Not Supported |
| iOS 26.0 - iOS 26.0.1 | Supported |
| iOS 26.1+ | Not Supported |

¹ While *technically* affected by the exploit DSPloit abuses, offsets havent been found for these versions and DSPloit therefore doesnt support them.

Important Notes:
- This tool does **not** work on M5 or A19 (Pro) devices regardless of iOS version because of MIE.
- YMMV on M-series CPUs. If you are on an M-series device, try going to DSPloit settings, selecting `Modify Offsets`, and setting `t1sz_boot` to `0x11`.
- Issues involving DSPloit not working on either unsupported or *technically* supported versions will be closed immediately.

<p align="center">
  <a href="https://celloserenity.github.io/altdirect/?url=https://raw.githubusercontent.com/royan/dsploit/refs/heads/main/source.json" target="_blank">
    <img src="https://github.com/CelloSerenity/altdirect/blob/main/assets/png/AltSource_Blue.png?raw=true" alt="Add AltSource" width="200">
  </a>
  <a href="https://github.com/royan/dsploit/releases/download/0.1/dsploit_v0.1.ipa" target="_blank">
    <img src="https://github.com/CelloSerenity/altdirect/blob/main/assets/png/Download_Blue.png?raw=true" alt="Download .ipa" width="200">
  </a>
</p>

## Features
### Implemented
- Font Overwrite
- Custom Overwrite
- Card Overwrite
- File Manager (Full Disk r/w)
- MobileGestalt Editor
- 3 App Bypass
- DirtyZero 2
- 5 App Dock
- Status Bar Tweaks
- Hide labels
- Upside Down
- Floating Dock (Broken)
- Grid App Switcher
- Performance HUD
- JIT Enabler (only for apps with `get-task-allow`)
- **65+ Kernel Exploit Tools** (Process Inspector, AMFI Bypass, PAC/PPL Bypass, Heap Sprayer, ROP Builder, KASLR Defeater, IOSurface Exploiter, SEP Commander, CoreTrust Bypass, Kernel Fuzzer, and more)

### Coming Soon
- App Decrypt

## Known Issues
- wont work on M5, A19 and A19 Pro due to MTE
- the kernel may panic when DSPloit is closed from the app switcher.
- dirtyzero does not work.
- apps don't detect JIT enabled however they are enabled.
- remotecall is super bugged and may not work properly.

### Fixes
**kernelcache download fix (manual fallback):**

1. Download the IPSW tool for your device [here](https://github.com/blacktop/ipsw/releases/tag/v3.1.671).
2. Extract the archive.
3. Open Terminal.
4. Navigate to the extracted folder:
   ```sh
   cd /path/to/ipsw_3.1.671_something_something/
   ```
5. Extract the kernel:
   ```sh
   ./ipsw extract --kernel [drag your ipsw here]
   ```
6. Get the kernelcache file.
7. Transfer the kernelcache to your iPhone.
8. In the Files app:
   - Go to "On My iPhone" > "DSPloit"
   - Place the kernelcache file there.
9. Rename the file to `kernelcache` (without extension).

## Tips
- deleting and redownloading kernelcache is known to fix many issues. do this before asking me for support.
- closing and reopening the app can fix font change issues.
- respringing is needed to apply springboard changes such as font changes.

## Credits
- Royan - Lead Developer & DSPloit Creator
- opa334 for the kernel exploit poc, ChOma and XPF
- AppInstaller iOS for help with offsets
- AlfieCG for libgrabkernel2
- Everyone who contributed! (Visible <a href="https://github.com/royan/dsploit/graphs/contributors">Here</a>)

<br> 
<div align="center">a beautiful kexploit ❤️</div>
