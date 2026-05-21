#!/usr/bin/env python3
"""
patch_macho_ios.py — Patch Mach-O binary from macOS platform to iOS
Usage: python3 patch_macho_ios.py <input> [output]
"""

import sys
import struct

LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_IPHONEOS = 0x25
LC_VERSION_MIN_MACOSX = 0x24

PLATFORM_MACOS = 1
PLATFORM_IOS = 2

def patch(src, dst):
    with open(src, 'rb') as f:
        data = bytearray(f.read())

    magic = struct.unpack_from('<I', data, 0)[0]
    assert magic == 0xFEEDFACF, "Not a 64-bit Mach-O"

    ncmds = struct.unpack_from('<I', data, 16)[0]
    offset = 32
    patched = False

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, offset)

        if cmd == LC_BUILD_VERSION:
            platform = struct.unpack_from('<I', data, offset + 8)[0]
            print(f"Found LC_BUILD_VERSION: platform={platform}")
            if platform == PLATFORM_MACOS:
                struct.pack_into('<I', data, offset + 8, PLATFORM_IOS)
                struct.pack_into('<I', data, offset + 12, 0x100000)  # iOS 16.0
                print("Patched: macOS -> iOS 16.0")
                patched = True

        elif cmd == LC_VERSION_MIN_MACOSX:
            struct.pack_into('<I', data, offset, LC_VERSION_MIN_IPHONEOS)
            struct.pack_into('<I', data, offset + 8, 0x100000)
            print("Patched: LC_VERSION_MIN_MACOSX -> LC_VERSION_MIN_IPHONEOS")
            patched = True

        offset += cmdsize

    if not patched:
        print("WARNING: No platform load command found")

    with open(dst, 'wb') as f:
        f.write(data)
    print(f"Done: {src} -> {dst}")

if __name__ == '__main__':
    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else src + '_ios'
    patch(src, dst)
