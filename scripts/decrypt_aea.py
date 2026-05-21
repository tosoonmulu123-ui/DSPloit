#!/usr/bin/env python3
"""Decrypt AEA files using python-aea library."""
import aea, base64, sys, os

IPSW = "/mnt/d/Backup/Personal/Hp/iPhone/DSPloit/iPhone11,8_18.2_22C152_Restore"

files = [
    ("092-09638-208.dmg.aea", "NMbAVocVR+x7DKrSzwG/evwjaie/2Fu83CFIuqjgsjc="),
    ("092-08785-200.dmg.aea", "OKrxlPCcFBq/kajWCTD1gPYgqhYozYorX+WjH/At04o="),
]

for fname, key_b64 in files:
    src = os.path.join(IPSW, fname)
    dst = src.replace(".aea", "")
    
    if os.path.exists(dst):
        print(f"[SKIP] {fname} already decrypted")
        continue
    
    print(f"[DECRYPT] {fname} ({os.path.getsize(src)/1024/1024:.0f} MiB)...")
    key = base64.b64decode(key_b64)
    
    with open(src, "rb") as f:
        data = f.read()
    
    print(f"  Loaded {len(data)/1024/1024:.0f} MiB, decrypting...")
    plaintext = aea.decode(data, symmetric_key=key)
    print(f"  Decrypted: {len(plaintext)/1024/1024:.0f} MiB")
    
    with open(dst, "wb") as f:
        f.write(plaintext)
    print(f"  Saved: {dst}")
    print()

print("DONE!")
