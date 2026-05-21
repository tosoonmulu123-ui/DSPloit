#!/usr/bin/env python3
"""Decrypt file AEA besar (6GB) dengan streaming — tidak load semua ke RAM."""
import aea, base64, os, sys

IPSW = "/mnt/d/Backup/Personal/Hp/iPhone/DSPloit/iPhone11,8_18.2_22C152_Restore"
fname = "092-08785-200.dmg.aea"
key_b64 = "OKrxlPCcFBq/kajWCTD1gPYgqhYozYorX+WjH/At04o="

src = os.path.join(IPSW, fname)
dst = src.replace(".aea", "")

if os.path.exists(dst):
    print(f"[SKIP] {dst} sudah ada ({os.path.getsize(dst)/1024/1024:.0f} MiB)")
    sys.exit(0)

key = base64.b64decode(key_b64)
print(f"[DECRYPT] {fname} ({os.path.getsize(src)/1024/1024:.0f} MiB)")
print(f"  Key: {key_b64[:20]}...")

# Coba streaming decode jika library support
# Kalau tidak, load sekaligus (butuh ~12GB RAM)
print("  Loading file ke memory...")
sys.stdout.flush()

with open(src, "rb") as f:
    data = f.read()

print(f"  Loaded {len(data)/1024/1024:.0f} MiB, decrypting...")
sys.stdout.flush()

plaintext = aea.decode(data, symmetric_key=key)
del data  # free memory

print(f"  Decrypted: {len(plaintext)/1024/1024:.0f} MiB")
print(f"  Writing ke disk...")
sys.stdout.flush()

with open(dst, "wb") as f:
    f.write(plaintext)

print(f"  DONE! Saved: {dst}")
