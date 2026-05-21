import struct
KC = r'd:\Backup\Personal\Hp\iPhone\DSPloit\iPhone11,8_18.2_22C152_Restore\kernelcache.release.iphone11b'
with open(KC, 'rb') as f:
    data = f.read()

# Find Mach-O magic
idx = data.find(b'\xfe\xed\xfa\xcf')
print(f"FEEDFACF at offset: {idx}")

# Find compression markers
for sig in [b'bvx2', b'comp', b'lzss', b'lzfse']:
    i = data.find(sig)
    if i >= 0:
        print(f"{sig.decode()!r} at offset: {i}")

# Check if it's LZFSE compressed after IM4P header
# IM4P is ASN.1 DER: SEQUENCE { IA5String "IM4P", IA5String type, IA5String desc, OCTET STRING payload }
# Find the OCTET STRING tag (0x04) followed by large length
print(f"\nFirst 128 bytes hex:")
print(' '.join(f'{b:02x}' for b in data[:128]))

# Try to find the payload start by looking for known patterns
# The payload in IM4P is usually after the header strings
# Look for 'complzfse' or raw data start
complzfse = data.find(b'complzfse')
print(f"\ncomplzfse at: {complzfse}")
bvx2 = data.find(b'bvx2')
print(f"bvx2 at: {bvx2}")

# Check if there's already a decompressed kernelcache
import os
decompressed = KC.replace('.release.iphone11b', '.release.iphone11b.decompressed')
if os.path.exists(decompressed):
    print(f"\nDecompressed file exists: {decompressed}")
    print(f"Size: {os.path.getsize(decompressed)}")

# Also check for 'kernelcache' without extension
parent = os.path.dirname(KC)
for f in os.listdir(parent):
    if 'kernel' in f.lower():
        fp = os.path.join(parent, f)
        print(f"  {f}: {os.path.getsize(fp)} bytes")
