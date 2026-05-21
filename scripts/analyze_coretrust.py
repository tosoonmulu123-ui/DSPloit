#!/usr/bin/env python3
"""
analyze_coretrust.py — CoreTrust certificate validation analysis
iOS 18.2 (22C152) iPhone XR (A12)

Goal: Find how CoreTrust validates certificates and whether there's
a bypass path (like TrollStore used on iOS 14-16).

CoreTrust is responsible for:
1. Validating code signature certificate chains
2. Checking if cert is rooted in Apple CA
3. On older iOS: had bugs where certain cert formats were accepted

Key question: Does iOS 18.2 CoreTrust still have any cert validation bypass?
"""
import struct, os

KC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kernelcache")

def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]

def read_u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]

with open(KC, 'rb') as f:
    data = f.read()

print(f"Kernelcache: {len(data)} bytes")

# Parse fileset to find CoreTrust component
ncmds = read_u32(data, 0x10)
cmd_off = 0x20
ct_entry = None

for _ in range(ncmds):
    cmd = read_u32(data, cmd_off)
    cmdsize = read_u32(data, cmd_off + 4)
    if cmdsize == 0: break
    if cmd == 0x80000035:  # LC_FILESET_ENTRY
        vmaddr = read_u64(data, cmd_off + 8)
        fileoff = read_u64(data, cmd_off + 16)
        entry_id_off = read_u32(data, cmd_off + 24)
        name_start = cmd_off + entry_id_off
        name_end = data.find(b'\x00', name_start)
        name = data[name_start:name_end].decode('ascii', errors='ignore')
        if 'CoreTrust' in name:
            ct_entry = {'name': name, 'vmaddr': vmaddr, 'fileoff': fileoff}
    cmd_off += cmdsize

if not ct_entry:
    print("CoreTrust fileset entry NOT FOUND")
    exit(1)

print(f"\nCoreTrust component: {ct_entry['name']}")
print(f"  vmaddr: 0x{ct_entry['vmaddr']:x}")
print(f"  fileoff: 0x{ct_entry['fileoff']:x}")

# Parse CoreTrust segments
ct_off = ct_entry['fileoff']
ct_magic = read_u32(data, ct_off)
assert ct_magic == 0xFEEDFACF, f"Not Mach-O at CoreTrust offset"

ct_ncmds = read_u32(data, ct_off + 0x10)
ct_cmd_off = ct_off + 0x20

ct_segments = []
for _ in range(ct_ncmds):
    cmd = read_u32(data, ct_cmd_off)
    cmdsize = read_u32(data, ct_cmd_off + 4)
    if cmdsize == 0: break
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[ct_cmd_off+8:ct_cmd_off+24].split(b'\x00')[0].decode()
        vmaddr = read_u64(data, ct_cmd_off + 24)
        vmsize = read_u64(data, ct_cmd_off + 32)
        fileoff = read_u64(data, ct_cmd_off + 40)
        filesize = read_u64(data, ct_cmd_off + 48)
        ct_segments.append({'name': segname, 'vmaddr': vmaddr, 'vmsize': vmsize,
                           'fileoff': fileoff, 'filesize': filesize})
        print(f"  {segname:16s} vm=0x{vmaddr:x} size=0x{vmsize:x} fileoff=0x{fileoff:x}")
    ct_cmd_off += cmdsize

# Find CoreTrust strings
print(f"\n=== CoreTrust Strings ===")
ct_strings = [
    b'CT_evaluate',
    b'CoreTrust',
    b'certificate',
    b'cert_chain',
    b'leaf_cert',
    b'anchor',
    b'Apple',
    b'root_ca',
    b'CT_queryAmfiTrust',
    b'amfi_trust',
    b'CT_codesign',
    b'provisioning',
    b'CT_verify',
    b'OID',
    b'1.2.840.113635',  # Apple OID prefix
    b'SHA256',
    b'SHA1',
    b'RSA',
    b'ECDSA',
    b'CT_flags',
    b'allow',
    b'deny',
    b'valid',
    b'invalid',
    b'trusted',
    b'untrusted',
]

# Search in CoreTrust __TEXT segment
ct_text = None
ct_data = None
ct_data_const = None
for seg in ct_segments:
    if seg['name'] == '__TEXT':
        ct_text = seg
    elif seg['name'] == '__DATA':
        ct_data = seg
    elif seg['name'] == '__DATA_CONST':
        ct_data_const = seg

found_strings = []
for s in ct_strings:
    idx = data.find(s)
    while idx >= 0:
        # Check if it's in CoreTrust range
        for seg in ct_segments:
            if seg['fileoff'] <= idx < seg['fileoff'] + seg['filesize']:
                va = seg['vmaddr'] + (idx - seg['fileoff'])
                found_strings.append((va, s.decode('ascii', errors='ignore')))
                print(f"  0x{va:x}: \"{s.decode('ascii', errors='ignore')}\"")
                break
        idx = data.find(s, idx + 1)
        if len(found_strings) > 100:
            break

# Analyze CoreTrust __DATA
print(f"\n=== CoreTrust __DATA Analysis ===")
if ct_data:
    print(f"  VA: 0x{ct_data['vmaddr']:x}")
    print(f"  Size: 0x{ct_data['vmsize']:x} ({ct_data['vmsize']} bytes)")
    print(f"  Fileoff: 0x{ct_data['fileoff']:x}")
    
    # Dump non-zero values
    print(f"\n  Non-zero slots:")
    ptr_count = 0
    for off in range(0, min(ct_data['filesize'], 0x100), 8):
        val = read_u64(data, ct_data['fileoff'] + off)
        if val != 0:
            is_ptr = val > 0xfffffff000000000 and val < 0xfffffffc00000000
            tag = "← kernel ptr" if is_ptr else ""
            print(f"    +0x{off:x}: 0x{val:016x} {tag}")
            if is_ptr:
                ptr_count += 1
    print(f"\n  Kernel pointers in __DATA: {ptr_count}")
    print(f"  NOTE: CoreTrust __DATA is at same VA range as AMFI __DATA")
    print(f"  If AMFI __DATA is writable, CoreTrust __DATA might be too!")

# Analyze CoreTrust __DATA_CONST
print(f"\n=== CoreTrust __DATA_CONST Analysis ===")
if ct_data_const:
    print(f"  VA: 0x{ct_data_const['vmaddr']:x}")
    print(f"  Size: 0x{ct_data_const['vmsize']:x}")
    
    # Count function pointers
    ptr_count = 0
    for off in range(0, min(ct_data_const['filesize'], 0x2000), 8):
        val = read_u64(data, ct_data_const['fileoff'] + off)
        if val > 0xfffffff000000000 and val < 0xfffffffc00000000:
            ptr_count += 1
    print(f"  Function pointers: {ptr_count}")

# Key analysis: CoreTrust validation flow
print(f"\n=== CoreTrust Validation Flow ===")
print("""
On iOS, code signing validation works like this:

1. Binary loaded → kernel calls AMFI MAC hook (mpo_vnode_check_exec)
2. AMFI checks trust cache first (CDHash lookup)
3. If not in trust cache → AMFI asks amfid daemon
4. amfid calls MISValidateSignatureAndCopyInfo
5. MIS calls CoreTrust to validate certificate chain
6. CoreTrust checks:
   a. Certificate format (X.509 DER)
   b. Certificate chain (leaf → intermediate → root)
   c. Root CA must be Apple Root CA
   d. Leaf cert must have code signing OID
   e. CDHash in CodeDirectory matches binary

TrollStore bypass (iOS 14-16):
- CoreTrust had a bug where certain certificate formats
  were accepted without proper root CA validation
- Specifically: certificates with certain OID extensions
  could bypass the Apple Root CA check
- This was patched in iOS 16.7 / 17.0

iOS 18.2 status:
- TrollStore bypass is PATCHED
- CoreTrust validation is strict
- No known certificate bypass for iOS 18

BUT: CoreTrust __DATA might be writable (same as AMFI __DATA)!
If we can patch CoreTrust globals → might bypass validation.
""")

# Summary
print(f"\n=== SUMMARY FOR EXPERIMENT ===")
print(f"""
CoreTrust __DATA (unslid): 0x{ct_data['vmaddr']:x}
CoreTrust __DATA size: 0x{ct_data['vmsize']:x}
CoreTrust __DATA_CONST: 0x{ct_data_const['vmaddr']:x if ct_data_const else 0}

EXPERIMENT PLAN:
1. Test write to CoreTrust __DATA (might be writable like AMFI __DATA!)
2. If writable: scan for validation flags/pointers
3. Patch CoreTrust to accept any certificate
4. Sign binary with self-signed cert → CoreTrust accepts → binary runs

ALTERNATIVE (AMFI IOKit):
- AMFI has IOKit user client with active methods (Exp 56/58)
- Some methods accept struct input
- If we find the right input format → might trigger trust cache add
- Or: find OOB bug → kernel code execution → call trust_cache_runtime_add
""")
