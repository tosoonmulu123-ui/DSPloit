import struct
data = open('kernelcache', 'rb').read()

# 'amfi-allows-trust-cache-load' string is at vmaddr 0xfffffff007499af4
# This is likely read from device tree at boot and stored in a global variable
# The code that reads it probably does:
#   PE_parse_boot_argn("amfi-allows-trust-cache-load", &var, sizeof(var))
# And stores result in __DATA

# Let's find the string 'amfi-allows-trust-cache-load' exact location
target = b'amfi-allows-trust-cache-load'
idx = data.find(target)
str_vmaddr = 0xfffffff007004000 + idx
print(f'String "amfi-allows-trust-cache-load" at vmaddr: 0x{str_vmaddr:x}')
print()

# Now search __DATA_CONST for pointers to this string
# __DATA_CONST: vmaddr=0xfffffff007900000, fileoff=0x8fc000, size=0x490000
DC_VM = 0xfffffff007900000
DC_OFF = 0x8fc000
DC_SIZE = 0x490000

dc_data = data[DC_OFF:DC_OFF+DC_SIZE]
print('Searching __DATA_CONST for pointer to this string...')
str_bytes = struct.pack('<Q', str_vmaddr)
for i in range(0, DC_SIZE-8, 8):
    val = struct.unpack_from('<Q', dc_data, i)[0]
    if val == str_vmaddr:
        ref_addr = DC_VM + i
        print(f'  Found ref at 0x{ref_addr:x} (__DATA_CONST+0x{i:x})')

# Also search __DATA
DATA_VM = 0xfffffff00a0e0000
DATA_OFF = 0x30dc000
DATA_SIZE = 0x328000
data_section = data[DATA_OFF:DATA_OFF+DATA_SIZE]

print('Searching __DATA for pointer to this string...')
for i in range(0, DATA_SIZE-8, 8):
    val = struct.unpack_from('<Q', data_section, i)[0]
    if val == str_vmaddr:
        ref_addr = DATA_VM + i
        print(f'  Found ref at 0x{ref_addr:x} (__DATA+0x{i:x})')

print()
# The AMFI kext likely stores the parsed value near its other globals
# We know AMFI globals are around 0xfffffff00a330000
# Let's look for the specific pattern:
# The error message says "has unexpected size (%u)" which means
# it reads a uint32 from device tree

# Key insight: the AMFI kext initialization reads boot-args and
# stores them in global variables. These are in __DATA (writable!)
# We already found flags at:
#   0xfffffff00a3301a8 = 1
#   0xfffffff00a3301f8 = 1
#   ... etc (the 10 flags we zero)
# But there might be MORE flags we haven't touched

# Let's dump ALL non-zero values in the AMFI region
print('=== FULL AMFI __DATA region dump (non-zero values) ===')
amfi_start = 0xfffffff00a330000 - DATA_VM  # offset in __DATA
amfi_end = amfi_start + 0x2000  # scan 8KB

count = 0
for i in range(amfi_start, min(amfi_end, DATA_SIZE), 8):
    val = struct.unpack_from('<Q', data_section, i)[0]
    if val != 0:
        addr = DATA_VM + i
        if val < 0x100:
            print(f'  0x{addr:x} = {val:<5} (small value / flag)')
        elif val > 0xfffffff000000000:
            print(f'  0x{addr:x} = 0x{val:x} (kernel pointer)')
        else:
            print(f'  0x{addr:x} = 0x{val:x}')
        count += 1

print(f'\nTotal non-zero entries in AMFI region: {count}')

# Compare with the 10 flags we already zero (from JailbreakEngine step 6)
print('\n=== FLAGS WE ALREADY ZERO (from step 6) ===')
amfi_base = 0xfffffff00a330098  # from code
offsets = [0x110, 0x160, 0x1b0, 0x200, 0x250, 0x2a0, 0x2f0, 0x340, 0x398, 0x408]
for off in offsets:
    addr = amfi_base + off
    data_off = (addr - DATA_VM)
    if data_off < DATA_SIZE:
        val = struct.unpack_from('<Q', data_section, data_off)[0]
        print(f'  0x{addr:x} (base+0x{off:x}) = {val}')

print('\n=== FLAGS WE HAVE NOT TOUCHED ===')
known_addrs = set(amfi_base + off for off in offsets)
for i in range(amfi_start, min(amfi_end, DATA_SIZE), 8):
    val = struct.unpack_from('<Q', data_section, i)[0]
    addr = DATA_VM + i
    if val != 0 and val < 0x100 and addr not in known_addrs:
        print(f'  0x{addr:x} = {val} *** UNTOUCHED FLAG ***')
