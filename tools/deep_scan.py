import struct
data = open('kernelcache', 'rb').read()

# FOUND: 'amfi_allow' at some offset
idx = data.find(b'amfi_allow')
context = data[idx:idx+100]
end = context.find(b'\x00')
full_string = context[:end].decode('ascii', errors='ignore')
print(f'Full string: "{full_string}"')
print(f'  vmaddr: 0x{0xfffffff007004000+idx:x}')
print()

# Search for all amfi strings with allow/enforce/disable/trust
print('=== AMFI enforcement-related strings ===')
i = 0
found = set()
while True:
    idx = data.find(b'amfi', i)
    if idx < 0: break
    start = idx
    while start > 0 and data[start-1] >= 0x20 and data[start-1] < 0x7f:
        start -= 1
    end2 = idx
    while end2 < len(data) and data[end2] >= 0x20 and data[end2] < 0x7f:
        end2 += 1
    s = data[start:end2].decode('ascii', errors='ignore')
    if len(s) > 5 and len(s) < 200 and s not in found:
        lower = s.lower()
        if any(k in lower for k in ['allow', 'enforce', 'disable', 'trust', 'bypass', 'unrestrict', 'invalid', 'skip']):
            vmaddr = 0xfffffff007004000 + start
            print(f'  0x{vmaddr:x}: {s[:100]}')
            found.add(s)
    i = idx + 1

print()
print('=== Boot-arg / sysctl style variables ===')
for pattern in [b'amfi_allow', b'amfi_unrestrict', b'cs-enforcement-disable', b'PE_i_can_has_debugger', b'amfi_get_out_of_my_way', b'cs_enforcement_disable']:
    idx = data.find(pattern)
    if idx >= 0:
        end2 = idx
        while end2 < len(data) and data[end2] >= 0x20 and data[end2] < 0x7f:
            end2 += 1
        s = data[idx:end2].decode('ascii', errors='ignore')
        print(f'  FOUND: "{s}" at vmaddr 0x{0xfffffff007004000+idx:x}')
    else:
        print(f'  NOT FOUND: {pattern.decode()}')

print()
print('=== PMAP_CS allow/disable strings ===')
i = 0
while True:
    idx = data.find(b'pmap_cs', i)
    if idx < 0: break
    end2 = idx
    while end2 < len(data) and data[end2] >= 0x20 and data[end2] < 0x7f:
        end2 += 1
    s = data[idx:end2].decode('ascii', errors='ignore')
    if 'allow' in s.lower() or 'disable' in s.lower() or 'invalid' in s.lower():
        print(f'  0x{0xfffffff007004000+idx:x}: {s[:100]}')
    i = idx + 1
