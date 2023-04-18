import idc

keyEA = 0x4051B8
valueEA = 0x0040524C
b = idc.get_wide_byte(valueEA)
idc.patch_byte(valueEA,0x34)
print(chr(b))
for i in range(0,0x34):
    b = 0x20^idc.get_wide_byte(keyEA+i)
    idc.patch_byte(keyEA+i,b)