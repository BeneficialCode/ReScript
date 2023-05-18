import struct
import numpy as np
import binascii

flare = 'FLARE On!'
start = 0x60

hexdump = b'2F3E61EE45EB79DE3D2F1BAFD7BB47879CC49A73AEF5A4C9C1C53246249B02A0595016D65194B7A6BA239DE7CE92AE8A181A99859958E0FE94790C436FF3B91A8124C470CF27BD056F6EFFC47C84775AB37792DDFF3C842544A9DC5F9628E48EC761E92ADA3177A7'
hexdump = hexdump.lower()
hexlist = [hexdump[i*8:(i+1)*8] for i in range(0x1a)]

def calc_hash(str):
    result = np.uint32(0)
    for char in str:
        result = np.uint32(ord(char)+37*result)
    return result

flag = ''
for i in range(0x1a):
    for char in range(0x20,0x7f):
        concat = chr(char)+chr(start)+flare
        hash_value = calc_hash(concat)
        hex_hash = binascii.hexlify(hash_value)
        if hex_hash == hexlist[i]:
            flag += chr(char)
            break
    start += 1

print(flag)