def ror_xor(x,n,k):
    n = n%8
    while n!=0:
        cf = x&1
        x = ((x>>1)+(cf<<7))
        n = n-1
    return chr(x^k)

key = ""

# the lines with ror_xor() are copied from Windbg print-outs
key += ror_xor(0xc3, 0x56, 0x46)
key += ror_xor(0xcc, 0xf5, 0x15)
key += ror_xor(0xba, 0xac, 0xf4)
key += ror_xor(0x4e, 0x1b, 0xbd)
key += ror_xor(0xf2, 0xb5, 0xff)
key += ror_xor(0xeb, 0x93, 0x4c)
key += ror_xor(0x27, 0x7e, 0xef)
key += ror_xor(0x19, 0xb8, 0x46)
key += ror_xor(0xc6, 0x23, 0xeb)
key += ror_xor(0x42, 0xda, 0xe6)
key += ror_xor(0x06, 0x0a, 0xb2)
key += ror_xor(0x16, 0xf2, 0xeb)
key += ror_xor(0x5d, 0x01, 0xf1)
key += ror_xor(0x53, 0x61, 0xc4)
key += ror_xor(0x55, 0x5c, 0x34)
key += ror_xor(0x0e, 0xc8, 0x67)
key += ror_xor(0x66, 0x4c, 0x39)
key += ror_xor(0xf4, 0xd6, 0xb5)
key += ror_xor(0xf9, 0x16, 0x8e)
key += ror_xor(0x30, 0x55, 0xef)
key += ror_xor(0x9a, 0x67, 0x40)
key += ror_xor(0x77, 0xb8, 0x1b)
key += ror_xor(0x56, 0xc1, 0x74)
key += ror_xor(0x6b, 0xf8, 0x0d)
key += ror_xor(0xf0, 0xbc, 0x60)
key += ror_xor(0x8e, 0x11, 0x26)
key += ror_xor(0xdc, 0xfa, 0x45)
key += ror_xor(0x2e, 0x9b, 0xa8)
key += ror_xor(0x50, 0x6b, 0x4a)
key += ror_xor(0xe1, 0xf9, 0x96)
key += ror_xor(0x5a, 0xd4, 0xc9)
key += ror_xor(0x80, 0x75, 0x65)
key += ror_xor(0x48, 0x87, 0xe2)
key += ror_xor(0x5d, 0xca, 0x32)
key += ror_xor(0x53, 0xce, 0x60)
key += ror_xor(0xc2, 0xbe, 0x64)
key += ror_xor(0xb8, 0x4e, 0x8c)
key += ror_xor(0xd2, 0x6e, 0x65)
key += ror_xor(0x01, 0xf1, 0xe3)
key += ror_xor(0xc3, 0xb9, 0x8e)
key += ror_xor(0xbc, 0x6e, 0x9f)

print(key)