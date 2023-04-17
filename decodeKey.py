import idc

def ROR(x,n,bits = 32):
    n = n % bits
    mask = (2**n)-1
    mask_bits = x & mask
    return (x>>n)|(mask_bits<<(bits-n))

def ROL(x,n,bits = 32):
    n = n %bits
    return ROR(x,bits-n,bits)

def decode_key():
    keyStart = 0x4010E4
    keyLen = 0x25
    index = keyLen-1
    rolling_sum = 0
    result = []
    while index>=0:
        # how to get the bx's value?
        # bx's initialize value = 0
        # ah = 1
        # count  -> and dx,3
        # adc --> +1
        addval = ROL(1,rolling_sum&3)+1
        newval = idc.get_wide_byte(keyStart+index)
        rolling_sum += newval

        # 下面为逆运算
        # add bx,ax
        newval -= addval
        # and eax,0ffh
        newval &=0xFF
        # xor al,0xc7
        newval ^=0xc7
        result.append(chr(newval))
        index -= 1
    print(''.join(result))

def main():
    decode_key()

if __name__ == '__main__':
    main()