import idc

begin = 0x29c1ce
end = 0x29cce0
ea = begin
secret = []

tmp = ''
while ea < end:
    
    mnem = idc.print_insn_mnem(ea)
    # Check whether mnem is jz
    if mnem == "jz":
        tmp += '0'
    elif mnem == 'jnz':
        tmp += '1'
    
    if len(tmp) == 8:
        secret.append(chr(int(tmp[::-1],2)))
        tmp = ''
    
    ea = idc.next_addr(ea)

print(''.join(secret))

