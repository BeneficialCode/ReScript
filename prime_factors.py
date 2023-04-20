import struct
import idc

primes_addr = 0x2214
factorization_array_addr = 0x5004

secret = []

def get_prime(p):
    return idc.get_wide_word(primes_addr+2*p)

for i in range(23):
    base_fact_addr = idc.get_wide_dword(factorization_array_addr+4*i)
    res_fact = 1
    p = 0
    for j in range(3476):
        prime = get_prime(p)
        pow = idc.get_wide_word(base_fact_addr+2*j)
        if pow != 0:
            res_fact *= prime**pow
        p+=1

    secret.append(res_fact)

print(b''.join([struct.pack('>H',i) for i in secret]).decode('utf-8'))

    