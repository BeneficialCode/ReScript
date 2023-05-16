import sys
import hashlib
from Crypto.Cipher import AES
import struct

def derive_key(key):
    # sha-1 hash algorithm used
    key_sha1 = hashlib.sha1(key.encode()).digest()
    #print(key_sha1)

    b0 = b""
    for x in key_sha1:
        b0 += int.to_bytes(x^0x36,1,byteorder='little')
    
    b1 = b""
    for x in key_sha1:
        b1 += int.to_bytes(x^0x5C,1,byteorder='little')
    
    # pad remaining bytes with the appropriate value
    b0 += b"\x36"*(64-len(b0))
    b1 += b"\x5c"*(64-len(b1))
    #print(b0)
    #print(b1)
    b0_sha1 = hashlib.sha1(b0).digest()
    b1_sha1 = hashlib.sha1(b1).digest()

    return b0_sha1+b1_sha1

unpad = lambda s:s[0:-s[-1]] # remove pkcs5 padding

fname = sys.argv[1]
with open(fname,'rb+') as f:
    encrypted_data = f.read()

    key = "thosefilesreallytiedthefoldertogether"
    # 256-bit key / 8 = 32 bytes
    aes_key = derive_key(key)[:32]
    print(aes_key)

    iv_name = fname[fname.rfind('\\')+1:]
    iv = hashlib.md5(iv_name.lower().encode()).digest()
    print(iv)

    decryptor = AES.new(aes_key,AES.MODE_CBC,iv)
    decrypted_data = unpad(decryptor.decrypt(encrypted_data))
    f.seek(0)
    f.write(decrypted_data)
    f.truncate(len(decrypted_data))


