import argparse
import struct
from collections import namedtuple
import enum

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.number import bytes_to_long,long_to_bytes

from helperlib import print_hexII,print_hexdump,hexdump

class Item(namedtuple('Item',['code','type','trust_code','data','comment'])):
    def __str__(self):
        l = [
            'Item',
            f'\tCode:{self.code:X}',
            f'\tType:{self.type!r}',
            f'\tTrust:{self.trust_code!r}',
            f'\tData:\n\t'+'\n\t'.join(hexdump(self.data,header=True)),
            f'\tComment:{self.comment}',
        ]
        return '\n'.join(l)

class EntryType(enum.IntEnum):
    THUMBPRINT_HASH = 1
    CERTIFICATE_PUBLISHER = 1
    ISSUER_NAME = 1
    IMAGE_HASH = 4
    VERSION_INFO = 7

class TrustLevel(enum.IntEnum):
    KnownGoodImage = 0
    KnownBadImage = 1
    UnknownImage_2 = 2
    UnknownImage = 3
    KnownBadImageBootCritical = 4

PUBLIC_EXPONENT = 0x010001
MODULUS = int.from_bytes(struct.pack("256B", *[
0xb3, 0x95, 0xde, 0x5b, 0xc2, 0xe1, 0x89, 0xf7, 0x56, 0xc2, 0x20,
0xbf, 0x27, 0xd2, 0x88, 0x1a, 0x0a, 0xac, 0xdb, 0xc7, 0x19, 0x36,
0x7b, 0xce, 0x37, 0x83, 0xd1, 0xec, 0x42, 0xd3, 0xab, 0x30, 0x54,
0xa5, 0x51, 0x11, 0xd8, 0xcc, 0xec, 0x80, 0xab, 0x89, 0x5a, 0xae,
0x18, 0x71, 0x11, 0x7c, 0x85, 0x1a, 0x1a, 0x53, 0x54, 0x46, 0x3e,
0x55, 0x5c, 0x43, 0x5d, 0x4b, 0x9f, 0xc7, 0x54, 0x57, 0x75, 0xc5,
0x02, 0xe2, 0x63, 0xa9, 0x94, 0x56, 0xa7, 0x3b, 0xe0, 0xc3, 0xed,
0x5f, 0x66, 0x9d, 0x60, 0x78, 0x1e, 0xac, 0x92, 0x3d, 0x48, 0xe9,
0x51, 0x5d, 0x79, 0x2a, 0x22, 0x9a, 0x9e, 0xd3, 0xbc, 0x15, 0xbe,
0x7a, 0x4e, 0x97, 0xe8, 0x1f, 0x9c, 0x80, 0xf5, 0xfb, 0x94, 0x0b,
0x5f, 0xb7, 0x6f, 0x0d, 0x57, 0xa0, 0x09, 0x55, 0x68, 0x78, 0xf3,
0x5d, 0x7b, 0x9a, 0x9b, 0x08, 0xa3, 0xa6, 0x41, 0x18, 0xf0, 0x17,
0x11, 0x89, 0x9b, 0x71, 0x73, 0x27, 0xa2, 0x55, 0x51, 0xc0, 0xee,
0xa5, 0x70, 0x6f, 0xb8, 0x40, 0x2a, 0x85, 0xe9, 0x91, 0x20, 0x4b,
0x0c, 0xd2, 0x29, 0xa2, 0x01, 0x36, 0x96, 0x1c, 0xbb, 0xd5, 0xef,
0x95, 0x68, 0x43, 0xfb, 0x77, 0x42, 0x88, 0x1a, 0xae, 0x60, 0x14,
0xfe, 0x0b, 0x0d, 0xd3, 0x28, 0x04, 0x98, 0x15, 0x71, 0x3e, 0xba,
0xb3, 0x80, 0x65, 0x6d, 0x2b, 0x7f, 0x30, 0xca, 0xf2, 0x6c, 0xa6,
0x47, 0xd3, 0x3c, 0x57, 0x50, 0x0d, 0xb3, 0xbb, 0xed, 0x6d, 0x75,
0xf2, 0x0f, 0x26, 0x29, 0xf7, 0xc6, 0xe4, 0x20, 0x5e, 0xaf, 0x87,
0xf1, 0x8b, 0x8e, 0x57, 0x99, 0x00, 0xf3, 0x84, 0xe5, 0x25, 0x10,
0x05, 0x2c, 0xeb, 0x77, 0xa3, 0xdb, 0xbd, 0x7e, 0xd4, 0xb5, 0x60,
0xb6, 0x6a, 0xa0, 0x99, 0x25, 0x59, 0x2f, 0x10, 0x69, 0xf4, 0x62,
0xe1, 0x8c, 0x2b]), 'big')


PUBLIC_KEY = RSA.construct((MODULUS,PUBLIC_EXPONENT))

def parse(fp):
    tag = fp.read(1)[0]
    size = struct.unpack('<I',fp.read(3)+b'\0')[0]
    return tag,fp.read(size)

def rsa_encrypt(msg,length=200):
    cipher = PKCS1_v1_5.new(PUBLIC_KEY)
    res = []
    for i in range(0,len(msg),length):
        res.append(cipher.encrypt(msg[i:i+length]))
    return b''.join(res)

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('FILE',type=argparse.FileType('rb'))
    
    args = parser.parse_args(args=argv)
    fp = args.FILE

    code = 0x80000000
    while True:
        try:
            tag,data = parse(fp)
            if tag == 0x5c:
                assert len(data)>=4
                code = struct.unpack_from('<I',data)[0]
            elif tag == 0x5D:
                code = 0x80000000
            elif tag == 0xA9:
                assert len(data)>=4
                offset = struct.unpack_from('<I',data)[0]+4
                assert offset < len(data)
                some_type = struct.unpack_from('<B',data[offset:])[0]
                if some_type == 9:
                    data_type,trust_code = struct.unpack_from('<BB',data[4:])
                    some_data = data[6:offset]
                    item = Item(code,EntryType(data_type),TrustLevel(trust_code),
                    some_data,data[offset+2:])
                    print(str(item))
            elif tag == 0xAC:
                print("Encrypted Signature:")
                print_hexdump(data,colored=True,header=True)
                signature = rsa_encrypt(bytes(reversed(data)),245)
                print("Decrypted Signature (DER):")
                print_hexdump(signature,colored=True,header=True,folded=True)
                signature = signature.split(b'\x00',1)[1]
                try:
                    assert signature[0]== 0x30
                    l = signature[1]
                    signature = signature[2:2+l]
                    assert signature[0] ==0x30

                    l = signature[1]
                    algo = signature[2:2+l]
                    hashsum = signature[2+l:]

                    assert algo[0]==0x6
                    l = algo[1]
                    algo = algo[2:l+2]

                    a = algo[0]
                    b = a%40
                    a = a//40
                    oid = [a,b]+list(algo[1:])
                    print("HashingAlgorithm:",'.'.join(map(str,oid)))

                    assert hashsum[0] == 0x4
                    l = hashsum[1]
                    hashsum = hashsum[2:l+2]
                    print("Hash:",hashsum.hex())
                except:
                    pass
            else:
                raise ValueError("Unknown tag {:02x}".format(tag))
        except IndexError:
            break
    
if __name__ == '__main__':
    main()
