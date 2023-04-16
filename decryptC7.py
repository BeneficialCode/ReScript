from itertools import product
import array
import string


keys = [['the final countdown','oh happy dayz'],# bypass the anti-debug detect
['omglob','UNACCEPTABLE!'],# bypass being debugged
["you're so bad","you're so good"], # bypass vmware detect
["f",'\x01'],# bypass vmware detect
["I'm gonna sandbox your face","Sandboxes are fun to play in"],
["Such fire. Much burn. Wow.","I can haz decode?"],
["\x09\x00\x00\x01","Feel the sting of the Monarch!"],# bypass NtGlobalFlag detect
["! 50 1337","1337"],
["MATH IS HARD","LETS GO SHOPPING"],
["SHOPPING IS HARD","LETS GO MATH"],
["\x01\x02\x03\x05\x00\x78\x30\x38\x0d","\x07w"],
["backdoge.exe"],
["192.203.230.10"],
["jackRAT"]]


def xor(data,key,size):
    l = len(key)
    return bytearray(
        (data[i]^ord(key[i%l])) for i in range(0,size)
    )

fh = open('backdoge.exe', 'rb')
fh.seek(0x113f8)
encrypt_file = fh.read(0x106240)
fh.close()

# 求多个可迭代对象的笛卡尔积
for x in product(*keys):
    version = encrypt_file
    for y in x:
        # B -- unsigned char
        version = xor(version,array.array('u',y),2) # just decrypt first byte and second byte
    print("{} {}".format(hex(version[0]),hex(version[1])))
    if version[0] == 0x4d and version[1] == 0x5a: # MZ
        version = encrypt_file
        print(x)
        for y in x:
            version = xor(version,array.array('u',y),len(encrypt_file))
        print("{} {}".format(hex(version[0]),hex(version[1])))
        open("decrypted.exe",'wb').write(version)
        quit()
