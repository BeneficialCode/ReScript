file = "sub_892492E0.mem"
buf = bytearray(open(file,'rb').read())
with open(file,'wb') as f:
    f.write(buf.replace(b"\xc6\x45\x9e\x00",b"\xc6\x45\x9e\x01"))
    f.close()
