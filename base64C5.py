import base64
from hashlib import md5

if md5(str(15245815).encode('utf-8')).hexdigest()[:6] == '233333':
    print(15245815)

encrypt_key = 'flarebearstare'

def decrypt(text):
    key = ""
    for i in range(0,len(text)):
        key += chr(text[i]-ord(encrypt_key[i%14]))

    return key

def c1_2016():
    encoded = 'x2dtJEOmyjacxDemx2eczT5cVS9fVUGvWTuZWjuexjRqy24rV29q'
    custom_b64 = 'ZYXABCDEFGHIJKLMNOPQRSTUVWzyxabcdefghijklmnopqrstuvw0123456789+/'
    std_b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    encoded = encoded.translate(str.maketrans(custom_b64,std_b64))
    flag = base64.b64decode(encoded)
    print(flag)

def main():
    key = 'UDYs1D7bNmdE1o3g5ms1V6RrYCVvODJF1DpxKTxAJ9xuZW=='.swapcase()

    key_decoded = base64.b64decode(key)
    key_decrypted = decrypt(key_decoded)
    print("[+] KEY: {}".format(key_decrypted))
    c1_2016()

if __name__ == '__main__':
    main()
   