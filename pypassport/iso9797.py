from Crypto.Cipher import DES


def pad(data, block_size=8):
    padding_length = block_size - (len(data) % block_size)
    padding = b'\x80' + b'\x00' * (padding_length - 1)
    return data + padding


def unpad(tounpad):
    i = -1
    while tounpad[i] == 0x00:
        i -= 1

    if tounpad[i] == 0x80:
        return tounpad[0:i]
    else:
        return tounpad


def mac(key, msg):
    #Source: PKI for machine readable travel document offering
    #        ICC read-only access
    #Release:1.1
    #October 01,2004
    #p46 of 57

    size = int(len(msg) / 8)
    iv = b'\x00' * 8
    tdesa = DES.new(key[0:8], DES.MODE_CBC, iv)

    for i in range(size):
        cb = tdesa.encrypt(msg[i * 8:i * 8 + 8])

    tdesb = DES.new(key[8:16], DES.MODE_ECB)
    tdesa = DES.new(key[0:8], DES.MODE_ECB)

    res = tdesb.decrypt(cb)
    a = tdesa.encrypt(res)

    return a
