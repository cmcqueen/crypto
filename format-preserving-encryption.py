#!/usr/bin/env python3

# Standard Python library modules
import struct

# 3rd-party modules
from Crypto.Cipher import AES

def fpe2encrypt(message, key, rounds=10, message_width=32, decrypt=False):
    '''
    message is an integer.
    key is a 16-byte string
    '''
    widths = [0, 0]
    widths[0] = (message_width + 1) // 2
    widths[1] = message_width - widths[0]

    # Split message into working parts
    work = [0, 0]
    work[0] = message & ((1 << widths[0]) - 1)
    message >>= widths[0]
    work[1] = message & ((1 << widths[1]) - 1)

    aes_obj = AES.new(key, AES.MODE_ECB)

    for round in (range(rounds) if not decrypt else range(rounds-1, -1, -1)):
        i_from = round % 2
        i_to = (round + 1) % 2
        byte_data = struct.pack("<QQ", round, work[i_from])
        encrypt_data = aes_obj.encrypt(byte_data)
        temp, = struct.unpack("<8xQ", encrypt_data)
        temp %= (1 << widths[i_to])
        if not decrypt:
            work[i_to] = (work[i_to] + temp) % (1 << widths[i_to])
        else:
            work[i_to] = (work[i_to] - temp) % (1 << widths[i_to])
    return (work[1] << widths[0]) | work[0]

if __name__ == "__main__":
    key = b"testtesttestaaaa"
    for i in range(16):
        encrypted = fpe2encrypt(i, key)
        decrypted = fpe2encrypt(encrypted, key, decrypt=True)
        print("{0:08X} {1:08X} {2:08X}".format(i, encrypted, decrypted))
