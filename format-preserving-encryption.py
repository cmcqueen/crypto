#!/usr/bin/env python3

# Standard Python library modules
import struct

# 3rd-party modules
from Crypto.Cipher import AES

class FPE2:
    def __init__(self, key, rounds=10, message_width=32):
        '''
        key is a 16- 24- or 32-byte string
        '''
        self.key = key
        self.aes_obj = AES.new(key, AES.MODE_ECB)
        self.rounds = rounds
        widths = [(message_width + 1) // 2, message_width // 2]
        modulos = [ 1 << width for width in widths ]
        masks = [ modulo - 1 for modulo in modulos ]
        self.message_width = message_width
        self.widths = widths
        self.modulos = modulos
        self.masks = masks

    def split_message(self, message):
        '''Split message into working parts'''
        work = [0, 0]
        work[0] = message & self.masks[0]
        message >>= self.widths[0]
        work[1] = message & self.masks[1]
        return work

    def encrypt(self, message):
        '''
        message is an integer.
        '''
        work = self.split_message(message)
        for round in range(self.rounds):
            i_from = round % 2
            i_to = (round + 1) % 2
            byte_data = struct.pack("<QQ", round, work[i_from])
            encrypt_data = self.aes_obj.encrypt(byte_data)
            temp, = struct.unpack("<8xQ", encrypt_data)
            temp %= (1 << self.widths[i_to])
            work[i_to] = (work[i_to] + temp) % (1 << self.widths[i_to])
        return (work[1] << self.widths[0]) | work[0]

    def decrypt(self, message):
        '''
        message is an integer.
        '''
        work = self.split_message(message)
        for round in range(self.rounds-1, -1, -1):
            i_from = round % 2
            i_to = (round + 1) % 2
            byte_data = struct.pack("<QQ", round, work[i_from])
            encrypt_data = self.aes_obj.encrypt(byte_data)
            temp, = struct.unpack("<8xQ", encrypt_data)
            temp %= self.modulos[i_to]
            work[i_to] = (work[i_to] - temp) % self.modulos[i_to]
        return (work[1] << self.widths[0]) | work[0]

if __name__ == "__main__":
    key = b"testtesttestaaaa"
    fpe_obj = FPE2(key)
    for i in range(16):
        encrypted = fpe_obj.encrypt(i)
        decrypted = fpe_obj.decrypt(encrypted)
        print("{0:08X} {1:08X} {2:08X}".format(i, encrypted, decrypted))
        assert (i == decrypted)

