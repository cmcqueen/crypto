#!/usr/bin/env python3

# Standard Python library modules
import struct

# 3rd-party modules
from Crypto.Cipher import AES

class FPEInteger:
    """
    Format-Preserving Encryption.
    This uses AES, but it does not conform to the proposed AES-FFX[radix] standard.
    Inputs and outputs for encryption and decryption are integers of 96 or fewer bits.
    """
    def __init__(self, key, rounds=10, radix=2, width=32):
        '''
        key is a 16- 24- or 32-byte string
        '''
        self.key = key
        self.aes_obj = AES.new(key, AES.MODE_ECB)
        self.rounds = rounds
        part_widths = [(width + 1) // 2, width // 2]
        modulos = [ radix**part_width for part_width in part_widths ]
        self.modulos = modulos

        if radix**width <= 2**32:
            self.block_encrypt_func = self.block_encrypt_func_small
        else:
            self.block_encrypt_func = self.block_encrypt_func_large

    def split_message(self, message):
        '''Split message into working parts. Return a list of parts.'''
        work_0 = message % self.modulos[0]
        message //= self.modulos[0]
        work_1 = message % self.modulos[1]
        return [ work_0, work_1 ]

    def join_message(self, work):
        '''Join list of message parts back into message. Return the message.
        Inverse of self.split_message().'''
        return (work[1] * self.modulos[0]) + work[0]

    def block_encrypt_func_small(self, work_val, round_num, out_modulo):
        '''Block encryption function--small one for block size 2**32 or smaller.'''
        byte_data = struct.pack("<QQ", round_num, work_val)
        encrypt_data = self.aes_obj.encrypt(byte_data)
        temp, = struct.unpack("<8xQ", encrypt_data)
        temp %= out_modulo
        return temp

    def block_encrypt_func_large(self, work_val, round_num, out_modulo):
        '''Block encryption function--large one for block size bigger than 2**32.'''
        byte_data = struct.pack("<QQ", round_num, work_val)
        encrypt_data = self.aes_obj.encrypt(byte_data)
        temp_lo, temp_hi = struct.unpack("<QQ", encrypt_data)
        temp = (temp_hi << 64) | temp_lo
        temp %= out_modulo
        return temp

    def encrypt(self, message):
        '''message is an integer. Returns an integer.'''
        work = self.split_message(message)
        i_from, i_to = 0, 1
        for round_num in range(self.rounds):
            temp = self.block_encrypt_func(work[i_from], round_num, self.modulos[i_to])
            work[i_to] = (work[i_to] + temp) % self.modulos[i_to]
            i_from, i_to = i_to, i_from
        return self.join_message(work)

    def decrypt(self, message):
        '''message is an integer. Returns an integer.'''
        work = self.split_message(message)
        i_from, i_to = (self.rounds - 1) % 2, self.rounds % 2
        for round_num in range(self.rounds-1, -1, -1):
            temp = self.block_encrypt_func(work[i_from], round_num, self.modulos[i_to])
            work[i_to] = (work[i_to] - temp) % self.modulos[i_to]
            i_from, i_to = i_to, i_from
        return self.join_message(work)

if __name__ == "__main__":
    radix = 10
    width = 7

    if radix == 10:
        print_base = 'd'
        print_width = width
    elif radix == 8:
        print_base = 'o'
        print_width = width
    else:
        print_base = 'X'
        max_val = radix**width
        print_width = 1
        while 16**print_width < max_val:
            print_width += 1
    #print(print_base, print_width)

    fpe_obj = FPEInteger(key=b"testtesttestaaaa", radix=radix, width=width)
    #print(fpe_obj.block_encrypt_func.__name__)

    run_range = 16
    #run_range = radix**width
    for i in range(run_range):
        try:
            encrypted = fpe_obj.encrypt(i)
            decrypted = fpe_obj.decrypt(encrypted)
            if 1:
                print("{0:0{width}{base}} {1:0{width}{base}} {2:0{width}{base}}".format(i, encrypted, decrypted,
                    width=print_width, base=print_base))
            assert (i == decrypted)
        except KeyboardInterrupt:
            print('Completed {0} calculations'.format(i))
            break

