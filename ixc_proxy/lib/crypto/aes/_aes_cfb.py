#!/usr/bin/env python3

import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("please install cryptography module")
    sys.exit(-1)


def encrypt(key, iv, byte_data):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    return encryptor.update(byte_data) + encryptor.finalize()


def decrypt(key, iv, byte_data):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    return decryptor.update(byte_data) + decryptor.finalize()


def get_size(byte_size):
    n = int(byte_size / 16)
    r = byte_size % 16

    if r != 0: n += 1

    return n * 16

