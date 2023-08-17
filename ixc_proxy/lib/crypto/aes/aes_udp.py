#!/usr/bin/env python3
"""UDP版本的AES加密模块"""

import sys
sys.path.append("../../../")

import hashlib
import os

import ixc_proxy.lib.base_proto.tunnel_udp as tunnel
import ixc_proxy.lib.crypto.aes._aes_cfb as aes_cfb

FIXED_HEADER_SIZE = 48


class encrypt(tunnel.builder):
    __key = b""
    __iv = b""
    # 需要补充的`\0`
    __const_fill = b""

    __real_size = 0
    __body_size = 0

    def __init__(self):
        if tunnel.MIN_FIXED_HEADER_SIZE % 16 != 0:
            self.__const_fill = b"f" * (16 - tunnel.MIN_FIXED_HEADER_SIZE % 16)

        super(encrypt, self).__init__(FIXED_HEADER_SIZE)
        self.set_max_pkt_size(self.block_size - self.block_size % 16)

    def wrap_header(self, base_hdr):
        iv = os.urandom(16)
        self.__iv = iv
        seq = [
            base_hdr,
            self.__const_fill
        ]
        e_data = aes_cfb.encrypt(self.__key, self.__iv, b"".join(seq))
        return iv + e_data

    def wrap_body(self, size, body_data):
        filled = bytes(aes_cfb.get_size(size) - size)

        return aes_cfb.encrypt(self.__key, self.__iv, body_data + filled)

    def __set_aes_key(self, new_key):
        self.__key = hashlib.md5(new_key.encode()).digest()

    def reset(self):
        super(encrypt, self).reset()

    def config(self, config):
        """重写这个方法,用于协议配置"""
        self.__set_aes_key(config["key"])


class decrypt(tunnel.parser):
    __key = b""
    __iv = b""
    # 向量字节的开始位置
    __iv_begin_pos = 0
    # 向量字节的结束位置
    __iv_end_pos = 0
    __const_fill = b""

    def __init__(self):
        self.__iv_begin_pos = 0
        self.__iv_end_pos = self.__iv_begin_pos + 16

        if tunnel.MIN_FIXED_HEADER_SIZE % 16 != 0:
            self.__const_fill = b"f" * (16 - tunnel.MIN_FIXED_HEADER_SIZE % 16)

        super(decrypt, self).__init__(FIXED_HEADER_SIZE)

    def unwrap_header(self, header_data):
        self.__iv = header_data[self.__iv_begin_pos:self.__iv_end_pos]
        data = aes_cfb.decrypt(self.__key, self.__iv, header_data[self.__iv_end_pos:FIXED_HEADER_SIZE])
        real_hdr = data[0:tunnel.MIN_FIXED_HEADER_SIZE]

        # 丢弃误码的包
        if self.__const_fill != data[tunnel.MIN_FIXED_HEADER_SIZE:]: return None

        return real_hdr

    def unwrap_body(self, length, body_data):
        d = aes_cfb.decrypt(self.__key, self.__iv, body_data)

        return d[0:length]

    def __set_aes_key(self, key):
        new_key = hashlib.md5(key.encode()).digest()
        self.__key = new_key

    def reset(self):
        super(decrypt, self).reset()

    def config(self, config):
        """重写这个方法,用于协议配置"""
        self.__set_aes_key(config["key"])

"""
length = 1500
L = []

for n in range(length):
    L.append(33)

key = "hello"
builder = encrypt()
builder.config({"key": key})

packets = builder.build_packets(bytes(16), 2, b"hello,world")

parser = decrypt()
parser.config({"key": "hello"})

for pkt in packets:
    ret = parser.parse(pkt)
    if ret: print(ret)
"""