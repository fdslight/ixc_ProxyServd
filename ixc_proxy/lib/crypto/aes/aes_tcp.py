#!/usr/bin/env python3
"""TCP版本的AES加密模块"""
"""
import sys
sys.path.append("../../../")
"""

import hashlib
import os

import ixc_proxy.lib.base_proto.tunnel_tcp as tunnel

FIXED_HEADER_SIZE = 48


class encrypt(tunnel.builder):
    __key = b""
    __iv = b""
    # 需要补充的`\0`
    __const_fill = b""

    def __init__(self):
        if tunnel.MIN_FIXED_HEADER_SIZE % 16 != 0:
            self.__const_fill = b"f" * (16 - tunnel.MIN_FIXED_HEADER_SIZE % 16)

        super(encrypt, self).__init__(FIXED_HEADER_SIZE)

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

    def get_payload_length(self, pkt_len):
        return aes_cfb.get_size(pkt_len)

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
        if self.__const_fill != data[tunnel.MIN_FIXED_HEADER_SIZE:]: raise proto_utils.ProtoError("data wrong")

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
key="name"
builder = encrypt()
builder.config({"key":key})

e_rs = builder.build_packet(bytes(16),proto_utils.ACT_IPDATA,b"hello")
builder.reset()

parser = decrypt()
parser.config({"key":"name"})
parser.input(e_rs)

while parser.can_continue_parse():
    parser.parse()
print(parser.get_pkt())

e_rs = builder.build_packet(bytes(16),proto_utils.ACT_IPDATA,b"world")
builder.reset()
parser.input(e_rs)

while parser.can_continue_parse():
    parser.parse()
print(parser.get_pkt())
"""
