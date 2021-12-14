#!/usr/bin/env python3
"""协议规范
magic:4bytes 固定为 值为 b"n2n\0"
type: 1bytes 数据类型,0为普通数据,1为PING请求,2为PONG请求
"""
import struct

MAGIC_NUM = b'n2n\x00'
TYPE_DATA = 0
TYPE_PING = 1
TYPE_PONG = 2

TYPES = (
    TYPE_DATA, TYPE_PING, TYPE_PONG
)


class parser(object):
    def __init__(self):
        pass

    def parse(self, byte_data: bytes):
        if len(byte_data) < 5: return None
        magic, _type = struct.unpack("!4sB", byte_data[0:5])
        if magic != MAGIC_NUM: return None
        if _type not in TYPES: return None

        return _type, byte_data[5:]


class builder(object):
    def __init__(self):
        pass

    def build(self, _type: int, byte_data: bytes):
        if _type not in TYPES:
            raise ValueError("unsupport argument type value %s" % _type)
        seq = [
            struct.pack("!4sB", MAGIC_NUM, _type),
            byte_data
        ]

        return b"".join(seq)
