#!/usr/bin/env python3
"""TCP隧道
协议格式如下:
session_id:16 byte 会话ID,16 bytes的MD5值
reverse:4bit 保留
action:4 bit 包动作
rand_byte_size:2 bytes 产生的随机byte数目
tot_length: 2 bytes 包的总长度
real_length: 2 bytes 加密前的长度
"""
MIN_FIXED_HEADER_SIZE = 23

import pywind.lib.reader as reader
import ixc_proxy.lib.base_proto.utils as proto_utils
import struct

_FMT = "!16sbHHH"

import random, os


class builder(object):
    __fixed_hdr_size = 0

    def __init__(self, fixed_hdr_size):
        self.__fixed_hdr_size = fixed_hdr_size
        if fixed_hdr_size < MIN_FIXED_HEADER_SIZE: raise ValueError(
            "min fixed header size is %s" % MIN_FIXED_HEADER_SIZE)

    def __build_proto_headr(self, session_id, rand_size, tot_len, real_size, action):
        res = struct.pack(
            _FMT, session_id, action, rand_size, tot_len, real_size
        )
        return res

    def gen_rand_bytes(self):
        n = random.randint(0, 14)

        return (n, os.urandom(n),)

    def build_packet(self, session_id, action, byte_data):
        if len(session_id) != 16: raise proto_utils.ProtoError("the size of session_id must be 16")

        seq = []

        a, b = (0, 60000,)

        while 1:
            _byte_data = byte_data[a:b]
            if not _byte_data: break

            rand_length, rand_bytes = self.gen_rand_bytes()
            pkt_len = len(_byte_data)
            tot_len = self.get_payload_length(pkt_len) + rand_length
            base_hdr = self.__build_proto_headr(session_id, rand_length, tot_len, pkt_len, action)

            e_hdr = self.wrap_header(base_hdr)
            e_body = b"".join([rand_bytes, self.wrap_body(pkt_len, _byte_data)])

            seq.append(b"".join((e_hdr, e_body,)))
            a, b = (b, b + 60000,)

        return b"".join(seq)

    def wrap_header(self, base_hdr):
        """重写这个方法"""
        return base_hdr

    def wrap_body(self, size, body_data):
        """重写这个方法"""
        return body_data

    def reset(self):
        pass

    def get_payload_length(self, pkt_len):
        """获取负载长度,加密前后可能数据包长度不一致,重写这个方法"""
        return pkt_len

    def config(self, config):
        """重写这个方法,用于协议配置"""
        pass


class parser(object):
    __reader = None
    __fixed_hdr_size = MIN_FIXED_HEADER_SIZE
    __session_id = None
    __rand_length = None
    # 数据负荷大小
    __tot_length = 0
    # 解密后的数据大小
    __real_length = 0
    __header_ok = False
    __action = 0
    __results = None

    def __init__(self, fixed_hdr_size):
        """
        :param fixed_hdr_size: 固定头长度
        """
        self.__reader = reader.reader()
        self.__fixed_hdr_size = fixed_hdr_size
        self.__results = []

        if fixed_hdr_size < MIN_FIXED_HEADER_SIZE: raise ValueError(
            "min fixed header size is %s" % MIN_FIXED_HEADER_SIZE)

    def __parse_header(self, hdr):
        return struct.unpack(_FMT, hdr)

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def parse(self):
        size = self.__reader.size()

        if self.__header_ok:
            if size < self.__tot_length: return
            self.__reader.read(self.__rand_length)
            e_body = self.__reader.read(self.__tot_length - self.__rand_length)
            body = self.unwrap_body(self.__real_length, e_body)

            self.__results.append((self.__session_id, self.__action, body,))
            self.reset()
            return
        if self.__reader.size() < self.__fixed_hdr_size: return
        hdr = self.unwrap_header(self.__reader.read(self.__fixed_hdr_size))
        if not hdr:
            self.reset()
            return
        self.__session_id, \
        self.__action, self.__rand_length, self.__tot_length, self.__real_length = self.__parse_header(hdr)
        self.__header_ok = True

    def unwrap_header(self, header):
        """重写这个方法"""
        return header

    def unwrap_body(self, real_size, body_data):
        """重写这个方法"""
        return body_data

    def reset(self):
        self.__tot_length = 0
        self.__header_ok = False
        self.__real_length = 0

    def can_continue_parse(self):
        size = self.__reader.size()
        if not self.__header_ok and size < self.__fixed_hdr_size: return False
        if not self.__header_ok: return True

        return size >= self.__tot_length

    def get_pkt(self):
        try:
            return self.__results.pop(0)
        except IndexError:
            return None

    def config(self, config):
        """重写这个方法,用于协议配置"""
        pass
