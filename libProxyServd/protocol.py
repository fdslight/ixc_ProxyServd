#!/usr/bin/env python3

"""
#### 代理协议说明,协议加载到HTTPS上,验证等操作通过HTTPS进行 ####

version:1 byte 版本号,目前强制为1
type:1 byte 数据帧类型
    0：空数据包
    1：ping请求
    2：pong响应
    3：TCP数据包
    4：UDP数据包

    17:创建TCP请求
    18:创建TCP请求响应
    19:删除TCP请求
    20:删除TCP请求响应

payload_length:2 bytes 数据长度
user_id:16bytes 用户ID
session_id:4bytes 由客户端随机生成

type 17 格式：
    addr_type:1 byte 4表示IPv4，6表示IPv6
    pad:1byte 填充字节
    port：2bytes 目标端口
    address:ipv4为4个字节,ipv6为16个字节

type 18,20 格式：
    err_code:4bytes 0表示未发生故障，1表示连接失败

type 3格式：
    window_size:2bytes 窗口大小
    TCP DATA

type 4格式:
    addr_type:addr_type:1 byte 4表示IPv4，6表示IPv6
    pad:1 byte 填充字节
    port:2 bytes 目标端口
    addr:4 or 16bytes
    udp data
"""

import struct
import pywind.lib.reader as reader

TYPE_PING = 1
TYPE_PONG = 2
TYPE_TCP_DATA = 3
TYPE_UDP_DATA = 4

TYPE_TCP_CONN_REQ = 17
TYPE_TCP_CONN_RESP = 18

TYPE_TCP_DEL_REQ = 19
TYPE_TCP_DEL_RESP = 20


class parser(object):
    __reader = None
    __header_ok = None

    __type = None
    __payload_len = None
    __session_id = None

    __results = None

    def __init__(self):
        self.__reader = reader.reader()
        self.__header_ok = False
        self.__results = []

    def __parse_header(self):
        if self.__reader.size() < 8: return
        version, _type, payload_len, session_id = struct.unpack("!BBHI", self.__reader.read(8))

        self.__type = _type
        self.__payload_len = payload_len
        self.__session_id = session_id

        self.__header_ok = True

    def __parse_body(self):
        if self.__reader.size() < self.__payload_len: return
        byte_data = self.__reader.read(self.__payload_len)
        self.__header_ok = False

    def parse(self, byte_data: bytes):
        self.__reader._putvalue(byte_data)

        if not self.__header_ok:
            self.__parse_header()
        if not self.__header_ok:
            return
        self.__parse_body()

    def get_result(self):
        try:
            return self.__results.pop(0)
        except IndexError:
            return None


class builder(object):
    def __init__(self):
        pass

    def build_data(self, _type: int, session_id: int, byte_data: bytes):
        payload_len = len(byte_data)
        header = struct.pack("!BBHI", 1, _type, payload_len, session_id)

        return b"".join([header, byte_data])

    def build_ping(self, session_id: int):
        return self.build_data(TYPE_PING, session_id, b"")

    def build_pong(self, session_id: int):
        return self.build_data(TYPE_PONG, session_id, b"")
