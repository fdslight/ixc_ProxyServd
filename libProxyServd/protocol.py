#!/usr/bin/env python3

"""
#### 代理协议说明,协议加载到HTTPS上,验证等操作通过HTTPS进行 ####

version:1 byte 版本号,目前强制为1
type:1 byte 数据帧类型
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
    addr_len:1byte 填充字节
    port：2bytes 目标端口
    address:ipv4为4个字节,ipv6为16个字节

type 18,20 格式：
    err_code:4bytes 0表示未发生故障或者已经知道，1表示连接失败

type 3格式：
    window_size:2bytes 窗口大小
    TCP DATA

type 4格式:
    addr_type:addr_type:1 byte 4表示IPv4，6表示IPv6
    addr_len:1 byte 填充字节
    port:2 bytes 目标端口
    addr:4 or 16bytes
    udp data
"""

import struct, socket
import pywind.lib.reader as reader

TYPE_PING = 1
TYPE_PONG = 2
TYPE_TCP_DATA = 3
TYPE_UDP_DATA = 4

TYPE_TCP_CONN_REQ = 17
TYPE_TCP_CONN_RESP = 18

TYPE_TCP_DEL_REQ = 19
TYPE_TCP_DEL_RESP = 20

ADDR_TYPE_IP = 4
ADDR_TYPE_IP6 = 6

TYPES = (
    TYPE_PING, TYPE_PONG,
    TYPE_TCP_DATA,
    TYPE_UDP_DATA,
    TYPE_TCP_CONN_REQ,
    TYPE_TCP_CONN_RESP,
    TYPE_TCP_DEL_REQ,
    TYPE_TCP_DEL_RESP
)


class ProtocolErr(Exception): pass


class parser(object):
    __reader = None
    __header_ok = None
    __type = None
    __payload_len = None
    __session_id = None

    __results = None
    __request_info = None
    __user_id = None

    def __parse_addr_header(self):
        if self.__reader.size() < 4: return None
        byte_data = self.__reader.read(4)
        addr_type, addr_len, port = struct.unpack("!BBH", byte_data)

        if addr_type not in (4, 6,): raise ProtocolErr("Wrong address type")

        if addr_type == 4 and self.__reader.size() < 4:
            self.__reader.push(byte_data)
        if addr_type == 6 and self.__reader.size() < 16:
            self.__reader.push(byte_data)

        if addr_type == 4 and addr_len != 4:
            raise ProtocolErr("wrong address length for IPv4")
        if addr_type == 6 and addr_len != 16:
            raise ProtocolErr("wrong address length for IPv6")
        address = self.__reader.read(addr_len)
        if addr_type == 4:
            fa = socket.AF_INET
        else:
            fa = socket.AF_INET6
        s_addr = socket.inet_ntop(fa, address)

        self.__payload_len = self.__payload_len - addr_len - 4
        if self.__payload_len != 0 and self.__type == TYPE_TCP_CONN_REQ:
            raise ProtocolErr("Wrong payload length for TCP connection request")

        return addr_type, s_addr, port

    def __init__(self):
        self.__reader = reader.reader()
        self.__header_ok = False
        self.__addr_header_ok = False
        self.__results = []

    def __parse_header(self):
        if self.__reader.size() < 24: return
        version, _type, payload_len, user_id, session_id = struct.unpack("!BBH16sI", self.__reader.read(24))

        if version != 1:
            raise ProtocolErr("Wrong protocol version number")

        if _type not in TYPES:
            raise ProtocolErr("Wrong data packet format")

        self.__type = _type
        self.__payload_len = payload_len
        self.__user_id = user_id
        self.__session_id = session_id

        self.__header_ok = True

    def __parse_body(self):
        if self.__reader.size() < self.__payload_len: return
        if self.__type in (4, 17,):
            self.__request_info = self.__parse_addr_header()
            if not self.__request_info: return
        if self.__reader.size() < self.__payload_len: return
        byte_data = self.__reader.read(self.__payload_len)

        if self.__type in (4, 17,):
            info = self.__request_info
            if self.__type == 4:
                x = list(info)
                x.append(byte_data)
                info = tuple(x)
        else:
            info = byte_data

        if self.__type == TYPE_TCP_DATA:
            if len(byte_data) < 2:
                raise ProtocolErr("Wrong TCP data format")
            win_size, = struct.unpack("!H", byte_data[0:2])
            info = byte_data[2:]

        self.__results.append(
            (self.__type, self.__user_id, self.__session_id, info,)
        )
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

    def build_data(self, _type: int, user_id: bytes, session_id: int, byte_data: bytes):
        if _type not in TYPES:
            raise ProtocolErr("wrong data packet type")

        payload_len = len(byte_data)
        header = struct.pack("!BBH16sI", 1, _type, payload_len, user_id, session_id)

        return b"".join([header, byte_data])

    def build_request(self, addr_type: int, address: str, port: int, byte_data=b""):
        """
        :param addr_type:
        :param address:
        :param port:
        :param byte_data: 如果为UDP或者UDPLite协议那么数据不能为空
        :return:
        """
        if addr_type not in (4, 6,):
            raise ProtocolErr("wrong address type value")

        if addr_type == 4:
            fa = socket.AF_INET
        else:
            fa = socket.AF_INET6

        byte_addr = socket.inet_pton(fa, address)
        if port < 1 or port > 0xfffe:
            raise ValueError("wrong port number")

        addr_len = len(byte_addr)
        data = struct.pack("!BBH", addr_type, addr_len, port)

        result = b"".join([data, byte_addr, byte_data])

        return result

    def build_tcp_conn_request(self, user_id: bytes, session_id: int, addr_type: int, ipaddr: str, port: int):
        request_data = self.build_request(addr_type, ipaddr, port)
        return self.build_data(TYPE_TCP_CONN_REQ, user_id, session_id, request_data)

    def build_udp_data(self, user_id: bytes, session_id: int, addr_type: int, ipaddr: str, port: int, byte_data: bytes):
        udp_data = self.build_request(addr_type, ipaddr, port, byte_data=byte_data)
        return self.build_data(TYPE_UDP_DATA, user_id, session_id, udp_data)

    def build_tcp_data(self, user_id: bytes, session_id: int, win_size: int, byte_data: bytes):
        """
        :param user_id:
        :param session_id:
        :param win_size:
        :param byte_data:
        :return:
        """
        if win_size > 0xfff or win_size < 0:
            raise ValueError("Wrong window size value %s" % win_size)

        payload_data = b"".join([struct.pack("!H", win_size), byte_data])
        return self.build_data(TYPE_TCP_DATA, user_id, session_id, payload_data)

    def build_ping(self, user_id: bytes, session_id: int):
        return self.build_data(TYPE_PING, user_id, session_id, b"")

    def build_pong(self, user_id: bytes, session_id: int):
        return self.build_data(TYPE_PONG, user_id, session_id, b"")


cls = builder()
cls_parser = parser()
build_data = cls.build_tcp_data(bytes(16), 1200, 1500, b"zzzz")
cls_parser.parse(build_data)
print(cls_parser.get_result())
