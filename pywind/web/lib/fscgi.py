#!/usr/bin/env python3
import struct
import pywind as reader

FCGI_VERSION_1 = 1

FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_DATA = 8
FCGI_GET_VALUES = 9
FCGI_GET_VALUES_RESULT = 10
FCGI_UNKNOWN_TYPE = 11

FCGI_TYPES = (
    FCGI_BEGIN_REQUEST,
    FCGI_ABORT_REQUEST,
    FCGI_END_REQUEST,
    FCGI_PARAMS,
    FCGI_STDIN,
    FCGI_STDOUT,
    FCGI_STDERR,
    FCGI_DATA,
    FCGI_GET_VALUES,
    FCGI_GET_VALUES_RESULT,
    FCGI_UNKNOWN_TYPE,
)

FCGI_HEADER_FMT = "!BBHHBB"
FCGI_BeginRequestBody_FMT = "!HB5s"
FCGI_EndRequestBody_FMT = "!IB3s"

FCGI_RESPONDER = 1
FCGI_AUTHORIZER = 2
FCGI_FILTER = 3

FCGI_ROLES = (
    FCGI_RESPONDER,
    FCGI_AUTHORIZER,
    FCGI_HEADER_FMT,
)

FCGI_REQUEST_COMPLETE = 0
FCGI_CANT_MPX_CONN = 1
FCGI_OVERLOADED = 2


class FCGIError(Exception): pass


class fcgi_parser(object):
    __reader = None
    __header_ok = None

    __length = None
    __pad_length = None
    __tot_length = None
    __type = None
    __id = None

    __results = None

    def __init__(self):
        self.__reader = reader.reader()
        self.__header_ok = False
        self.__results = []

    def input(self, byte_data):
        self.__reader._putvalue(byte_data)

    def parse(self):
        if not self.__header_ok:
            self.__parse_header()
        if not self.__header_ok:
            return
        self.__parse_body()

    def __parse_header(self):
        if self.__reader.size() < 8: return
        ver, _type, _id, length, pad_length, _ = struct.unpack(FCGI_HEADER_FMT, self.__reader.read(8))
        if ver != 1:
            raise FCGIError("unsupport FCGI version %s" % ver)

        if _type not in FCGI_TYPES:
            raise FCGIError("unkown FCGI type %s" % type)

        self.__length = length
        self.__pad_length = pad_length
        self.__tot_length = length + pad_length
        self.__header_ok = True
        self.__type = _type
        self.__id = _id

    def __parse_body(self):
        if self.__reader.size() < self.__tot_length: return

        rdata = self.__reader.read(self.__length)
        # 丢弃填充数据
        self.__reader.read(self.__pad_length)

        rs = rdata

        if self.__type == FCGI_BEGIN_REQUEST:
            rs = self.parse_BeginRequestBody(rdata)

        if self.__type == FCGI_ABORT_REQUEST:
            rs = self.parse_EndRequestBody(rdata)

        if self.__type == FCGI_END_REQUEST:
            rs = self.parse_EndRequestBody((rdata))

        if self.__type == FCGI_PARAMS:
            rs = self.parse_key_value(rdata)

        return (self.__type, self.__id, rs,)

    def __parse_key_value(self, byte_data):
        name_length = byte_data[0]

        if (name_length & 0x10) >> 7 == 1:
            name_length, = struct.unpack("!I", byte_data[0:4])
            name_length = name_length & 0x7fffffff
            byte_data = byte_data[4:]
        else:
            byte_data = byte_data[1:]

        if len(byte_data) <= name_length or name_length < 1:
            raise FCGIError("wrong params length")

        value_length = byte_data[0]
        if (value_length & 0x10) >> 7 == 1:
            name_length, = struct.unpack("!I", byte_data[0:4])
            value_length = name_length & 0x7fffffff
            byte_data = byte_data[4:]
        else:
            byte_data = byte_data[1:]

        if len(byte_data) <= value_length or value_length < 1:
            raise FCGIError("wrong params length")

        b_name = byte_data[0:name_length]
        byte_data = byte_data[name_length:]
        b_value = byte_data[0:value_length]
        byte_data = byte_data[value_length:]

        if len(b_name) != name_length or len(b_value) != value_length:
            raise FCGIError("wrong params length")

        rs = (
            b_name.decode("iso-8859-1"),
            b_value.decode("iso-8859-1"),
            byte_data,
        )

        return rs

    def parse_key_value(self, byte_data):
        size = len(byte_data)

        if size < 4:
            raise FCGIError("wrong key value format")

        results = []
        while 1:
            name, value, byte_data = self.__parse_key_value(byte_data)
            results.append((name, value,))
            if not byte_data: break

        return results

    def parse_BeginRequestBody(self, byte_data):
        if len(byte_data) != 8:
            raise FCGIError("wrong BeginRequestBody")

        role, flags = struct.unpack("!HB", byte_data[0:3])
        rs = (role, bool(flags & 1),)

        return rs

    def parse_EndRequestBody(self, byte_data):
        if len(byte_data) != 8:
            raise FCGIError("wrong EndRequestBody")

        app_status, proto_status = struct.unpack("!IB", byte_data[0:5])

        return (app_status, proto_status,)


class fcgi_builder(object):
    def __init__(self):
        pass

    def build_header(self, _t, _id, length, pad_length):
        return struct.pack(FCGI_HEADER_FMT, FCGI_VERSION_1, _t, _id, length, pad_length, 0)

    def build_BeginRequestBody(self, role, flags):
        return struct.pack(FCGI_BeginRequestBody_FMT, role, flags, b"\0\0\0\0\0")

    def build_EndRequestBody(self, app_status, protocol_status):
        return struct.pack(FCGI_EndRequestBody_FMT, app_status, protocol_status, b"\0\0\0")

    def build_key_value_pair(self, name, value):
        """构建name-value对
        :param name:
        :param value:
        :return:
        """
        b_name = name.encode()
        b_value = value.encode()

        b_name_len = len(b_name)
        b_value_len = len(b_value)

        if b_name_len < 128 and b_value_len < 128:
            a = struct.pack("!BB", b_name_len, b_value_len)
        elif b_name_len < 128 and b_value_len >= 128:
            b_value_len = b_value_len | 0x80000000
            a = struct.pack("!BI", b_name_len, b_value_len)
        elif b_name_len >= 128 and b_value_len < 128:
            b_name_len = b_name_len | 0x80000000
            a = struct.pack("!IB", b_name_len, b_value_len)
        else:
            b_name_len = b_name_len | 0x80000000
            b_value_len = b_value_len | 0x80000000
            a = struct.pack("!II", b_name_len, b_value_len)

        return b"".join([a, b_name, b_value, ])

    def build_key_value_pairs(self, seq):
        """一次性构建多个key-value对
        :param seq:
        :return:
        """
        results = []
        for name, value in seq:
            byte_data = self.build_key_value_pair(name, value)
            results.append(byte_data)

        return b"".join(results)

    def build_data(self, _type, _id, byte_data):
        length = len(byte_data)
        pad_length = length % 8

        header = self.build_header(_type, _id, length, pad_length)

        return b"".join([header, byte_data, bytes(pad_length)])

    def build_request(self, _id, kv_pairs):
        byte_data = self.build_key_value_pairs()
