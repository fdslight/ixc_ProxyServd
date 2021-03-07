#!/usr/bin/env python3
"""RPC协议如下
version:1 byte 版本号,固定值为1
type:1 byte,1表示RPC请求,2表示RPC响应
reverse:2 bytes 保留字节
length:4 bytes 负载长度
rpc_request_id:4 bytes 发送request的客户端ID,由RPC中转服务器自动生成,通常为文件描述符

RPC request 格式:
namespace_length:1 byte 命名空间长度
fn_name_length:1 byte 函数名长度
namespace: 256 bytes 命名空间
function:256 bytes 函数名
arg_data:参数数据


RPC response 格式
is_error:4 bytes 是否发生故障,0表示未发生故障,1表示命名空间未找到,2表示函数未找到,3表示参数错误,4表示系统错误,5表示调用超时
result_data:variable
"""

HEADER_FMT = "!bb2sII"
REQ_FMT = "!bb256s256s"

HEADER_SIZE = 12

VERSION = 1
RPC_REQ = 1
RPC_RESP = 2

RPC_TYPES = (
    RPC_REQ, RPC_RESP,
)

RPC_ERR_NO = 0
RPC_ERR_NS = 1
RPC_ERR_FN = 2
RPC_ERR_ARGS = 3
RPC_ERR_SYS = 4
RPC_ERR_TIMEOUT = 5
# 预定义的RPC故障最大code
RPC_ERR_CODE_MAX = 5

import socket, struct

import pywind.lib.reader as reader


def get_cstr_from_bytes(byte_data: bytes):
    """从bytes字节流中获取C风格的字符串,即以"\0"作为结束表记
    :param byte_data:
    :return:
    """
    p = byte_data.find(b"\0")
    if p < 0: return byte_data.decode()

    s = byte_data[0:p]

    return s.decode()


class RPCErr(Exception):
    pass


class RPCRequestErr(Exception):
    pass


class RPCResponseErr(Exception):
    pass


class RPCNSNotFoundErr(Exception):
    pass


class RPCMethodNotFoundErr(Exception):
    pass


class RPCArgErr(Exception):
    pass


class RPCbuilder(object):
    @staticmethod
    def build_data(_type, _id, byte_data):
        length = len(byte_data)
        pkt = struct.pack(HEADER_FMT, VERSION, _type, b"", length, _id)

        return b"".join([pkt, byte_data])

    @staticmethod
    def build_request(_id, namepsace, fn, arg_data):
        byte_ns = namepsace.encode("iso-8859-1")
        byte_fn = fn.encode("iso-8859-1")
        ns_len = len(byte_ns)
        fn_len = len(byte_fn)

        a = struct.pack(REQ_FMT, ns_len, fn_len, byte_ns, byte_fn)
        b = b"".join([a, arg_data])

        return RPCbuilder.build_data(RPC_REQ, _id, b)

    @staticmethod
    def build_response(_id, is_error, byte_msg):
        a = struct.pack("!i", is_error)
        b = b"".join([a, byte_msg])

        return RPCbuilder.build_data(RPC_RESP, _id, b)


class RPCParser(object):
    __reader = None
    __results = None

    __header_ok = None

    __namespace = None
    __fn = None
    __type = None
    __id = None
    __length = None

    def __init__(self):
        self.__header_ok = False
        self.__results = []
        self.__reader = reader.reader()

    def __parse_header(self):
        if self.__reader.size() < HEADER_SIZE: return
        _, self.__type, __, self.__length, self.__id = struct.unpack(HEADER_FMT,
                                                                     self.__reader.read(HEADER_SIZE))
        if self.__type not in RPC_TYPES:
            raise RPCErr("unkown data frame type")

        self.__header_ok = True

    def __parse_rpc_request(self):
        if self.__reader.size() < 514: raise RPCRequestErr("wrong RPC request length")
        ns_len, fn_len, byte_ns, byte_fn = struct.unpack(REQ_FMT, self.__reader.read(514))

        ns = byte_ns[0:ns_len].decode("iso-8859-1")
        fn = byte_fn[0:fn_len].decode("iso-8859-1")
        arg_data = self.__reader.read(self.__length - 514)

        self.__results.append(
            (self.__type, self.__id, (ns, fn, arg_data,),)
        )

    def __parse_rpc_response(self):
        if self.__reader.size() < 4:
            raise RPCResponseErr("wrong RPC response length")
        is_error, = struct.unpack("!i", self.__reader.read(4))

        self.__results.append(
            (self.__type, self.__id, (is_error, self.__reader.read(self.__length - 4)))
        )

    def __parse_body(self):
        if self.__reader.size() < self.__length: return

        self.__header_ok = False

        if RPC_REQ == self.__type:
            self.__parse_rpc_request()
        else:
            self.__parse_rpc_response()

    def parse(self, byte_data=b""):
        self.__reader._putvalue(byte_data)

        if not self.__header_ok:
            self.__parse_header()
        if not self.__header_ok: return
        self.__parse_body()

    def get_result(self):
        rs = None
        try:
            rs = self.__results.pop(0)
        except IndexError:
            pass

        return rs


class RPCSocket(object):
    __s = None
    __reader = None
    __parser = None

    def __init__(self, *args, is_unix_socket=False, is_ipv6=False, **kwargs):
        self.__as_service = False
        self.__reader = reader.reader()
        self.__parser = RPCParser()

        if is_unix_socket:
            fa = socket.AF_UNIX
        elif is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        self.__s = socket.socket(fa, socket.SOCK_STREAM)
        #self.__s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0xffff)

        self.myinit(*args, **kwargs)

    def myinit(self, *args, **kwargs):
        """重写这个方法
        :param args:
        :param kwargs:
        :return:
        """
        pass

    @property
    def socket(self):
        return self.__s

    @property
    def parser(self):
        return self.__parser

    def release(self):
        self.socket.close()


class RPCClient(RPCSocket):
    __my_id = 0

    def __send_data(self, byte_data):
        """
        :param byte_data:
        :return:
        """
        while 1:
            if not byte_data: break
            try:
                sent_size = self.socket.send(byte_data)
            except:
                raise RPCErr("cannot send RPC request")
            byte_data = byte_data[sent_size:]

    def myinit(self, address):
        self.socket.connect(address)

    def set_my_id(self, _id: int):
        """设置ID
        :param _id:
        :return:
        """
        self.__my_id = _id

    def call_fn(self, dst_id: int, ns: str, fn: str, arg_data: bytes):
        """ 调用函数
        :param dst_id:
        :param ns:
        :param fn:
        :param arg_data:
        :return:
        """
        rs = None
        byte_data = RPCbuilder.build_request(self.__my_id, ns, fn, arg_data)
        self.__send_data(byte_data)

        while 1:
            try:
                recv_data = self.socket.recv(2048)
                if not recv_data:
                    raise RPCErr("cannot receive RPC response")
            except:
                raise RPCErr("cannot recevice RPC response")
            self.parser.parse(recv_data)
            rs = self.parser.get_result()
            if rs: break

        _type, _id, o = rs
        if _type != RPC_RESP:
            raise RPCResponseErr("wrong RPC type for response")

        is_err, msg = o
        # 这里只处理预定义的故障码,其他的故障码可自定义处理
        if RPC_ERR_NS == is_err:
            raise RPCNSNotFoundErr("not found namespace %s" % ns)
        if RPC_ERR_FN == is_err:
            raise RPCMethodNotFoundErr("not found method %s.%s" % (ns, fn))
        if RPC_ERR_ARGS == is_err:
            raise RPCArgErr("wrong function argument about %s.%s" % (ns, fn,))
        if RPC_ERR_SYS == is_err:
            raise RPCErr(msg.decode())

        return o


"""
data = RPCbuilder.build_response(1000, 0, b"hello,world")
p = RPCParser()
p.parse(data)

print(p.get_result())
"""
