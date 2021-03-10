#!/usr/bin/env python3

import pywind.web.lib.httputils as httputils
import pywind.web.lib.httpchunked as httpchunked
import pywind as reader
import pywind.lib.writer as writer
import socket, ssl


class HttpErr(Exception): pass


class _builder(object):
    __req_headers = None
    __user_agent = None

    def __init__(self):
        self.__req_headers = []
        self.__user_agent = 'Mozilla/5.0'

    def wrap_header(self, method, host, path, qs_seq, user_agent, headers):
        """生成请求头
        :param method:
        :param path:
        :param qs_seq:
        :param headers
        :param user_agent:
        :return bytes:
        """
        return b""

    def wrap_body(self, byte_data):
        """装饰HTTP BODY
        :param byte_data:
        :return bytes:
        """
        pass

    def set_header(self, name, value):
        if name.lower() == "host": return
        if name.lower() == "user-agent":
            self.__user_agent = value
            return
        self.__req_headers.append((name, value,))

    def set_headers(self, seq):
        for k, v in seq: self.set_header(k, v)

    def get_header_data(self, method, host, path="/", qs_seq=None):
        return self.wrap_header(method, host, path, qs_seq, self.__user_agent, self.__req_headers)

    def get_body_data(self, body_data):
        return self.wrap_body(body_data)

    def reset(self):
        self.__req_headers = []


class _parser(object):
    __reader = None

    __is_chunked = None

    header_ok = None

    __content_length = None
    __responsed_length = None

    __status = None
    __headers = None
    __chunked = None

    __is_start = False

    __data = None
    __cookies = None

    def __init__(self):
        self.__reader = reader.reader()
        self.header_ok = False
        self.__is_chunked = False
        self.__content_length = 0
        self.__responsed_length = 0
        self.__is_start = False
        self.__data = []
        self.__cookies = []

    def __parse_content_length(self):
        is_length = False
        is_chunked = False

        for k, v in self.__headers:
            name = k.lower()
            if name == "content-length":
                is_length = True
                try:
                    self.__content_length = int(v)
                except ValueError:
                    raise HttpErr("wrong content length value")
                continue

            if name == "transfer-encoding" and v.lower() == "chunked": is_chunked = True

        if is_length and is_chunked:
            raise HttpErr("conflict content length define")

        if is_chunked:
            self.__is_chunked = True
            self.__chunked = httpchunked.parser()
        return

    def __parse_header(self):
        self.unwrap_header()
        if not self.header_ok: return
        self.__is_start = True
        self.__parse_content_length()

    def __parse_body(self):
        rdata = self.reader.read()

        if self.__is_chunked and self.__chunked.is_ok():
            return

        body_data = self.unwrap_body(rdata)

        if self.__is_chunked:
            self.__chunked.input(body_data)

            try:
                self.__chunked.parse()
            except httpchunked.ChunkedErr:
                raise HttpErr("wrong chunked body")

            self.__chunked.parse()

            while 1:
                data = self.__chunked.get_chunk()
                if not data: break
                self.__data.append(data)

            return

        size = len(body_data)
        n = self.__content_length - self.__responsed_length

        if size <= n:
            self.__responsed_length += size
        else:
            # 截断多余的数据
            self.__responsed_length = self.__content_length
            body_data = body_data[0:n]

        self.__data.append(body_data)

    def __parse_cookie(self, sts):
        """解析单个cookie
        :param sts:
        :return:
        """
        sts = sts.lstrip()
        if sts[0:4] != "name": return None
        tmplist = sts.split(";")
        tmplist2 = []

        for s in tmplist:
            if s: tmplist2.append(s.strip())
        s = tmplist2.pop()
        ret = {}

        sec = False
        if s.lower() == "secure":
            sec = True
        else:
            tmplist2.append(s)
        if sec and not self.__ssl_on: return None

        for s in tmplist2:
            p = s.find("=")
            if p < 1: continue
            name = s[0:p].strip()
            p += 1
            val = s[p:].strip()
            ret[name] = val

        return ret

    def unwrap_header(self):
        """重写这个方法
        :return:
        """
        pass

    def unwrap_body(self, body_data):
        """重写这个方法
        :param body_data
        :return:
        """
        pass

    def parse(self, byte_data):
        if self.response_ok(): return
        self.__reader._putvalue(byte_data)

        if not self.header_ok:
            self.__parse_header()
        if not self.header_ok: return

        self.__parse_body()

    @property
    def reader(self):
        return self.__reader

    def set_status(self, stcode):
        self.__status = stcode

    def set_headers(self, headers):
        seq = []

        # 为保证http1x和http2x协议的一致性
        # 字段名全部转换成小写
        for k, v in headers:
            seq.append((k.lower(), v))
        self.__headers = seq

        for k, v in self.__headers:
            if k != "set-cookie": continue
            cookie = self.__parse_cookie(v)
            if not cookie: continue
            self.__cookies.append(cookie)

    @property
    def status(self):
        return self.__status

    @property
    def headers(self):
        return self.__headers

    def reset(self):
        self.header_ok = False
        self.__is_chunked = False
        self.__content_length = 0
        self.__responsed_length = 0
        self.__is_start = False
        self.__cookies = []

    def get_data(self):
        data = b"".join(self.__data)
        self.__data = []

        return data

    @property
    def cookies(self):
        return self.__cookies

    @property
    def status(self):
        return self.__status

    def response_ok(self):
        if self.__is_chunked: return self.__chunked.is_ok()
        return self.__responsed_length == self.__content_length and self.__is_start


class http1x_builder(_builder):
    def wrap_header(self, method, host, path, qs_seq, user_agent, headers):
        method = method.upper()

        if not qs_seq:
            uri = path
        else:
            uri = "%s?%s" % (path, httputils.build_qs(qs_seq))

        headers.append(("Host", host))
        headers.append(("User-Agent", user_agent))
        sts = httputils.build_http1x_req_header(method, uri, headers)

        return sts.encode("iso-8859-1")

    def wrap_body(self, byte_data):
        return byte_data


class http1x_parser(_parser):
    def unwrap_header(self):
        size = self.reader.size()
        rdata = self.reader.read()

        p = rdata.find(b"\r\n\r\n")

        if p > 0 and p < 10: raise HttpErr("wrong http1x response header")
        if p < 0 and size > 8192: raise HttpErr("the http1x response header too long")

        if p < 0: return
        p += 4
        header_data = rdata[0:p]
        body_data = rdata[p:]

        sts = header_data.decode("iso-8859-1")

        try:
            resp, fields = httputils.parse_http1x_response_header(sts)
        except httputils.Http1xHeaderErr:
            raise HttpErr("wrong http response header")

        _, status = resp

        self.set_status(int(status[0:3]))
        self.set_headers(fields)

        self.reader._putvalue(body_data)
        self.header_ok = True

    def unwrap_body(self, body_data):
        return body_data


class http2x_parser(_parser):
    pass


class http2x_builder(_builder):
    pass


class client(object):
    __method = None
    __host = None
    __path = None
    __qs_seq = None

    # 是否已经发送过头部数据
    __is_sent_header = False

    __sent_body_ok = None

    timeout = 10
    headers = None

    __ssl_on = None

    __parser = None
    __builder = None

    __socket = None
    __is_ipv6 = None
    __connect_ok = False

    __is_error = False
    # 故障码ƒ
    __errcode = -1

    __reader = None
    __writer = None

    __connect_ok = None
    __port = None

    __request_ok = None

    __response_header_ok = None

    # 需要发送的内容长度
    __send_length = 0
    # 已经发送的内容长度
    __sent_length = 0

    __is_http2 = None

    __tls_ctx = None
    __alpn_on = None

    __write_ok = None

    __ssl_ok = None
    __is_closed = None
    __request_headers = None
    __sent = None

    def __init__(self, host, ssl_on=False, is_ipv6=False):
        self.__sent_ok = False
        self.headers = []
        self.__is_ipv6 = is_ipv6
        self.__reader = reader.reader()
        self.__writer = writer.writer()
        self.__connect_ok = False
        self.__request_ok = False
        self.__is_http2 = False
        self.__alpn_on = False
        self.__write_ok = False
        self.__ssl_ok = False
        self.__ssl_on = ssl_on
        self.__host = host
        self.__is_closed = False

    def request(self, method, path="/", qs_seq=None, port=None, headers=None):
        if self.__is_closed: raise HttpErr("request has been closed")
        self.__sent = []

        if self.__parser: self.__parser.reset()
        if self.__builder: self.__builder.reset()

        if self.__ssl_on and not port:
            port = 443
        if not self.__ssl_on and not port:
            port = 80

        self.__port = port
        self.__method = method
        self.__path = path
        self.__qs_seq = qs_seq
        self.__is_sent_header = False
        self.__sent_body_ok = False

        if not headers:
            self.__request_headers = []
        else:
            self.__request_headers = headers

        if not self.__socket:
            if self.__is_ipv6:
                af = socket.AF_INET6
            else:
                af = socket.AF_INET
            self.__socket = socket.socket(af, socket.SOCK_STREAM)
        return

    def __connect(self):
        err = self.__socket.connect_ex((self.__host, self.__port))
        if not err:
            self.__connect_ok = True
            if self.__ssl_on:
                self.__tls_ctx = ssl._create_unverified_context()

                ssl_verinfo = ssl.OPENSSL_VERSION_INFO
                # 只有openssl 1.0.2版本及其以上才支持ALPN
                if ssl_verinfo[0] >= 1 and ssl_verinfo[1] >= 0 and ssl_verinfo[2] >= 2:
                    self.__alpn_on = True

                if self.__alpn_on:
                    alpn_protocols = ["http/1.1"]
                    self.__tls_ctx.set_alpn_protocols(alpn_protocols)
                self.__socket = self.__tls_ctx.wrap_socket(self.__socket)
            self.__socket.setblocking(0)
        return

    def __write(self):
        size = self.__writer.size()
        data = self.__writer._getvalue()

        try:
            sent_size = self.__socket.send(data)
        except BlockingIOError:
            self.__write_ok = False
            self.__writer.write(data)
        except ssl.SSLWantWriteError:
            return

        except (ConnectionError, ssl.SSLEOFError):
            raise HttpErr("the connection has been closed")

        if size == sent_size:
            self.__write_ok = True
            return

        bdata = data[sent_size:]

        self.__writer.write(bdata)
        self.__write_ok = False

    def __read(self):
        while 1:
            try:
                rdata = self.__socket.recv(4096)
            except BlockingIOError:
                break
            except ssl.SSLWantReadError:
                break
            if self.__ssl_on and not self.__ssl_ok:
                if self.__alpn_on:
                    protocol = self.__socket.selected_alpn_protocol()
                    if protocol == "h2": self.__is_http2 = True
                self.__ssl_ok = True

            if rdata:
                # if not self.__fd: self.__fd = open("test.txt", "wb")
                # self.__fd.write(rdata)
                self.__reader._putvalue(rdata)
            else:
                raise HttpErr("the connection has been closed")
        return

    def __send_header(self):
        if not self.__ssl_on or not self.__is_http2:
            self.__builder = http1x_builder()
        if self.__is_http2:
            self.__builder = http2x_builder()

        self.__builder.set_headers(self.__request_headers)
        hdr_data = self.__builder.get_header_data(
            self.__method, self.__host, self.__path, self.__qs_seq
        )
        self.__is_sent_header = True
        self.__writer.write(hdr_data)
        self.__write()

    def __handle_resp_header(self):
        if not self.__ssl_on or not self.__is_http2:
            if not self.__parser: self.__parser = http1x_parser()
        if self.__is_http2 and not self.__parser:
            self.__parser = http2x_parser()

        self.__read()
        rdata = self.__reader.read()
        self.__parser.parse(rdata)

        if self.__parser.header_ok:
            self.__response_header_ok = True

    def __handle_resp_body(self):
        self.__read()
        self.__parser.parse(self.__reader.read())

    @property
    def cookies(self):
        return self.__parser.cookies

    @property
    def status(self):
        return self.__parser.status

    def close(self):
        if self.__socket:
            self.__socket.close()
            self.__is_closed = True
        return

    def is_error(self):
        return self.__is_error

    def response_ok(self):
        if not self.__parser: return False
        return self.__parser.response_ok()

    def get_data(self):
        return self.__parser.get_data()

    @property
    def err_code(self):
        return self.__errcode

    def handle(self):
        if not self.__connect_ok:
            self.__connect()
            return

        if not self.__is_sent_header:
            self.__send_header()
            return

        if not self.__write_ok:
            self.__write()
            return

        if not self.__response_header_ok:
            self.__handle_resp_header()
            return
        self.__handle_resp_body()
        return

    def send_body(self, body_data):
        if not self.__is_sent_header:
            self.__send_header()
        self.__write_ok = False
        self.__sent.append(body_data)


"""
import socket

s = socket.socket()
s.connect(("www.baidu.com", 80))

parser = http1x_parser()
builder = http1x_builder()

builder.set_header("User-Agent", "Firefox")

header = builder.get_header_data("GET", "www.baidu.com")

s.send(header)
data = s.recv(4096)
parser.parse(data)

print(parser.headers)
print(parser.get_data())

s.close()
"""
"""
hc = client()
hc.request("GET", "tieba.baidu.com")

while 1:
    hc.handle()
    if hc.response_ok():
        break
hc.close()
fd = open("test.txt", "wb")
fd.write(hc.get_data())
fd.close()
"""
