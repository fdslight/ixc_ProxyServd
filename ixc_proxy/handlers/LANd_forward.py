#!/usr/bin/env python3

import pywind.evtframework.handlers.ssl_handler as ssl_handler
import pywind.web.lib.httputils as httputils
import pywind.web.lib.websocket as wslib

import socket, time, random, os, ssl, sys
import ixc_proxy.lib.logging as logging
import ixc_proxy.lib.intranet_pass as intranet_pass
import ixc_proxy.lib.utils as utils
import ixc_proxy.handlers.LANd_raw as fwd

import base64


class client(ssl_handler.ssl_handler):
    """把任意数据包转换成私有协议
    """
    __address = None
    __path = None
    __http_handshake_ok = None
    __http_handshake_key = None
    __parser = None
    __builder = None
    __time = None
    __ssl_ok = None
    __auth_id = None

    __is_msg_tunnel = None
    __session_id = None

    __forwarding_addr = None
    __forwarding_is_ipv6 = None
    __forward_fd = None
    __wait_sent = None

    def ssl_init(self, address, path, auth_id, session_id=None, is_msg_tunnel=False, is_ipv6=False):
        """
        :param address:
        :param path:
        :param auth_id:
        :param session_id:如果指定是隧道消息,那么session_id不能为空
        :param is_msg_tunnel:指定这个消息是否是消息隧道,如果为False,表示这个是连接建立信道
        :param is_ipv6:
        :return:
        """
        self.__address = address
        self.__path = path
        self.__http_handshake_ok = False

        if not is_msg_tunnel:
            self.__parser = intranet_pass.parser()
            self.__builder = intranet_pass.builder()

        self.__time = time.time()
        self.__ssl_ok = False
        self.__auth_id = auth_id
        self.__is_msg_tunnel = is_msg_tunnel
        self.__session_id = session_id

        self.__forward_fd = -1
        self.__wait_sent = []
        self.__forward_conn_ok = False

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.set_alpn_protocols(["http/1.1"])

        kwargs = {}
        kwargs["do_handshake_on_connect"] = False

        # 检查如果为域名则开启SNI
        if not utils.is_ipv6_address(address[0]) or not utils.is_ipv4_address(address[0]):
            kwargs["server_hostname"] = address[0]

        s = context.wrap_socket(s, **kwargs)

        logging.print_general("connecting,%s" % auth_id, self.__address)
        self.set_socket(s)
        try:
            self.connect(address)
        except:
            return -1

        return self.fileno

    def ssl_handshake_ok(self):
        self.__ssl_ok = True
        logging.print_general("TLS handshake OK,%s" % self.__auth_id, self.__address)

        if not self.__is_msg_tunnel:
            self.send_handshake_request()
            return

        logging.print_general("https_handshake_ok,msg_tunnel", self.__address)
        self.__forward_fd = self.create_handler(self.fileno, fwd.client, self.__forwarding_addr,
                                                is_ipv6=self.__forwarding_is_ipv6)
        if self.__forward_fd < 0:
            self.close_conn()
            return

        self.send_handshake_request()

    def connect_ok(self):
        logging.print_general("connect_ok,%s" % self.__auth_id, self.__address)

        if self.__is_msg_tunnel:
            logging.print_general("connect_ok,msg_tunnel,%s" % self.__auth_id, self.__address)

        self.tcp_loop_read_num = 200
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        # 注意这里要加入写事件,让TLS能够握手成功
        self.add_evt_write(self.fileno)
        self.set_timeout(self.fileno, 10)

    def set_forwarding_addr(self, address, is_ipv6=False):
        """设置重定向地址
        :param address:
        :param is_ipv6:
        :return:
        """
        self.__forwarding_addr = address
        self.__forwarding_is_ipv6 = False

    def rand_string(self, length=8):
        seq = []
        for i in range(length):
            n = random.randint(65, 122)
            seq.append(chr(n))

        s = "".join(seq)
        self.__http_handshake_key = s

        return s

    def send_handshake_request(self):
        """发送握手请求
        :param user:
        :param passwd:
        :return:
        """
        kv_pairs = [("Connection", "Upgrade"), ("Upgrade", "websocket",), (
            "User-Agent", "LANd_pass",),
                    ("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"),
                    ("Sec-WebSocket-Version", 13,), ("Sec-WebSocket-Key", self.rand_string(),),
                    ("Sec-WebSocket-Protocol", "intranet_pass",),
                    ("X-Auth-Id", self.__auth_id,)
                    ]

        if self.__is_msg_tunnel:
            kv_pairs.append(("X-Msg-Tunnel", 1,))
            byte_s = base64.b64encode(self.__session_id)
            kv_pairs.append(("X-Session-Id", byte_s.decode(),))
        else:
            kv_pairs.append(("X-Msg-Tunnel", 0,))

        if int(self.__address[1]) == 443:
            host = ("Host", self.__address[0],)
            origin = ("Origin", "https://%s" % self.__address[0])
        else:
            host = ("Host", "%s:%s" % self.__address,)
            origin = ("Origin", "https://%s:%s" % self.__address,)

        kv_pairs.append(host)
        kv_pairs.append(origin)

        s = httputils.build_http1x_req_header("GET", self.__path, kv_pairs)
        self.writer.write(s.encode("iso-8859-1"))
        self.add_evt_write(self.fileno)

    def handle_handshake_response(self):
        """处理握手响应
        :return:
        """
        size = self.reader.size()
        data = self.reader.read()
        p = data.find(b"\r\n\r\n")

        if p < 10 and size > 2048:
            logging.print_general("wrong_http_response_header", self.__address)
            self.close_conn()
            return

        if p < 0:
            self.reader._putvalue(data)
            return
        p += 4

        self.reader._putvalue(data[p:])

        s = data[0:p].decode("iso-8859-1")

        try:
            resp, kv_pairs = httputils.parse_http1x_response_header(s)
        except httputils.Http1xHeaderErr:
            logging.print_general("wrong_http_reponse_header", self.__address)
            self.close_conn()
            return

        version, status = resp

        if status.find("101") != 0:
            logging.print_general("https_handshake_error:%s" % status, self.__address)
            self.close_conn()
            return

        accept_key = self.get_http_kv_pairs("sec-websocket-accept", kv_pairs)
        if wslib.gen_handshake_key(self.__http_handshake_key) != accept_key:
            logging.print_general("https_handshake_error:wrong websocket response key", self.__address)
            self.close_conn()
            return

        self.__http_handshake_ok = True
        logging.print_general("https_handshake_ok", self.__address)

        if not self.__is_msg_tunnel: return
        while 1:
            try:
                data = self.__wait_sent.pop(0)
            except IndexError:
                break
            self.send_data(data)

    def get_http_kv_pairs(self, name, kv_pairs):
        for k, v in kv_pairs:
            if name.lower() == k.lower():
                return v
            ''''''
        return

    def handle_ping(self):
        n = random.randint(0, 128)
        pong = self.__builder.build_pong(length=n)
        self.send_data(pong)

    def handle_pong(self):
        self.__time = time.time()

    def send_ping(self):
        n = random.randint(1, 100)
        ping = self.__builder.build_ping(length=n)
        self.send_data(ping)

    def handle_conn_request(self, session_id, remote_addr, remote_port, is_ipv6):
        self.dispatcher.handle_conn_request(self.__address, self.__path, self.__auth_id, session_id, remote_addr,
                                            remote_port, is_ipv6)

    def handle_conn_close(self, session_id):
        fd = self.dispatcher.session_get(session_id)
        if not fd: return
        logging.print_general("close %s" % self.__auth_id, self.__address)
        self.dispatcher.session_del(session_id)
        self.delete_handler(fd)

    def handle_conn_data(self, session_id, data):
        self.dispatcher.send_conn_data_to_local(session_id, data)

    def tcp_readable(self):
        self.__time = time.time()

        if not self.__http_handshake_ok:
            self.handle_handshake_response()
            return
        rdata = self.reader.read()
        if self.__is_msg_tunnel:
            self.send_message_to_handler(self.fileno, self.__forward_fd, rdata)
            return

        self.__parser.input(rdata)

        while 1:
            try:
                self.__parser.parse()
            except intranet_pass.ProtoErr:
                if self.dispatcher.debug:
                    logging.print_error()
                self.delete_handler(self.fileno)
                break
            rs = self.__parser.get_result()
            if not rs: break
            _type, o = rs
            if _type == intranet_pass.TYPE_PING:
                self.handle_ping()
                continue
            if _type == intranet_pass.TYPE_PONG:
                self.handle_pong()
                continue
            if _type == intranet_pass.TYPE_CONN_REQ:
                self.handle_conn_request(*o)
                continue

    def tcp_writable(self):
        if not self.__ssl_ok: return
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.delete_handler(self.fileno)
            return

        t = time.time()

        if t - self.__time > 60:
            logging.print_general("timeout,%s" % self.__auth_id, self.__address)
            self.delete_handler(self.fileno)
            return

        if t - self.__time > 20 and not self.__is_msg_tunnel: self.send_ping()
        self.set_timeout(self.fileno, 10)

    def tcp_error(self):
        logging.print_general("server_disconnect,%s" % self.__auth_id, self.__address)
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        logging.print_general("disconnect,%s" % self.__auth_id, self.__address)
        self.unregister(self.fileno)
        self.close()

        if not self.__is_msg_tunnel:
            self.dispatcher.delete_fwd_conn(self.__auth_id)
            return

        if self.__forward_fd > 0:
            self.delete_handler(self.__forward_fd)

    def send_data(self, byte_data):
        """发送数据
        :param byte_data:
        :return:
        """
        self.__time = time.time()
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)
        self.send_now()

    def message_from_handler(self, from_fd, byte_data):
        if not self.__http_handshake_ok:
            self.__wait_sent.append(byte_data)
            return

        self.send_data(byte_data)

    def close_conn(self):
        self.delete_handler(self.fileno)

    def tell_forwarding_close(self):
        self.delete_handler(self.fileno)
