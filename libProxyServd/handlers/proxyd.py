#!/usr/bin/env python3

import socket, time, hashlib

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.httputils as httputils
import pywind.web.lib.websocket as wslib

import libProxyServd.protocol as protocol


class listener(tcp_handler.tcp_handler):
    def init_func(self, creator, address, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(address)
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_accept(self):
        while 1:
            try:
                cs, address = self.accept()
                self.create_handler(self.fileno, cs, address)
            except BlockingIOError:
                break
            ''''''
        return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class proxy_handler(tcp_handler.tcp_handler):
    __address = None

    __update_time = 0
    __conn_timeout = 0

    __LOOP_TIMEOUT = 5

    __session_id = None

    __over_http = None
    __http_handshake_ok = None
    __http_auth_id = None
    __http_ws_key = None

    __builder = None
    __parser = None

    def init_func(self, creator, cs, caddr):
        self.__address = caddr
        self.__update_time = time.time()
        self.__session_id = None

        self.__http_handshake_ok = False

        self.__builder = protocol.builder()
        self.__parser = protocol.parser()

        self.set_socket(cs)
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_readable(self):
        if not self.__http_handshake_ok:
            self.do_http_handshake()
            return
        rdata = self.reader.read()
        while 1:
            try:
                self.__parser.parse(rdata)
            except protocol.ProtocolErr:
                self.delete_handler(self.fileno)
                break
            result = self.__parser.get_result()
            if not result: break

    def tcp_writable(self):
        if self.writer.size() == 0: self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        t = time.time()

        if t - self.__update_time > self.__conn_timeout:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def send_msg(self, session_id, address, action, message):
        # 检查session_id是否一致
        if session_id != self.__session_id: return
        if not self.__http_handshake_ok: return
        self.add_evt_write(self.fileno)

    def do_http_handshake(self):
        size = self.reader.size()
        data = self.reader.read()

        p = data.find(b"\r\n\r\n")

        if p < 10 and size > 2048:
            self.delete_handler(self.fileno)
            return

        if p < 0:
            self.reader._putvalue(data)
            return
        p += 4

        self.reader._putvalue(data[p:])

        s = data[0:p].decode("iso-8859-1")

        try:
            request, kv_pairs = httputils.parse_htt1x_request_header(s)
        except httputils.Http1xHeaderErr:
            self.delete_handler(self.fileno)
            return

        method, url, version = request
        upgrade = self.get_http_kv_value("upgrade", kv_pairs)
        origin = self.get_http_kv_value("origin", kv_pairs)

        if upgrade != "websocket" and method != "GET":
            self.response_http_error("400 Bad Request")
            return

        if not origin:
            self.response_http_error("403 Forbidden")
            return

        self.__http_ws_key = self.get_http_kv_value("sec-websocket-key", kv_pairs)
        if not self.__http_ws_key:
            self.response_http_error("400 Bad Request")
            return

        self.__http_handshake_ok = True
        self.response_http_ok()

    def response_http(self, status):
        headers = [("Content-Length", 0,)]

        if status[0:3] == "101":
            headers += [("Connection", "Upgrade",), ("Upgrade", "websocket",)]
            headers += [("Sec-WebSocket-Accept", wslib.gen_handshake_key(self.__http_ws_key))]
            headers += [("Sec-WebSocket-Protocol", "chat")]
            headers += [("X-Auth-Id", hashlib.sha256(self.__http_auth_id.encode()).hexdigest())]
        s = httputils.build_http1x_resp_header(status, headers)

        self.add_evt_write(self.fileno)
        self.writer.write(s.encode("iso-8859-1"))

    def response_http_error(self, status):
        self.response_http(status)
        self.delete_this_no_sent_data()

    def response_http_ok(self):
        self.response_http("101 Switching Protocols")

    def get_http_kv_value(self, name, kv_pairs):
        for k, v in kv_pairs:
            if name.lower() == k.lower():
                return v
            ''''''
        return None

    @property
    def session_id(self):
        return self.__session_id
