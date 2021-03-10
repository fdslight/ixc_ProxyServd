#!/usr/bin/env python3
import socket, time, hashlib

import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.httputils as httputils
import pywind.web.lib.websocket as wslib

import ixc_proxy.lib.base_proto.utils as proto_utils
import ixc_proxy.lib.logging as logging


class tcp_tunnel(tcp_handler.tcp_handler):
    __crypto = None
    __crypto_configs = None
    __conn_timeout = None
    __over_http = None

    def init_func(self, creator, address, crypto, crypto_configs, conn_timeout=800, is_ipv6=False, over_http=False):
        self.__crypto_configs = crypto_configs
        self.__crypto = crypto
        self.__conn_timeout = conn_timeout
        self.__over_http = over_http

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
                self.create_handler(self.fileno, _tcp_tunnel_handler, self.__crypto, self.__crypto_configs, cs, address,
                                    self.__conn_timeout, over_http=self.__over_http)
            except BlockingIOError:
                break
            ''''''
        return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class _tcp_tunnel_handler(tcp_handler.tcp_handler):
    __encrypt = None
    __decrypt = None
    __address = None

    __update_time = 0
    __conn_timeout = 0

    __LOOP_TIMEOUT = 5

    __session_id = None

    __over_http = None
    __http_handshake_ok = None
    __http_auth_id = None
    __http_ws_key = None

    def init_func(self, creator, crypto, crypto_configs, cs, address, conn_timeout, over_http=False):
        http_configs = self.dispatcher.http_configs

        self.__address = address
        self.__conn_timeout = conn_timeout
        self.__update_time = time.time()
        self.__session_id = None

        self.__http_handshake_ok = False
        self.__over_http = over_http
        self.__http_auth_id = http_configs["auth_id"]

        cs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.set_socket(cs)
        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_configs)
        self.__decrypt.config(crypto_configs)

        logging.print_general("tcp_connect", address)

        return self.fileno

    def tcp_readable(self):
        if self.__over_http and not self.__http_handshake_ok:
            self.do_http_handshake()
            return

        rdata = self.reader.read()
        print(dir(self.__decrypt))
        self.__decrypt.input(rdata)

        while self.__decrypt.can_continue_parse():
            try:
                self.__decrypt.parse()
            except proto_utils.ProtoError:
                self.delete_handler(self.fileno)
                return
            while 1:
                pkt_info = self.__decrypt.get_pkt()
                if not pkt_info: break
                session_id, action, message = pkt_info

                if action not in proto_utils.ACTS: continue

                self.__session_id = session_id

                if self.__session_id and self.__session_id != session_id:
                    self.delete_handler(self.fileno)
                    return

                if action == proto_utils.ACT_PONG: continue
                if action == proto_utils.ACT_PING:
                    self.send_msg(session_id, self.__address, proto_utils.ACT_PONG, proto_utils.rand_bytes())
                    continue

                self.__update_time = time.time()
                self.dispatcher.handle_msg_from_tunnel(self.fileno, session_id, self.__address, action, message)

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
        logging.print_general("tcp_disconnect", self.__address)

    def send_msg(self, session_id, address, action, message):
        # 检查session_id是否一致
        if session_id != self.__session_id: return
        # 如果流量加载在HTTP协议上并且没有握手成功那么丢弃数据包
        if self.__over_http and not self.__http_handshake_ok: return

        sent_pkt = self.__encrypt.build_packet(session_id, action, message)
        self.writer.write(sent_pkt)
        self.add_evt_write(self.fileno)
        self.__encrypt.reset()

    def do_http_handshake(self):
        size = self.reader.size()
        data = self.reader.read()

        p = data.find(b"\r\n\r\n")

        if p < 10 and size > 2048:
            logging.print_general("wrong_http_header_length_for_request_header", self.__address)
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
            logging.print_general("wrong_http_request_protocol", self.__address)
            self.delete_handler(self.fileno)
            return

        method, url, version = request
        upgrade = self.get_http_kv_value("upgrade", kv_pairs)
        origin = self.get_http_kv_value("origin", kv_pairs)

        if upgrade != "websocket" and method != "GET":
            logging.print_general("http_handshake_method_fail:upgrade:%s,method:%s" % (upgrade, method,),
                                  self.__address)
            self.response_http_error("400 Bad Request")
            return

        if not origin:
            logging.print_general("http_origin_none", self.__address)
            self.response_http_error("403 Forbidden")
            return

        self.__http_ws_key = self.get_http_kv_value("sec-websocket-key", kv_pairs)
        if not self.__http_ws_key:
            logging.print_general("http_websocket_key_not_found", self.__address)
            self.response_http_error("400 Bad Request")
            return

        self.__http_handshake_ok = True
        logging.print_general("http_handshake_ok", self.__address)
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
        logging.print_general("http_handshake_error:%s" % status, self.__address)
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

    def is_tcp(self):
        return True


class udp_tunnel(udp_handler.udp_handler):
    def init_func(self, creator, address, crypto, crypto_configs, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.__encrypt = crypto.encrypt()
        self.__decrypt = crypto.decrypt()

        self.__encrypt.config(crypto_configs)
        self.__decrypt.config(crypto_configs)

        return self.fileno

    def udp_readable(self, message, address):
        result = self.__decrypt.parse(message)
        if not result: return

        session_id, action, byte_data = result
        if action not in proto_utils.ACTS: return

        # 丢弃PING和PONG的数据包
        if action == proto_utils.ACT_PING:
            self.send_msg(session_id, address, proto_utils.ACT_PONG, proto_utils.rand_bytes())
            return

        if action == proto_utils.ACT_PONG: return

        self.dispatcher.handle_msg_from_tunnel(self.fileno, session_id, address, action, byte_data)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_timeout(self):
        pass

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def send_msg(self, session_id, address, action, message):
        ippkts = self.__encrypt.build_packets(session_id, action, message)
        self.__encrypt.reset()

        for ippkt in ippkts: self.sendto(ippkt, address)

        self.add_evt_write(self.fileno)

    def is_tcp(self):
        return False
