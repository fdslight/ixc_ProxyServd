#!/usr/bin/env python3
import base64
import socket, time, hashlib, zlib

import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.httputils as httputils
import pywind.web.lib.websocket as wslib

import ixc_proxy.lib.base_proto.utils as proto_utils
import ixc_proxy.lib.logging as logging
import ixc_proxy.lib.base_proto.tunnel_tcp as tunnel_tcp


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
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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
    # 是否在请求头部设置了session id
    __isset_http_session_id = None

    # 是否开启zlib支持,根据客户端请求,如果客户端有发送zlib数据包,那么说明支持
    __enable_zlib = None

    def init_func(self, creator, crypto, crypto_configs, cs, address, conn_timeout, over_http=False):
        cs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        http_configs = self.dispatcher.http_configs

        self.__address = address
        self.__conn_timeout = conn_timeout
        self.__update_time = time.time()
        self.__session_id = None

        self.__http_handshake_ok = False
        self.__over_http = over_http
        self.__http_auth_id = http_configs["auth_id"]
        self.__isset_http_session_id = False

        self.__enable_zlib = False

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

    @property
    def access(self):
        return self.dispatcher.access

    def tcp_readable(self):
        if self.__over_http and not self.__http_handshake_ok:
            self.do_http_handshake()
            return

        rdata = self.reader.read()
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

                if self.__isset_http_session_id:
                    action, message = pkt_info
                    session_id = self.__session_id
                else:
                    session_id, action, message = pkt_info

                if action not in proto_utils.ACTS: continue

                if self.__session_id and self.__session_id != session_id:
                    self.delete_handler(self.fileno)
                    return

                if not self.access.user_exists(session_id):
                    self.delete_handler(self.fileno)
                    return

                self.__session_id = session_id

                if action == proto_utils.ACT_PONG: continue
                if action == proto_utils.ACT_PING:
                    self.send_msg(session_id, self.__address, proto_utils.ACT_PONG, proto_utils.rand_bytes())
                    continue

                # 如果是zlib报文那么首先解压
                if action in (proto_utils.ACT_ZLIB_IPDATA, proto_utils.ACT_ZLIB_DNS,):
                    self.__enable_zlib = True
                    try:
                        message = zlib.decompress(message)
                    except zlib.error:
                        self.delete_handler(self.fileno)
                        return

                    if action == proto_utils.ACT_ZLIB_IPDATA:
                        action = proto_utils.ACT_IPDATA
                    else:
                        action = proto_utils.ACT_DNS

                self.dispatcher.handle_msg_from_tunnel(self.fileno, session_id, self.__address, action, message)
            ''''''
        ''''''

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
        if not self.__session_id: return
        # 检查session_id是否一致
        if session_id != self.__session_id: return
        # 如果流量加载在HTTP协议上并且没有握手成功那么丢弃数据包
        if self.__over_http and not self.__http_handshake_ok: return

        if self.__enable_zlib:
            if action in (proto_utils.ACT_IPDATA, proto_utils.ACT_DNS,):
                length = len(message)
                new_msg = zlib.compress(message)
                comp_length = len(new_msg)
                if comp_length < length:
                    if action == proto_utils.ACT_DNS:
                        action = proto_utils.ACT_ZLIB_DNS
                    else:
                        action = proto_utils.ACT_ZLIB_IPDATA
                    message = new_msg
                ''''''
            ''''''
        if self.__isset_http_session_id:
            sent_pkt = self.__encrypt.build_packet(action, message)
        else:
            sent_pkt = self.__encrypt.build_packet(session_id, action, message)

        self.__update_time = time.time()
        self.writer.write(sent_pkt)
        self.add_evt_write(self.fileno)
        self.__encrypt.reset()
        self.send_now()

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

        real_ip_keys = (
            "x-real-ip", "x-forwarded-for",
        )
        for name in real_ip_keys:
            real_ip = self.get_http_kv_value(name, kv_pairs)
            if real_ip: break

        if real_ip: logging.print_general("http_request_from:%s" % real_ip, self.__address)

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

        session_id = self.get_http_kv_value("x-user-session-id", kv_pairs)
        if session_id:
            try:
                byte_session_id = base64.b16decode(session_id)
            except:
                logging.print_general("wrong web request header session id value %s" % session_id, self.__address)
                self.response_http_error("400 Bad Request")
                return
            if len(byte_session_id) != 16:
                logging.print_general("wrong web request header session id value length %s" % session_id,
                                      self.__address)
                self.response_http_error("400 Bad Request")
                return

            if not self.access.user_exists(session_id):
                self.response_http_error("403 Forbidden")
                return

            logging.print_general("use_http_ext_session_id", self.__address)

            self.__session_id = byte_session_id
            self.__isset_http_session_id = True

            # 当session id出现在HTTP头部时,使用精简协议
            self.__encrypt = tunnel_tcp.over_http_builder()
            self.__decrypt = tunnel_tcp.over_http_parser()
        else:
            self.__isset_http_session_id = False

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

    def is_tunnel_handler(self):
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
        # 对发送过来的数据包进行解压
        if action in (proto_utils.ACT_ZLIB_IPDATA, proto_utils.ACT_ZLIB_DNS,):
            try:
                byte_data = zlib.decompress(byte_data)
            except zlib.error:
                return
            if action == proto_utils.ACT_ZLIB_IPDATA:
                action = proto_utils.ACT_IPDATA
            else:
                action = proto_utils.ACT_DNS
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
        # 尝试压缩数据,查看数据能否被压缩,如果被压缩那么使用压缩后的数据
        if action == proto_utils.ACT_DNS or action == proto_utils.ACT_IPDATA:
            length = len(message)
            new_msg = zlib.compress(message)
            comp_length = len(new_msg)
            if comp_length < length:
                if action == proto_utils.ACT_DNS:
                    action = proto_utils.ACT_ZLIB_DNS
                else:
                    action = proto_utils.ACT_ZLIB_IPDATA
                message = new_msg
            ''''''
        ippkts = self.__encrypt.build_packets(session_id, action, message)
        self.__encrypt.reset()

        for ippkt in ippkts: self.sendto(ippkt, address)

        self.add_evt_write(self.fileno)
        self.send_now()

    def is_tcp(self):
        return False

    def is_tunnel_handler(self):
        return True
