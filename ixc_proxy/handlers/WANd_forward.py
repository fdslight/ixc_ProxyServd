#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.web.lib.websocket as ws
import pywind.web.lib.httputils as httputils
import socket, time, random, os, sys
import ixc_proxy.lib.logging as logging
import ixc_proxy.lib.intranet_pass as intranet_pass

import base64


class listener(tcp_handler.tcp_handler):
    __address = None

    def init_func(self, creator_fd, address):
        if os.path.isfile(address):
            sys.stderr.write("the %s is exists\r\n" % address)
            return -1

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        self.set_socket(s)
        self.bind(address)
        os.chmod(address, 0o777)
        self.listen(10)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def tcp_accept(self):
        while 1:
            try:
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, handler, cs, caddr)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class handler(tcp_handler.tcp_handler):
    # 是否已经成功握手
    __handshake_ok = None
    __caddr = None
    __parser = None
    __builder = None

    __time = None
    __auth_id = None

    __is_msg_tunnel = None
    __session_id = None

    __wait_sent = None

    def init_func(self, creator_fd, cs, caddr):
        self.__is_msg_tunnel = False
        self.__handshake_ok = False

        self.__caddr = ("UNIX_SOCKET", 0)

        self.__parser = intranet_pass.parser()
        self.__builder = intranet_pass.builder()

        self.__wait_sent = []

        self.__time = time.time()

        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        logging.print_general("connect_ok", self.__caddr)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def do_handshake(self):
        size = self.reader.size()
        rdata = self.reader.read()
        p = rdata.find(b"\r\n\r\n")

        if p < 5 and size > 2048:
            self.delete_handler(self.fileno)
            return

        s = rdata.decode("iso-8859-1")
        try:
            rq, kv = httputils.parse_htt1x_request_header(s)
        except httputils.Http1xHeaderErr:
            self.delete_handler(self.fileno)
            return

        m, uri, ver = rq

        if ver.lower() != "http/1.1":
            self.delete_handler(self.fileno)
            return

        if m != "GET":
            self.delete_handler(self.fileno)
            return

        upgrade = self.get_kv_value(kv, "upgrade")
        if not upgrade:
            if self.dispatcher.debug:
                sys.stderr.write("no upgrade field\r\n")
            self.send_403_response()
            return
        if upgrade.lower() != "websocket":
            if self.dispatcher.debug:
                sys.stderr.write("it is not websocket field\r\n")
            self.send_403_response()
            return

        connection = self.get_kv_value(kv, "connection")
        if not connection:
            if self.dispatcher.debug:
                sys.stderr.write("no connection field\r\n")
            self.send_403_response()
            return
        if connection.lower() != "upgrade":
            if self.dispatcher.debug:
                sys.stderr.write("connection is not upgrade\r\n")
            self.send_403_response()
            return

        sec_ws_key = self.get_kv_value(kv, "sec-websocket-key")
        if not sec_ws_key:
            if self.dispatcher.debug:
                sys.stderr.write("no websocket key\r\n")
            self.send_403_response()
            return

        origin = self.get_kv_value(kv, "origin")
        if not origin:
            if self.dispatcher.debug:
                sys.stderr.write("no origin key\r\n")
            self.send_403_response()
            return
        ws_ver = self.get_kv_value(kv, "sec-websocket-version")

        try:
            v = int(ws_ver)
        except ValueError:
            self.send_403_response()
            return

        if v != 13:
            if self.dispatcher.debug:
                sys.stderr.write("wrong websocket version\r\n")
            self.send_403_response()
            return

        sec_ws_proto = self.get_kv_value(kv, "sec-websocket-protocol")
        if not sec_ws_proto:
            if self.dispatcher.debug:
                sys.stderr.write("no sec-websocket-protocol\r\n")
            self.send_403_response()
            return

        auth_id = self.get_kv_value(kv, "x-auth-id")
        if not auth_id:
            if self.dispatcher.debug:
                sys.stderr.write("no auth-id field\r\n")
            self.send_403_response()
            return

        is_msg_tunnel = self.get_kv_value(kv, "x-msg-tunnel")
        if not is_msg_tunnel:
            sys.stderr.write("not found X-Msg-Tunnel value\r\n")
            self.send_403_response()
            return

        if not self.dispatcher.auth_id_exists(auth_id):
            if self.dispatcher.debug:
                sys.stderr.write("not found %s service\r\n" % auth_id)
            self.send_403_response()
            return

        if self.dispatcher.auth_id_exists(auth_id) and not is_msg_tunnel:
            self.send_403_response()
            return

        try:
            v = bool(int(is_msg_tunnel))
        except ValueError:
            sys.stderr.write("wrong X-Msg-Tunnel value type\r\n")
            self.send_403_response()
            return

        self.__is_msg_tunnel = v
        if v:
            s = self.get_kv_value(kv, "x-session-id")
            self.__session_id = base64.b64decode(s.encode())
            if not self.dispatcher.session_get(self.__session_id):
                sys.stderr.write("session id not exists\r\n")
                self.send_403_response()
                return
        else:
            self.dispatcher.reg_fwd_conn(auth_id, self.fileno)

        resp_headers = [
            ("Content-Length", "0"),
        ]

        resp_headers += [("Connection", "Upgrade",), ("Upgrade", "websocket",)]
        resp_headers += [("Sec-WebSocket-Accept", ws.gen_handshake_key(sec_ws_key))]
        resp_headers += [("Sec-WebSocket-Protocol", "intranet_pass")]

        logging.print_general("handshake_ok", self.__caddr)

        self.__handshake_ok = True
        self.__auth_id = auth_id
        self.send_response("101 Switching Protocols", resp_headers)
        self.tcp_loop_read_num = 10

        if not v: return

        # 注意这里如果是消息隧道一定要等待握手协议发送完毕再告知连接成功,连接成功会发送堆积在服务器上的数据
        self.dispatcher.tell_listener_conn_ok(self.__session_id, self.fileno)

    def send_response(self, status, headers):
        s = httputils.build_http1x_resp_header(status, headers)
        byte_data = s.encode("iso-8859-1")

        self.writer.write(byte_data)
        self.add_evt_write(self.fileno)

    def send_403_response(self):
        self.send_response("403 Forbidden", [("Content-Length", 0,)])
        self.delete_this_no_sent_data()

    def get_kv_value(self, kv_pairs, name):
        for k, v in kv_pairs:
            if name.lower() == k.lower():
                return v
            ''''''
        return None

    def handle_ping(self):
        n = random.randint(1, 100)
        pong = self.__builder.build_pong(length=n)
        self.send_data(pong)

    def handle_pong(self):
        self.__time = time.time()

    def send_ping(self):
        n = random.randint(1, 100)
        ping = self.__builder.build_ping(length=n)
        self.send_data(ping)

    def handle_data(self):
        rdata = self.reader.read()
        self.__time = time.time()

        if self.__is_msg_tunnel:
            fd, _ = self.dispatcher.session_get(self.__session_id)
            if not fd:
                sys.stderr.write("session id not exists\r\n")
                self.delete_handler(self.fileno)
                return
            self.send_message_to_handler(self.fileno, fd, rdata)
            return

        self.__parser.input(rdata)

        while 1:
            try:
                self.__parser.parse()
            except intranet_pass.ProtoErr:
                if self.dispatcher.debug:
                    logging.print_error()
                self.delete_handler(self.fileno)
                return

            rs = self.__parser.get_result()
            if not rs: break
            _type, o = rs

            if _type == intranet_pass.TYPE_PING:
                self.handle_ping()
                continue
            if _type == intranet_pass.TYPE_PONG:
                self.handle_pong()
                continue
            ''''''

    def send_data(self, byte_data):
        self.__time = time.time()
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)
        self.send_now()

    def rand_bytes(self):
        n = random.randint(0, 128)
        return os.urandom(n)

    def tcp_readable(self):
        if not self.__handshake_ok:
            self.do_handshake()
            return
        self.handle_data()

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_error(self):
        logging.print_general("client_disconnect", self.__caddr)
        if self.__is_msg_tunnel:
            self.dispatcher.tell_session_close(self.__session_id)
            return
        self.delete_handler(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        if t - self.__time > 60:
            if self.__is_msg_tunnel and self.__handshake_ok:
                self.dispatcher.tell_session_close(self.__session_id)
                return
            self.delete_handler(self.fileno)
        if t - self.__time > 20 and not self.__is_msg_tunnel: self.send_ping()
        self.set_timeout(self.fileno, 10)

    def tcp_delete(self):
        logging.print_general("disconnect", self.__caddr)
        if self.__auth_id and not self.__is_msg_tunnel: self.dispatcher.unreg_fwd_conn(self.__auth_id)
        self.unregister(self.fileno)
        self.close()

    def send_conn_request(self, session_id, remote_addr, remote_port, is_ipv6=False):
        byte_data = self.__builder.build_conn_request(session_id, remote_addr, remote_port, is_ipv6=is_ipv6)
        self.send_data(byte_data)

    def message_from_handler(self, from_fd, byte_data):
        self.send_data(byte_data)
