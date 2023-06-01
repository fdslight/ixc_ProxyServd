#!/usr/bin/env python3
import time, socket

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import pywind.web.lib.httputils as httputils

import ixc_proxy.lib.logging as logging

TIMEOUT = 75


class tcp_listener(tcp_handler.tcp_handler):
    __redirect_is_ipv6 = None
    __redirect_address = None

    def init_func(self, creator_fd, address, redirect_address, listen_is_ipv6=False, redirect_is_ipv6=False):
        if listen_is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if listen_is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.__redirect_is_ipv6 = redirect_is_ipv6
        self.__redirect_address = redirect_address

        self.set_socket(s)
        self.bind(address)
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
            self.create_handler(self.fileno, redirect_tcp_handler, cs, caddr, self.__redirect_address,
                                is_ipv6=self.__redirect_is_ipv6)


class redirect_tcp_handler(tcp_handler.tcp_handler):
    __caddr = None
    __redirect_fd = None

    __time = None
    __traffic_size = None
    __http_handshake_ok = None

    def init_func(self, creator_fd, cs, caddr, redirect_addr, is_ipv6=False):
        self.__http_handshake_ok = False

        self.__time = time.time()
        self.__traffic_size = 0

        self.set_socket(cs)
        self.__caddr = caddr
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)
        cs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        self.__redirect_fd = self.create_handler(self.fileno, redirect_tcp_client, redirect_addr, is_ipv6=is_ipv6)
        logging.print_general("connected_from", (caddr[0], caddr[1],))

        return self.fileno

    def do_http_handshake(self):
        size = self.reader.size()
        rdata = self.reader.read()
        p = rdata.find(b"\r\n\r\n")
        # 限制请求头部长度
        if p < 0 and size > 4096:
            self.delete_handler(self.fileno)
            return
        if p < 0: return
        if p == 0:
            self.delete_handler(self.fileno)
            return
        p += 4
        self.reader._putvalue(rdata[p:])
        s = httputils.build_http1x_resp_header(
            "200 OK"
        )
        self.writer.write(s.encode())
        self.add_evt_write(self.fileno)
        self.__http_handshake_ok = False

    def tcp_readable(self):
        self.__time = time.time()
        if not self.dispatcher.have_traffic():
            self.delete_handler(self.fileno)
            return
        self.__traffic_size += self.reader.size()
        self.dispatcher.traffic_statistics(self.reader.size())

        if self.dispatcher.enable_listen_over_http:
            if not self.__http_handshake_ok:
                self.do_http_handshake()
            if not self.__http_handshake_ok: return

        self.send_message_to_handler(self.fileno, self.__redirect_fd, self.reader.read())

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        logging.print_general("disconnect traffic_size:%s from" % str(self.__traffic_size),
                              (self.__caddr[0], self.__caddr[1],))
        self.delete_handler(self.__redirect_fd)
        self.unregister(self.fileno)
        self.close()

    def tcp_timeout(self):
        t = time.time()
        if t - self.__time > TIMEOUT:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, 10)

    def message_from_handler(self, from_fd, byte_data):
        if not self.dispatcher.have_traffic():
            self.delete_handler(self.fileno)
            return
        size = len(byte_data)
        self.__traffic_size += size
        self.dispatcher.traffic_statistics(size)
        self.writer.write(byte_data)
        self.add_evt_write(self.fileno)

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd == "conn_err":
            self.delete_handler(self.fileno)
            return


class redirect_tcp_client(tcp_handler.tcp_handler):
    __creator = None
    __sent = None

    def init_func(self, creator_fd, address, is_ipv6=False):
        self.__creator = creator_fd
        self.__sent = []

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        while 1:
            try:
                self.writer.write(self.__sent.pop(0))
            except IndexError:
                break
            ''''''
        self.add_evt_write(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.ctl_handler(self.fileno, self.__creator, "conn_err")
            return

    def tcp_error(self):
        self.ctl_handler(self.fileno, self.__creator, "conn_err")

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def tcp_readable(self):
        self.send_message_to_handler(self.fileno, self.__creator, self.reader.read())

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def message_from_handler(self, from_fd, byte_data):
        if not self.is_conn_ok():
            self.__sent.append(byte_data)
            return

        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)


class udp_listener(udp_handler.udp_handler):
    __redirect_is_ipv6 = None
    __redirect_address = None

    __session_fds = None
    __session_fds_reverse = None

    def init_func(self, creator_fd, address, redirect_address, listen_is_ipv6=False, redirect_is_ipv6=False):
        self.__session_fds = {}
        self.__session_fds_reverse = {}

        if listen_is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if listen_is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.__redirect_is_ipv6 = redirect_is_ipv6
        self.__redirect_address = redirect_address

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        name = "%s-%s" % address
        if name in self.__session_fds_reverse:
            fd = self.__session_fds_reverse[name]
            self.send_message_to_handler(self.fileno, fd, message)
            return

        fd = self.create_handler(self.fileno, redirect_udp_client, self.__redirect_address,
                                 is_ipv6=self.__redirect_is_ipv6)
        self.__session_fds[fd] = address
        self.__session_fds_reverse[name] = fd
        self.send_message_to_handler(self.fileno, fd, message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def handler_ctl(self, from_fd, cmd, *args, **kwargs):
        if cmd == "conn_err":
            addr, port = self.__session_fds[from_fd]
            name = "%s-%s" % (addr, port,)
            del self.__session_fds[from_fd]
            del self.__session_fds_reverse[name]
        return

    def message_from_handler(self, from_fd, data):
        # 找不到直接丢弃数据包
        if from_fd not in self.__session_fds: return

        addr, port = self.__session_fds[from_fd]
        self.sendto(data, (addr, port,))
        self.add_evt_write(self.fileno)


class redirect_udp_client(udp_handler.udp_handler):
    __creator = None
    __time = None

    def init_func(self, creator_fd, address, is_ipv6=False):
        self.__creator = creator_fd
        self.__time = time.time()

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.set_socket(s)
        self.connect(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def udp_readable(self, message, address):
        self.__time = time.time()
        self.send_message_to_handler(self.fileno, self.__creator, message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.handler_ctl(self.fileno, "conn_err")

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def udp_timeout(self):
        t = time.time()

        if t - self.__time > TIMEOUT:
            self.handler_ctl(self.fileno, "conn_err")
        return

    def message_from_handler(self, from_fd, data):
        self.send(data)
        self.add_evt_write(self.fileno)
