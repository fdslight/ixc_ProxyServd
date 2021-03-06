#!/usr/bin/env python3

"""用来管理局域网的机器
"""

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import socket, time

import ixc_proxy.lib.wol as wol


class listener(tcp_handler.tcp_handler):
    __key = None

    __wol_bind_ip = None

    def init_func(self, creator_fd, address, wol_bind_ip, key, is_ipv6=False):
        self.__key = key
        self.__wol_bind_ip = wol_bind_ip

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
                cs, caddr = self.accept()
            except BlockingIOError:
                break
            self.create_handler(self.fileno, handler, cs, caddr, self.__wol_bind_ip, self.__key)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class handler(tcp_handler.tcp_handler):
    __caddr = None
    __builder = None
    __parser = None
    __time = None
    __key = None

    __bind_ip = None

    def init_func(self, creator_fd, cs, caddr, wol_bind_ip, key):
        self.__key = key
        self.__bind_ip = wol_bind_ip
        self.__caddr = caddr
        self.__builder = wol.builder()
        self.__parser = wol.parser()
        self.__time = time.time()

        cs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.set_socket(cs)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def wake_up(self, key, seq):
        if key != self.__key:
            is_error = 1
        else:
            is_error = 0

        if not is_error:
            cls = wol.wake_on_lan(bind_ip=self.__bind_ip)
            for hwaddr in seq: cls.wake(hwaddr)
            cls.release()

        data = self.__builder.build_response(is_error=is_error)
        self.writer.write(data)
        self.add_evt_write(self.fileno)

    def tcp_readable(self):
        rdata = self.reader.read()
        self.__parser.input(rdata)

        while 1:
            try:
                self.__parser.parse()
            except wol.WOLProtoErr:
                self.delete_handler(self.fileno)
                break
            rs = self.__parser.get_result()
            if not rs: break
            _t, o = rs
            if _t == wol.TYPE_WAKEUP_REQ:
                self.__time = time.time()
                self.wake_up(*o)

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        t = time.time()
        if t - self.__time > 30:
            self.delete_handler(self.fileno)
            return
        self.set_timeout(self.fileno, 10)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()
