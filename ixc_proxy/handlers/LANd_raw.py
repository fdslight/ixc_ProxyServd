#!/usr/bin/env python3

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import time, socket
import ixc_proxy.lib.logging as logging


class client(tcp_handler.tcp_handler):
    __creator = None
    __session_id = None
    __auth_id = None
    __wait_sent = None
    __time = None
    __address = None

    def init_func(self, creator_fd, address, is_ipv6=False):
        self.__creator = creator_fd
        self.__wait_sent = []
        self.__time = time.time()
        self.__address = address

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.set_socket(s)
        self.connect(address)

        return self.fileno

    def connect_ok(self):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)
        self.tcp_loop_read_num = 5

        while 1:
            try:
                self.writer.write(self.__wait_sent.pop(0))
            except IndexError:
                break
            ''''''
        self.add_evt_write(self.fileno)

    def tcp_readable(self):
        self.__time = time.time()
        rdata = self.reader.read()
        self.send_message_to_handler(self.fileno, self.__creator, rdata)

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        if not self.is_conn_ok():
            self.get_handler(self.__creator).tell_forwarding_close()
            return

        t = time.time()
        # 限制300s没数据那么就关闭连接
        if t - self.__time > 300:
            self.get_handler(self.__creator).tell_forwarding_close()
            return
        self.set_timeout(self.fileno, 10)

    def tcp_error(self):
        logging.print_general("local server close connection", self.__address)
        self.get_handler(self.__creator).tell_forwarding_close()

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def send_data(self, byte_data):
        if not self.is_conn_ok():
            self.__wait_sent.append(byte_data)
            return

        self.__time = time.time()
        self.writer.write(byte_data)
        self.add_evt_write(self.fileno)
        self.send_now()

    def message_from_handler(self, from_fd, byte_data):
        self.send_data(byte_data)
