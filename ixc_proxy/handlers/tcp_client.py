#!/usr/bin/env python3
"""实现一个TCP客户端
"""
import socket
import pywind.evtframework.handlers.tcp_handler as tcp_handler


class tcp_client(tcp_handler.tcp_handler):
    __sent_buf = None
    __conn_id = None

    def init_func(self, creator_fd, user_id: bytes, conn_id: bytes, server_address: tuple, is_ipv6=False):
        """
        """
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        self.__user_id = user_id
        self.__conn_id = conn_id

        s = socket.socket(fa, socket.SOCK_STREAM)
        self.set_socket(s)
        self.connect(server_address)
        self.__sent_buf = []

        return self.fileno

    def connect_ok(self):
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        while 1:
            try:
                self.send_msg(self.__sent_buf.pop(0))
            except IndexError:
                break
            ''''''
        return

    def send_msg(self, msg: bytes):
        if not self.is_conn_ok():
            self.__sent_buf.append(msg)
            return

        self.add_evt_write(self.fileno)
        self.writer.write(msg)

    def tcp_readable(self):
        pass

    def tcp_writable(self):
        if self.writer.size() == 0: return

    def tcp_timeout(self):
        if not self.is_conn_ok():
            return

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def is_tcp(self):
        return False

    def is_tunnel_handler(self):
        return False
