#!/usr/bin/env python3
import os
import socket
import pywind.evtframework.handlers.udp_handler as udp_handler

import ixc_proxy.lib.n2n as n2n


class n2n_raw(udp_handler.udp_handler):
    """接收未处理过的UDP数据包
    """
    __client_addr = None

    def init_func(self, creator_fd, address, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def udp_readable(self, message, address):
        self.__client_addr = address
        self.dispatcher.send_to_wrapper_client(self.fileno, message)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def message_from_handler(self, from_fd, data):
        self.sendto(data, self.__client_addr)
        self.add_evt_write(self.fileno)


class n2n_wrapper(udp_handler.udp_handler):
    """接收NAT后的服务器数据包
    """
    __builder = None
    __paser = None
    __client_addr = None

    def init_func(self, creator_fd, address, is_ipv6=False):
        self.__builder = n2n.builder()
        self.__paser = n2n.parser()

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def send_data(self, message: bytes):
        if not self.__client_addr: return
        self.sendto(message, self.__client_addr)
        self.add_evt_write(self.fileno)

    def handle_ping(self):
        byte_data = self.__builder.build(n2n.TYPE_PONG, os.urandom(32))
        self.send_data(byte_data)

    def udp_readable(self, message, address):
        rs = self.__paser.parse(message)
        if not rs: return
        _type, msg = rs

        if _type not in n2n.TYPES: return
        self.__client_addr = address

        if _type == n2n.TYPE_PING:
            self.handle_ping()
            return

        if _type == n2n.TYPE_DATA:
            self.dispatcher.send_to_raw_client(self.fileno, msg)
            return
        # 忽略PONG帧

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def send_ping(self):
        wrap_data = self.__builder.build(n2n.TYPE_PING, os.urandom(32))
        self.send_data(wrap_data)

    def message_from_handler(self, from_fd, data):
        """处理来自UDP RAW的数据
        :param from_fd:
        :param data:
        :return:
        """
        wrap_data = self.__builder.build(n2n.TYPE_DATA, data)
        self.send_data(wrap_data)

    def udp_timeout(self):
        self.send_ping()
        self.set_timeout(self.fileno, 10)
