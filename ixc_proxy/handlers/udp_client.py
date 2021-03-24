#!/usr/bin/env python3

import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, time


class client(udp_handler.udp_handler):
    __max_conns = None
    __cur_conns = None
    __map = None
    __my_address = None
    __up_time = None
    __user_id = None

    __is_ipv6 = None

    def init_func(self, creator_fd, user_id: bytes, address: tuple, is_ipv6=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        s = socket.socket(fa, socket.SOCK_DGRAM)

        if is_ipv6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            bind_addr = ("::", 0)
        else:
            bind_addr = ("0.0.0.0", 0)

        self.__max_conns = 32
        self.__cur_conns = 0
        self.__map = {}
        self.__my_address = address
        self.__up_time = time.time()
        self.__user_id = user_id
        self.__is_ipv6 = is_ipv6

        self.set_socket(s)
        self.bind(bind_addr)

        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def udp_readable(self, message, address):
        _id = address[0]
        if _id not in self.__map: return
        self.dispatcher.send_udp_msg_to_tunnel(self.__user_id, address, self.__my_address, message,
                                               is_ipv6=self.__is_ipv6)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        now = time.time()
        if now - self.__up_time < 120:
            self.set_timeout(self.fileno, 10)
            return
        self.dispatcher.udp_del(self.__user_id, self.__my_address)
        self.delete_handler(self.fileno)

    def udp_error(self):
        self.dispatcher.udp_del(self.__user_id, self.__my_address)
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def send_msg(self, message: bytes, address: tuple):
        _id = address[0]
        if _id not in self.__map:
            if self.__cur_conns == self.__max_conns: return
            self.__cur_conns += 1
            self.__map[_id] = None
        self.__up_time = time.time()
        self.sendto(message, address)
        self.add_evt_write(self.fileno)

    def is_tcp(self):
        """考虑隧道fd被重复使用的情况
        """
        return False

    def is_tunnel_handler(self):
        return False
