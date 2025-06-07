#!/usr/bin/env python3

import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, time


class client(udp_handler.udp_handler):
    __my_address = None
    __up_time = None
    __user_id = None

    __is_ipv6 = None
    __is_udplite = False

    def init_func(self, creator_fd, user_id: bytes, address: tuple, is_ipv6=False, is_udplite=False):
        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET
        if is_udplite:
            s = socket.socket(fa, socket.SOCK_DGRAM)
        else:
            s = socket.socket(fa, socket.SOCK_DGRAM, socket.IPPROTO_UDPLITE)

        if is_ipv6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            bind_addr = ("::", 0, 0, 0)
        else:
            bind_addr = ("0.0.0.0", 0)

        self.__my_address = address
        self.__up_time = time.time()
        self.__user_id = user_id
        self.__is_ipv6 = is_ipv6
        self.__is_udplite = is_udplite

        self.set_socket(s)
        # 可能出现操作系统端口被用尽的情况
        try:
            self.bind(bind_addr)
        except OSError:
            self.close()
            return -1

        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        return self.fileno

    def udp_readable(self, message, address):
        _id = address[0]
        self.dispatcher.send_udp_msg_to_tunnel(self.__user_id, address, self.__my_address, message,
                                               is_ipv6=self.__is_ipv6, is_udplite=self.__is_udplite)

    def udp_writable(self):
        print("ZZZZZZZZZZZZZZZZZZZZ")
        self.remove_evt_write(self.fileno)

    def udp_timeout(self):
        now = time.time()
        if now - self.__up_time < 120:
            self.set_timeout(self.fileno, 10)
            return
        self.dispatcher.udp_del(self.__user_id, self.__my_address)
        self.delete_handler(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.dispatcher.udp_del(self.__user_id, self.__my_address)
        self.unregister(self.fileno)
        self.close()

    def send_msg(self, message: bytes, address: tuple):
        self.__up_time = time.time()
        self.sendto(message, address)
        self.add_evt_write(self.fileno)

    def is_tcp(self):
        """考虑隧道fd被重复使用的情况
        """
        return False

    def is_tunnel_handler(self):
        return False
