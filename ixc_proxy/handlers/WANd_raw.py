#!/usr/bin/env python3
import pywind.evtframework.handlers.tcp_handler as tcp_handler
import socket, time, os, sys
import ixc_proxy.lib.logging as logging


class listener(tcp_handler.tcp_handler):
    __is_ipv6 = None
    __remote_info = None
    __auth_id = None

    def init_func(self, creator_fd, address, auth_id, remote_info, is_ipv6=False):
        self.__is_ipv6 = is_ipv6
        self.__remote_info = remote_info
        self.__auth_id = auth_id

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

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
            self.create_handler(self.fileno, handler, cs, caddr, self.__auth_id, self.__remote_info)

    def tcp_error(self):
        self.delete_handler(self.fileno)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()


class handler(tcp_handler.tcp_handler):
    __remote_info = None
    __caddr = None
    __auth_id = None
    __time = None

    __timeout = None
    __session_id = None

    __wait_fwd_data = None
    __conn_ok = None

    __wait_sent = None

    def init_func(self, creator_fd, cs, caddr, auth_id, remote_info):
        self.__caddr = caddr
        self.__remote_info = remote_info
        self.__auth_id = auth_id
        self.__time = time.time()
        self.__timeout = remote_info["timeout"]
        self.__wait_fwd_data = []
        self.__conn_ok = False
        self.__wait_sent = []

        remote_addr = remote_info["address"]
        remote_port = remote_info["port"]
        is_ipv6 = remote_info["is_ipv6"]

        self.set_socket(cs)

        self.__session_id = self.dispatcher.send_conn_request(self.fileno, auth_id, remote_addr, remote_port,
                                                              is_ipv6=is_ipv6)
        if not self.__session_id:
            sys.stderr.write("send conn request fail from auth_id:%s\r\n" % auth_id)
            self.close()
            return -1

        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)

        self.tcp_loop_read_num = 200
        logging.print_general("accepted", self.__caddr)

        return self.fileno

    def tcp_readable(self):
        rdata = self.reader.read()
        if self.__conn_ok:
            self.__time = time.time()
        else:
            self.__wait_sent.append(rdata)
            return
        self.dispatcher.send_data_to_msg_tunnel(self.__session_id, rdata)

    def tcp_writable(self):
        if self.writer.is_empty(): self.remove_evt_write(self.fileno)

    def tcp_timeout(self):
        t = time.time()

        if not self.__conn_ok:
            self.dispatcher.tell_session_close(self.__session_id)
            self.delete_handler(self.fileno)
            return

        if t - self.__time > self.__timeout:
            self.dispatcher.tell_session_close(self.__session_id)
            return

        self.set_timeout(self.fileno, 10)

    def tcp_error(self):
        self.dispatcher.tell_session_close(self.__session_id)

    def tcp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def tell_conn_ok(self):
        self.__conn_ok = True
        while 1:
            try:
                byte_data = self.__wait_sent.pop(0)
            except IndexError:
                break
            self.dispatcher.send_data_to_msg_tunnel(self.__session_id, byte_data)

    def send_data(self, byte_data):
        self.__time = time.time()
        self.add_evt_write(self.fileno)
        self.writer.write(byte_data)
        self.send_now()

    def message_from_handler(self, from_fd, byte_data):
        self.send_data(byte_data)
