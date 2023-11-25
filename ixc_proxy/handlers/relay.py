#!/usr/bin/env python3
import time, socket

import pywind.evtframework.handlers.tcp_handler as tcp_handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import ixc_proxy.lib.logging as logging

TIMEOUT = 75


class tcp_listener(tcp_handler.tcp_handler):
    __redirect_is_ipv6 = None
    __redirect_address = None
    __redirect_slave_address = None
    __master_node_ok = None

    def init_func(self, creator_fd, address, redirect_address, listen_is_ipv6=False, redirect_is_ipv6=False,
                  tcp_redirect_slave=None, **kwargs):
        if listen_is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_STREAM)
        if listen_is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.__redirect_is_ipv6 = redirect_is_ipv6
        self.__redirect_address = redirect_address
        self.__redirect_slave_address = tcp_redirect_slave
        self.__master_node_ok = True

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

            is_slave = False
            if self.__redirect_slave_address:
                if self.__master_node_ok:
                    redirect_address = self.__redirect_address
                    logging.print_general("use tcp master node", redirect_address)
                else:
                    redirect_address = self.__redirect_slave_address
                    logging.print_general("use tcp slave node", redirect_address)
                    is_slave = True
            else:
                redirect_address = self.__redirect_address

            self.create_handler(self.fileno, redirect_tcp_handler, cs, caddr, redirect_address,
                                is_ipv6=self.__redirect_is_ipv6, is_slave=is_slave)
            ''''''
        ''''''

    def tell_master_status(self, is_ok: bool):
        # 如果未设置从节点的值,那么忽略
        if self.__redirect_slave_address: self.__master_node_ok = is_ok


class redirect_tcp_handler(tcp_handler.tcp_handler):
    __caddr = None
    __redirect_fd = None

    __time = None
    __traffic_size = None
    __creator = None
    __is_slave = None

    def init_func(self, creator_fd, cs, caddr, redirect_addr, is_ipv6=False, is_slave=False):
        self.__time = time.time()
        self.__traffic_size = 0

        self.set_socket(cs)
        self.__caddr = caddr
        self.__creator = creator_fd
        self.__is_slave = is_slave
        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 10)
        cs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        self.__redirect_fd = self.create_handler(self.fileno, redirect_tcp_client, redirect_addr, is_ipv6=is_ipv6)
        if self.__redirect_fd < 0:
            logging.print_error(
                "cannot create redirect socket for redirect %s,%s" % (redirect_addr[0], redirect_addr[1],))
            self.delete_handler(self.fileno)
            return
        logging.print_general("connected_from", (caddr[0], caddr[1],))

        return self.fileno

    def tcp_readable(self):
        self.__time = time.time()
        if not self.dispatcher.have_traffic():
            self.delete_handler(self.fileno)
            return
        self.__traffic_size += self.reader.size()
        self.dispatcher.traffic_statistics(self.reader.size())
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
            master_ok = False
            # 让master和slave之间反复切换,如果无法连接
            if self.__is_slave: master_ok = True
            self.get_handler(self.__creator).tell_master_status(master_ok)
            self.delete_handler(self.fileno)
            return

        if cmd == "conn_close":
            self.delete_handler(self.fileno)
            return
        ''''''


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
        try:
            self.connect(address)
        except socket.gaierror:
            self.close()
            return -1

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
        cmd = "conn_close"
        if not self.is_conn_ok():
            cmd = "conn_err"
        self.ctl_handler(self.fileno, self.__creator, cmd)

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

    __udp_heartbeat_address = None

    def init_func(self, creator_fd, address, redirect_address, listen_is_ipv6=False, redirect_is_ipv6=False,
                  udp_heartbeat_address=None, **kwargs):
        self.__session_fds = {}
        self.__session_fds_reverse = {}

        if not udp_heartbeat_address:
            self.__udp_heartbeat_address = []
        else:
            self.__udp_heartbeat_address = udp_heartbeat_address

        if listen_is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if listen_is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.__redirect_is_ipv6 = redirect_is_ipv6
        self.__redirect_address = redirect_address

        self.set_socket(s)
        self.bind(address)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, 10)
        self.send_heartbeat_to_clients()

        return self.fileno

    def send_heartbeat_to_clients(self):
        """向所有客户端发送一个字节的数据
        """
        for c_addr, port in self.__udp_heartbeat_address:
            # 这里c_addr建议不要使用域名,域名查询会导致阻塞
            try:
                self.sendto(b"\0", (c_addr, port,))
            except socket.gaierror:
                continue
        self.add_evt_write(self.fileno)

    def udp_readable(self, message, address):
        # 丢弃心跳包
        if message == b"\0": return

        if not self.dispatcher.have_traffic():
            self.delete_handler(self.fileno)
            return

        self.dispatcher.traffic_statistics(len(message))
        name = "%s-%s" % (address[0], address[1],)
        if name in self.__session_fds_reverse:
            fd = self.__session_fds_reverse[name]
            self.send_message_to_handler(self.fileno, fd, message)
            return
        fd = self.create_handler(self.fileno, redirect_udp_client, self.__redirect_address,
                                 is_ipv6=self.__redirect_is_ipv6)
        if fd < 0:
            logging.print_error("cannot create redirect udp client for redirect %s,%s" % (
                self.__redirect_address[0], self.__redirect_address[1],))
            return
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
            address = self.__session_fds[from_fd]
            name = "%s-%s" % (address[0], address[1],)
            self.delete_handler(from_fd)
            del self.__session_fds[from_fd]
            del self.__session_fds_reverse[name]
        return

    def message_from_handler(self, from_fd, data):
        self.dispatcher.traffic_statistics(len(data))
        # 找不到直接丢弃数据包
        if from_fd not in self.__session_fds: return

        addr = self.__session_fds[from_fd]
        self.sendto(data, addr)
        self.add_evt_write(self.fileno)

    def udp_timeout(self):
        self.set_timeout(self.fileno, 10)
        self.send_heartbeat_to_clients()


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

        s = socket.socket(fa, socket.SOCK_DGRAM)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.set_socket(s)

        try:
            self.connect(address)
        except socket.gaierror:
            self.close()
            return -1

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
        self.handler_ctl(self.__creator, "conn_err")

    def udp_delete(self):
        self.unregister(self.fileno)
        self.close()

    def udp_timeout(self):
        t = time.time()

        if t - self.__time > TIMEOUT:
            self.handler_ctl(self.__creator, "conn_err")
        return

    def message_from_handler(self, from_fd, data):
        self.send(data)
        self.add_evt_write(self.fileno)
