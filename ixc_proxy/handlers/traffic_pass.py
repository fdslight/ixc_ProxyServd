#!/usr/bin/env python3
"""实现P2P代理,让非白名单的IP地址走代理"""
import pywind.evtframework.handlers.handler as handler
import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, os, time
import ixc_proxy.lib.fdsl_ctl as fdsl_ctl
import ixc_proxy.lib.ippkts as ippkts
import ixc_proxy.lib.utils as utils


class traffic_read(handler.handler):
    """读取局域网的源数据包"""
    __tunnel_fd = -1

    def init_func(self, creator_fd, gw_configs, enable_ipv6=False):
        """
        :param creator_fd:
        :param tunnel_ip: 隧道IPV4或者IPV6地址
        :param gw_configs:
        :param enable_ipv6:是否开启ipv6支持
        :return:
        """
        dgram_proxy_subnet, prefix = utils.extract_subnet_info(gw_configs["dgram_proxy_subnet"])
        dgram_proxy_subnet6, prefix6 = utils.extract_subnet_info(gw_configs["dgram_proxy_subnet6"])

        dev_path = "/dev/%s" % fdsl_ctl.FDSL_DEV_NAME
        fileno = os.open(dev_path, os.O_RDONLY)

        subnet = utils.calc_subnet(dgram_proxy_subnet, prefix, is_ipv6=False)
        subnet6 = utils.calc_subnet(dgram_proxy_subnet6, prefix6, is_ipv6=True)

        byte_subnet = socket.inet_aton(subnet)
        byte_subnet6 = socket.inet_pton(socket.AF_INET6, subnet6)

        r = fdsl_ctl.set_udp_proxy_subnet(fileno, byte_subnet, prefix, False)

        if enable_ipv6:
            r = fdsl_ctl.set_udp_proxy_subnet(fileno, byte_subnet6, prefix, True)
        self.__tunnel_fd = creator_fd

        self.set_fileno(fileno)
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def set_tunnel_ip(self, tunnel_ip):
        if utils.is_ipv6_address(tunnel_ip):
            r = fdsl_ctl.set_tunnel(self.fileno, socket.inet_pton(socket.AF_INET6, tunnel_ip), True)
        else:
            r = fdsl_ctl.set_tunnel(self.fileno, socket.inet_aton(tunnel_ip), False)

        return

    def evt_read(self):
        n = 0
        while n < 5:
            try:
                pkt = os.read(self.fileno, 8192)
                self.dispatcher.handle_msg_from_dgramdev(pkt)
            except BlockingIOError:
                break
            n += 1
            if not pkt: continue
        return

    def delete(self):
        self.unregister(self.fileno)
        os.close(self.fileno)


class ip4_raw_send(handler.handler):
    """把数据包发送到局域网的设备"""
    __creator_fd = -1
    __sent = None
    __socket = None

    def init_func(self, creator_fd):
        self.__creator_fd = creator_fd
        self.__sent = []

        family = socket.AF_INET

        s = socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_UDP | socket.IPPROTO_ICMP | socket.IPPROTO_UDP | 136)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.setblocking(0)

        self.__socket = s
        self.set_fileno(s.fileno())
        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        return self.fileno

    def evt_read(self):
        """丢弃所有收到的包"""
        while 1:
            try:
                _ = self.__socket.recvfrom(8192)
            except BlockingIOError:
                break
            ''''''
        return

    def evt_write(self):
        if not self.__sent: self.remove_evt_write(self.fileno)

        while 1:
            try:
                ippkt = self.__sent.pop(0)
            except IndexError:
                break

            ip_ver = (ippkt[0] & 0xf0) >> 4
            # 目前只支持IPv4
            if ip_ver != 4: continue

            dst_addr_pkt = ippkt[16:20]
            dst_addr = socket.inet_ntoa(dst_addr_pkt)
            pkt_len = (ippkt[2] << 8) | ippkt[3]
            try:
                sent_len = self.__socket.sendto(ippkt, (dst_addr, 0))
            except BlockingIOError:
                self.__sent.insert(0, ippkt)
                return

            if pkt_len > sent_len:
                self.__sent.insert(0, ippkt)
                break
            ''''''
        return

    def message_from_handler(self, from_fd, byte_data):
        self.add_evt_write(self.fileno)
        self.__sent.append(byte_data)

    def delete(self):
        self.unregister(self.fileno)
        self.__socket.close()


class p2p_proxy(udp_handler.udp_handler):
    # 代理超时时间
    __PROXY_TIMEOUT = 180
    __LOOP_TIMEOUT = 10

    __internal_ip = None
    __byte_internal_ip = None
    __port = None

    # 允许发送的对端机器
    __permits = None

    __update_time = 0

    __session_id = None
    __is_udplite = False

    __is_ipv6 = False
    __packets = None
    __mtu = None

    def init_func(self, creator_fd, session_id, internal_address, mtu=1500, is_udplite=False, is_ipv6=False):
        if not is_udplite:
            proto = 17
        else:
            proto = 136

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        self.__is_udplite = is_udplite
        self.__is_ipv6 = is_ipv6
        self.__update_time = time.time()
        self.__internal_ip = internal_address[0]
        self.__byte_internal_ip = socket.inet_pton(fa, self.__internal_ip)
        self.__port = internal_address[1]
        self.__packets = []
        self.__mtu = mtu

        try:
            s = socket.socket(fa, socket.SOCK_DGRAM, proto)
        except OSError:
            return -1
        self.__permits = {}

        self.set_socket(s)

        if is_ipv6:
            self.bind(("::", 0))
        else:
            self.bind(("0.0.0.0", 0))

        self.register(self.fileno)
        self.add_evt_read(self.fileno)

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)
        self.__session_id = session_id

        return self.fileno

    def udp_readable(self, message, address):
        addr_id = "%s-%s" % address

        if addr_id not in self.__permits: return

        n_saddr = socket.inet_aton(address[0])
        sport = address[1]

        udp_packets = ippkts.build_udp_packets(n_saddr, self.__byte_internal_ip, sport, self.__port, message,
            mtu=self.__mtu, is_udplite=self.__is_udplite, is_ipv6=self.__is_ipv6)

        self.__packets += udp_packets
        self.__send_to_tunnel()

    def task_loop(self):
        self.__send_to_tunnel()

    def __send_to_tunnel(self):
        try:
            pkt = self.__packets.pop(0)
        except IndexError:
            self.del_loop_task(self.fileno)
            return
        self.add_to_loop_task(self.fileno)
        self.dispatcher.send_msg_to_tunnel_from_p2p_proxy(self.__session_id, pkt)

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def udp_error(self):
        self.delete_handler(self.fileno)

    def udp_delete(self):
        self.dispatcher.tell_del_dgram_proxy(self.__session_id, self.__internal_ip, self.__port)
        self.unregister(self.fileno)
        self.close()

    def udp_timeout(self):
        t = time.time()

        if t - self.__update_time > self.__PROXY_TIMEOUT:
            self.delete_handler(self.fileno)
            return

        self.set_timeout(self.fileno, self.__LOOP_TIMEOUT)

    def send_msg(self, message, address):
        self.__update_time = time.time()

        self.add_evt_write(self.fileno)
        self.sendto(message, address)
        self.add_permit(address)

    def add_permit(self, address):
        """允许接收的数据包来源
        :param address: 
        :return: 
        """
        addr_id = "%s-%s" % address
        if addr_id not in self.__permits: self.__permits[addr_id] = None
