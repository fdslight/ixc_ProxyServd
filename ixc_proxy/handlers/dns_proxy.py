#!/usr/bin/env python3
import pywind.evtframework.handlers.udp_handler as udp_handler
import socket, struct, time


class dns_client(udp_handler.udp_handler):
    __dns_server = None

    __map = None

    __cur_dns_id = None

    def get_dns_id(self):
        self.__cur_dns_id += 1
        if self.__cur_dns_id == 0xffff:
            self.__cur_dns_id = 1

        return self.__cur_dns_id

    def init_func(self, creator_fd, dnsserver: str, is_ipv6=False):
        self.__dns_server = dnsserver
        self.__map = {}
        self.__cur_dns_id = 0

        if is_ipv6:
            fa = socket.AF_INET6
            bind_addr = "::"
        else:
            fa = socket.AF_INET
            bind_addr = "0.0.0.0"

        s = socket.socket(fa, socket.SOCK_DGRAM)
        self.set_socket(s)
        if is_ipv6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.bind((bind_addr, 0))

        self.register(self.fileno)
        self.add_evt_read(self.fileno)
        self.set_timeout(self.fileno, 5)

        return self.fileno

    def udp_readable(self, message, address):
        # 此处检查地址是否是DNS服务器
        if address[0] != self.__dns_server: return
        if address[1] != 53: return
        if len(message) < 8: return

        wan_dns_id, = struct.unpack("!H", message[0:2])
        # 不在映射记录表里那么删除记录
        if wan_dns_id not in self.__map: return
        o = self.__map[wan_dns_id]
        lan_dns_id = o["dns_id"]
        _id = o["id"]

        _list = [
            struct.pack("!H", lan_dns_id),
            message[2:]
        ]
        del self.__map[wan_dns_id]
        self.dispatcher.handle_dns_msg_from_server(_id, b"".join(_list))

    def udp_writable(self):
        self.remove_evt_write(self.fileno)

    def send_msg(self, _id: bytes, messsage: bytes):
        if len(messsage) < 8: return
        lan_dns_id, = struct.unpack("!H", messsage[0:2])

        flags = False
        wan_dns_id = 0
        # 查找是否有可用的DNS ID
        for i in range(10):
            wan_dns_id = self.get_dns_id()
            if wan_dns_id not in self.__map:
                flags = True
                break
            continue
        if not flags: return
        self.__map[wan_dns_id] = {"dns_id": lan_dns_id, "id": _id, "time": time.time()}

        _list = [
            struct.pack("!H", wan_dns_id),
            messsage[2:],
        ]
        self.sendto(b"".join(_list), (self.__dns_server, 53))
        self.add_evt_write(self.fileno)

    def udp_timeout(self):
        dels = []
        now = time.time()
        for wan_dns_id in self.__map:
            o = self.__map[wan_dns_id]
            t = o["time"]
            if now - t >= 5: dels.append(wan_dns_id)
        for wan_dns_id in dels: del self.__map[wan_dns_id]
        self.set_timeout(self.fileno, 5)
