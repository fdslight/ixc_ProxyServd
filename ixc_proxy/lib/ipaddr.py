#!/usr/bin/env python3
"""
分配与释放IP地址
"""

import socket
from ixc_proxy import lib as utils


class IpaddrNoEnoughErr(Exception):
    """IP地址资源不够
    """
    pass


"""
class ipalloc(object):
    __no_use_iplist = None
    __subnet = None
    __subnet_num = None
    __prefix = None
    __prefix_num = None

    __cur_max_ipaddr_num = None

    __is_ipv6 = None

    __fa = None

    def __init__(self, subnet, prefix, is_ipv6=False):

        self.__no_use_iplist_num = []
        self.__subnet = subnet
        self.__prefix = prefix
        self.__is_ipv6 = is_ipv6

        if not is_ipv6:
            self.__fa = socket.AF_INET
            self.__cur_max_ipaddr_num = utils.bytes2number(socket.inet_pton(socket.AF_INET, subnet))
            self.__prefix_num = utils.calc_net_prefix_num(prefix)
        else:
            self.__fa = socket.AF_INET6
            self.__cur_max_ipaddr_num = utils.bytes2number(socket.inet_pton(socket.AF_INET6, subnet))
            self.__prefix_num = utils.calc_net_prefix_num(prefix, is_ipv6=True)

        self.__subnet_num = self.__cur_max_ipaddr_num
        return

    def put_addr(self, byte_ip):
        n = utils.bytes2number(byte_ip)

        if n == self.__cur_max_ipaddr_num:
            self.__cur_max_ipaddr_num -= 1
            return
        self.__no_use_iplist_num.append(n)

    def get_addr(self):
        if self.__no_use_iplist: return self.__no_use_iplist.pop(0)
        size = 4
        if self.__is_ipv6: size = 16

        self.__cur_max_ipaddr_num += 1
        byte_ip = utils.number2bytes(self.__cur_max_ipaddr_num, size)

        if self.__cur_max_ipaddr_num & self.__prefix_num != self.__subnet_num:
            raise IpaddrNoEnoughErr("not enough ip address")

        return byte_ip
"""


class ipalloc(object):
    __byte_subnet = None
    __byte_subnet_max = None
    __byte_subnet_cur = None
    __emptys = None

    def __init__(self, subnet, prefix, is_ipv6=False):
        self.__emptys = {}

        if is_ipv6:
            fa = socket.AF_INET6
        else:
            fa = socket.AF_INET

        subnet = utils.calc_subnet(subnet, prefix, is_ipv6=is_ipv6)
        self.__byte_subnet = socket.inet_pton(fa, subnet)
        s = utils.get_ip_addr_max(subnet, prefix, is_ipv6=is_ipv6)
        # 最后一个IP地址是广播地址,保留
        self.__byte_subnet_max = utils.ip_addr_minus(socket.inet_pton(fa, s))
        # 子网为基地址，需要加1
        self.__byte_subnet_cur = utils.ip_addr_plus(self.__byte_subnet)

    def put_addr(self, byte_ip):
        if byte_ip in self.__emptys: return
        self.__emptys[byte_ip] = None

    def get_addr(self):
        byte_ip = None
        if self.__emptys:
            for k in self.__emptys:
                byte_ip = k
                break
            del self.__emptys[byte_ip]
            return byte_ip

        if self.__byte_subnet_cur == self.__byte_subnet_max:
            raise IpaddrNoEnoughErr("not enough ip address")

        byte_ip = self.__byte_subnet_cur
        self.__byte_subnet_cur = utils.ip_addr_plus(byte_ip)

        return byte_ip


"""
byte_ip = socket.inet_pton(socket.AF_INET, "255.255.255.255")
byte_ip = utils.ip_addr_plus(byte_ip)
a = socket.inet_ntop(socket.AF_INET, byte_ip)
b = utils.ip_addr_minus(byte_ip)
b = socket.inet_ntop(socket.AF_INET, b)
print(a, b)
"""
"""
print(utils.get_ip_addr_max("192.168.2.0",23))
"""
"""
cls = ip_alloc("192.168.1.0", 24)
ip_a = cls.get_addr()
ip_b = cls.get_addr()
print(socket.inet_ntop(socket.AF_INET, ip_a))
print(socket.inet_ntop(socket.AF_INET, ip_b))

cls.put_addr(ip_b)
cls.put_addr(ip_a)

ip_a = cls.get_addr()
ip_b = cls.get_addr()
print(socket.inet_ntop(socket.AF_INET, ip_a))
print(socket.inet_ntop(socket.AF_INET, ip_b))
"""
