#!/usr/bin/env python3

import socket, struct


def byte_hwaddr_to_str(byte_hwaddr: bytes):
    """硬件地址转换成字符串类型
    """
    seq = []
    for i in byte_hwaddr:
        s = hex(i)
        s = s[2:]
        if len(s) < 2: s = "0%s" % s
        seq.append(s)

    return ":".join(seq)


def str_hwaddr_to_bytes(s: str):
    seq = s.split(":")
    new_seq = []

    for x in seq:
        t = "0x%s" % x
        n = int(t, 16)
        new_seq.append(n)

    return bytes(new_seq)


def is_hwaddr(s: str):
    """检查是否是硬件地址
    """
    _list = s.split(":")
    if len(_list) != 6: return False
    result = True
    for x in _list:
        t = "0x%s" % x
        try:
            v = int(t, 16)
        except ValueError:
            result = False
            break
        if v < 0:
            result = False
            break
        ''''''
    return result


def ip_prefix_convert(n, is_ipv6=False):
    """转换IP地址前缀
    :param n:
    :param is_ipv6
    :return:
    """
    seq = []
    cnt = 4

    if is_ipv6: cnt = 16

    a = int(n / 8)
    b = n % 8

    for i in range(a):
        seq.append(0xff)

    v = 0
    for i in range(b):
        v |= 1 << (7 - i)

    seq.append(v)

    if len(seq) < cnt:
        for i in range(cnt - len(seq)):
            seq.append(0x00)

    if is_ipv6:
        return socket.inet_ntop(socket.AF_INET6, bytes(seq)[0:cnt])

    return socket.inet_ntop(socket.AF_INET, bytes(seq)[0:cnt])


def parse_ip_with_prefix(ip):
    """example:  x.x.x.x/prefix
    :param ip:
    :param is_ipv6:
    :return:
    """
    p = ip.find("/")
    if p < 2: return None

    addr = ip[0:p]
    p += 1
    s_prefix = ip[p:]

    try:
        prefix = int(s_prefix)
    except ValueError:
        return None

    return (addr, prefix,)


def check_ipaddr(ip, prefix, is_ipv6=False):
    import socket

    if is_ipv6:
        fa = socket.AF_INET6
    else:
        fa = socket.AF_INET

    try:
        socket.inet_pton(fa, ip)
    except:
        return False

    if prefix < 0: return False

    if is_ipv6 and prefix > 128: return False
    if not is_ipv6 and prefix > 32: return False

    return True


def calc_subnet(ip, prefix, is_ipv6=False):
    if is_ipv6:
        af = socket.AF_INET6
        n = 16
    else:
        af = socket.AF_INET
        n = 4

    msk = ip_prefix_convert(prefix, is_ipv6=is_ipv6)

    try:
        n_ip = socket.inet_pton(af, ip)
        n_msk = socket.inet_pton(af, msk)
    except:
        return None

    results = []

    for i in range(n):
        results.append(n_ip[i] & n_msk[i])

    return socket.inet_ntop(af, bytes(results))


def is_subnet(ip, prefix, subnet, is_ipv6=False):
    return calc_subnet(ip, prefix, is_ipv6=is_ipv6) == subnet


def is_same_network(ip_a: str, ip_b: str, prefix: int, is_ipv6=False):
    """判断连个ip地址是否处在相同的网络
    """
    subnet_a = calc_subnet(ip_a, prefix, is_ipv6=is_ipv6)
    subnet_b = calc_subnet(ip_b, prefix, is_ipv6=is_ipv6)

    return subnet_a == subnet_b


def is_mask(s: str):
    """检查是否是掩码格式
    """
    _list = s.split(".")
    if len(_list) != 4: return False
    result = True
    masks = [
        0b1111_1111,
        0b1111_1110,
        0b1111_1100,
        0b1111_1000,
        0b1111_0000,

        0b1110_0000,
        0b1100_0000,
        0b1000_0000,
        0b0000_0000
    ]

    last_value = 0xff

    for x in _list:
        try:
            v = int(x)
        except ValueError:
            result = False
            break
        if v not in masks:
            result = False
            break
        if last_value != 0xff and v != 0:
            result = False
            break

    return result


def is_port_number(n):
    """检查是否是端口号
    :param n:
    :return:
    """
    try:
        v = int(n)
    except ValueError:
        return False

    if v > 0xffff or v < 1: return False

    return True


def is_ipv4_address(sts_ipaddr):
    """检查是否是IPv4地址"""
    if not isinstance(sts_ipaddr, str): return False
    if len(sts_ipaddr) < 7: return False

    seq = sts_ipaddr.split(".")
    if len(seq) != 4: return False

    for c in seq:
        try:
            v = int(c)
            if v > 255: return False
        except ValueError:
            return False
        ''''''
    try:
        socket.inet_aton(sts_ipaddr)
    except OSError:
        return False
    return True


def is_ipv6_address(sts_ipaddr):
    """检查是否是IPv6地址"""
    if not isinstance(sts_ipaddr, str): return False
    if sts_ipaddr.find(":") < 0: return False
    seq = sts_ipaddr.split(":")

    for s in seq:
        if not s: continue
        s = "0x%s" % s
        try:
            int(s, 16)
        except ValueError:
            return False

    try:
        socket.inet_pton(socket.AF_INET6, sts_ipaddr)
    except OSError:
        return False
    return True


def mask_to_prefix(mask: str, is_ipv6=False):
    """掩码地址转换成prefix
    """
    map_values = {
        0b1111_1111: 8,
        0b1111_1110: 7,
        0b1111_1100: 6,
        0b1111_1000: 5,
        0b1111_0000: 4,
        0b1110_0000: 3,
        0b1100_0000: 2,
        0b1000_0000: 1,
        0b0000_0000: 0
    }

    if is_ipv6:
        fa = socket.AF_INET6
    else:
        fa = socket.AF_INET
    byte_mask = socket.inet_pton(fa, mask)
    old_value = None
    prefix = 0

    for x in byte_mask:
        if old_value is not None:
            if x != 0 and old_value != 0xff: return None
        if x not in map_values: return None
        old_value = x
        prefix += map_values[x]

    return prefix
