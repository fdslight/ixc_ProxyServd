#!/usr/bin/env python3

import struct

HEADER_FMT = "!HHHHHH"


def is_aaaa_request(dnspkt: bytes):
    xid, flags, questions, answer_rrs, authority_rrs, add_rrs = struct.unpack(HEADER_FMT, dnspkt[0:12])

    # 检查QR值
    if flags & 0x8000 != 0: return False
    # 一般AAAA查询或者A查询都只有一个问题
    if questions != 1: return False

    is_aaaa = False
    dns_fmt_ok = False
    dnspkt = dnspkt[12:]

    while 1:
        try:
            length = dnspkt[0]
        except IndexError:
            break

        offset = length + 1
        dnspkt = dnspkt[offset:]

        if length == 0:
            dns_fmt_ok = True
            break
        ''''''
    if not dns_fmt_ok: return False
    if len(dnspkt) < 4: return False

    _type, = struct.unpack("!H", dnspkt[0:2])

    if _type == 28: is_aaaa = True

    return is_aaaa


"""
zz = "7d710100000100000000000003777777036d736e02636e0000010001"
seq = []
b, e = (0, 2,)
while 1:
    s = zz[b:e]
    if not s: break
    s = "0x%s" % s
    n = int(s, 16)
    seq.append(n)
    b = e
    e += 2

dnspkt = bytes(seq)
print(is_aaaa_request(dnspkt))
"""