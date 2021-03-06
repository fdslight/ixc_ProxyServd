#!/usr/bin/env python3

import socket


def is_number(value):
    """是否是数字
    """
    if value == None: return False
    try:
        int(value)
    except ValueError:
        return False

    return True


def is_port(value):
    if not is_number(value): return False

    v = int(value)
    if v < 1: return False
    if v > 0xffff: return False

    return True


def is_ipv4(s):
    try:
        socket.inet_pton(socket.AF_INET, s)
    except:
        return False

    return True


def is_ipv6(s):
    try:
        socket.inet_pton(socket.AF_INET6, s)
    except:
        return False

    return True
